package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/monitoring"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

// Service is the AI review service (HTTP handlers and pipeline).
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Secrets   *secrets.Store
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	HTTP      *http.Client
	// LocalHTTP is used for self-hosted providers: it may reach private
	// networks (but never loopback, link-local or metadata addresses).
	LocalHTTP *http.Client
	// NewProvider builds providers; tests replace it.
	NewProvider func(Config) (Provider, error)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("already exists or already queued")
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("a referenced item does not exist")
	case errors.Is(err, ErrAuth), errors.Is(err, ErrRateLimited), errors.Is(err, ErrRefused):
		err = httpx.E(http.StatusBadGateway, "ai_provider_error", err.Error()).WithDiag(DiagCode(err))
	}
	httpx.WriteError(w, r, s.Log, err)
}

func pathID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return uuid.Nil, errNotFound
	}
	return id, nil
}

func (s *Service) requireOrg(r *http.Request, perm authz.Permission) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if err := s.Authz.Require(r.Context(), p, perm, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}); err != nil {
		return nil, err
	}
	return p, nil
}

// requireFinding checks perm on the finding's repository.
func (s *Service) requireFinding(ctx context.Context, p *authz.Principal, perm authz.Permission, findingID uuid.UUID) (uuid.UUID, error) {
	var repo uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT repository_id FROM findings WHERE organization_id = $1 AND id = $2`, p.OrganizationID, findingID).Scan(&repo); err != nil {
		return repo, errNotFound
	}
	err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: repo})
	if errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(perm) {
		return repo, errNotFound
	}
	return repo, err
}

// Register mounts the user API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/ai/providers", s.listProviders)
	mux.HandleFunc("POST /api/v1/ai/providers", s.createProvider)
	mux.HandleFunc("POST /api/v1/ai/providers/{id}/test", s.testProvider)
	mux.HandleFunc("DELETE /api/v1/ai/providers/{id}", s.deleteProvider)
	mux.HandleFunc("GET /api/v1/ai/configurations", s.listConfigs)
	mux.HandleFunc("POST /api/v1/ai/configurations", s.saveConfig)
	mux.HandleFunc("PUT /api/v1/ai/configurations/{id}", s.saveConfig)
	mux.HandleFunc("POST /api/v1/findings/{id}/ai-review", s.requestReview)
	mux.HandleFunc("GET /api/v1/findings/{id}/ai-reviews", s.findingReviews)
	mux.HandleFunc("GET /api/v1/ai/reviews", s.listReviews)
	mux.HandleFunc("POST /api/v1/ai/reviews/{id}/approve", s.approve)
	mux.HandleFunc("POST /api/v1/ai/reviews/{id}/reject", s.reject)
}

// --- providers ---------------------------------------------------------------

type ProviderView struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Kind          string    `json:"kind"`
	BaseURL       string    `json:"base_url"`
	Status        string    `json:"status"`
	StatusMessage string    `json:"status_message"`
	DefaultModel  string    `json:"default_model"`
	CreatedAt     time.Time `json:"created_at"`
	secretID      *uuid.UUID
}

func (s *Service) loadProviders(ctx context.Context, orgID uuid.UUID, id *uuid.UUID) ([]ProviderView, error) {
	rows, err := s.DB.Query(ctx, `SELECT id, name, kind, base_url, status, status_message, created_at, secret_id FROM ai_providers
		WHERE organization_id = $1 AND archived_at IS NULL AND ($2::uuid IS NULL OR id = $2) ORDER BY name`, orgID, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (ProviderView, error) {
		var p ProviderView
		err := r.Scan(&p.ID, &p.Name, &p.Kind, &p.BaseURL, &p.Status, &p.StatusMessage, &p.CreatedAt, &p.secretID)
		p.DefaultModel = DefaultModel(p.Kind)
		return p, err
	})
}

func (s *Service) listProviders(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermAIReview) && !p.HasOrgWide(authz.PermAIConfigure) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	out, err := s.loadProviders(r.Context(), p.OrganizationID, nil)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []ProviderView{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type providerRequest struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	APIKey  string `json:"api_key"`
	BaseURL string `json:"base_url"`
	Model   string `json:"test_model"`
}

func (s *Service) provider(ctx context.Context, orgID uuid.UUID, pv ProviderView) (Provider, error) {
	var key []byte
	if pv.secretID != nil {
		var err error
		if key, err = s.Secrets.Reveal(ctx, s.DB, orgID, *pv.secretID, secrets.KindAI); err != nil {
			return nil, err
		}
	}
	client := s.HTTP
	if pv.Kind == SelfHosted && s.LocalHTTP != nil {
		client = s.LocalHTTP
	}
	cfg := Config{Kind: pv.Kind, APIKey: string(key), BaseURL: pv.BaseURL, HTTP: client}
	if s.NewProvider != nil {
		return s.NewProvider(cfg)
	}
	return New(cfg)
}

func (s *Service) checkProvider(ctx context.Context, orgID uuid.UUID, pv ProviderView, model string) ProviderView {
	status, msg := "ok", "credentials accepted"
	prov, err := s.provider(ctx, orgID, pv)
	if err == nil {
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err = prov.Validate(cctx, model)
		cancel()
	}
	if err != nil {
		status, msg = "error", err.Error()
	}
	_, _ = s.DB.Exec(ctx, `UPDATE ai_providers SET status = $2, status_message = $3, updated_at = now() WHERE id = $1`, pv.ID, status, msg)
	pv.Status, pv.StatusMessage = status, msg
	return pv
}

func (s *Service) createProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermAIConfigure)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req providerRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Name, req.APIKey, req.BaseURL = strings.TrimSpace(req.Name), strings.TrimSpace(req.APIKey), strings.TrimSpace(req.BaseURL)
	if req.Name == "" || len(req.Name) > 200 || len(req.APIKey) > 1000 || (req.APIKey == "" && req.Kind != SelfHosted) {
		s.fail(w, r, httpx.BadRequest("name and api_key are required"))
		return
	}
	switch req.Kind {
	case Anthropic, OpenAI, XAI:
		if req.BaseURL != "" && !strings.HasPrefix(req.BaseURL, "https://") {
			s.fail(w, r, httpx.BadRequest("base_url must use https"))
			return
		}
	case SelfHosted:
		// Local servers usually speak plain http on a private network.
		if _, err := (scm.NetPolicy{AllowPrivate: true, AllowHTTP: true}).ValidateBaseURL(req.BaseURL); err != nil {
			s.fail(w, r, httpx.BadRequest("base_url: "+err.Error()+" (e.g. http://host.docker.internal:11434/v1 for Ollama on this host)"))
			return
		}
	default:
		s.fail(w, r, httpx.BadRequest("kind must be anthropic, openai, xai or self_hosted"))
		return
	}
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var sec *uuid.UUID
		if req.APIKey != "" {
			id, err := s.Secrets.Create(ctx, tx, p.OrganizationID, secrets.KindAI, "ai:"+req.Name, []byte(req.APIKey), &p.UserID)
			if err != nil {
				return err
			}
			sec = &id
		}
		if _, err := tx.Exec(ctx, `INSERT INTO ai_providers (id, organization_id, name, kind, base_url, secret_id, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, id, p.OrganizationID, req.Name, req.Kind, req.BaseURL, sec, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_provider.create", TargetType: "ai_provider", TargetID: id.String(), Metadata: map[string]any{"name": req.Name, "kind": req.Kind}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pvs, err := s.loadProviders(ctx, p.OrganizationID, &id)
	if err != nil || len(pvs) == 0 {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, s.checkProvider(ctx, p.OrganizationID, pvs[0], req.Model))
}

func (s *Service) testProvider(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireOrg(r, authz.PermAIConfigure)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pvs, err := s.loadProviders(r.Context(), p.OrganizationID, &id)
	if err != nil || len(pvs) == 0 {
		s.fail(w, r, errNotFound)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.checkProvider(r.Context(), p.OrganizationID, pvs[0], r.URL.Query().Get("model")))
}

func (s *Service) deleteProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermAIConfigure)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var inUse bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ai_configurations c JOIN ai_configuration_versions v ON v.id = c.current_version_id
			WHERE c.organization_id = $1 AND c.archived_at IS NULL AND v.provider_id = $2)`, p.OrganizationID, id).Scan(&inUse); err != nil {
			return err
		}
		if inUse {
			return httpx.Conflict("a configuration uses this provider")
		}
		var sec *uuid.UUID
		if err := tx.QueryRow(ctx, `UPDATE ai_providers SET archived_at = now() WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL RETURNING secret_id`,
			p.OrganizationID, id).Scan(&sec); err != nil {
			return err
		}
		if sec != nil { // self-hosted providers may have no key
			if err := s.Secrets.Update(ctx, tx, p.OrganizationID, *sec, secrets.KindAI, []byte("revoked")); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_provider.delete", TargetType: "ai_provider", TargetID: id.String()})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- configurations ------------------------------------------------------------

// ConfigVersion is one immutable AI configuration version.
type ConfigVersion struct {
	ID             uuid.UUID `json:"id"`
	Version        int       `json:"version"`
	ProviderID     uuid.UUID `json:"provider_id"`
	Model          string    `json:"model"`
	Effort         string    `json:"effort"`
	Instructions   string    `json:"instructions"`
	AutoReview     bool      `json:"auto_review"`
	Categories     []string  `json:"categories"`
	MinSeverity    string    `json:"min_severity"`
	ApprovalPolicy string    `json:"approval_policy"`
	// AllowSelfApproval lets the submitter of an interactive (MCP) review
	// approve it (single-person installations).
	AllowSelfApproval bool      `json:"allow_self_approval"`
	DailyLimit        int       `json:"daily_limit"`
	SendCodeContext   bool      `json:"send_code_context"`
	RedactionPatterns []string  `json:"redaction_patterns"`
	ChangeNote        string    `json:"change_note"`
	CreatedAt         time.Time `json:"created_at"`
}

// Configuration with its current version.
type Configuration struct {
	ID        uuid.UUID     `json:"id"`
	Name      string        `json:"name"`
	IsDefault bool          `json:"is_default"`
	Current   ConfigVersion `json:"current"`
	// UsedToday counts automated reviews in the last 24h against the limit.
	UsedToday int `json:"used_today"`
}

const cvSelect = `SELECT v.id, v.version, v.provider_id, v.model, v.effort, v.instructions, v.auto_review, v.categories, v.min_severity,
	v.approval_policy, v.daily_limit, v.send_code_context, v.redaction_patterns, v.change_note, v.created_at, v.allow_self_approval FROM ai_configuration_versions v`

func scanCV(r pgx.Row) (ConfigVersion, error) {
	var v ConfigVersion
	err := r.Scan(&v.ID, &v.Version, &v.ProviderID, &v.Model, &v.Effort, &v.Instructions, &v.AutoReview, &v.Categories,
		&v.MinSeverity, &v.ApprovalPolicy, &v.DailyLimit, &v.SendCodeContext, &v.RedactionPatterns, &v.ChangeNote, &v.CreatedAt, &v.AllowSelfApproval)
	return v, err
}

func (s *Service) listConfigs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermAIReview) && !p.HasOrgWide(authz.PermAIConfigure) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT c.id, c.name, c.is_default, c.current_version_id,
		(SELECT count(*) FROM ai_reviews ar JOIN ai_configuration_versions v ON v.id = ar.config_version_id
		 WHERE v.configuration_id = c.id AND ar.source = 'automated' AND ar.created_at > now() - interval '24 hours')
		FROM ai_configurations c WHERE c.organization_id = $1 AND c.archived_at IS NULL ORDER BY c.is_default DESC, c.name`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type row struct {
		c   Configuration
		cur uuid.UUID
	}
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		err := r.Scan(&x.c.ID, &x.c.Name, &x.c.IsDefault, &x.cur, &x.c.UsedToday)
		return x, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := []Configuration{}
	for _, x := range list {
		if x.c.Current, err = scanCV(s.DB.QueryRow(ctx, cvSelect+` WHERE v.id = $1`, x.cur)); err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, x.c)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type configRequest struct {
	Name      string `json:"name"`
	IsDefault *bool  `json:"is_default"`
	ConfigVersion
}

// categories AI review can be configured for (DAST findings are
// excluded: they carry no source code to review).
var categories = slices.DeleteFunc(slices.Clone(scanners.FindingCategories), func(c string) bool { return c == "dast" })

func (req *configRequest) validate() error {
	v := &req.ConfigVersion
	if v.Effort == "" {
		v.Effort = "medium"
	}
	if !slices.Contains([]string{"low", "medium", "high"}, v.Effort) {
		return httpx.BadRequest("effort must be low, medium or high")
	}
	if v.MinSeverity == "" {
		v.MinSeverity = "medium"
	}
	if !slices.Contains(scanners.Severities, v.MinSeverity) {
		return httpx.BadRequest("invalid min_severity")
	}
	if v.ApprovalPolicy == "" {
		v.ApprovalPolicy = "always"
	}
	if !slices.Contains([]string{"always", "false_positives", "never"}, v.ApprovalPolicy) {
		return httpx.BadRequest("approval_policy must be always, false_positives or never")
	}
	if v.DailyLimit == 0 {
		v.DailyLimit = 200
	}
	if v.DailyLimit < 1 || v.DailyLimit > 100000 {
		return httpx.BadRequest("daily_limit must be between 1 and 100000")
	}
	if len(v.Instructions) > 8000 || len(v.Model) > 200 {
		return httpx.BadRequest("instructions max 8000 characters; model max 200")
	}
	if v.Categories == nil {
		v.Categories = []string{"sast", "sca", "iac"}
	}
	for _, c := range v.Categories {
		if !slices.Contains(categories, c) {
			return httpx.BadRequest("invalid category " + c)
		}
	}
	if v.RedactionPatterns == nil {
		v.RedactionPatterns = []string{}
	}
	if _, err := CompilePatterns(v.RedactionPatterns); err != nil {
		return httpx.BadRequest(err.Error())
	}
	return nil
}

// saveConfig creates a configuration (POST) or a new version of one (PUT).
func (s *Service) saveConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermAIConfigure)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req configRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := req.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	pvs, err := s.loadProviders(ctx, p.OrganizationID, &req.ProviderID)
	if err != nil || len(pvs) == 0 {
		s.fail(w, r, httpx.BadRequest("provider does not exist"))
		return
	}
	if req.Model == "" {
		req.Model = DefaultModel(pvs[0].Kind)
	}
	if req.Model == "" {
		s.fail(w, r, httpx.BadRequest("model is required for "+pvs[0].Kind))
		return
	}
	isNew := r.Method == http.MethodPost
	var id uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		version := 1
		if isNew {
			if strings.TrimSpace(req.Name) == "" {
				return httpx.BadRequest("name is required")
			}
			id = uuid.Must(uuid.NewV7())
			var any bool
			_ = tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ai_configurations WHERE organization_id = $1 AND archived_at IS NULL)`, p.OrganizationID).Scan(&any)
			if _, err := tx.Exec(ctx, `INSERT INTO ai_configurations (id, organization_id, name, is_default) VALUES ($1, $2, $3, $4)`,
				id, p.OrganizationID, strings.TrimSpace(req.Name), !any); err != nil {
				return err
			}
		} else {
			if id, err = pathID(r); err != nil {
				return err
			}
			if err := tx.QueryRow(ctx, `SELECT COALESCE(max(v.version), 0) + 1 FROM ai_configuration_versions v
				JOIN ai_configurations c ON c.id = v.configuration_id WHERE c.id = $1 AND c.organization_id = $2 AND c.archived_at IS NULL`,
				id, p.OrganizationID).Scan(&version); err != nil || version == 1 {
				return errNotFound
			}
			if req.Name != "" {
				if _, err := tx.Exec(ctx, `UPDATE ai_configurations SET name = $2 WHERE id = $1`, id, strings.TrimSpace(req.Name)); err != nil {
					return err
				}
			}
		}
		vid := uuid.Must(uuid.NewV7())
		v := req.ConfigVersion
		if _, err := tx.Exec(ctx, `INSERT INTO ai_configuration_versions (id, organization_id, configuration_id, version, provider_id, model, effort,
			instructions, auto_review, categories, min_severity, approval_policy, daily_limit, send_code_context, redaction_patterns, change_note, created_by,
			allow_self_approval)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
			vid, p.OrganizationID, id, version, v.ProviderID, v.Model, v.Effort, v.Instructions, v.AutoReview, v.Categories,
			v.MinSeverity, v.ApprovalPolicy, v.DailyLimit, v.SendCodeContext, v.RedactionPatterns, v.ChangeNote, p.UserID,
			v.AllowSelfApproval); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ai_configurations SET current_version_id = $2 WHERE id = $1`, id, vid); err != nil {
			return err
		}
		if req.IsDefault != nil && *req.IsDefault {
			if _, err := tx.Exec(ctx, `UPDATE ai_configurations SET is_default = (id = $2) WHERE organization_id = $1 AND archived_at IS NULL`, p.OrganizationID, id); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_configuration.save", TargetType: "ai_configuration", TargetID: id.String(),
			Metadata: map[string]any{"version": version, "model": v.Model, "auto_review": v.AutoReview, "approval_policy": v.ApprovalPolicy,
				"allow_self_approval": v.AllowSelfApproval}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, map[bool]int{true: http.StatusCreated, false: http.StatusOK}[isNew], map[string]any{"id": id})
}

// --- queue & pipeline --------------------------------------------------------

// defaultConfig returns the organization's default configuration version.
func defaultConfig(ctx context.Context, q db.Querier, orgID uuid.UUID) (ConfigVersion, error) {
	return scanCV(q.QueryRow(ctx, cvSelect+` JOIN ai_configurations c ON c.current_version_id = v.id
		WHERE c.organization_id = $1 AND c.is_default AND c.archived_at IS NULL`, orgID))
}

// Enqueue queues a finding for review with the default configuration.
func Enqueue(ctx context.Context, q db.Querier, orgID, findingID uuid.UUID, by *uuid.UUID) error {
	cv, err := defaultConfig(ctx, q, orgID)
	if err != nil {
		return httpx.Conflict("no AI configuration: an administrator must add a provider and a default configuration")
	}
	tag, err := q.Exec(ctx, `INSERT INTO ai_review_queue (id, organization_id, finding_id, config_version_id, requested_by)
		VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`, uuid.Must(uuid.NewV7()), orgID, findingID, cv.ID, by)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		_, err = q.Exec(ctx, `UPDATE findings SET ai_status = 'queued' WHERE id = $1`, findingID)
	}
	return err
}

// OnScanFinished queues new findings of a scan for automatic review when
// the default configuration enables it (within its daily limit).
func (s *Service) OnScanFinished(ctx context.Context, orgID, jobID uuid.UUID) {
	cv, err := defaultConfig(ctx, s.DB, orgID)
	if err != nil || !cv.AutoReview {
		return
	}
	minRank := scanners.SeverityRank(cv.MinSeverity)
	sevs := []string{}
	for _, sv := range scanners.Severities {
		if scanners.SeverityRank(sv) >= minRank {
			sevs = append(sevs, sv)
		}
	}
	tag, err := s.DB.Exec(ctx, `
		WITH used AS (SELECT count(*) AS n FROM ai_review_queue WHERE organization_id = $1 AND enqueued_at > now() - interval '24 hours'),
		picked AS (
		  SELECT f.id FROM findings f WHERE f.organization_id = $1 AND f.first_scan_job_id = $2 AND f.status = 'open'
		    AND f.category = ANY($3) AND f.severity = ANY($4)
		  ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity), f.id
		  LIMIT GREATEST($5 - (SELECT n FROM used), 0))
		INSERT INTO ai_review_queue (id, organization_id, finding_id, config_version_id)
		SELECT gen_random_uuid(), $1, id, $6 FROM picked ON CONFLICT DO NOTHING`,
		orgID, jobID, cv.Categories, sevs, cv.DailyLimit, cv.ID)
	if err != nil {
		s.Log.Error("auto-review enqueue failed", "err", err)
		return
	}
	_, _ = s.DB.Exec(ctx, `UPDATE findings f SET ai_status = 'queued' FROM ai_review_queue q
		WHERE q.finding_id = f.id AND q.status = 'queued' AND f.first_scan_job_id = $1`, jobID)
	if n := tag.RowsAffected(); n > 0 {
		s.Log.Info("queued findings for AI review", "job_id", jobID, "count", n)
		// Feedback loop 7 (new findings → AI triage) in the monitoring
		// feed. PATHOS 3.0 M7 (AI intelligence) hooks in here: the queue
		// is the single entry point of automated AI review.
		var repo uuid.UUID
		_ = s.DB.QueryRow(ctx, `SELECT repository_id FROM scan_jobs WHERE id = $1`, jobID).Scan(&repo)
		if _, err := monitoring.Record(ctx, s.DB, monitoring.Event{OrgID: orgID, RepositoryID: &repo, Type: monitoring.TypeAITriageQueued,
			Severity: "info", Title: fmt.Sprintf("%d new finding%s queued for AI triage", n, map[bool]string{true: "", false: "s"}[n == 1]),
			Summary: "AI review runs with the organization's AI configuration; its conclusions are labelled AI-inferred, never close or " +
				"approve anything on their own, and secret values are never sent to the model.",
			EvidenceLabel: monitoring.EvidenceVerified, Evidence: map[string]any{"scan_job_id": jobID, "ai_config_version_id": cv.ID},
			SubjectType: "scan_job", SubjectID: &jobID, Details: map[string]any{"queued": n, "min_severity": cv.MinSeverity}}); err != nil {
			s.Log.Warn("monitoring event not recorded", "err", err, "error_code", monitoring.CodeRecordFailed)
		}
	}
}

// RunWorker processes the review queue until ctx is cancelled.
func (s *Service) RunWorker(ctx context.Context) {
	for ctx.Err() == nil {
		n, err := s.ProcessOne(ctx)
		if err != nil {
			s.Log.Error("ai review worker", "err", err)
		}
		if n == 0 {
			select {
			case <-ctx.Done():
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// ProcessOne leases and reviews one queued finding. It returns the number
// processed (0 when the queue is empty).
func (s *Service) ProcessOne(ctx context.Context) (int, error) {
	// Expired leases go back to the queue.
	_, _ = s.DB.Exec(ctx, `UPDATE ai_review_queue SET status = 'queued' WHERE status = 'running' AND lease_expires_at < now()`)
	var qid, orgID, findingID, cvID uuid.UUID
	var attempts int
	err := s.DB.QueryRow(ctx, `UPDATE ai_review_queue SET status = 'running', attempts = attempts + 1, lease_expires_at = now() + interval '5 minutes'
		WHERE id = (SELECT id FROM ai_review_queue WHERE status = 'queued' AND not_before <= now() ORDER BY enqueued_at FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING id, organization_id, finding_id, config_version_id, attempts`).Scan(&qid, &orgID, &findingID, &cvID, &attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	rerr := s.review(ctx, orgID, findingID, cvID)
	switch {
	case rerr == nil:
		_, err = s.DB.Exec(ctx, `UPDATE ai_review_queue SET status = 'done', finished_at = now() WHERE id = $1`, qid)
	case errors.Is(rerr, ErrRateLimited) && attempts < 5:
		_, err = s.DB.Exec(ctx, `UPDATE ai_review_queue SET status = 'queued', error = $2, not_before = now() + make_interval(secs => $3) WHERE id = $1`,
			qid, rerr.Error(), 30*attempts*attempts)
	default:
		s.Log.Warn("ai review failed", "finding_id", findingID, "err", rerr)
		_, err = s.DB.Exec(ctx, `UPDATE ai_review_queue SET status = 'failed', error = $2, finished_at = now() WHERE id = $1`, qid, truncate(rerr.Error(), 1000))
		_, _ = s.DB.Exec(ctx, `UPDATE findings SET ai_status = 'failed' WHERE id = $1`, findingID)
	}
	return 1, err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// LoadEvidence builds the evidence for a finding.
func LoadEvidence(ctx context.Context, q db.Querier, orgID, findingID uuid.UUID, withCode bool) (Evidence, string, error) {
	var ev Evidence
	var severity string
	err := q.QueryRow(ctx, `SELECT f.scanner_keys[1], f.category, f.rule_id, f.title, f.description, f.severity, f.cwe, f.cve, f.cvss::float8,
		f.package_name, f.package_version, f.fixed_version, f.file_path, f.start_line, f.snippet, f.snippet_start_line,
		r.environment, r.criticality, r.visibility, r.technologies
		FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE f.organization_id = $1 AND f.id = $2`, orgID, findingID).
		Scan(&ev.Scanner, &ev.Category, &ev.RuleID, &ev.Title, &ev.Description, &ev.Severity, &ev.CWE, &ev.CVE, &ev.CVSS,
			&ev.PackageName, &ev.PackageVersion, &ev.FixedVersion, &ev.FilePath, &ev.StartLine, &ev.CodeContext, &ev.ContextStart,
			&ev.Repository.Environment, &ev.Repository.Criticality, &ev.Repository.Visibility, &ev.Repository.Technologies)
	if err != nil {
		return ev, "", err
	}
	severity = ev.Severity
	if !withCode {
		ev.CodeContext, ev.ContextStart = "", nil
	}
	return ev, severity, nil
}

func (s *Service) review(ctx context.Context, orgID, findingID, cvID uuid.UUID) error {
	cv, err := scanCV(s.DB.QueryRow(ctx, cvSelect+` WHERE v.id = $1`, cvID))
	if err != nil {
		return err
	}
	pvs, err := s.loadProviders(ctx, orgID, &cv.ProviderID)
	if err != nil || len(pvs) == 0 {
		return errors.New("ai provider no longer exists")
	}
	prov, err := s.provider(ctx, orgID, pvs[0])
	if err != nil {
		return err
	}
	ev, severity, err := LoadEvidence(ctx, s.DB, orgID, findingID, cv.SendCodeContext)
	if err != nil {
		return err
	}
	extra, _ := CompilePatterns(cv.RedactionPatterns)
	system, user, sha := Prompt(ev, cv.Instructions, extra)
	cctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
	defer cancel()
	resp, err := prov.Review(cctx, Request{Model: cv.Model, Effort: cv.Effort, System: system, User: user, Schema: Schema()})
	if err != nil {
		return err
	}
	out, err := Validate(resp.JSON)
	if err != nil {
		return err
	}
	return s.record(ctx, orgID, findingID, severity, &cv, "automated", pvs[0].Kind, resp, out, sha, nil)
}

// record stores a review and applies or queues the decision.
func (s *Service) record(ctx context.Context, orgID, findingID uuid.UUID, severity string, cv *ConfigVersion, source, provider string,
	resp Response, out Output, sha string, reviewer *uuid.UUID) error {
	policy := "always"
	var cvID *uuid.UUID
	if cv != nil {
		policy, cvID = cv.ApprovalPolicy, &cv.ID
	}
	// Continuous monitoring (PATHOS 3.0 M9, feedback loop 7): automated
	// triage of new findings never approves anything on its own; every AI
	// decision waits for a person, whatever the configuration's policy.
	if source == "automated" {
		if on, err := monitoring.Enabled(ctx, s.DB, orgID); err == nil && on {
			policy = "always"
		}
	}
	d := Decide(out, severity, policy)
	status := "applied"
	if d.NeedsApproval {
		status = "pending_approval"
	}
	raw, _ := json.Marshal(out)
	return db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var actor *[16]byte
		if reviewer != nil {
			a := [16]byte(*reviewer)
			actor = &a
		}
		if err := db.SetChangeContext(ctx, tx, actor, "ai", "AI review ("+source+"): "+out.Verdict); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE ai_reviews SET status = 'superseded' WHERE finding_id = $1 AND status = 'pending_approval'`, findingID); err != nil {
			return err
		}
		id := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO ai_reviews (id, organization_id, finding_id, config_version_id, source, provider, model, verdict,
			confidence, suggested_severity, rationale, remediation, output, transmitted_sha256, input_tokens, output_tokens, status, reviewed_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
			id, orgID, findingID, cvID, source, provider, truncate(resp.Model, 200), out.Verdict, out.Confidence, out.SuggestedSeverity,
			out.Rationale, out.Remediation, raw, sha, resp.InputTokens, resp.OutputTokens, status, reviewer); err != nil {
			return err
		}
		aiStatus := "pending_approval"
		if !d.NeedsApproval {
			aiStatus = "reviewed"
			if err := applyStatus(ctx, tx, findingID, d.NewStatus); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET ai_status = $2, updated_at = now() WHERE id = $1`, findingID, aiStatus); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: orgID, ActorID: reviewer, Action: "ai_review.create", TargetType: "finding",
			TargetID: findingID.String(), Metadata: map[string]any{"review_id": id, "verdict": out.Verdict, "source": source,
				"status": status, "transmitted_sha256": sha, "model": resp.Model}})
	})
}

// applyStatus changes a finding's status for an AI decision. Only findings
// still awaiting triage are changed; human decisions are never overridden.
func applyStatus(ctx context.Context, tx pgx.Tx, findingID uuid.UUID, status string) error {
	if status == "" {
		return nil
	}
	_, err := tx.Exec(ctx, `UPDATE findings SET status = $2, updated_at = now(),
		resolved_at = CASE WHEN $2 = 'false_positive' THEN now() ELSE resolved_at END
		WHERE id = $1 AND status IN ('open', 'needs_review')`, findingID, status)
	return err
}

// --- HTTP: reviews -----------------------------------------------------------

func (s *Service) requestReview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.requireFinding(ctx, p, authz.PermAIReview, id); err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := Enqueue(ctx, tx, p.OrganizationID, id, &p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_review.request", TargetType: "finding", TargetID: id.String()})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

// ReviewView is the API representation of a review.
type ReviewView struct {
	ID                uuid.UUID  `json:"id"`
	FindingID         uuid.UUID  `json:"finding_id"`
	FindingTitle      string     `json:"finding_title"`
	FindingSeverity   string     `json:"finding_severity"`
	FindingStatus     string     `json:"finding_status"`
	RepositoryName    string     `json:"repository_name"`
	Source            string     `json:"source"`
	Provider          string     `json:"provider"`
	Model             string     `json:"model"`
	Verdict           string     `json:"verdict"`
	Confidence        float64    `json:"confidence"`
	SuggestedSeverity string     `json:"suggested_severity"`
	Rationale         string     `json:"rationale"`
	Remediation       string     `json:"remediation"`
	EvidenceCited     []string   `json:"evidence_cited"`
	Status            string     `json:"status"`
	ReviewedBy        *string    `json:"reviewed_by"`
	DecidedBy         *string    `json:"decided_by"`
	DecidedAt         *time.Time `json:"decided_at"`
	DecisionNote      string     `json:"decision_note"`
	TransmittedSHA256 string     `json:"transmitted_sha256"`
	CreatedAt         time.Time  `json:"created_at"`
}

const reviewSelect = `SELECT ar.id, ar.finding_id, f.title, f.severity, f.status, r.full_name, ar.source, ar.provider, ar.model, ar.verdict,
	ar.confidence::float8, ar.suggested_severity, ar.rationale, ar.remediation, COALESCE(ar.output->'evidence_cited', '[]'),
	ar.status, COALESCE(NULLIF(u1.display_name, ''), u1.email), COALESCE(NULLIF(u2.display_name, ''), u2.email), ar.decided_at,
	ar.decision_note, ar.transmitted_sha256, ar.created_at
	FROM ai_reviews ar JOIN findings f ON f.id = ar.finding_id JOIN repositories r ON r.id = f.repository_id
	LEFT JOIN countries co ON co.id = r.country_id
	LEFT JOIN users u1 ON u1.id = ar.reviewed_by LEFT JOIN users u2 ON u2.id = ar.decided_by`

func scanReview(row pgx.Row) (ReviewView, error) {
	var v ReviewView
	var ev []byte
	err := row.Scan(&v.ID, &v.FindingID, &v.FindingTitle, &v.FindingSeverity, &v.FindingStatus, &v.RepositoryName, &v.Source, &v.Provider,
		&v.Model, &v.Verdict, &v.Confidence, &v.SuggestedSeverity, &v.Rationale, &v.Remediation, &ev, &v.Status, &v.ReviewedBy,
		&v.DecidedBy, &v.DecidedAt, &v.DecisionNote, &v.TransmittedSHA256, &v.CreatedAt)
	_ = json.Unmarshal(ev, &v.EvidenceCited)
	if v.EvidenceCited == nil {
		v.EvidenceCited = []string{}
	}
	return v, err
}

func (s *Service) findingReviews(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.requireFinding(ctx, p, authz.PermFindingsRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, reviewSelect+` WHERE ar.organization_id = $1 AND ar.finding_id = $2 ORDER BY ar.created_at DESC LIMIT 20`, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReviewView, error) { return scanReview(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []ReviewView{}
	}
	var queued string
	_ = s.DB.QueryRow(ctx, `SELECT ai_status FROM findings WHERE id = $1`, id).Scan(&queued)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "ai_status": queued})
}

func (s *Service) listReviews(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.None() || !p.HasAnywhere(authz.PermAIReview) && !p.HasAnywhere(authz.PermFindingsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	args = append([]any{p.OrganizationID}, args...)
	status := r.URL.Query().Get("status")
	where := "ar.organization_id = $1 AND " + scope
	if status != "" {
		if !slices.Contains([]string{"pending_approval", "applied", "rejected", "superseded"}, status) {
			s.fail(w, r, httpx.BadRequest("invalid status"))
			return
		}
		args = append(args, status)
		where += " AND ar.status = $" + strconv.Itoa(len(args))
	}
	rows, err := s.DB.Query(ctx, reviewSelect+" WHERE "+where+" ORDER BY ar.created_at DESC LIMIT 200", args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReviewView, error) { return scanReview(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []ReviewView{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type decisionRequest struct {
	Note string `json:"note"`
}

func (s *Service) approve(w http.ResponseWriter, r *http.Request) { s.decide(w, r, true) }
func (s *Service) reject(w http.ResponseWriter, r *http.Request)  { s.decide(w, r, false) }

// decide approves (applies) or rejects a pending review. Approval needs
// ai.review and findings.triage on the repository, and a different person
// from the human who submitted an interactive review (four-eyes).
func (s *Service) decide(w http.ResponseWriter, r *http.Request, approve bool) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req decisionRequest
	if r.ContentLength > 0 {
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if len(req.Note) > 2000 {
		s.fail(w, r, httpx.BadRequest("note must be at most 2000 characters"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var findingID uuid.UUID
		var verdict, status, severity string
		var reviewer *uuid.UUID
		var selfOK bool
		if err := tx.QueryRow(ctx, `SELECT ar.finding_id, ar.verdict, ar.status, f.severity, ar.reviewed_by,
			COALESCE((SELECT v.allow_self_approval FROM ai_configuration_versions v WHERE v.id = ar.config_version_id), false)
			FROM ai_reviews ar JOIN findings f ON f.id = ar.finding_id WHERE ar.organization_id = $1 AND ar.id = $2 FOR UPDATE OF ar`, p.OrganizationID, id).
			Scan(&findingID, &verdict, &status, &severity, &reviewer, &selfOK); err != nil {
			return errNotFound
		}
		for _, perm := range []authz.Permission{authz.PermAIReview, authz.PermFindingsTriage} {
			if _, err := s.requireFinding(ctx, p, perm, findingID); err != nil {
				return err
			}
		}
		if status != "pending_approval" {
			return httpx.Conflict("review is " + status)
		}
		self := approve && reviewer != nil && *reviewer == p.UserID
		if self && !selfOK {
			return httpx.Conflict("a different person must approve a review you submitted (single-person installs: enable self-approval in the AI configuration)")
		}
		if approve && verdict == FalsePositive && severity == "critical" && strings.TrimSpace(req.Note) == "" {
			return httpx.BadRequest("closing a Critical finding as a false positive requires a note")
		}
		newStatus := map[bool]string{true: "applied", false: "rejected"}[approve]
		if _, err := tx.Exec(ctx, `UPDATE ai_reviews SET status = $2, decided_by = $3, decided_at = now(), decision_note = $4 WHERE id = $1`,
			id, newStatus, p.UserID, req.Note); err != nil {
			return err
		}
		if approve {
			uid := [16]byte(p.UserID)
			if err := db.SetChangeContext(ctx, tx, &uid, "ai", "AI review approved: "+req.Note); err != nil {
				return err
			}
			target := map[string]string{FalsePositive: "false_positive", NeedsReview: "needs_review"}[verdict]
			if err := applyStatus(ctx, tx, findingID, target); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET ai_status = 'reviewed' WHERE id = $1`, findingID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "ai_review." + map[bool]string{true: "approve", false: "reject"}[approve], TargetType: "finding", TargetID: findingID.String(),
			Metadata: map[string]any{"review_id": id, "verdict": verdict, "note": req.Note, "self_approved": self}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SubmitInteractive records a review a human produced with their own AI
// assistant through the PATHOS MCP server. It is attributed to that person
// and follows the default configuration's approval policy.
func (s *Service) SubmitInteractive(ctx context.Context, p *authz.Principal, findingID uuid.UUID, out Output) (string, error) {
	if _, err := s.requireFinding(ctx, p, authz.PermAIReview, findingID); err != nil {
		return "", err
	}
	var severity string
	if err := s.DB.QueryRow(ctx, `SELECT severity FROM findings WHERE id = $1`, findingID).Scan(&severity); err != nil {
		return "", err
	}
	cv, err := defaultConfig(ctx, s.DB, p.OrganizationID)
	var cvp *ConfigVersion
	if err == nil {
		cvp = &cv
	}
	if err := s.record(ctx, p.OrganizationID, findingID, severity, cvp, "interactive_mcp", "mcp", Response{Model: "user-assistant"}, out, "", &p.UserID); err != nil {
		return "", err
	}
	var st string
	_ = s.DB.QueryRow(ctx, `SELECT status FROM ai_reviews WHERE finding_id = $1 ORDER BY created_at DESC LIMIT 1`, findingID).Scan(&st)
	return st, nil
}
