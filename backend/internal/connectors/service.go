package connectors

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/platform/buildinfo"
	"pathos/internal/platform/db"
	"pathos/internal/platform/diag"
	"pathos/internal/platform/httpx"
	"pathos/internal/secrets"
)

// Flag is the feature flag of the module.
const Flag = "connectors"

// credentialKind is the secret kind of registry kinds' credentials.
const credentialKind = secrets.KindIntegration

// Service serves /api/v1/connectors (API role).
type Service struct {
	Env       *Env
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// Wait is how long POST /check waits for the jobs service to run a
	// "jobs" kind's check before answering 202 (default 25 s).
	Wait time.Duration
}

// Register mounts the routes.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/connectors/kinds", s.kinds)
	mux.HandleFunc("GET /api/v1/connectors", s.list)
	mux.HandleFunc("POST /api/v1/connectors", s.create)
	mux.HandleFunc("GET /api/v1/connectors/{id}", s.get)
	mux.HandleFunc("PUT /api/v1/connectors/{id}", s.update)
	mux.HandleFunc("DELETE /api/v1/connectors/{id}", s.remove)
	mux.HandleFunc("POST /api/v1/connectors/{id}/check", s.check)
	mux.HandleFunc("GET /api/v1/connectors/{id}/checks", s.checks)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, ErrNotFound), errors.Is(err, pgx.ErrNoRows):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("a connector with this name already exists")
	}
	httpx.WriteError(w, r, s.Log, err)
}

// principal returns the caller once the module is enabled for the
// organization (feature_disabled, PTH-PLAT-1007, otherwise).
func (s *Service) principal(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	if err := featureflags.Require(r.Context(), s.Env.DB, p.OrganizationID, Flag); err != nil {
		return nil, err
	}
	return p, nil
}

// forbidden names the permissions that would grant access.
func forbidden(perms ...authz.Permission) error {
	names := make([]string, len(perms))
	for i, p := range perms {
		names[i] = string(p)
	}
	return httpx.E(http.StatusForbidden, "forbidden", "you need one of these permissions: "+strings.Join(names, ", ")).WithDiag("PTH-AUTH-1002")
}

// anyReadable reports whether p can read at least one kind.
func anyReadable(p *authz.Principal) bool {
	for _, k := range Kinds() {
		if k.CheckedBy != RunsNone && k.canRead(p) {
			return true
		}
	}
	return false
}

var readPerms = []authz.Permission{authz.PermReposRead, authz.PermFindingsRead, authz.PermFindingsTriage, authz.PermNotificationsManage,
	authz.PermAIReview, authz.PermAIConfigure, authz.PermSettingsManage}

// SourceRef names the row behind a connector.
type SourceRef struct {
	Table string `json:"table"`
	ID    string `json:"id"`
}

// View is a connector in the list.
type View struct {
	ID               uuid.UUID  `json:"id"`
	Kind             string     `json:"kind"`
	Category         string     `json:"category"`
	Name             string     `json:"name"`
	Status           string     `json:"status"`
	Enabled          bool       `json:"enabled"`
	LastCheckAt      *time.Time `json:"last_check_at"`
	LastOKAt         *time.Time `json:"last_ok_at"`
	LastErrorCode    string     `json:"last_error_code"`
	LastSyncAt       *time.Time `json:"last_sync_at"`
	CheckRequestedAt *time.Time `json:"check_requested_at"`
	CheckedBy        string     `json:"checked_by"`
	ManagedAt        string     `json:"managed_at"`
	CanManage        bool       `json:"can_manage"`
	Source           SourceRef  `json:"source"`
}

// Detail is GET /api/v1/connectors/{id}.
type Detail struct {
	View
	// Metadata is the non-secret description of the connection (host,
	// auth method, API version, ...).
	Metadata map[string]string `json:"metadata"`
	// Config is the stored configuration of a registry kind ({} for
	// existing kinds, whose settings stay on their own page).
	Config     map[string]any `json:"config"`
	Credential struct {
		Set bool `json:"set"`
	} `json:"credential"`
	LastCheck *HealthResult `json:"last_check"`
}

// HealthResult is one health check as the API returns it.
type HealthResult struct {
	ID         uuid.UUID      `json:"id"`
	Status     string         `json:"status"`
	Trigger    string         `json:"trigger"`
	CheckedAt  time.Time      `json:"checked_at"`
	DurationMS int            `json:"duration_ms"`
	Steps      []Step         `json:"steps"`
	Observed   map[string]any `json:"observed"`
	// Error is the full error envelope (with error_code) of a failing or
	// degraded check; null when the check passed.
	Error any `json:"error"`
}

func (s *Service) view(c Connector, p *authz.Principal) View {
	k, _ := LookupKind(c.Kind)
	st, code := EffectiveStatus(c, s.Env)
	v := View{ID: c.ID, Kind: c.Kind, Category: k.Category, Name: c.Name, Status: st, Enabled: c.Enabled, LastCheckAt: c.LastCheckAt,
		LastOKAt: c.LastOKAt, LastErrorCode: code, LastSyncAt: c.LastSyncAt, CheckRequestedAt: c.CheckRequestedAt, CheckedBy: k.CheckedBy,
		ManagedAt: k.ManagedAt, CanManage: k.canManage(p), Source: SourceRef{Table: c.SourceTable, ID: c.SourceKey}}
	if c.SourceTable == "" {
		v.Source = SourceRef{Table: "connectors", ID: c.ID.String()}
	}
	return v
}

// Envelope builds the error envelope of a stored check (nil when the check
// has no error code).
func Envelope(r *http.Request, h HealthCheck) any {
	if h.ErrorCode == "" {
		return nil
	}
	e, _ := diag.Lookup(h.ErrorCode)
	he := &httpx.Error{Status: e.HTTPStatus, Code: "connector_check_" + h.Status, Message: h.Message, Diag: h.ErrorCode}
	if he.Message == "" {
		he.Message = e.Title
	}
	return httpx.ErrorObject(r, he)
}

func result(r *http.Request, h HealthCheck) *HealthResult {
	return &HealthResult{ID: h.ID, Status: h.Status, Trigger: h.Trigger, CheckedAt: h.CheckedAt, DurationMS: h.DurationMS,
		Steps: h.Steps, Observed: h.Observed, Error: Envelope(r, h)}
}

func (s *Service) kinds(w http.ResponseWriter, r *http.Request) {
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !anyReadable(p) {
		s.fail(w, r, forbidden(readPerms...))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": Kinds(), "categories": Categories})
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !anyReadable(p) {
		s.fail(w, r, forbidden(readPerms...))
		return
	}
	q := r.URL.Query()
	category, kind, status := q.Get("category"), q.Get("kind"), q.Get("status")
	all, err := Reconcile(r.Context(), s.Env.DB, s.Env, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := []View{}
	for _, c := range all {
		k, _ := LookupKind(c.Kind)
		if !k.canRead(p) {
			continue
		}
		v := s.view(c, p)
		if (category != "" && v.Category != category) || (kind != "" && v.Kind != kind) || (status != "" && v.Status != status) {
			continue
		}
		items = append(items, v)
	}
	rank := map[string]int{}
	for i, c := range Categories {
		rank[c.Key] = i
	}
	slices.SortStableFunc(items, func(a, b View) int {
		if a.Category != b.Category {
			return rank[a.Category] - rank[b.Category]
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// load returns a connector the caller may read (404 otherwise, so another
// kind's connectors look absent).
func (s *Service) load(r *http.Request, p *authz.Principal) (Connector, Kind, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return Connector{}, Kind{}, ErrNotFound
	}
	c, err := Get(r.Context(), s.Env.DB, s.Env, p.OrganizationID, id)
	if err != nil {
		return c, Kind{}, err
	}
	k, _ := LookupKind(c.Kind)
	if !k.canRead(p) {
		return c, k, ErrNotFound
	}
	return c, k, nil
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, _, err := s.load(r, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := Detail{View: s.view(c, p), Metadata: c.Meta, Config: c.Config}
	if d.Metadata == nil {
		d.Metadata = map[string]string{}
	}
	if d.Config == nil {
		d.Config = map[string]any{}
	}
	d.Credential.Set = c.SecretID != nil
	last, err := LastCheck(r.Context(), s.Env.DB, p.OrganizationID, c.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if last != nil {
		d.LastCheck = result(r, *last)
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

// CheckResponse is POST /api/v1/connectors/{id}/check.
type CheckResponse struct {
	// Status is the check's status, or "pending" when the jobs service has
	// not finished it yet (202).
	Status      string        `json:"status"`
	Connector   View          `json:"connector"`
	Result      *HealthResult `json:"result"`
	RequestedAt *time.Time    `json:"requested_at,omitempty"`
}

func (s *Service) check(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, k, err := s.load(r, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !k.canManage(p) {
		s.fail(w, r, httpx.E(http.StatusForbidden, "forbidden", "running a check needs the permission that manages this connection").WithDiag("PTH-AUTH-1002"))
		return
	}
	if k.Checker == nil {
		s.fail(w, r, httpx.BadRequest("this kind has no health check"))
		return
	}
	trigger := TriggerUser
	if r.URL.Query().Get("trigger") == TriggerVerify {
		trigger = TriggerVerify
	}
	_ = audit.Write(ctx, s.Env.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "connector.check", TargetType: "connector", TargetID: c.ID.String(), Metadata: map[string]any{"kind": c.Kind}})
	if k.CheckedBy == RunsInAPI {
		h, err := Run(ctx, s.Env, c, trigger, &p.UserID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		c.Status, c.LastCheckAt, c.LastErrorCode = h.Status, &h.CheckedAt, h.ErrorCode
		if h.Status == StatusHealthy || h.Status == StatusDegraded {
			c.LastOKAt = &h.CheckedAt
		}
		httpx.WriteJSON(w, http.StatusOK, CheckResponse{Status: h.Status, Connector: s.view(c, p), Result: result(r, h)})
		return
	}
	// The API server never calls this kind: the jobs service runs the
	// check; wait for it a little, then answer 202 (poll GET /checks).
	var at time.Time
	if err := s.Env.DB.QueryRow(ctx, `UPDATE connectors SET check_requested_at = now(), check_requested_by = $3
		WHERE organization_id = $1 AND id = $2 RETURNING check_requested_at`, p.OrganizationID, c.ID, p.UserID).Scan(&at); err != nil {
		s.fail(w, r, err)
		return
	}
	wait := s.Wait
	if wait == 0 {
		wait = 25 * time.Second
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		last, err := LastCheck(ctx, s.Env.DB, p.OrganizationID, c.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if last != nil && !last.CheckedAt.Before(at) {
			cur, err := Get(ctx, s.Env.DB, s.Env, p.OrganizationID, c.ID)
			if err != nil {
				s.fail(w, r, err)
				return
			}
			httpx.WriteJSON(w, http.StatusOK, CheckResponse{Status: last.Status, Connector: s.view(cur, p), Result: result(r, *last)})
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
	c.CheckRequestedAt = &at
	httpx.WriteJSON(w, http.StatusAccepted, CheckResponse{Status: "pending", Connector: s.view(c, p), RequestedAt: &at})
}

func (s *Service) checks(w http.ResponseWriter, r *http.Request) {
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, _, err := s.load(r, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			s.fail(w, r, httpx.BadRequest("limit must be between 1 and 200"))
			return
		}
		limit = n
	}
	var before *HealthCheck
	if cur := r.URL.Query().Get("cursor"); cur != "" {
		b, err := decodeCursor(cur)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		before = &b
	}
	list, err := Checks(r.Context(), s.Env.DB, p.OrganizationID, c.ID, limit+1, before)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	next := ""
	if len(list) > limit {
		list = list[:limit]
		next = encodeCursor(list[len(list)-1])
	}
	items := make([]HealthResult, 0, len(list))
	for _, h := range list {
		items = append(items, *result(r, h))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func encodeCursor(h HealthCheck) string {
	return base64.RawURLEncoding.EncodeToString([]byte(h.CheckedAt.UTC().Format(time.RFC3339Nano) + "|" + h.ID.String()))
}

func decodeCursor(s string) (HealthCheck, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return HealthCheck{}, err
	}
	ts, id, ok := strings.Cut(string(raw), "|")
	if !ok {
		return HealthCheck{}, errors.New("cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		return HealthCheck{}, err
	}
	u, err := uuid.Parse(id)
	return HealthCheck{CheckedAt: t, ID: u}, err
}

// --- kinds stored in the registry (POST/PUT/DELETE) ------------------------

type input struct {
	Kind    string         `json:"kind"`
	Name    string         `json:"name"`
	Config  map[string]any `json:"config"`
	Enabled *bool          `json:"enabled"`
	// Credential is write-only: stored encrypted, never returned.
	Credential *string `json:"credential"`
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in input
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	k, ok := LookupKind(in.Kind)
	switch {
	case !ok:
		s.fail(w, r, validation("kind", "unknown connector kind"))
		return
	case !k.Creatable && k.ManagedAt != "":
		s.fail(w, r, httpx.BadRequest("connections of this kind are created on "+k.ManagedAt+" until the Connectors page reaches parity"))
		return
	case !k.Creatable:
		s.fail(w, r, httpx.BadRequest("this kind cannot be created yet ("+k.Status+")"))
		return
	case !k.canManage(p):
		s.fail(w, r, httpx.E(http.StatusForbidden, "forbidden", "creating this kind needs the permission that manages it").WithDiag("PTH-AUTH-1002"))
		return
	}
	if k.Create != nil {
		s.createSource(w, r, p, k, &in)
		return
	}
	cfg, err := s.validate(k, &in, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	enabled := in.Enabled == nil || *in.Enabled
	err = db.InTx(ctx, s.Env.DB, func(tx pgx.Tx) error {
		var sid *uuid.UUID
		if in.Credential != nil && *in.Credential != "" {
			n, err := s.Env.Secrets.Create(ctx, tx, p.OrganizationID, credentialKind, "connector: "+in.Name, []byte(*in.Credential), &p.UserID)
			if err != nil {
				return err
			}
			sid = &n
		}
		raw, _ := json.Marshal(cfg)
		if _, err := tx.Exec(ctx, `INSERT INTO connectors (id, organization_id, kind, name, config, secret_id, enabled, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, p.OrganizationID, k.Kind, in.Name, raw, sid, enabled, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "connector.create", TargetType: "connector", TargetID: id.String(),
			Metadata: map[string]any{"kind": k.Kind, "name": in.Name, "credential": sid != nil}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := Get(ctx, s.Env.DB, s.Env, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, Detail{View: s.view(c, p), Metadata: map[string]string{}, Config: c.Config,
		Credential: struct {
			Set bool `json:"set"`
		}{c.SecretID != nil}})
}

// createSource creates a creatable kind kept in a legacy table (Generic
// Git, Bitbucket Data Center in scm_connections) through its own service,
// then answers 201 with the registry row reconciliation added for it.
func (s *Service) createSource(w http.ResponseWriter, r *http.Request, p *authz.Principal, k Kind, in *input) {
	ctx := r.Context()
	in.Name = strings.TrimSpace(in.Name)
	switch {
	case in.Name == "" || len(in.Name) > 200:
		s.fail(w, r, validation("name", "required, at most 200 characters"))
		return
	case in.Credential != nil && len(*in.Credential) > 65536:
		s.fail(w, r, validation("credential", "at most 64 KiB"))
		return
	case in.Enabled != nil && !*in.Enabled:
		s.fail(w, r, validation("enabled", "connections of this kind are created enabled; disable them on "+k.ManagedAt))
		return
	}
	if in.Config == nil {
		in.Config = map[string]any{}
	}
	cred := ""
	if in.Credential != nil {
		cred = *in.Credential
	}
	key, err := k.Create(ctx, s.Env, p, in.Name, in.Config, cred)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := Reconcile(ctx, s.Env.DB, s.Env, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, c := range all {
		if c.SourceTable == k.Source && c.SourceKey == key {
			d := Detail{View: s.view(c, p), Metadata: c.Meta, Config: map[string]any{}}
			if d.Metadata == nil {
				d.Metadata = map[string]string{}
			}
			ref, _ := in.Config["credential_ref"].(string)
			d.Credential.Set = cred != "" || strings.TrimSpace(ref) != ""
			httpx.WriteJSON(w, http.StatusCreated, d)
			return
		}
	}
	s.fail(w, r, ErrNotFound)
}

func validation(field, msg string) error {
	return &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "validation_failed", Message: field + ": " + msg, Fields: map[string]string{field: msg}}
}

func (s *Service) validate(k Kind, in *input, creating bool) (map[string]any, error) {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 200 {
		return nil, validation("name", "required, at most 200 characters")
	}
	if in.Credential != nil && len(*in.Credential) > 65536 {
		return nil, validation("credential", "at most 64 KiB")
	}
	if creating && k.CredentialRequired && (in.Credential == nil || *in.Credential == "") {
		return nil, validation("credential", "required for this kind")
	}
	if in.Config == nil {
		in.Config = map[string]any{}
	}
	cfg, err := k.Validate(in.Config)
	if err != nil {
		var he *httpx.Error
		if errors.As(err, &he) {
			return nil, he
		}
		return nil, validation("config", err.Error())
	}
	if raw, _ := json.Marshal(cfg); len(raw) > 60000 {
		return nil, validation("config", "too large")
	}
	return cfg, nil
}

func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, k, err := s.load(r, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if c.SourceTable != "" {
		s.fail(w, r, httpx.BadRequest("this connection is edited on "+k.ManagedAt))
		return
	}
	if !k.canManage(p) {
		s.fail(w, r, httpx.E(http.StatusForbidden, "forbidden", "editing this kind needs the permission that manages it").WithDiag("PTH-AUTH-1002"))
		return
	}
	var in input
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.Kind != "" && in.Kind != c.Kind {
		s.fail(w, r, validation("kind", "the kind of a connector cannot change"))
		return
	}
	cfg, err := s.validate(k, &in, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	enabled := c.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	err = db.InTx(ctx, s.Env.DB, func(tx pgx.Tx) error {
		sid := c.SecretID
		if in.Credential != nil {
			switch {
			case *in.Credential == "" && sid != nil && !k.CredentialRequired:
				if _, err := tx.Exec(ctx, `UPDATE connectors SET secret_id = NULL WHERE id = $1`, c.ID); err != nil {
					return err
				}
				if err := s.Env.Secrets.Delete(ctx, tx, p.OrganizationID, *sid); err != nil {
					return err
				}
				sid = nil
			case *in.Credential == "":
			case sid != nil:
				if err := s.Env.Secrets.Update(ctx, tx, p.OrganizationID, *sid, credentialKind, []byte(*in.Credential)); err != nil {
					return err
				}
			default:
				n, err := s.Env.Secrets.Create(ctx, tx, p.OrganizationID, credentialKind, "connector: "+in.Name, []byte(*in.Credential), &p.UserID)
				if err != nil {
					return err
				}
				sid = &n
			}
		}
		raw, _ := json.Marshal(cfg)
		// A changed configuration invalidates the last check.
		if _, err := tx.Exec(ctx, `UPDATE connectors SET name = $3, config = $4, secret_id = $5, enabled = $6, status = 'unknown',
			last_error_code = '', updated_at = now() WHERE organization_id = $1 AND id = $2`, p.OrganizationID, c.ID, in.Name, raw, sid, enabled); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "connector.update", TargetType: "connector", TargetID: c.ID.String(),
			Metadata: map[string]any{"kind": c.Kind, "name": in.Name, "credential_changed": in.Credential != nil, "enabled": enabled}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cur, err := Get(ctx, s.Env.DB, s.Env, p.OrganizationID, c.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d := Detail{View: s.view(cur, p), Metadata: map[string]string{}, Config: cur.Config}
	d.Credential.Set = cur.SecretID != nil
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (s *Service) remove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, k, err := s.load(r, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if c.SourceTable != "" {
		s.fail(w, r, httpx.BadRequest("this connection is deleted on "+k.ManagedAt))
		return
	}
	if !k.canManage(p) {
		s.fail(w, r, httpx.E(http.StatusForbidden, "forbidden", "deleting this kind needs the permission that manages it").WithDiag("PTH-AUTH-1002"))
		return
	}
	err = db.InTx(ctx, s.Env.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM connectors WHERE organization_id = $1 AND id = $2`, p.OrganizationID, c.ID); err != nil {
			return err
		}
		if c.SecretID != nil {
			if err := s.Env.Secrets.Delete(ctx, tx, p.OrganizationID, *c.SecretID); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "connector.delete", TargetType: "connector", TargetID: c.ID.String(), Metadata: map[string]any{"kind": c.Kind, "name": c.Name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// TroubleshootContext returns the redacted context of a connector for AI
// troubleshooting (POST /api/v1/diagnostics/troubleshoot with subject
// {kind: "connector", id}). It holds non-secret configuration metadata
// and the last check only: never the credential, a URL path or query, a
// request or response body or an e-mail address. ok is false when the
// caller may not read the connector or the module is off.
func (s *Service) TroubleshootContext(ctx context.Context, p *authz.Principal, id uuid.UUID) (map[string]string, string, bool, error) {
	if p == nil {
		return nil, "", false, nil
	}
	if on, err := featureflags.Enabled(ctx, s.Env.DB, p.OrganizationID, Flag); err != nil || !on {
		return nil, "", false, err
	}
	c, err := Get(ctx, s.Env.DB, s.Env, p.OrganizationID, id)
	if errors.Is(err, ErrNotFound) {
		return nil, "", false, nil
	}
	if err != nil {
		return nil, "", false, err
	}
	k, _ := LookupKind(c.Kind)
	if !k.canRead(p) {
		return nil, "", false, nil
	}
	st, code := EffectiveStatus(c, s.Env)
	out := map[string]string{
		"connector.kind": c.Kind, "connector.category": k.Category, "connector.status": st, "connector.checked_by": k.CheckedBy,
		"pathos.version": buildinfo.Version, "offline_mode": yesNo(s.Env.Offline),
	}
	for key, v := range c.Meta {
		if key == "host" {
			v = HostOf(v)
			if v == "" {
				continue
			}
		}
		out["connector."+key] = Redact(v)
	}
	for key, v := range c.Config {
		if s, ok := v.(string); ok && safeConfigKey(key) {
			out["connector.config."+key] = Redact(s)
		}
	}
	out["connector.credential_set"] = yesNo(c.SecretID != nil || c.SourceTable != "")
	message := ""
	last, err := LastCheck(ctx, s.Env.DB, p.OrganizationID, c.ID)
	if err != nil {
		return nil, "", false, err
	}
	if last != nil {
		out["check.status"] = last.Status
		out["check.error_code"] = last.ErrorCode
		out["check.at"] = last.CheckedAt.UTC().Format(time.RFC3339)
		message = last.Message
		for i, st := range last.Steps {
			if i >= 10 {
				break
			}
			out["check.step."+strconv.Itoa(i)] = st.Check + ": " + st.Status + " " + st.ErrorCode + " " + Redact(st.Detail)
		}
	}
	if code != "" {
		out["connector.last_error_code"] = code
	}
	return out, message, true, nil
}

// safeConfigKey excludes configuration keys that could hold a secret by
// name (a registry kind's credential is never in config, but a careless
// kind declaration must not leak one).
func safeConfigKey(k string) bool {
	k = strings.ToLower(k)
	for _, bad := range []string{"secret", "token", "password", "key", "credential", "auth", "cert", "private"} {
		if strings.Contains(k, bad) {
			return false
		}
	}
	return len(k) <= 40
}
