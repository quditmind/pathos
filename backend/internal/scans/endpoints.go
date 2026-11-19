package scans

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
)

// Verification of a repository's declared public endpoints (URLs, domains,
// IPs). It is opt-in per repository, needs an authorization statement like
// web application targets, covers only the endpoints declared when the
// statement was recorded, and runs on a worker through the egress proxy
// (never on the API server). It is a scan target of kind "endpoints".

const (
	endpointsTargetName = "Declared public endpoints"
	endpointsTargetRef  = "declared-public-endpoints"
	errOfflineEndpoints = "endpoint verification is disabled in offline mode (PATHOS_OFFLINE=true)"
	defaultEndpointRate = 2
	maxEndpointRate     = 10
)

func (s *Service) registerEndpointVerification(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/repositories/{id}/endpoint-verification", s.getEndpointVerification)
	mux.HandleFunc("PUT /api/v1/repositories/{id}/endpoint-verification", s.putEndpointVerification)
	mux.HandleFunc("POST /api/v1/repositories/{id}/endpoint-verification/run", s.runEndpointVerification)
}

// LeasedEndpoint is a declared endpoint sent to the worker.
type LeasedEndpoint struct {
	Kind       string `json:"kind"`
	Value      string `json:"value"`
	Authorized bool   `json:"authorized"`
}

// EndpointStatus is the verification state of one declared endpoint.
type EndpointStatus struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	// Authorized: covered by the authorization statement.
	Authorized bool `json:"authorized"`
	// Status: verified, unreachable, dns_failed, blocked, skipped, error or
	// not_checked.
	Status    string          `json:"status"`
	Detail    string          `json:"detail"`
	Checks    json.RawMessage `json:"checks"`
	CheckedAt *time.Time      `json:"checked_at"`
	ScanJobID *uuid.UUID      `json:"scan_job_id"`
}

// EndpointVerification is the repository's verification setting and state.
type EndpointVerification struct {
	Configured        bool             `json:"configured"`
	Enabled           bool             `json:"enabled"`
	TargetID          *uuid.UUID       `json:"scan_target_id"`
	AuthorizedBy      *string          `json:"authorized_by"`
	AuthorizedAt      *time.Time       `json:"authorized_at"`
	AuthorizationNote string           `json:"authorization_note"`
	RateLimit         int              `json:"rate_limit"`
	Nuclei            bool             `json:"nuclei"`
	Offline           bool             `json:"offline"`
	OpenFindings      int              `json:"open_findings"`
	LastScan          any              `json:"last_scan"`
	Endpoints         []EndpointStatus `json:"endpoints"`
	// Unauthorized counts declared endpoints the statement does not cover.
	Unauthorized int `json:"unauthorized"`
}

func endpointKey(kind, value string) string { return kind + ":" + value }

// declaredEndpoints lists a repository's declared public endpoints.
func declaredEndpoints(ctx context.Context, q db.Querier, repoID uuid.UUID) ([]LeasedEndpoint, error) {
	rows, err := q.Query(ctx, `SELECT kind, value FROM repository_public_endpoints WHERE repository_id = $1
		ORDER BY array_position(ARRAY['url','domain','ip'], kind), position, value`, repoID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (LeasedEndpoint, error) {
		var e LeasedEndpoint
		return e, r.Scan(&e.Kind, &e.Value)
	})
}

// leaseEndpoints are the endpoints a worker verifies, each marked with
// whether the authorization statement covers it.
func leaseEndpoints(ctx context.Context, tx pgx.Tx, repoID uuid.UUID, scope []string) ([]LeasedEndpoint, error) {
	eps, err := declaredEndpoints(ctx, tx, repoID)
	for i := range eps {
		eps[i].Authorized = slices.Contains(scope, endpointKey(eps[i].Kind, eps[i].Value))
	}
	return eps, err
}

func (s *Service) endpointVerification(ctx context.Context, p *authz.Principal, repoID uuid.UUID) (EndpointVerification, error) {
	out := EndpointVerification{Offline: s.Offline, RateLimit: defaultEndpointRate, Endpoints: []EndpointStatus{}}
	var scope []string
	t, err := scanTarget(s.DB.QueryRow(ctx, targetSelect+` WHERE t.organization_id = $1 AND t.repository_id = $2 AND t.kind = 'endpoints'`,
		p.OrganizationID, repoID))
	switch {
	case errors.Is(err, errNotFound):
	case err != nil:
		return out, err
	default:
		out.Configured, out.Enabled, out.TargetID = true, t.Enabled, &t.ID
		out.AuthorizedBy, out.AuthorizedAt, out.AuthorizationNote = t.AuthorizedBy, t.AuthorizedAt, t.AuthorizationNote
		out.Nuclei, out.OpenFindings, out.LastScan = t.Config.Nuclei, t.OpenFindings, t.LastScan
		if t.Config.RateLimit > 0 {
			out.RateLimit = t.Config.RateLimit
		}
		if err := s.DB.QueryRow(ctx, `SELECT authorized_scope FROM scan_targets WHERE id = $1`, t.ID).Scan(&scope); err != nil {
			return out, err
		}
	}
	rows, err := s.DB.Query(ctx, `SELECT e.kind, e.value, COALESCE(v.status, 'not_checked'), COALESCE(v.detail, ''), COALESCE(v.checks, '{}'),
		v.checked_at, v.scan_job_id
		FROM repository_public_endpoints e LEFT JOIN endpoint_verifications v ON v.repository_id = e.repository_id AND v.kind = e.kind AND v.value = e.value
		WHERE e.repository_id = $1 ORDER BY array_position(ARRAY['url','domain','ip'], e.kind), e.position, e.value`, repoID)
	if err != nil {
		return out, err
	}
	eps, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (EndpointStatus, error) {
		var e EndpointStatus
		err := r.Scan(&e.Kind, &e.Value, &e.Status, &e.Detail, &e.Checks, &e.CheckedAt, &e.ScanJobID)
		e.Authorized = slices.Contains(scope, endpointKey(e.Kind, e.Value))
		return e, err
	})
	if err != nil {
		return out, err
	}
	for _, e := range eps {
		if out.Configured && !e.Authorized {
			out.Unauthorized++
		}
	}
	if eps != nil {
		out.Endpoints = eps
	}
	return out, nil
}

func (s *Service) getEndpointVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err == nil {
		err = s.requireRepo(ctx, p, authz.PermScansRead, id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.endpointVerification(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type endpointVerificationRequest struct {
	Enabled *bool `json:"enabled"`
	// Authorized records the statement that the caller is authorized to
	// test the declared endpoints; it covers the endpoints declared now.
	Authorized        bool    `json:"authorized"`
	AuthorizationNote *string `json:"authorization_note"`
	RateLimit         *int    `json:"rate_limit"`
	Nuclei            *bool   `json:"nuclei"`
}

func (s *Service) putEndpointVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	repoID, err := pathID(r, "id")
	if err == nil {
		err = s.requireRepo(ctx, p, authz.PermReposManage, repoID)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req endpointVerificationRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.RateLimit != nil && (*req.RateLimit < 1 || *req.RateLimit > maxEndpointRate) {
		s.fail(w, r, httpx.BadRequest("rate_limit must be between 1 and 10 requests per second"))
		return
	}
	if req.AuthorizationNote != nil && len(strings.TrimSpace(*req.AuthorizationNote)) > 2000 {
		s.fail(w, r, httpx.BadRequest("the authorization note is limited to 2000 characters"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		eps, err := declaredEndpoints(ctx, tx, repoID)
		if err != nil {
			return err
		}
		scope := make([]string, 0, len(eps))
		for _, e := range eps {
			scope = append(scope, endpointKey(e.Kind, e.Value))
		}
		var id uuid.UUID
		var enabled bool
		var cfgRaw []byte
		var note string
		err = tx.QueryRow(ctx, `SELECT id, enabled, config, authorization_note FROM scan_targets
			WHERE organization_id = $1 AND repository_id = $2 AND kind = 'endpoints' FOR UPDATE`, p.OrganizationID, repoID).
			Scan(&id, &enabled, &cfgRaw, &note)
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var cfg TargetConfig
		_ = json.Unmarshal(cfgRaw, &cfg)
		wasEnabled, hadNuclei := exists && enabled, cfg.Nuclei
		if !exists {
			enabled = true
			cfg.RateLimit = defaultEndpointRate
		}
		if req.Enabled != nil {
			enabled = *req.Enabled
		}
		if req.RateLimit != nil {
			cfg.RateLimit = *req.RateLimit
		}
		if req.Nuclei != nil {
			cfg.Nuclei = *req.Nuclei
		}
		if req.AuthorizationNote != nil {
			note = strings.TrimSpace(*req.AuthorizationNote)
		}
		if !exists && !enabled {
			return httpx.BadRequest("endpoint verification is not enabled for this repository")
		}
		if enabled && s.Offline {
			return httpx.Conflict(errOfflineEndpoints)
		}
		if enabled && len(eps) == 0 {
			return httpx.BadRequest("declare public URLs, domains or IP addresses in the repository's exposure section first")
		}
		// Turning verification on, or adding Nuclei, needs a fresh statement.
		if enabled && (!wasEnabled || (cfg.Nuclei && !hadNuclei)) && !req.Authorized {
			return httpx.BadRequest("confirm that you are authorized to test these endpoints")
		}
		raw, _ := json.Marshal(cfg)
		if !exists {
			id = uuid.Must(uuid.NewV7())
			if _, err := tx.Exec(ctx, `INSERT INTO scan_targets (id, organization_id, repository_id, kind, name, reference, egress_host, config,
				authorized_by, authorized_at, authorization_note, authorized_scope, enabled, created_by)
				VALUES ($1, $2, $3, 'endpoints', $4, $5, '', $6, $7, now(), $8, $9, true, $7)`,
				id, p.OrganizationID, repoID, endpointsTargetName, endpointsTargetRef, raw, p.UserID, note, scope); err != nil {
				return err
			}
		} else if _, err := tx.Exec(ctx, `UPDATE scan_targets SET config = $2, enabled = $3, authorization_note = $4,
			authorized_by = CASE WHEN $5 THEN $6::uuid ELSE authorized_by END,
			authorized_at = CASE WHEN $5 THEN now() ELSE authorized_at END,
			authorized_scope = CASE WHEN $5 THEN $7::text[] ELSE authorized_scope END, updated_at = now() WHERE id = $1`,
			id, raw, enabled, note, req.Authorized, p.UserID, scope); err != nil {
			return err
		}
		action := "endpoint_verification.update"
		if !exists {
			action = "endpoint_verification.enable"
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: action, TargetType: "repository", TargetID: repoID.String(),
			Metadata: map[string]any{"scan_target_id": id, "enabled": enabled, "authorized": req.Authorized, "authorization_note": note,
				"scope": map[bool]any{true: scope, false: nil}[req.Authorized], "rate_limit": cfg.RateLimit, "nuclei": cfg.Nuclei}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.endpointVerification(ctx, p, repoID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) runEndpointVerification(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	repoID, err := pathID(r, "id")
	if err == nil {
		err = s.requireRepo(ctx, p, authz.PermScansRun, repoID)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.Offline {
		s.fail(w, r, httpx.Conflict(errOfflineEndpoints))
		return
	}
	var res EnqueueResult
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var id uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT id FROM scan_targets WHERE organization_id = $1 AND repository_id = $2 AND kind = 'endpoints'`,
			p.OrganizationID, repoID).Scan(&id); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return httpx.Conflict("endpoint verification is not enabled for this repository")
			}
			return err
		}
		var err error
		if res, err = EnqueueTarget(ctx, tx, p.OrganizationID, id, "manual", &p.UserID); err != nil {
			return err
		}
		if res.Coalesced {
			return nil
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan.request", TargetType: "scan_target", TargetID: id.String(),
			Metadata: map[string]any{"job_id": res.JobID, "trigger": "manual", "kind": "endpoints", "repository_id": repoID}})
	})
	if errors.Is(err, ErrNotScannable) || errors.Is(err, ErrScanPrerequisite) {
		err = httpx.Conflict(err.Error())
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, res)
}

// recordEndpoints stores the per-endpoint outcome of a pathos-endpoints
// result (the findings are stored like any scanner's).
func recordEndpoints(ctx context.Context, tx pgx.Tx, orgID, repoID, jobID uuid.UUID, raw []byte) error {
	rep, err := scanners.ParseEndpointReport(raw)
	if err != nil {
		return nil // the result itself records the parse failure
	}
	b := &pgx.Batch{}
	for _, e := range rep.Endpoints {
		checks, _ := json.Marshal(e.Checks)
		if len(checks) > 60000 || e.Checks == nil {
			checks = []byte(`{}`)
		}
		b.Queue(`INSERT INTO endpoint_verifications (organization_id, repository_id, kind, value, status, detail, checks, scan_job_id, checked_at)
			SELECT $1, $2, $3, $4, $5, $6, $7, $8, now()
			WHERE EXISTS (SELECT 1 FROM repository_public_endpoints WHERE repository_id = $2 AND kind = $3 AND value = $4)
			ON CONFLICT (repository_id, kind, value) DO UPDATE SET status = EXCLUDED.status, detail = EXCLUDED.detail,
			  checks = EXCLUDED.checks, scan_job_id = EXCLUDED.scan_job_id, checked_at = now()`,
			orgID, repoID, e.Kind, e.Value, e.Status, truncate(e.Detail, 2000), checks, jobID)
	}
	return tx.SendBatch(ctx, b).Close()
}
