package gates

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
	"pathos/internal/featureflags"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Flag is the feature flag of the gates and remediation API.
const Flag = "remediation_workspace"

// Service serves the gates API (behind the remediation_workspace flag).
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the endpoints.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/gates", s.list)
	mux.HandleFunc("POST /api/v1/gates", s.create)
	mux.HandleFunc("GET /api/v1/gates/{id}", s.get)
	mux.HandleFunc("PUT /api/v1/gates/{id}", s.update)
	mux.HandleFunc("DELETE /api/v1/gates/{id}", s.remove)
	mux.HandleFunc("POST /api/v1/gates/evaluate", s.evaluate)
	mux.HandleFunc("GET /api/v1/gates/decisions", s.listDecisions)
	mux.HandleFunc("GET /api/v1/gates/decisions/{id}", s.getDecision)
	mux.HandleFunc("POST /api/v1/gates/decisions/{id}/exceptions", s.requestException)
	mux.HandleFunc("GET /api/v1/gate-exceptions", s.listExceptions)
	mux.HandleFunc("POST /api/v1/gate-exceptions/{id}/approve", s.decideException("approved"))
	mux.HandleFunc("POST /api/v1/gate-exceptions/{id}/reject", s.decideException("rejected"))
	mux.HandleFunc("POST /api/v1/gate-exceptions/{id}/revoke", s.decideException("revoked"))
}

// Errors of the gates API.
var (
	errNotFound          = httpx.ErrNotFound
	ErrPolicyRequired    = httpx.E(http.StatusUnprocessableEntity, "gate_policy_required", "a gate needs an existing security policy of this organization (policy_id)").WithDiag("PTH-GATE-1101")
	ErrNoExceptions      = httpx.E(http.StatusConflict, "gate_exceptions_not_allowed", "this gate does not allow exceptions").WithDiag("PTH-GATE-1102")
	ErrSelfApproval      = httpx.E(http.StatusConflict, "self_approval", "the person who requested an exception or approval cannot decide it").WithDiag("PTH-GATE-1103")
	ErrNotPending        = httpx.E(http.StatusConflict, "exception_not_pending", "the exception is not in a state that allows this action").WithDiag("PTH-GATE-1104")
	ErrManagedGate       = httpx.E(http.StatusConflict, "managed_gate", "this gate is generated from a repository's pull request settings; change it there").WithDiag("PTH-GATE-1105")
	errNothingToExcept   = httpx.E(http.StatusUnprocessableEntity, "nothing_to_except", "the decision has no blocking gate an exception or approval could apply to").WithDiag("PTH-GATE-1102")
	maxExceptionLifetime = 365 * 24 * time.Hour
)

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("a gate with this name already exists")
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("a referenced item does not exist")
	}
	httpx.WriteError(w, r, s.Log, err)
}

// begin checks the flag and returns the principal.
func (s *Service) begin(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, authz.ErrForbidden
	}
	if err := featureflags.Require(r.Context(), s.DB, p.OrganizationID, Flag); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Service) requireOrg(ctx context.Context, p *authz.Principal, perm authz.Permission) error {
	return s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID})
}

// requireRepo checks perm on a repository; an unknown or invisible
// repository is not found.
func (s *Service) requireRepo(ctx context.Context, p *authz.Principal, perm authz.Permission, repoID uuid.UUID) error {
	err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: repoID})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, org.ErrScopeNotFound):
		return errNotFound
	case errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(perm):
		return errNotFound
	}
	return err
}

// requireApplication checks perm on every active repository of an
// application of the organization (an application is visible as a whole).
func (s *Service) requireApplication(ctx context.Context, p *authz.Principal, perm authz.Permission, appID uuid.UUID) error {
	var exists bool
	if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE organization_id = $1 AND id = $2)`, p.OrganizationID, appID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errNotFound
	}
	rows, err := s.DB.Query(ctx, `SELECT id FROM repositories WHERE organization_id = $1 AND application_id = $2 AND archived_at IS NULL`, p.OrganizationID, appID)
	if err != nil {
		return err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		if err := s.requireOrg(ctx, p, perm); err != nil {
			return errNotFound
		}
	}
	for _, id := range ids {
		if err := s.requireRepo(ctx, p, perm, id); err != nil {
			return err
		}
	}
	return nil
}

// --- gates -------------------------------------------------------------------

// Gate is a security gate as returned by the API.
type Gate struct {
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	Stage           string     `json:"stage"`
	Mode            string     `json:"mode"`
	AllowExceptions bool       `json:"allow_exceptions"`
	ApplicationID   *uuid.UUID `json:"application_id"`
	RepositoryID    *uuid.UUID `json:"repository_id"`
	RepositoryName  string     `json:"repository_name"`
	Enabled         bool       `json:"enabled"`
	Managed         bool       `json:"managed"`
	Policy          struct {
		PolicyRef
		Enabled bool `json:"enabled"`
	} `json:"policy"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const gateSelect = `SELECT g.id, g.name, g.stage, g.mode, g.allow_exceptions, g.application_id, g.repository_id,
	COALESCE(NULLIF(r.display_name, ''), r.full_name, ''), g.enabled, g.managed, p.id, p.name, p.version, p.enabled, g.created_at, g.updated_at
	FROM security_gates g JOIN security_policies p ON p.id = g.policy_id LEFT JOIN repositories r ON r.id = g.repository_id`

func scanGate(row pgx.Row) (Gate, error) {
	var g Gate
	err := row.Scan(&g.ID, &g.Name, &g.Stage, &g.Mode, &g.AllowExceptions, &g.ApplicationID, &g.RepositoryID, &g.RepositoryName,
		&g.Enabled, &g.Managed, &g.Policy.ID, &g.Policy.Name, &g.Policy.Version, &g.Policy.Enabled, &g.CreatedAt, &g.UpdatedAt)
	return g, err
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermRemediationRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	args := []any{p.OrganizationID}
	where := "g.organization_id = $1"
	if v := r.URL.Query().Get("stage"); v != "" {
		st, ok := NormalizeStage(v)
		if !ok {
			s.fail(w, r, httpx.BadRequest("unknown stage"))
			return
		}
		args = append(args, st)
		where += " AND g.stage = $2"
	}
	// Gates bound to a repository are listed to people who can see it.
	f := authz.FilterFor(p, authz.PermRemediationRead)
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", len(args)+1)
	args = append(args, sargs...)
	where += " AND (g.repository_id IS NULL OR " + scope + ")"
	rows, err := s.DB.Query(r.Context(), gateSelect+" WHERE "+where+" ORDER BY array_position(ARRAY['ide','pre_commit','pull_request','ci','release','deploy'], g.stage), lower(g.name) LIMIT 1000", args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Gate, error) { return scanGate(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []Gate{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Service) loadGate(ctx context.Context, p *authz.Principal, r *http.Request) (Gate, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return Gate{}, errNotFound
	}
	g, err := scanGate(s.DB.QueryRow(ctx, gateSelect+" WHERE g.organization_id = $1 AND g.id = $2", p.OrganizationID, id))
	if err != nil {
		return g, err
	}
	if g.RepositoryID != nil {
		if err := s.requireRepo(ctx, p, authz.PermRemediationRead, *g.RepositoryID); err != nil {
			return g, err
		}
	} else if !p.HasAnywhere(authz.PermRemediationRead) {
		return g, authz.ErrForbidden
	}
	return g, nil
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := s.loadGate(r.Context(), p, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

type gateInput struct {
	Name            string     `json:"name"`
	Stage           string     `json:"stage"`
	PolicyID        uuid.UUID  `json:"policy_id"`
	Mode            string     `json:"mode"`
	AllowExceptions *bool      `json:"allow_exceptions"`
	ApplicationID   *uuid.UUID `json:"application_id"`
	RepositoryID    *uuid.UUID `json:"repository_id"`
	Enabled         *bool      `json:"enabled"`
}

func (s *Service) validateGate(ctx context.Context, orgID uuid.UUID, in *gateInput) error {
	in.Name = strings.TrimSpace(in.Name)
	if in.Name == "" || len(in.Name) > 200 {
		return httpx.BadRequest("name is required (at most 200 characters)")
	}
	st, ok := NormalizeStage(in.Stage)
	if !ok {
		return httpx.BadRequest("stage must be one of " + strings.Join(Stages, ", "))
	}
	in.Stage = st
	if !slices.Contains(Modes, in.Mode) {
		return httpx.BadRequest("mode must be block, warn or require_approval")
	}
	// Rule 7: a gate cannot exist without a policy of this organization
	// (generated pull request policies belong to their repository's gate).
	var managed string
	err := s.DB.QueryRow(ctx, `SELECT managed_by FROM security_policies WHERE organization_id = $1 AND id = $2`, orgID, in.PolicyID).Scan(&managed)
	if errors.Is(err, pgx.ErrNoRows) || in.PolicyID == uuid.Nil {
		return ErrPolicyRequired
	}
	if err != nil {
		return err
	}
	if managed != "" {
		return ErrManagedGate
	}
	if in.ApplicationID != nil {
		var ok bool
		if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM applications WHERE organization_id = $1 AND id = $2)`, orgID, *in.ApplicationID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return httpx.BadRequest("application_id: no such application")
		}
	}
	if in.RepositoryID != nil {
		var ok bool
		if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM repositories WHERE organization_id = $1 AND id = $2)`, orgID, *in.RepositoryID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return httpx.BadRequest("repository_id: no such repository")
		}
	}
	return nil
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireOrg(ctx, p, authz.PermGatesManage); err != nil {
		s.fail(w, r, err)
		return
	}
	var in gateInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.validateGate(ctx, p.OrganizationID, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	allow := in.AllowExceptions == nil || *in.AllowExceptions
	enabled := in.Enabled == nil || *in.Enabled
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO security_gates (id, organization_id, name, stage, policy_id, mode, allow_exceptions, application_id,
			repository_id, enabled, created_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			id, p.OrganizationID, in.Name, in.Stage, in.PolicyID, in.Mode, allow, in.ApplicationID, in.RepositoryID, enabled, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "security_gate.create", TargetType: "security_gate", TargetID: id.String(),
			Metadata: map[string]any{"name": in.Name, "stage": in.Stage, "mode": in.Mode, "policy_id": in.PolicyID, "allow_exceptions": allow, "enabled": enabled}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := scanGate(s.DB.QueryRow(ctx, gateSelect+" WHERE g.id = $1", id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, g)
}

func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireOrg(ctx, p, authz.PermGatesManage); err != nil {
		s.fail(w, r, err)
		return
	}
	before, err := s.loadGate(ctx, p, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if before.Managed {
		s.fail(w, r, ErrManagedGate)
		return
	}
	var in gateInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.validateGate(ctx, p.OrganizationID, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	allow := in.AllowExceptions == nil || *in.AllowExceptions
	enabled := before.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE security_gates SET name = $3, stage = $4, policy_id = $5, mode = $6, allow_exceptions = $7,
			application_id = $8, repository_id = $9, enabled = $10, updated_at = now() WHERE organization_id = $1 AND id = $2 AND NOT managed`,
			p.OrganizationID, before.ID, in.Name, in.Stage, in.PolicyID, in.Mode, allow, in.ApplicationID, in.RepositoryID, enabled); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "security_gate.update", TargetType: "security_gate", TargetID: before.ID.String(),
			Metadata: map[string]any{"before": map[string]any{"name": before.Name, "stage": before.Stage, "mode": before.Mode, "policy_id": before.Policy.ID, "enabled": before.Enabled},
				"after": map[string]any{"name": in.Name, "stage": in.Stage, "mode": in.Mode, "policy_id": in.PolicyID, "enabled": enabled, "allow_exceptions": allow}}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := scanGate(s.DB.QueryRow(ctx, gateSelect+" WHERE g.id = $1", before.ID))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, g)
}

func (s *Service) remove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireOrg(ctx, p, authz.PermGatesManage); err != nil {
		s.fail(w, r, err)
		return
	}
	g, err := s.loadGate(ctx, p, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if g.Managed {
		s.fail(w, r, ErrManagedGate)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM security_gates WHERE organization_id = $1 AND id = $2 AND NOT managed`, p.OrganizationID, g.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "security_gate.delete", TargetType: "security_gate", TargetID: g.ID.String(),
			Metadata: map[string]any{"name": g.Name, "stage": g.Stage, "policy_id": g.Policy.ID}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- evaluation --------------------------------------------------------------

type evaluateInput struct {
	Stage         string     `json:"stage"`
	RepositoryID  *uuid.UUID `json:"repository_id"`
	ApplicationID *uuid.UUID `json:"application_id"`
	CommitSHA     string     `json:"commit_sha"`
	PullRequest   int        `json:"pull_request"`
	ScanID        *uuid.UUID `json:"scan_id"`
}

func validCommit(s string) bool {
	if len(s) < 7 || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

func (s *Service) evaluate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in evaluateInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	stage, ok := NormalizeStage(in.Stage)
	if !ok {
		s.fail(w, r, httpx.BadRequest("stage must be one of "+strings.Join(Stages, ", ")))
		return
	}
	if (in.RepositoryID == nil) == (in.ApplicationID == nil) {
		s.fail(w, r, httpx.BadRequest("give exactly one of repository_id or application_id"))
		return
	}
	in.CommitSHA = strings.ToLower(strings.TrimSpace(in.CommitSHA))
	if in.CommitSHA != "" && !validCommit(in.CommitSHA) {
		s.fail(w, r, httpx.BadRequest("commit_sha must be a hexadecimal commit id"))
		return
	}
	if in.PullRequest < 0 || in.PullRequest > 1<<30 {
		s.fail(w, r, httpx.BadRequest("invalid pull_request"))
		return
	}
	if in.ScanID != nil && in.ApplicationID != nil {
		s.fail(w, r, httpx.BadRequest("scan_id needs repository_id"))
		return
	}
	if in.RepositoryID != nil {
		err = s.requireRepo(ctx, p, authz.PermScansRead, *in.RepositoryID)
	} else {
		err = s.requireApplication(ctx, p, authz.PermScansRead, *in.ApplicationID)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var d Decision
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		d, err = Evaluate(ctx, tx, Input{OrgID: p.OrganizationID, Stage: stage, RepositoryID: in.RepositoryID, ApplicationID: in.ApplicationID,
			CommitSHA: in.CommitSHA, PullRequest: in.PullRequest, ScanJobID: in.ScanID, RequestedBy: &p.UserID, RequestID: httpx.RequestID(r)})
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d.RequestedByEmail = p.Email
	if d.Blocks() {
		s.Log.Info("gate decision", "decision_id", d.ID, "stage", d.Stage, "outcome", d.Outcome, "error_code", "PTH-GATE-1001")
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

// --- decisions ---------------------------------------------------------------

const decisionSelect = `SELECT d.id, d.stage, d.outcome, d.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name, ''), d.application_id,
	d.scan_job_id, d.commit_sha, d.pull_request, d.gates, d.policy_ids, d.policy_versions, d.reasons, d.evidence, COALESCE(u.email, ''), d.created_at,
	COALESCE((SELECT jsonb_agg(jsonb_build_object('id', e.id, 'kind', e.kind, 'status', e.status, 'expires_at', e.expires_at) ORDER BY e.created_at)
	          FROM gate_exceptions e WHERE e.decision_id = d.id), '[]')
	FROM gate_decisions d LEFT JOIN repositories r ON r.id = d.repository_id LEFT JOIN users u ON u.id = d.requested_by`

func scanDecision(row pgx.Row) (Decision, error) {
	var d Decision
	var gates, reasons, evidence, exceptions []byte
	err := row.Scan(&d.ID, &d.Stage, &d.Outcome, &d.RepositoryID, &d.RepositoryName, &d.ApplicationID, &d.ScanJobID, &d.CommitSHA, &d.PullRequest,
		&gates, &d.PolicyIDs, &d.PolicyVersions, &reasons, &evidence, &d.RequestedByEmail, &d.CreatedAt, &exceptions)
	if err != nil {
		return d, err
	}
	d.DocsURL = docsURL
	if err := json.Unmarshal(gates, &d.Gates); err != nil {
		return d, err
	}
	if err := json.Unmarshal(reasons, &d.Reasons); err != nil {
		return d, err
	}
	if err := json.Unmarshal(evidence, &d.Evidence); err != nil {
		return d, err
	}
	return d, json.Unmarshal(exceptions, &d.Exceptions)
}

// VisibilitySQL returns a SQL condition (alias r for the decision's or
// exception's repository, app for its application id column) limiting rows
// to what the principal may read.
func VisibilitySQL(p *authz.Principal, perm authz.Permission, appCol string, first int) (string, []any) {
	f := authz.FilterFor(p, perm)
	scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", first)
	if f.All {
		return "true", nil
	}
	// Application-level rows: visible when every active repository of the
	// application is in scope.
	appScope, appArgs := org.ScopeSQL(f, "ar.id", "ar.business_unit_id", "ar.country_id", first+len(args))
	return "((r.id IS NOT NULL AND " + scope + ") OR (r.id IS NULL AND " + appCol + " IS NOT NULL AND NOT EXISTS (SELECT 1 FROM repositories ar WHERE ar.application_id = " +
		appCol + " AND ar.archived_at IS NULL AND NOT " + appScope + ")))", append(args, appArgs...)
}

func (s *Service) listDecisions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermRemediationRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	args := []any{p.OrganizationID}
	where := []string{"d.organization_id = $1"}
	if v := q.Get("stage"); v != "" {
		st, ok := NormalizeStage(v)
		if !ok {
			s.fail(w, r, httpx.BadRequest("unknown stage"))
			return
		}
		args = append(args, st)
		where = append(where, fmt.Sprintf("d.stage = $%d", len(args)))
	}
	if v := q.Get("outcome"); v != "" {
		if _, ok := outcomeRank[v]; !ok {
			s.fail(w, r, httpx.BadRequest("unknown outcome"))
			return
		}
		args = append(args, v)
		where = append(where, fmt.Sprintf("d.outcome = $%d", len(args)))
	}
	for _, k := range []string{"repository_id", "application_id"} {
		if v := q.Get(k); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				s.fail(w, r, httpx.BadRequest("invalid "+k))
				return
			}
			args = append(args, id)
			where = append(where, fmt.Sprintf("d.%s = $%d", k, len(args)))
		}
	}
	if v := q.Get("cursor"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		args = append(args, id)
		where = append(where, fmt.Sprintf("d.id < $%d", len(args)))
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			s.fail(w, r, httpx.BadRequest("limit must be 1-200"))
			return
		}
		limit = n
	}
	vis, vargs := VisibilitySQL(p, authz.PermRemediationRead, "d.application_id", len(args)+1)
	args = append(args, vargs...)
	where = append(where, vis)
	// UUIDv7 ids are time-ordered: keyset pagination on id.
	rows, err := s.DB.Query(ctx, decisionSelect+" WHERE "+strings.Join(where, " AND ")+fmt.Sprintf(" ORDER BY d.id DESC LIMIT %d", limit+1), args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Decision, error) { return scanDecision(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next *string
	if len(items) > limit {
		items = items[:limit]
		c := items[limit-1].ID.String()
		next = &c
	}
	if items == nil {
		items = []Decision{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (s *Service) loadDecision(ctx context.Context, p *authz.Principal, r *http.Request, perm authz.Permission) (Decision, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return Decision{}, errNotFound
	}
	d, err := scanDecision(s.DB.QueryRow(ctx, decisionSelect+" WHERE d.organization_id = $1 AND d.id = $2", p.OrganizationID, id))
	if err != nil {
		return d, err
	}
	switch {
	case d.RepositoryID != nil:
		err = s.requireRepo(ctx, p, perm, *d.RepositoryID)
	case d.ApplicationID != nil:
		err = s.requireApplication(ctx, p, perm, *d.ApplicationID)
	default:
		err = s.requireOrg(ctx, p, perm)
	}
	return d, err
}

func (s *Service) getDecision(w http.ResponseWriter, r *http.Request) {
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.loadDecision(r.Context(), p, r, authz.PermRemediationRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

// --- exceptions and approvals --------------------------------------------------

// Exception is a gate exception or approval.
type Exception struct {
	ID               uuid.UUID      `json:"id"`
	GateID           uuid.UUID      `json:"gate_id"`
	GateName         string         `json:"gate_name"`
	DecisionID       *uuid.UUID     `json:"decision_id"`
	Kind             string         `json:"kind"`
	RepositoryID     *uuid.UUID     `json:"repository_id"`
	RepositoryName   string         `json:"repository_name"`
	ApplicationID    *uuid.UUID     `json:"application_id"`
	Scope            map[string]any `json:"scope"`
	Reason           string         `json:"reason"`
	Status           string         `json:"status"`
	RequestedByID    uuid.UUID      `json:"requested_by_id"`
	RequestedByEmail string         `json:"requested_by_email"`
	DecidedByEmail   string         `json:"decided_by_email"`
	DecisionNote     string         `json:"decision_note"`
	ExpiresAt        time.Time      `json:"expires_at"`
	CreatedAt        time.Time      `json:"created_at"`
	DecidedAt        *time.Time     `json:"decided_at"`
	// CanDecide: the caller may approve or reject it (not the requester).
	CanDecide bool `json:"can_decide"`
}

const exceptionSelect = `SELECT e.id, e.gate_id, g.name, e.decision_id, e.kind, e.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name, ''),
	e.application_id, e.scope, e.reason, CASE WHEN e.status IN ('requested', 'approved') AND e.expires_at <= now() THEN 'expired' ELSE e.status END,
	e.requested_by, COALESCE(ru.email, ''), COALESCE(du.email, ''), e.decision_note, e.expires_at, e.created_at, e.decided_at
	FROM gate_exceptions e JOIN security_gates g ON g.id = e.gate_id LEFT JOIN repositories r ON r.id = e.repository_id
	LEFT JOIN users ru ON ru.id = e.requested_by LEFT JOIN users du ON du.id = e.decided_by`

func scanException(row pgx.Row) (Exception, error) {
	var e Exception
	var scope []byte
	err := row.Scan(&e.ID, &e.GateID, &e.GateName, &e.DecisionID, &e.Kind, &e.RepositoryID, &e.RepositoryName, &e.ApplicationID, &scope,
		&e.Reason, &e.Status, &e.RequestedByID, &e.RequestedByEmail, &e.DecidedByEmail, &e.DecisionNote, &e.ExpiresAt, &e.CreatedAt, &e.DecidedAt)
	if err == nil {
		err = json.Unmarshal(scope, &e.Scope)
	}
	return e, err
}

type exceptionInput struct {
	Reason    string     `json:"reason"`
	ExpiresAt time.Time  `json:"expires_at"`
	GateID    *uuid.UUID `json:"gate_id"`
	// Scope: "decision" (default: the decision's pull request or commit) or
	// "repository" (any evaluation of the repository until it expires).
	Scope string `json:"scope"`
}

func (s *Service) requestException(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	d, err := s.loadDecision(ctx, p, r, authz.PermRemediationManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in exceptionInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	switch {
	case in.Reason == "" || len(in.Reason) > 4000:
		err = httpx.BadRequest("reason is required (at most 4000 characters)")
	case !in.ExpiresAt.After(time.Now().Add(time.Minute)):
		err = httpx.BadRequest("expires_at must be in the future")
	case in.ExpiresAt.After(time.Now().Add(maxExceptionLifetime)):
		err = httpx.BadRequest("expires_at: at most 365 days ahead")
	case in.Scope != "" && in.Scope != "decision" && in.Scope != "repository":
		err = httpx.BadRequest("scope must be decision or repository")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The gate the exception is for: one of the decision's blocking gates.
	var target *GateResult
	for i, g := range d.Gates {
		if g.ID == nil || (g.Effect != OutcomeBlock && g.Effect != OutcomeApproval) {
			continue
		}
		if in.GateID == nil || *in.GateID == *g.ID {
			if target != nil && in.GateID == nil {
				s.fail(w, r, httpx.BadRequest("the decision has several blocking gates; give gate_id"))
				return
			}
			target = &d.Gates[i]
		}
	}
	if target == nil {
		s.fail(w, r, errNothingToExcept)
		return
	}
	kind := "exception"
	if target.Effect == OutcomeApproval {
		kind = "approval"
	}
	var allow bool
	if err := s.DB.QueryRow(ctx, `SELECT allow_exceptions FROM security_gates WHERE organization_id = $1 AND id = $2`, p.OrganizationID, *target.ID).Scan(&allow); err != nil {
		s.fail(w, r, err)
		return
	}
	if kind == "exception" && !allow {
		s.fail(w, r, ErrNoExceptions)
		return
	}
	scope := map[string]any{}
	if in.Scope != "repository" {
		if d.PullRequest != nil {
			scope["pull_request"] = *d.PullRequest
		} else if d.CommitSHA != "" {
			scope["commit_sha"] = d.CommitSHA
		}
	}
	scopeJSON, _ := json.Marshal(scope)
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO gate_exceptions (id, organization_id, gate_id, decision_id, kind, repository_id, application_id,
			scope, reason, requested_by, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			id, p.OrganizationID, *target.ID, d.ID, kind, d.RepositoryID, d.ApplicationID, scopeJSON, in.Reason, p.UserID, in.ExpiresAt); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "gate_exception.request", TargetType: "gate_exception", TargetID: id.String(),
			Metadata: map[string]any{"kind": kind, "gate_id": target.ID, "decision_id": d.ID, "expires_at": in.ExpiresAt, "scope": scope}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	e, err := scanException(s.DB.QueryRow(ctx, exceptionSelect+" WHERE e.id = $1", id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, e)
}

func (s *Service) listExceptions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermRemediationRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	args := []any{p.OrganizationID}
	where := []string{"e.organization_id = $1"}
	if v := r.URL.Query().Get("status"); v != "" {
		if !slices.Contains([]string{"requested", "approved", "rejected", "expired", "revoked"}, v) {
			s.fail(w, r, httpx.BadRequest("unknown status"))
			return
		}
		args = append(args, v)
		where = append(where, fmt.Sprintf(`(CASE WHEN e.status IN ('requested', 'approved') AND e.expires_at <= now() THEN 'expired' ELSE e.status END) = $%d`, len(args)))
	}
	vis, vargs := VisibilitySQL(p, authz.PermRemediationRead, "e.application_id", len(args)+1)
	args = append(args, vargs...)
	where = append(where, vis)
	rows, err := s.DB.Query(ctx, exceptionSelect+" WHERE "+strings.Join(where, " AND ")+" ORDER BY e.created_at DESC LIMIT 500", args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Exception, error) { return scanException(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	canApprove := p.HasAnywhere(authz.PermGatesApproveExcept)
	for i := range items {
		items[i].CanDecide = canApprove && items[i].Status == "requested" && items[i].RequestedByID != p.UserID
	}
	if items == nil {
		items = []Exception{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

type decideInput struct {
	Note string `json:"note"`
}

func (s *Service) decideException(to string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		p, err := s.begin(r)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		id, err := uuid.Parse(r.PathValue("id"))
		if err != nil {
			s.fail(w, r, errNotFound)
			return
		}
		var in decideInput
		if err := httpx.DecodeJSON(w, r, &in); err != nil {
			s.fail(w, r, err)
			return
		}
		in.Note = strings.TrimSpace(in.Note)
		if len(in.Note) > 2000 {
			s.fail(w, r, httpx.BadRequest("note: at most 2000 characters"))
			return
		}
		e, err := scanException(s.DB.QueryRow(ctx, exceptionSelect+" WHERE e.organization_id = $1 AND e.id = $2", p.OrganizationID, id))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		perm := authz.PermGatesApproveExcept
		if to == "revoked" && e.RequestedByID == p.UserID {
			perm = authz.PermRemediationManage // requesters may withdraw their own request
		}
		switch {
		case e.RepositoryID != nil:
			err = s.requireRepo(ctx, p, perm, *e.RepositoryID)
		case e.ApplicationID != nil:
			err = s.requireApplication(ctx, p, perm, *e.ApplicationID)
		}
		if err != nil {
			s.fail(w, r, err)
			return
		}
		from := []string{"requested"}
		if to == "revoked" {
			from = []string{"requested", "approved"}
		}
		if !slices.Contains(from, e.Status) {
			s.fail(w, r, ErrNotPending)
			return
		}
		// Four eyes: the requester never approves or rejects (also a
		// database CHECK).
		if to != "revoked" && e.RequestedByID == p.UserID {
			s.fail(w, r, ErrSelfApproval)
			return
		}
		err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
			var decidedBy *uuid.UUID
			if to != "revoked" {
				decidedBy = &p.UserID
			}
			tag, err := tx.Exec(ctx, `UPDATE gate_exceptions SET status = $3, decided_by = COALESCE($4, decided_by), decided_at = CASE WHEN $4::uuid IS NOT NULL THEN now() ELSE decided_at END,
				decision_note = $5 WHERE organization_id = $1 AND id = $2 AND status = ANY($6) AND expires_at > now()`,
				p.OrganizationID, id, to, decidedBy, in.Note, from)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return ErrNotPending
			}
			return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action:     map[string]string{"approved": "gate_exception.approve", "rejected": "gate_exception.reject", "revoked": "gate_exception.revoke"}[to],
				TargetType: "gate_exception", TargetID: id.String(),
				Metadata: map[string]any{"kind": e.Kind, "gate_id": e.GateID, "requested_by": e.RequestedByEmail, "note": in.Note, "status": to}})
		})
		if err != nil {
			if db.IsCheckViolation(err) {
				err = ErrSelfApproval
			}
			s.fail(w, r, err)
			return
		}
		e, err = scanException(s.DB.QueryRow(ctx, exceptionSelect+" WHERE e.id = $1", id))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, e)
	}
}
