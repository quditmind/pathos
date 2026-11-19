// Package inventory is the PATHOS 3.0 M3 module: application onboarding
// (connect → discover → find existing asset → register → tag and classify
// → save to inventory → start discovery), application classification, the
// tag framework (category colours, mandatory categories per application
// type, automatic tagging rules, tag history, bulk tagging), the
// application profile hub API and the lifecycle overview.
//
// It builds on the existing inventory in package repos (applications,
// repositories, tags, asset settings and the import pipeline) without
// duplicating it: repositories are still registered by the existing import
// jobs, and tags and classification catalogues are the existing ones.
//
// Everything new is behind the "onboarding" feature flag (the lifecycle
// overview behind "lifecycle_overview"), off by default. GET
// /api/v1/applications/{id} is not flagged: it is the missing read of an
// existing resource.
package inventory

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Feature flags of the module.
const (
	FlagOnboarding = "onboarding"
	FlagLifecycle  = "lifecycle_overview"
)

// Service serves the module's API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the endpoints.
func (s *Service) Register(mux *http.ServeMux) {
	// Application profile hub.
	mux.HandleFunc("GET /api/v1/applications/{id}", s.getApplication)
	mux.HandleFunc("PATCH /api/v1/applications/{id}/classification", s.flagged(FlagOnboarding, s.updateClassification))
	mux.HandleFunc("GET /api/v1/applications/{id}/lifecycle", s.flagged(FlagOnboarding, s.applicationLifecycle))
	mux.HandleFunc("GET /api/v1/applications/{id}/activity", s.flagged(FlagOnboarding, s.applicationActivity))
	mux.HandleFunc("GET /api/v1/applications/{id}/onboarding", s.flagged(FlagOnboarding, s.getOnboarding))
	mux.HandleFunc("POST /api/v1/applications/{id}/onboarding/complete", s.flagged(FlagOnboarding, s.completeOnboarding))
	mux.HandleFunc("POST /api/v1/applications/{id}/onboarding/discovery", s.flagged(FlagOnboarding, s.startDiscovery))
	mux.HandleFunc("POST /api/v1/applications/{id}/detect", s.flagged(FlagOnboarding, s.redetect))

	// Onboarding flow.
	mux.HandleFunc("POST /api/v1/onboarding/match", s.flagged(FlagOnboarding, s.match))
	mux.HandleFunc("POST /api/v1/onboarding", s.flagged(FlagOnboarding, s.register))
	mux.HandleFunc("GET /api/v1/onboarding", s.flagged(FlagOnboarding, s.listDrafts))
	mux.HandleFunc("GET /api/v1/application-settings", s.flagged(FlagOnboarding, s.getSettings))
	mux.HandleFunc("PATCH /api/v1/application-settings", s.flagged(FlagOnboarding, s.updateSettings))

	// Tag framework.
	mux.HandleFunc("GET /api/v1/tag-framework", s.flagged(FlagOnboarding, s.tagFramework))
	mux.HandleFunc("PATCH /api/v1/tag-categories/{id}/framework", s.flagged(FlagOnboarding, s.updateCategoryFramework))
	mux.HandleFunc("POST /api/v1/tag-rules", s.flagged(FlagOnboarding, s.createRule))
	mux.HandleFunc("PATCH /api/v1/tag-rules/{id}", s.flagged(FlagOnboarding, s.updateRule))
	mux.HandleFunc("DELETE /api/v1/tag-rules/{id}", s.flagged(FlagOnboarding, s.deleteRule))
	mux.HandleFunc("POST /api/v1/tag-rules/{id}/apply", s.flagged(FlagOnboarding, s.applyRule))
	mux.HandleFunc("POST /api/v1/tag-assignments/bulk", s.flagged(FlagOnboarding, s.bulkAssign))
	mux.HandleFunc("GET /api/v1/tag-history", s.flagged(FlagOnboarding, s.tagHistory))

	// Lifecycle overview.
	mux.HandleFunc("GET /api/v1/lifecycle/overview", s.flagged(FlagLifecycle, s.lifecycleOverview))
}

// flagged answers PTH-PLAT-1007 (404) unless the organization has the flag on.
func (s *Service) flagged(flag string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := s.Principal(r.Context())
		if p == nil {
			s.fail(w, r, httpx.ErrUnauthenticated)
			return
		}
		if err := featureflags.Require(r.Context(), s.DB, p.OrganizationID, flag); err != nil {
			s.fail(w, r, err)
			return
		}
		h(w, r)
	}
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("an item with this name already exists")
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("a referenced item (application, business unit, region, user, tag or connection) does not exist")
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

func orgScope(p *authz.Principal) authz.Scope {
	return authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}
}

// appScope is the authorization scope of an application: its business
// unit, else the organization (as in package repos).
func appScope(p *authz.Principal, bu *uuid.UUID) authz.Scope {
	if bu != nil {
		return authz.Scope{Type: authz.ScopeBusinessUnit, ID: *bu}
	}
	return orgScope(p)
}

// visibleAppSQL is the condition under which the application aliased "a"
// is visible with perm: an org-wide grant, a grant on its business unit, or
// a visible repository in it (the rule of GET /api/v1/applications).
// Placeholders start at first; append the returned args.
func visibleAppSQL(p *authz.Principal, perm authz.Permission, first int) (string, []any) {
	f := authz.FilterFor(p, perm)
	if f.All {
		return "true", nil
	}
	if f.None() {
		return "false", nil
	}
	scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", first)
	buScope := "false"
	if len(f.BusinessUnits) > 0 {
		// Reuses scope's placeholders: the business units are its second.
		buScope, _ = org.ScopeSQL(authz.Filter{BusinessUnits: f.BusinessUnits}, "NULL::uuid", "a.business_unit_id", "NULL::uuid", first)
	}
	return "(" + buScope + " OR EXISTS (SELECT 1 FROM repositories r WHERE r.application_id = a.id AND r.archived_at IS NULL AND " + scope + "))", args
}

// appRow is the minimal application identity used for checks.
type appRow struct {
	ID       uuid.UUID
	Name     string
	BU       *uuid.UUID
	Status   string
	Archived bool
}

// loadVisibleApp loads an application visible to p with repos.read, else
// errNotFound (an invisible application looks absent).
func (s *Service) loadVisibleApp(ctx context.Context, q db.Querier, p *authz.Principal, id uuid.UUID) (appRow, error) {
	cond, args := visibleAppSQL(p, authz.PermReposRead, 3)
	var a appRow
	err := q.QueryRow(ctx, `SELECT a.id, a.name, a.business_unit_id, a.onboarding_status, a.archived_at IS NOT NULL
		FROM applications a WHERE a.organization_id = $1 AND a.id = $2 AND `+cond, append([]any{p.OrganizationID, id}, args...)...).
		Scan(&a.ID, &a.Name, &a.BU, &a.Status, &a.Archived)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, errNotFound
	}
	return a, err
}

// loadManagedApp loads an application p may change (repos.manage on its
// business unit or the organization). Invisible: 404; visible but not
// manageable: 403.
func (s *Service) loadManagedApp(ctx context.Context, q db.Querier, p *authz.Principal, id uuid.UUID) (appRow, error) {
	a, err := s.loadVisibleApp(ctx, q, p, id)
	if err != nil {
		return a, err
	}
	if a.Archived {
		return a, errNotFound
	}
	return a, s.Authz.Require(ctx, p, authz.PermReposManage, appScope(p, a.BU))
}

// errFields is a validation error with per-field messages (the frontend
// shows them next to the fields).
func errFields(status int, code, diagCode, msg string, fields map[string]string) *httpx.Error {
	e := httpx.E(status, code, msg).WithDiag(diagCode)
	e.Fields = fields
	return e
}
