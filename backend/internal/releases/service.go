// Package releases implements application versions (releases) with frozen
// SBOM and findings snapshots, a portfolio view of which versions contain
// a component or vulnerability, VEX export and import (imported statements
// are reviewable suggestions, never automatic decisions), and operational
// component policies over the SBOM inventory.
package releases

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Service holds dependencies.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/applications/{id}/versions", s.listVersions)
	mux.HandleFunc("POST /api/v1/applications/{id}/versions", s.createVersion)
	mux.HandleFunc("GET /api/v1/applications/{id}/versions/{vid}", s.getVersion)
	mux.HandleFunc("DELETE /api/v1/applications/{id}/versions/{vid}", s.deleteVersion)
	mux.HandleFunc("GET /api/v1/applications/{id}/versions/{vid}/vex", s.exportVersionVEX)
	mux.HandleFunc("POST /api/v1/applications/{id}/versions/{vid}/vex", s.importVersionVEX)
	mux.HandleFunc("GET /api/v1/repositories/{id}/vex", s.exportRepoVEX)
	mux.HandleFunc("POST /api/v1/repositories/{id}/vex", s.importRepoVEX)
	mux.HandleFunc("GET /api/v1/vex-imports", s.listImports)
	mux.HandleFunc("GET /api/v1/vex-suggestions", s.listSuggestions)
	mux.HandleFunc("POST /api/v1/vex-suggestions/{id}/{action}", s.decideSuggestion)
	mux.HandleFunc("GET /api/v1/portfolio/component-versions", s.portfolio)
	mux.HandleFunc("GET /api/v1/component-policies", s.listPolicies)
	mux.HandleFunc("POST /api/v1/component-policies", s.createPolicy)
	mux.HandleFunc("POST /api/v1/component-policies/evaluate", s.evaluateNow)
	mux.HandleFunc("PUT /api/v1/component-policies/{id}", s.updatePolicy)
	mux.HandleFunc("DELETE /api/v1/component-policies/{id}", s.deletePolicy)
	mux.HandleFunc("GET /api/v1/component-policy-violations", s.listViolations)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("a referenced item does not exist")
	}
	httpx.WriteError(w, r, s.Log, err)
}

func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, errNotFound
	}
	return id, nil
}

// app is an application with what authorization needs.
type app struct {
	ID    uuid.UUID
	Name  string
	BU    *uuid.UUID
	Repos []uuid.UUID // non-archived repositories
}

func (s *Service) loadApp(ctx context.Context, orgID, id uuid.UUID) (app, error) {
	a := app{ID: id}
	err := s.DB.QueryRow(ctx, `SELECT a.name, a.business_unit_id,
		COALESCE((SELECT array_agg(r.id ORDER BY r.full_name) FROM repositories r WHERE r.application_id = a.id AND r.archived_at IS NULL), '{}')
		FROM applications a WHERE a.organization_id = $1 AND a.id = $2`, orgID, id).Scan(&a.Name, &a.BU, &a.Repos)
	if err != nil {
		return a, errNotFound
	}
	return a, nil
}

func (s *Service) appScope(p *authz.Principal, a app) authz.Scope {
	if a.BU != nil {
		return authz.Scope{Type: authz.ScopeBusinessUnit, ID: *a.BU}
	}
	return authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}
}

func repoScope(id uuid.UUID) authz.Scope { return authz.Scope{Type: authz.ScopeRepository, ID: id} }

// canOnRepo reports whether p holds perm on a repository.
func (s *Service) canOnRepo(ctx context.Context, p *authz.Principal, perm authz.Permission, repo uuid.UUID) bool {
	ok, err := s.Authz.Can(ctx, p, perm, repoScope(repo))
	return err == nil && ok
}

// appForRead loads an application the caller may see: perm on the
// application's scope, or on one of its repositories (like the list of
// applications). Otherwise it does not exist for the caller.
func (s *Service) appForRead(r *http.Request, perm authz.Permission) (*authz.Principal, app, error) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		return p, app{}, err
	}
	a, err := s.loadApp(ctx, p.OrganizationID, id)
	if err != nil {
		return p, a, err
	}
	if ok, _ := s.Authz.Can(ctx, p, perm, s.appScope(p, a)); ok {
		return p, a, nil
	}
	for _, rid := range a.Repos {
		if s.canOnRepo(ctx, p, perm, rid) {
			return p, a, nil
		}
	}
	if p.HasAnywhere(perm) {
		return p, a, errNotFound
	}
	return p, a, authz.ErrForbidden
}

// appForManage requires repos.manage on the application's scope (as
// editing the application does).
func (s *Service) appForManage(r *http.Request) (*authz.Principal, app, error) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		return p, app{}, err
	}
	a, err := s.loadApp(ctx, p.OrganizationID, id)
	if err != nil {
		return p, a, err
	}
	return p, a, s.Authz.Require(ctx, p, authz.PermReposManage, s.appScope(p, a))
}

// requireRepo checks perm on a repository of the caller's organization;
// a repository the caller cannot read at all does not exist.
func (s *Service) requireRepo(ctx context.Context, p *authz.Principal, perm authz.Permission, id uuid.UUID) error {
	var exists bool
	if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM repositories WHERE organization_id = $1 AND id = $2)`, p.OrganizationID, id).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return errNotFound
	}
	err := s.Authz.Require(ctx, p, perm, repoScope(id))
	if errors.Is(err, authz.ErrForbidden) && !s.canOnRepo(ctx, p, authz.PermReposRead, id) {
		return errNotFound
	}
	return err
}

func safeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r == '/' || r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s)
}
