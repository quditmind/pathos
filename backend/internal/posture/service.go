// Package posture provides the ASPM inventory views: application posture
// and risk rollup, aggregation by organization dimension, scan coverage,
// unmanaged assets, benchmarking, dependency graphs and the security
// context graph (blast radius). Everything is computed from live data in the
// caller's repository scope; nothing is cached or estimated.
package posture

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

// Service serves the posture API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/posture/applications", s.applications)
	mux.HandleFunc("GET /api/v1/posture/aggregate", s.aggregate)
	mux.HandleFunc("GET /api/v1/posture/benchmark", s.benchmark)
	mux.HandleFunc("GET /api/v1/posture/coverage", s.coverage)
	mux.HandleFunc("GET /api/v1/posture/unmanaged", s.unmanaged)
	mux.HandleFunc("GET /api/v1/repositories/{id}/dependencies", s.dependencies)
	mux.HandleFunc("GET /api/v1/repositories/{id}/dependencies/paths", s.dependencyPaths)
	mux.HandleFunc("GET /api/v1/findings/{id}/dependency-paths", s.findingPaths)
	mux.HandleFunc("GET /api/v1/posture/blast-radius", s.blastRadius)
	mux.HandleFunc("GET /api/v1/posture/context-graph", s.contextGraph)
	mux.HandleFunc("GET /api/v1/posture/attack-paths", s.attackPaths)
	mux.HandleFunc("GET /api/v1/findings/{id}/related", s.related)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

// scope returns the repository visibility condition (alias r) for perm;
// placeholders start at first.
func scope(p *authz.Principal, perm authz.Permission, first int) (string, []any, error) {
	f := authz.FilterFor(p, perm)
	if f.None() {
		return "", nil, authz.ErrForbidden
	}
	expr, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", first)
	return expr, args, nil
}

// requireRepo checks perm on a repository, hiding existence from callers
// without access.
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

func intParam(r *http.Request, name string, def, lo, hi int) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, httpx.BadRequest(name + " must be between " + strconv.Itoa(lo) + " and " + strconv.Itoa(hi))
	}
	return n, nil
}

// openStatuses are the stored statuses of findings that still need work.
const openStatuses = `('open', 'in_progress', 'needs_review')`
