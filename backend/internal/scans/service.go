// Package scans manages scan profiles, scan jobs, workers, the internal
// worker API, result ingestion and the findings read API.
package scans

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

// Service holds shared dependencies.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// CloneCredential resolves a clone credential for a connection.
	CloneCredential func(ctx context.Context, orgID, connectionID uuid.UUID) (scm.Credential, error)
	// BootstrapToken lets workers register (PATHOS_WORKER_BOOTSTRAP_TOKEN).
	BootstrapToken string
	OrgID          uuid.UUID
	// OnScanFinished runs after a job completes (AI auto-review enqueue).
	OnScanFinished func(ctx context.Context, orgID, jobID uuid.UUID)
}

var errNotFound = errors.New("not found")

// Register mounts the user-facing API.
func (s *Service) Register(mux *http.ServeMux) {
	s.registerProfiles(mux)
	s.registerJobs(mux)
	s.registerFindings(mux)
	s.registerWorkersAdmin(mux)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("an item with this name already exists")
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("a referenced item does not exist")
	}
	httpx.WriteError(w, r, s.Log, err)
}

func pathID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, errNotFound
	}
	return id, nil
}

func (s *Service) orgScope(p *authz.Principal) authz.Scope {
	return authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}
}

// requireRepo checks perm on a repository, hiding existence from callers
// who hold the permission elsewhere but not here.
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

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}
