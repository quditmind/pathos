// Package scans manages scan profiles, scan jobs, workers, the internal
// worker API, result ingestion and the findings read API.
package scans

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"pathos/internal/platform/objstore"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
	"pathos/internal/secrets"
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
	// Artifacts stores raw reports and SBOMs; nil keeps them in PostgreSQL.
	Artifacts objstore.Store
	// OpenSnapshot opens a decrypted source snapshot (uploaded repositories).
	OpenSnapshot func(ctx context.Context, orgID, snapshotID uuid.UUID) (io.ReadCloser, string, int64, error)
	// Secrets encrypts scan target credentials.
	Secrets *secrets.Store
	// OnScanFinished runs after a job completes (AI auto-review enqueue).
	OnScanFinished func(ctx context.Context, orgID, jobID uuid.UUID)
	// StatusWriter returns the commit status writer of a repository's SCM
	// connection (pull request checks); nil disables posting.
	StatusWriter func(ctx context.Context, orgID, repoID uuid.UUID) (scm.StatusWriter, scm.RepoRef, error)
	// PublicURL links commit statuses back to PATHOS ("" = no link).
	PublicURL string
	// ClamAVAddress (host:port) scans uploaded build artifacts for malware;
	// ClamAVRequired refuses uploads while the scanner is unavailable.
	ClamAVAddress  string
	ClamAVRequired bool
}

var errNotFound = errors.New("not found")

// Register mounts the user-facing API.
func (s *Service) Register(mux *http.ServeMux) {
	s.registerProfiles(mux)
	s.registerPRChecks(mux)
	s.registerJobs(mux)
	s.registerFindings(mux)
	s.registerImports(mux)
	s.registerRules(mux)
	s.registerTargets(mux)
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
