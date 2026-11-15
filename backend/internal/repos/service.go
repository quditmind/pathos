// Package repos manages SCM connections, repositories, applications, tags
// and SCM webhooks.
package repos

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

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

// Service holds dependencies shared by the handlers.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Secrets   *secrets.Store
	Net       scm.NetPolicy
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	PublicURL string
	// NewClient builds SCM clients; tests replace it.
	NewClient func(cfg scm.Config) (scm.Client, error)
	// HTTP is the outbound client for SCM calls (defaults to Net.Client()).
	HTTP *http.Client
	// OnEvent is called for verified push / pull request / merge events on
	// imported repositories (Phase 4 enqueues scans here).
	OnEvent func(ctx context.Context, orgID, repoID uuid.UUID, ev scm.WebhookEvent)
}

func (s *Service) httpClient() *http.Client {
	if s.HTTP == nil {
		s.HTTP = s.Net.Client()
	}
	return s.HTTP
}

// Register mounts all routes. Webhook routes are public; the caller must
// mount them outside the authenticated mux (see RegisterPublic).
func (s *Service) Register(mux *http.ServeMux) {
	s.registerConnections(mux)
	s.registerRepositories(mux)
	s.registerApplications(mux)
	s.registerTags(mux)
}

// RegisterPublic mounts the unauthenticated webhook receivers.
func (s *Service) RegisterPublic(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/webhooks/github/{id}", s.githubWebhook)
	mux.HandleFunc("POST /api/webhooks/azure-devops/{id}", s.azureWebhook)
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
		err = httpx.BadRequest("a referenced item (application, business unit, country, user or tag) does not exist")
	case errors.Is(err, scm.ErrAuth), errors.Is(err, scm.ErrBlockedAddress):
		err = httpx.E(http.StatusBadGateway, "scm_error", err.Error())
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) orgScope(p *authz.Principal) authz.Scope {
	return authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}
}

// requireOrg checks an org-wide permission.
func (s *Service) requireOrg(r *http.Request, perm authz.Permission) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	if err := s.Authz.Require(r.Context(), p, perm, s.orgScope(p)); err != nil {
		return nil, err
	}
	return p, nil
}

// requireRepo checks perm on a specific repository (via its hierarchy).
func (s *Service) requireRepo(ctx context.Context, p *authz.Principal, perm authz.Permission, repoID uuid.UUID) error {
	return s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: repoID})
}

// targetScope is the narrowest scope implied by placement fields, used to
// authorize imports and moves: BU if set, else region of the country, else
// organization.
func (s *Service) targetScope(ctx context.Context, p *authz.Principal, buID, countryID *uuid.UUID) (authz.Scope, error) {
	if buID != nil {
		return authz.Scope{Type: authz.ScopeBusinessUnit, ID: *buID}, nil
	}
	if countryID != nil {
		var region uuid.UUID
		err := s.DB.QueryRow(ctx, `SELECT region_id FROM countries WHERE id = $1 AND organization_id = $2`, *countryID, p.OrganizationID).Scan(&region)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return authz.Scope{}, httpx.BadRequest("country does not exist")
			}
			return authz.Scope{}, err
		}
		return authz.Scope{Type: authz.ScopeRegion, ID: region}, nil
	}
	return s.orgScope(p), nil
}

// Connection is an SCM connection (credentials are never returned).
type Connection struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Provider       string     `json:"provider"`
	BaseURL        string     `json:"base_url"`
	AuthType       string     `json:"auth_type"`
	Owner          string     `json:"owner"`
	AppID          *int64     `json:"github_app_id"`
	InstallationID *int64     `json:"github_installation_id"`
	Status         string     `json:"status"`
	StatusMessage  string     `json:"status_message"`
	LastCheckedAt  *time.Time `json:"last_checked_at"`
	WebhookURL     string     `json:"webhook_url"`
	RepositoryCount int       `json:"repository_count"`
	CreatedAt      time.Time  `json:"created_at"`

	secretID        uuid.UUID
	webhookSecretID uuid.UUID
	orgID           uuid.UUID
}

const connCols = `c.id, c.name, c.provider, c.base_url, c.auth_type, c.owner, c.github_app_id, c.github_installation_id,
	c.status, c.status_message, c.last_checked_at, c.created_at, c.secret_id, c.webhook_secret_id, c.organization_id,
	(SELECT count(*) FROM repositories r WHERE r.scm_connection_id = c.id AND r.archived_at IS NULL)`

func (s *Service) scanConn(row pgx.Row) (Connection, error) {
	var c Connection
	err := row.Scan(&c.ID, &c.Name, &c.Provider, &c.BaseURL, &c.AuthType, &c.Owner, &c.AppID, &c.InstallationID,
		&c.Status, &c.StatusMessage, &c.LastCheckedAt, &c.CreatedAt, &c.secretID, &c.webhookSecretID, &c.orgID, &c.RepositoryCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, errNotFound
	}
	c.WebhookURL = s.webhookURL(c)
	return c, err
}

func (s *Service) webhookURL(c Connection) string {
	switch c.Provider {
	case scm.AzureDevOps, scm.AzureDevOpsServer:
		return s.PublicURL + "/api/webhooks/azure-devops/" + c.ID.String()
	}
	return s.PublicURL + "/api/webhooks/github/" + c.ID.String()
}

func (s *Service) getConn(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Connection, error) {
	return s.scanConn(q.QueryRow(ctx, `SELECT `+connCols+` FROM scm_connections c
		WHERE c.organization_id = $1 AND c.id = $2 AND c.archived_at IS NULL`, orgID, id))
}

// client builds an SCM client for a stored connection.
func (s *Service) client(ctx context.Context, c Connection) (scm.Client, error) {
	secret, err := s.Secrets.Reveal(ctx, s.DB, c.orgID, c.secretID, secrets.KindSCM)
	if err != nil {
		return nil, err
	}
	cfg := scm.Config{Provider: c.Provider, BaseURL: c.BaseURL, AuthType: c.AuthType, Owner: c.Owner, Secret: secret, HTTP: s.httpClient()}
	if c.AppID != nil {
		cfg.AppID = *c.AppID
	}
	if c.InstallationID != nil {
		cfg.InstallationID = *c.InstallationID
	}
	if _, err := s.Net.ValidateBaseURL(c.BaseURL); err != nil {
		return nil, err
	}
	if s.NewClient != nil {
		return s.NewClient(cfg)
	}
	return scm.New(cfg)
}

// CloneCredential returns a clone credential for a repository's connection.
// Used by the scan service when handing a job to a worker.
func (s *Service) CloneCredential(ctx context.Context, orgID, connectionID uuid.UUID) (scm.Credential, error) {
	c, err := s.getConn(ctx, s.DB, orgID, connectionID)
	if err != nil {
		return scm.Credential{}, err
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		return scm.Credential{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	return cl.CloneCredential(ctx)
}
