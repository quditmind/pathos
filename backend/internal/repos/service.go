// Package repos manages SCM connections, repositories, applications, tags
// and SCM webhooks.
package repos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/tenant"
	"pathos/internal/scm"
	"pathos/internal/secrets"
	"pathos/internal/vault"
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
	NewClient func(cfg scm.Config) (scm.FullClient, error)
	// Sources stores encrypted uploads and source snapshots (nil disables
	// local uploads).
	Sources SourceStore
	// Limits bounds uploads and archive processing.
	Limits Limits
	// EnqueueScan queues an onboarding scan (set by the server wiring).
	EnqueueScan func(ctx context.Context, orgID, repoID uuid.UUID, trigger string, requestedBy *uuid.UUID) error
	// HTTP is the outbound client for SCM calls (defaults to Net.Client()).
	HTTP *http.Client
	// Public checks repositories for anonymous import (nil: the public
	// SaaS APIs through HTTP; tests replace it).
	Public *PublicProbe
	// OnEvent is called for verified push / pull request / merge events on
	// imported repositories (Phase 4 enqueues scans here).
	OnEvent func(ctx context.Context, orgID, repoID uuid.UUID, ev scm.WebhookEvent)
	// HTTPOverridesCA makes HTTP (tests) serve connections with a CA bundle too.
	HTTPOverridesCA bool

	caMu      sync.Mutex
	caClients map[string]*http.Client
}

// httpClientFor returns the outbound client for a connection: the shared
// client, or one per distinct private CA bundle (cached; bundles are
// configuration, so the cache key is their hash).
func (s *Service) httpClientFor(caBundle string) (*http.Client, error) {
	if caBundle == "" || s.HTTPOverridesCA {
		return s.httpClient(), nil
	}
	sum := sha256.Sum256([]byte(caBundle))
	key := hex.EncodeToString(sum[:])
	s.caMu.Lock()
	defer s.caMu.Unlock()
	if c, ok := s.caClients[key]; ok {
		return c, nil
	}
	c, err := s.Net.ClientWithCA(caBundle)
	if err != nil {
		return nil, err
	}
	if s.caClients == nil {
		s.caClients = map[string]*http.Client{}
	}
	if len(s.caClients) > 256 {
		clear(s.caClients)
	}
	s.caClients[key] = c
	return c, nil
}

// validateStoredBase re-checks a stored base URL against the network policy.
func (s *Service) validateStoredBase(provider, base string) error {
	if provider == scm.GenericGit && strings.HasPrefix(base, "ssh://") {
		r, err := scm.ParseSSHURL(base)
		if err != nil {
			return err
		}
		if ip, err := netip.ParseAddr(r.Host); err == nil && !s.Net.Allowed(ip) {
			return scm.ErrBlockedAddress
		}
		return nil
	}
	_, err := s.Net.ValidateBaseURL(base)
	return err
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
	s.registerAssets(mux)
	s.registerDirectory(mux)
	s.registerSync(mux)
	s.registerInventory(mux)
	s.registerImports(mux)
	s.registerUploads(mux)
	s.registerInsights(mux)
}

// RegisterPublic mounts the unauthenticated webhook receivers.
func (s *Service) RegisterPublic(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/webhooks/github/{id}", s.webhookScope(s.githubWebhook))
	mux.HandleFunc("POST /api/webhooks/azure-devops/{id}", s.webhookScope(s.azureWebhook))
	mux.HandleFunc("POST /api/webhooks/gitlab/{id}", s.webhookScope(s.gitlabWebhook))
	mux.HandleFunc("POST /api/webhooks/bitbucket/{id}", s.webhookScope(s.bitbucketWebhook))
	mux.HandleFunc("POST /api/webhooks/bitbucket-data-center/{id}", s.webhookScope(s.bitbucketDataCenterWebhook))
}

// webhookScope scopes an inbound SCM webhook to the organization of the
// connection in its URL. The lookup of that organization is the only query
// in system scope; the handler then verifies the delivery's signature with
// the connection's own secret, so a delivery for one organization's
// connection can never act in another organization.
func (s *Service) webhookScope(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		if id, err := uuid.Parse(r.PathValue("id")); err == nil {
			var orgID uuid.UUID
			if err := s.DB.QueryRow(tenant.WithSystem(ctx), `SELECT organization_id FROM scm_connections WHERE id = $1`, id).Scan(&orgID); err == nil {
				ctx = tenant.WithOrg(ctx, orgID)
			}
		}
		next(w, r.WithContext(ctx))
	}
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	httpx.WriteError(w, r, s.Log, apiError(err))
}

// apiError maps a service error onto the API error the handlers return.
func apiError(err error) error {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("an item with this name already exists")
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("a referenced item (application, business unit, country, user or tag) does not exist")
	case errors.Is(err, scm.ErrAuth), errors.Is(err, scm.ErrBlockedAddress), errors.Is(err, scm.ErrNotFound),
		errors.Is(err, scm.ErrForbidden), errors.Is(err, scm.ErrRateLimited), errors.Is(err, scm.ErrTokenExpired):
		err = httpx.E(http.StatusBadGateway, "scm_error", err.Error()).WithDiag(scm.DiagCode(err))
	case errors.Is(err, scm.ErrNotSupported):
		err = httpx.BadRequest("not supported by this provider").WithDiag(scm.DiagCode(err))
	case vault.DiagCode(err) != "" && scm.DiagCode(err) == "" && !isHTTPError(err):
		// A credential stored as a vault: reference could not be resolved.
		err = httpx.E(http.StatusBadGateway, "scm_error", err.Error()).WithDiag(vault.DiagCode(err))
	case scm.DiagCode(err) != "" && !isHTTPError(err):
		// Transport, certificate and timeout errors name only the host.
		err = httpx.E(http.StatusBadGateway, "scm_error", err.Error()).WithDiag(scm.DiagCode(err))
	}
	return err
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
	ID              uuid.UUID  `json:"id"`
	Name            string     `json:"name"`
	Provider        string     `json:"provider"`
	BaseURL         string     `json:"base_url"`
	AuthType        string     `json:"auth_type"`
	Owner           string     `json:"owner"`
	AppID           *int64     `json:"github_app_id"`
	InstallationID  *int64     `json:"github_installation_id"`
	Status          string     `json:"status"`
	StatusMessage   string     `json:"status_message"`
	LastCheckedAt   *time.Time `json:"last_checked_at"`
	WebhookURL      string     `json:"webhook_url"`
	RepositoryCount int        `json:"repository_count"`
	CreatedAt       time.Time  `json:"created_at"`
	OAuthAppID      *uuid.UUID `json:"oauth_app_id"`
	Account         string     `json:"account"`
	Organizations   []string   `json:"organizations"`
	TokenExpiresAt  *time.Time `json:"token_expires_at"`
	// WebhookSigned (GitLab): a webhook signing token is set, so only
	// signed deliveries are accepted.
	WebhookSigned bool `json:"webhook_signed"`

	Capabilities scm.Capabilities `json:"capabilities"`

	// Private CA bundle: whether one is set and its certificates' metadata
	// (subject, expiry, fingerprint). The PEM itself is not returned.
	HasCABundle    bool         `json:"has_ca_bundle"`
	CACertificates []scm.CACert `json:"ca_certificates"`
	CABundlePEM    string       `json:"-"`
	// Generic Git over SSH: pinned host keys (known_hosts, configuration).
	SSHKnownHosts string             `json:"ssh_known_hosts"`
	SSHHostKeys   []scm.SSHKnownHost `json:"ssh_host_keys"`

	secretID        uuid.UUID
	webhookSecretID uuid.UUID
	orgID           uuid.UUID
}

const connCols = `c.id, c.name, c.provider, c.base_url, c.auth_type, c.owner, c.github_app_id, c.github_installation_id,
	c.status, c.status_message, c.last_checked_at, c.created_at, c.secret_id, c.webhook_secret_id, c.organization_id,
	(SELECT count(*) FROM repositories r WHERE r.scm_connection_id = c.id AND r.archived_at IS NULL),
	c.oauth_app_id, c.account, c.organizations, c.token_expires_at, c.webhook_signing_secret_id IS NOT NULL,
	c.ca_bundle_pem, c.ssh_known_hosts`

func (s *Service) scanConn(row pgx.Row) (Connection, error) {
	var c Connection
	err := row.Scan(&c.ID, &c.Name, &c.Provider, &c.BaseURL, &c.AuthType, &c.Owner, &c.AppID, &c.InstallationID,
		&c.Status, &c.StatusMessage, &c.LastCheckedAt, &c.CreatedAt, &c.secretID, &c.webhookSecretID, &c.orgID, &c.RepositoryCount,
		&c.OAuthAppID, &c.Account, &c.Organizations, &c.TokenExpiresAt, &c.WebhookSigned,
		&c.CABundlePEM, &c.SSHKnownHosts)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, errNotFound
	}
	c.CACertificates, c.SSHHostKeys = []scm.CACert{}, []scm.SSHKnownHost{}
	c.HasCABundle = c.CABundlePEM != ""
	if _, infos, perr := scm.ParseCABundle(c.CABundlePEM, time.Now()); perr == nil && infos != nil {
		c.CACertificates = infos
	}
	if c.SSHKnownHosts != "" {
		if hk, perr := scm.ParseKnownHosts(c.SSHKnownHosts); perr == nil {
			c.SSHHostKeys = hk
		}
	}
	if c.Organizations == nil {
		c.Organizations = []string{}
	}
	c.WebhookURL = s.webhookURL(c)
	c.Capabilities = providerCapabilities(c.Provider)
	return c, err
}

// providerCapabilities looks up the provider catalog.
func providerCapabilities(provider string) scm.Capabilities {
	for _, p := range scm.AllProviders() {
		if p.Key == provider {
			return p.Capabilities
		}
	}
	return scm.Capabilities{}
}

func (s *Service) webhookURL(c Connection) string {
	switch c.Provider {
	case scm.AzureDevOps, scm.AzureDevOpsServer:
		return s.PublicURL + "/api/webhooks/azure-devops/" + c.ID.String()
	case scm.GitLab:
		return s.PublicURL + "/api/webhooks/gitlab/" + c.ID.String()
	case scm.Bitbucket:
		return s.PublicURL + "/api/webhooks/bitbucket/" + c.ID.String()
	case scm.BitbucketDataCenter:
		return s.PublicURL + "/api/webhooks/bitbucket-data-center/" + c.ID.String()
	case scm.GenericGit:
		return "" // no webhooks: sync is ls-remote
	}
	return s.PublicURL + "/api/webhooks/github/" + c.ID.String()
}

func (s *Service) getConn(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Connection, error) {
	return s.scanConn(q.QueryRow(ctx, `SELECT `+connCols+` FROM scm_connections c
		WHERE c.organization_id = $1 AND c.id = $2 AND c.archived_at IS NULL`, orgID, id))
}

// client builds an SCM client for a stored connection.
func (s *Service) client(ctx context.Context, c Connection) (scm.FullClient, error) {
	secret, err := s.Secrets.Reveal(ctx, s.DB, c.orgID, c.secretID, secrets.KindSCM)
	if err != nil {
		return nil, err
	}
	if c.AuthType == scm.AuthAPIToken {
		// user name + token: the token may be a vault: reference.
		var cred scm.APITokenCredential
		if json.Unmarshal(secret, &cred) == nil && secrets.IsReference([]byte(cred.Token)) {
			if cred.Token, err = s.Secrets.ResolveValue(ctx, c.orgID, cred.Token); err != nil {
				return nil, err
			}
			// #nosec G117 -- in-memory only, handed to the SCM client
			if secret, err = json.Marshal(cred); err != nil {
				return nil, err
			}
		}
	}
	hc, err := s.httpClientFor(c.CABundlePEM)
	if err != nil {
		return nil, err
	}
	cfg := scm.Config{Provider: c.Provider, BaseURL: c.BaseURL, AuthType: c.AuthType, Owner: c.Owner, Secret: secret, HTTP: hc,
		Organizations: c.Organizations, KnownHosts: c.SSHKnownHosts, Net: s.Net}
	if c.AuthType == scm.AuthOAuth {
		if c.OAuthAppID == nil {
			return nil, errors.New("OAuth connection without an OAuth application")
		}
		app, err := s.oauthApp(ctx, s.DB, c.orgID, *c.OAuthAppID)
		if err != nil {
			return nil, err
		}
		cfg.OAuth = app
		ts := &tokenStore{s: s, conn: c, app: app}
		var tok scm.OAuthToken
		if json.Unmarshal(secret, &tok) == nil {
			ts.seen = tok.AccessToken
		}
		cfg.Tokens = ts
	}
	if c.AppID != nil {
		cfg.AppID = *c.AppID
	}
	if c.InstallationID != nil {
		cfg.InstallationID = *c.InstallationID
	}
	if err := s.validateStoredBase(c.Provider, c.BaseURL); err != nil {
		return nil, err
	}
	if s.NewClient != nil {
		return s.NewClient(cfg)
	}
	return scm.New(cfg)
}

// CloneCredential returns a clone credential for a repository's connection.
// Used when handing a job to a worker, which only reads: clients that can
// issue a credential limited to reading this one repository do so.
func (s *Service) CloneCredential(ctx context.Context, orgID, connectionID uuid.UUID, repoFullName string) (scm.Credential, error) {
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
	var cred scm.Credential
	if rc, ok := cl.(scm.RepoCloner); ok && repoFullName != "" {
		cred, err = rc.RepoCloneCredential(ctx, repoFullName)
	} else {
		cred, err = cl.CloneCredential(ctx)
	}
	if err == nil && c.Provider == scm.AzureDevOps && (c.AuthType == scm.AuthOAuth || c.AuthType == scm.AuthServicePrincipal) {
		cred.Scheme = "bearer"
	}
	if err == nil {
		cred.CABundle = c.CABundlePEM
	}
	return cred, err
}

// isHTTPError reports whether err already is an API error.
func isHTTPError(err error) bool {
	var he *httpx.Error
	return errors.As(err, &he)
}
