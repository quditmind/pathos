package scm

import (
	"context"
	"errors"
	"net/http"
	"time"
)

// Additional provider identifiers (match scm_connections.provider).
const (
	GitLab    = "gitlab"    // gitlab.com and self-managed GitLab
	Bitbucket = "bitbucket" // Bitbucket Cloud
)

// Authentication types (match scm_connections.auth_type).
const (
	AuthPAT              = "pat"
	AuthGitHubApp        = "github_app"
	AuthOAuth            = "oauth"
	AuthAPIToken         = "api_token"         // Bitbucket Cloud: Atlassian e-mail + API token
	AuthServicePrincipal = "service_principal" // Azure DevOps: Microsoft Entra ID client credentials
)

// Errors shared by all providers. Adapters wrap them so callers can use
// errors.Is; messages never contain credentials or response bodies.
var (
	// ErrNotSupported means the provider has no such concept (for example
	// projects on GitHub).
	ErrNotSupported = errors.New("scm: not supported by this provider")
	// ErrNotFound means the repository, branch or organization does not
	// exist or is not visible to the credential.
	ErrNotFound = errors.New("scm: not found or not visible to this credential")
	// ErrForbidden means the credential is valid but lacks permission.
	ErrForbidden = errors.New("scm: the credential does not have permission for this operation")
	// ErrRateLimited is transient; retry later.
	ErrRateLimited = errors.New("scm: rate limited by the provider, try again later")
	// ErrTokenExpired means an OAuth token could not be refreshed; the
	// connection must be reconnected.
	ErrTokenExpired = errors.New("scm: the authorization has expired or was revoked; reconnect the connection")
)

// Organization is a GitHub organization or user, GitLab group, Bitbucket
// workspace or Azure DevOps organization.
type Organization struct {
	ID          string `json:"id"`
	Name        string `json:"name"` // identifier used in API paths
	DisplayName string `json:"display_name"`
	Kind        string `json:"kind"` // user | organization | group | workspace
}

// Project is an Azure DevOps project or Bitbucket project.
type Project struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// RepoQuery selects one page of repositories.
type RepoQuery struct {
	Organization string // empty: everything the credential can see
	Project      string // Azure DevOps / Bitbucket only
	Search       string // case-insensitive name filter (server-side where supported)
	PageToken    string // opaque, from RepoPage.NextPageToken
	PageSize     int    // 0 = provider default (≤ 100)
}

// RepoPage is one page of repositories.
type RepoPage struct {
	Items         []RemoteRepo `json:"items"`
	NextPageToken string       `json:"next_page_token"`
}

// RepoRef identifies a remote repository. ExternalID is authoritative when
// set; FullName, Organization and Project help providers whose APIs are
// addressed by path.
type RepoRef struct {
	ExternalID   string `json:"external_id"`
	FullName     string `json:"full_name"`
	Organization string `json:"organization"`
	Project      string `json:"project"`
}

// Ref returns the reference of a listed repository.
func (r RemoteRepo) Ref() RepoRef {
	return RepoRef{ExternalID: r.ExternalID, FullName: r.FullName, Organization: r.Organization, Project: r.Project}
}

// Branch is a branch head.
type Branch struct {
	Name      string `json:"name"`
	CommitSHA string `json:"commit_sha"`
	Default   bool   `json:"is_default"`
}

// Commit is a commit summary.
type Commit struct {
	SHA         string     `json:"sha"`
	Message     string     `json:"message"` // first line only
	Author      string     `json:"author"`
	CommittedAt *time.Time `json:"committed_at"`
}

// RepoDetails is the preview shown before import.
type RepoDetails struct {
	Repository   RemoteRepo       `json:"repository"`
	Branches     []Branch         `json:"branches"`
	LatestCommit *Commit          `json:"latest_commit"`
	Languages    map[string]int64 `json:"languages"`  // bytes or percentage, as the provider reports
	Permission   string           `json:"permission"` // read | write | admin | unknown
}

// Discoverer is the extended discovery interface every provider client
// implements in addition to Client.
type Discoverer interface {
	ListOrganizations(ctx context.Context) ([]Organization, error)
	ListProjects(ctx context.Context, organization string) ([]Project, error)
	ListRepositoriesPage(ctx context.Context, q RepoQuery) (RepoPage, error)
	// GetRepository returns current metadata and proves the credential can
	// read the repository (ErrNotFound / ErrForbidden otherwise).
	GetRepository(ctx context.Context, ref RepoRef) (RemoteRepo, error)
	ListBranchHeads(ctx context.Context, ref RepoRef) ([]Branch, error)
	// LatestCommit returns the head commit of branch ("" = default branch).
	LatestCommit(ctx context.Context, ref RepoRef, branch string) (Commit, error)
	// Languages returns the language breakdown; empty if unknown.
	Languages(ctx context.Context, ref RepoRef) (map[string]int64, error)
	// Revoke invalidates the credential at the provider where an API
	// exists (OAuth tokens on GitHub and GitLab). Others return nil.
	Revoke(ctx context.Context) error
}

// FullClient is what New returns for every provider.
type FullClient interface {
	Client
	Discoverer
}

// OAuthToken is the stored form of an OAuth credential (JSON in secrets).
type OAuthToken struct {
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	TokenType    string     `json:"token_type,omitempty"`
	Scope        string     `json:"scope,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"` // nil: does not expire
}

// Expired reports whether the token is expired or expires within skew.
func (t OAuthToken) Expired(now time.Time, skew time.Duration) bool {
	return t.ExpiresAt != nil && !now.Add(skew).Before(*t.ExpiresAt)
}

// TokenStore serializes OAuth token refreshes for one connection. The
// implementation (internal/repos) locks the connection row, reloads the
// stored token, and only calls refresh if the stored token is still stale,
// so concurrent processes never spend the same refresh token twice.
type TokenStore interface {
	Current(ctx context.Context) (OAuthToken, error)
	RefreshLocked(ctx context.Context, refresh func(ctx context.Context, current OAuthToken) (OAuthToken, error)) (OAuthToken, error)
}

// OAuthApp is an administrator-registered OAuth application.
type OAuthApp struct {
	Provider     string // github | github_enterprise | gitlab | bitbucket | azure_devops
	BaseURL      string // self-managed servers; "" = cloud
	TenantID     string // Microsoft Entra ID tenant
	ClientID     string
	ClientSecret []byte
	Scopes       string // overrides DefaultScopes when set
}

// APITokenCredential is the stored form of a Bitbucket API token.
type APITokenCredential struct {
	Username string `json:"username"` // Atlassian account e-mail
	Token    string `json:"token"`
}

// ServicePrincipalCredential is the stored form of an Entra ID service
// principal: either a client secret or a PEM certificate + private key.
type ServicePrincipalCredential struct {
	TenantID       string `json:"tenant_id"`
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret,omitempty"`
	CertificatePEM string `json:"certificate_pem,omitempty"`
	PrivateKeyPEM  string `json:"private_key_pem,omitempty"`
}

// OAuthExchange is the provider-specific OAuth authorization-code flow.
type OAuthExchange interface {
	// AuthorizeURL builds the provider consent URL.
	AuthorizeURL(app OAuthApp, redirectURI, state, pkceChallenge string) (string, error)
	// Exchange trades an authorization code for a token.
	Exchange(ctx context.Context, hc *http.Client, app OAuthApp, redirectURI, code, pkceVerifier string) (OAuthToken, error)
	// Refresh trades a refresh token for a new token.
	Refresh(ctx context.Context, hc *http.Client, app OAuthApp, current OAuthToken) (OAuthToken, error)
}

// Capabilities describe what the UI can offer for a provider.
type Capabilities struct {
	Organizations bool `json:"organizations"`
	Projects      bool `json:"projects"`
	ServerSearch  bool `json:"server_search"`
}

// ProviderInfo describes a provider and its authentication methods for the
// connection wizard (GET /api/v1/scm-providers).
type ProviderInfo struct {
	Key             string       `json:"key"`
	Label           string       `json:"label"`
	Category        string       `json:"category"` // git | devops
	DefaultBaseURL  string       `json:"default_base_url"`
	BaseURLRequired bool         `json:"base_url_required"`
	BaseURLHelp     string       `json:"base_url_help"`
	OwnerLabel      string       `json:"owner_label"` // e.g. "Organization or user (optional)"
	Capabilities    Capabilities `json:"capabilities"`
	AuthMethods     []AuthMethod `json:"auth_methods"`
}

// AuthMethod is one way to authenticate to a provider.
type AuthMethod struct {
	Key         string      `json:"key"` // auth_type
	Label       string      `json:"label"`
	Description string      `json:"description"`
	OAuth       bool        `json:"oauth"` // uses a registered OAuth app and a browser redirect
	Fields      []AuthField `json:"fields"`
	DocsURL     string      `json:"docs_url"`
}

// AuthField is an input of an authentication method.
type AuthField struct {
	Name     string `json:"name"` // request field name
	Label    string `json:"label"`
	Type     string `json:"type"` // text | password | textarea | number | list
	Required bool   `json:"required"`
	Secret   bool   `json:"secret"`
	Help     string `json:"help"`
}
