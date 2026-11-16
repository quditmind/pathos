// Package scm talks to source code management platforms: GitHub
// (github.com and Enterprise Server), GitLab (gitlab.com and self-managed),
// Bitbucket Cloud and Azure DevOps (Services and Server).
//
// Credentials are passed in already decrypted and are never logged; error
// messages returned to callers never include response bodies that could
// echo credentials.
package scm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Provider identifiers (match scm_connections.provider).
const (
	GitHub            = "github"
	GitHubEnterprise  = "github_enterprise"
	AzureDevOps       = "azure_devops"
	AzureDevOpsServer = "azure_devops_server"
)

// RemoteRepo is a repository as reported by the SCM.
type RemoteRepo struct {
	ExternalID    string     `json:"external_id"`
	FullName      string     `json:"full_name"`
	Name          string     `json:"name"`
	URL           string     `json:"url"`
	CloneURL      string     `json:"clone_url"`
	DefaultBranch string     `json:"default_branch"`
	Visibility    string     `json:"visibility"` // public | private | internal
	Description   string     `json:"description"`
	Language      string     `json:"language"`
	Archived      bool       `json:"archived"`
	PushedAt      *time.Time `json:"pushed_at"`
	// Organization and Project locate the repository for providers whose
	// APIs are addressed by path (GitLab group, Bitbucket workspace and
	// project, Azure DevOps organization and project).
	Organization string `json:"organization"`
	Project      string `json:"project"`
	SizeBytes    int64  `json:"size_bytes"` // 0 = unknown
}

// Client is implemented per provider.
type Client interface {
	// Check validates credentials and returns a human-readable identity.
	Check(ctx context.Context) (string, error)
	ListRepositories(ctx context.Context) ([]RemoteRepo, error)
	ListBranches(ctx context.Context, repo RemoteRepo) ([]string, error)
	// CloneCredential returns the narrowest credential available for
	// cloning: a short-lived installation token for GitHub Apps, otherwise
	// the PAT.
	CloneCredential(ctx context.Context) (Credential, error)
}

// Credential is an HTTPS git credential handed to a worker for one job.
type Credential struct {
	Username string `json:"username"`
	Token    string `json:"token"`
	// Scheme is "basic" (default: username + token) or "bearer"
	// (Microsoft Entra ID access tokens for Azure DevOps).
	Scheme    string     `json:"scheme,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Config describes a connection.
type Config struct {
	Provider string
	BaseURL  string
	AuthType string // pat | github_app | oauth | api_token | service_principal
	Owner    string // optional org/user (GitHub), group (GitLab), workspace (Bitbucket) or project (Azure DevOps)
	// Secret is the stored credential: a PAT, a GitHub App PEM key, or JSON
	// (OAuthToken, APITokenCredential, ServicePrincipalCredential).
	Secret         []byte
	AppID          int64
	InstallationID int64
	// OAuth is the registered application (auth type oauth); Tokens
	// persists refreshed tokens.
	OAuth  *OAuthApp
	Tokens TokenStore
	// Organizations limits Azure DevOps discovery (service principals
	// cannot enumerate organizations).
	Organizations []string
	HTTP          *http.Client
}

// ErrAuth means the SCM rejected the credentials.
var ErrAuth = errors.New("scm: authentication failed (check the token and its scopes)")

// MaxRepositories caps discovery to keep a single call bounded.
const MaxRepositories = 5000

// New returns a client for cfg. Every provider client implements Client and
// Discoverer; authentication is handled by a provider-independent
// authorizer (see auth.go), so adapters do not depend on the auth type.
func New(cfg Config) (FullClient, error) {
	if cfg.HTTP == nil {
		return nil, errors.New("scm: HTTP client required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL(cfg.Provider, "")
	}
	switch cfg.Provider {
	case GitHub, GitHubEnterprise:
		return newGitHub(cfg)
	case GitLab:
		return newGitLab(cfg)
	case Bitbucket:
		return newBitbucket(cfg)
	case AzureDevOps, AzureDevOpsServer:
		return newAzureDevOps(cfg)
	}
	return nil, fmt.Errorf("scm: unknown provider %q", cfg.Provider)
}

// DefaultBaseURL returns the public API URL for cloud providers. For Azure
// DevOps Services an owner yields the legacy organization-scoped URL
// (https://dev.azure.com/<org>); without one the organization-less root is
// returned and organizations are passed per call.
func DefaultBaseURL(provider, owner string) string {
	switch provider {
	case GitHub:
		return "https://api.github.com"
	case GitLab:
		return "https://gitlab.com"
	case Bitbucket:
		return "https://api.bitbucket.org/2.0"
	case AzureDevOps:
		if owner != "" {
			return "https://dev.azure.com/" + owner
		}
		return "https://dev.azure.com"
	}
	return ""
}
