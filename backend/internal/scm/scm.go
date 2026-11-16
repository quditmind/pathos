// Package scm talks to source code management platforms: GitHub
// (github.com and Enterprise Server) and Azure DevOps (Services and Server).
//
// Credentials are passed in already decrypted and are never logged; error
// messages returned to callers never include response bodies that could
// echo credentials.
package scm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	Username  string     `json:"username"`
	Token     string     `json:"token"`
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

// New returns a client for cfg.
func New(cfg Config) (Client, error) {
	if cfg.HTTP == nil {
		return nil, errors.New("scm: HTTP client required")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	switch cfg.Provider {
	case GitHub, GitHubEnterprise:
		return newGitHub(cfg)
	case AzureDevOps, AzureDevOpsServer:
		if cfg.AuthType != "pat" {
			return nil, errors.New("scm: Azure DevOps supports PAT authentication")
		}
		return &azureDevOps{cfg: cfg}, nil
	}
	return nil, fmt.Errorf("scm: unknown provider %q", cfg.Provider)
}

// DefaultBaseURL returns the public API URL for cloud providers.
func DefaultBaseURL(provider, owner string) string {
	switch provider {
	case GitHub:
		return "https://api.github.com"
	case AzureDevOps:
		if owner != "" {
			return "https://dev.azure.com/" + owner
		}
	}
	return ""
}

// doJSON performs a request and decodes a JSON response into out.
func doJSON(ctx context.Context, c *http.Client, req *http.Request, out any) (*http.Response, error) {
	req = req.WithContext(ctx)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "PATHOS-ASPM")
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scm: request to %s failed: %w", req.URL.Host, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden && resp.Header.Get("X-RateLimit-Remaining") != "0":
		return resp, ErrAuth
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
		return resp, errors.New("scm: rate limited by the provider, try again later")
	case resp.StatusCode == http.StatusNotFound:
		return resp, fmt.Errorf("scm: %s not found (check the base URL and owner)", req.URL.Path)
	case resp.StatusCode >= 300:
		return resp, fmt.Errorf("scm: unexpected status %d from %s", resp.StatusCode, req.URL.Host)
	}
	// Azure DevOps answers some auth failures with a 203 HTML sign-in page.
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
		return resp, ErrAuth
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(resp.Body, 32<<20)).Decode(out); err != nil {
			return resp, fmt.Errorf("scm: invalid response from %s: %w", req.URL.Host, err)
		}
	}
	return resp, nil
}
