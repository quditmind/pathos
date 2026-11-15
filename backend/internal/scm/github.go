package scm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type gitHub struct {
	cfg Config
	key *rsa.PrivateKey // GitHub App only

	mu       sync.Mutex
	instTok  string
	instTokX time.Time
}

func newGitHub(cfg Config) (*gitHub, error) {
	g := &gitHub{cfg: cfg}
	switch cfg.AuthType {
	case "pat":
		if len(cfg.Secret) == 0 {
			return nil, errors.New("scm: token required")
		}
	case "github_app":
		k, err := ParseRSAPrivateKey(cfg.Secret)
		if err != nil {
			return nil, err
		}
		if cfg.AppID <= 0 || cfg.InstallationID <= 0 {
			return nil, errors.New("scm: GitHub App ID and installation ID are required")
		}
		g.key = k
	default:
		return nil, fmt.Errorf("scm: unsupported auth type %q for GitHub", cfg.AuthType)
	}
	return g, nil
}

// ParseRSAPrivateKey parses a PKCS#1 or PKCS#8 PEM RSA key (GitHub App keys).
func ParseRSAPrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("scm: GitHub App private key must be PEM encoded")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("scm: invalid GitHub App private key")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("scm: GitHub App private key must be RSA")
	}
	return rk, nil
}

// appJWT builds the short-lived RS256 JWT that authenticates as the App.
func (g *gitHub) appJWT(now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(), // clock skew allowance
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": strconv.FormatInt(g.cfg.AppID, 10),
	})
	signing := header + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, g.key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// token returns the bearer token for API calls.
func (g *gitHub) token(ctx context.Context) (string, error) {
	if g.cfg.AuthType == "pat" {
		return string(g.cfg.Secret), nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.instTok != "" && time.Until(g.instTokX) > 5*time.Minute {
		return g.instTok, nil
	}
	jwt, err := g.appJWT(time.Now())
	if err != nil {
		return "", err
	}
	req, _ := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/app/installations/%d/access_tokens", g.cfg.BaseURL, g.cfg.InstallationID), nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if _, err := doJSON(ctx, g.cfg.HTTP, req, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", ErrAuth
	}
	g.instTok, g.instTokX = out.Token, out.ExpiresAt
	return out.Token, nil
}

// InstallationToken returns a short-lived token (GitHub App) or the PAT;
// Phase 4 workers receive it for cloning.
func (g *gitHub) InstallationToken(ctx context.Context) (string, error) { return g.token(ctx) }

func (g *gitHub) get(ctx context.Context, path string, out any) (*http.Response, error) {
	u := path
	if !strings.HasPrefix(path, "http") {
		u = g.cfg.BaseURL + path
	}
	tok, err := g.token(ctx)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return doJSON(ctx, g.cfg.HTTP, req, out)
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink returns the next page URL if it is on the same host.
func (g *gitHub) nextLink(resp *http.Response) string {
	m := linkNext.FindStringSubmatch(resp.Header.Get("Link"))
	if m == nil {
		return ""
	}
	next, err := url.Parse(m[1])
	base, _ := url.Parse(g.cfg.BaseURL)
	if err != nil || next.Host != base.Host || next.Scheme != base.Scheme {
		return ""
	}
	return next.String()
}

func (g *gitHub) Check(ctx context.Context) (string, error) {
	if g.cfg.AuthType == "github_app" {
		var out struct {
			TotalCount int `json:"total_count"`
		}
		if _, err := g.get(ctx, "/installation/repositories?per_page=1", &out); err != nil {
			return "", err
		}
		return fmt.Sprintf("GitHub App installation %d (%d repositories)", g.cfg.InstallationID, out.TotalCount), nil
	}
	var u struct {
		Login string `json:"login"`
	}
	if _, err := g.get(ctx, "/user", &u); err != nil {
		return "", err
	}
	return "authenticated as " + u.Login, nil
}

type ghRepo struct {
	ID            int64      `json:"id"`
	FullName      string     `json:"full_name"`
	Name          string     `json:"name"`
	HTMLURL       string     `json:"html_url"`
	CloneURL      string     `json:"clone_url"`
	DefaultBranch string     `json:"default_branch"`
	Private       bool       `json:"private"`
	Visibility    string     `json:"visibility"`
	Description   *string    `json:"description"`
	Language      *string    `json:"language"`
	Archived      bool       `json:"archived"`
	PushedAt      *time.Time `json:"pushed_at"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

func (r ghRepo) remote() RemoteRepo {
	vis := r.Visibility
	if vis == "" {
		vis = map[bool]string{true: "private", false: "public"}[r.Private]
	}
	out := RemoteRepo{
		ExternalID: strconv.FormatInt(r.ID, 10), FullName: r.FullName, Name: r.Name, URL: r.HTMLURL,
		CloneURL: r.CloneURL, DefaultBranch: r.DefaultBranch, Visibility: vis, Archived: r.Archived, PushedAt: r.PushedAt,
	}
	if r.Description != nil {
		out.Description = *r.Description
	}
	if r.Language != nil {
		out.Language = *r.Language
	}
	return out
}

func (g *gitHub) ListRepositories(ctx context.Context) ([]RemoteRepo, error) {
	var path string
	switch {
	case g.cfg.AuthType == "github_app":
		path = "/installation/repositories?per_page=100"
	case g.cfg.Owner != "":
		// Try organization first; fall back to user repositories.
		path = "/orgs/" + url.PathEscape(g.cfg.Owner) + "/repos?per_page=100&type=all"
	default:
		path = "/user/repos?per_page=100&affiliation=owner,collaborator,organization_member"
	}
	var out []RemoteRepo
	for path != "" {
		var page []ghRepo
		var resp *http.Response
		var err error
		if g.cfg.AuthType == "github_app" {
			var wrapped struct {
				Repositories []ghRepo `json:"repositories"`
			}
			resp, err = g.get(ctx, path, &wrapped)
			page = wrapped.Repositories
		} else {
			resp, err = g.get(ctx, path, &page)
			if err != nil && g.cfg.Owner != "" && strings.Contains(path, "/orgs/") && resp != nil && resp.StatusCode == http.StatusNotFound {
				path = "/users/" + url.PathEscape(g.cfg.Owner) + "/repos?per_page=100&type=all"
				continue
			}
		}
		if err != nil {
			return nil, err
		}
		for _, r := range page {
			out = append(out, r.remote())
		}
		if len(out) >= MaxRepositories {
			return out[:MaxRepositories], nil
		}
		path = g.nextLink(resp)
	}
	return out, nil
}

func (g *gitHub) ListBranches(ctx context.Context, repo RemoteRepo) ([]string, error) {
	parts := strings.SplitN(repo.FullName, "/", 2)
	if len(parts) != 2 {
		return nil, errors.New("scm: invalid repository name")
	}
	path := fmt.Sprintf("/repos/%s/%s/branches?per_page=100", url.PathEscape(parts[0]), url.PathEscape(parts[1]))
	var out []string
	for path != "" && len(out) < 1000 {
		var page []struct {
			Name string `json:"name"`
		}
		resp, err := g.get(ctx, path, &page)
		if err != nil {
			return nil, err
		}
		for _, b := range page {
			out = append(out, b.Name)
		}
		path = g.nextLink(resp)
	}
	return out, nil
}
