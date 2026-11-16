package scm

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// gitLab implements FullClient for gitlab.com and self-managed GitLab
// (REST API v4). cfg.BaseURL is the instance root (https://gitlab.com);
// a trailing /api/v4 is accepted.
type gitLab struct {
	cfg  Config
	web  string // instance root
	root string // API root (web + /api/v4)
	base *url.URL
	auth authorizer
	api  *api

	mu       sync.Mutex
	username string
}

func newGitLab(cfg Config) (*gitLab, error) {
	web := strings.TrimSuffix(cfg.BaseURL, "/api/v4")
	base, err := parseBase(web)
	if err != nil {
		return nil, err
	}
	var auth authorizer
	switch cfg.AuthType {
	case AuthPAT:
		if len(cfg.Secret) == 0 {
			return nil, errors.New("scm: token required")
		}
		auth = bearerAuth{tok: string(cfg.Secret), k: AuthPAT}
	case AuthOAuth:
		if auth, err = newOAuthAuth(cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("scm: unsupported auth type %q for GitLab", cfg.AuthType)
	}
	return &gitLab{cfg: cfg, web: web, root: web + "/api/v4", base: base, auth: auth, api: &api{hc: cfg.HTTP, auth: auth}}, nil
}

func (g *gitLab) get(ctx context.Context, path string, out any) (*http.Response, error) {
	return g.api.get(ctx, g.root+path, out)
}

func (g *gitLab) nextLink(resp *http.Response) string {
	u, ok := sameOrigin(g.base, linkHeaderNext(resp))
	if !ok {
		return ""
	}
	return u.String()
}

func (g *gitLab) user(ctx context.Context) (string, int64, error) {
	var u struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
	}
	if _, err := g.get(ctx, "/user", &u); err != nil {
		return "", 0, err
	}
	g.mu.Lock()
	g.username = u.Username
	g.mu.Unlock()
	return u.Username, u.ID, nil
}

func (g *gitLab) cachedUser(ctx context.Context) (string, error) {
	g.mu.Lock()
	u := g.username
	g.mu.Unlock()
	if u != "" {
		return u, nil
	}
	u, _, err := g.user(ctx)
	return u, err
}

func (g *gitLab) Check(ctx context.Context) (string, error) {
	u, _, err := g.user(ctx)
	if err != nil {
		return "", err
	}
	return "authenticated as " + u, nil
}

// CloneCredential: OAuth tokens clone as "oauth2"; access tokens accept
// any non-empty username.
func (g *gitLab) CloneCredential(ctx context.Context) (Credential, error) {
	tok, exp, err := g.auth.secret(ctx)
	if err != nil {
		return Credential{}, err
	}
	user := "pathos"
	if g.auth.kind() == AuthOAuth {
		user = "oauth2"
	}
	return Credential{Username: user, Token: tok, ExpiresAt: exp}, nil
}

type glProject struct {
	ID                int64      `json:"id"`
	Name              string     `json:"name"`
	Path              string     `json:"path"`
	PathWithNamespace string     `json:"path_with_namespace"`
	WebURL            string     `json:"web_url"`
	HTTPURLToRepo     string     `json:"http_url_to_repo"`
	DefaultBranch     string     `json:"default_branch"`
	Visibility        string     `json:"visibility"`
	Description       *string    `json:"description"`
	Archived          bool       `json:"archived"`
	LastActivityAt    *time.Time `json:"last_activity_at"`
	Namespace         struct {
		FullPath string `json:"full_path"`
	} `json:"namespace"`
	Statistics *struct {
		RepositorySize int64 `json:"repository_size"`
	} `json:"statistics"`
	Permissions *struct {
		ProjectAccess *struct {
			AccessLevel int `json:"access_level"`
		} `json:"project_access"`
		GroupAccess *struct {
			AccessLevel int `json:"access_level"`
		} `json:"group_access"`
	} `json:"permissions"`
}

func (p glProject) remote() RemoteRepo {
	r := RemoteRepo{
		ExternalID: strconv.FormatInt(p.ID, 10), FullName: p.PathWithNamespace, Name: p.Path, URL: p.WebURL,
		CloneURL: p.HTTPURLToRepo, DefaultBranch: p.DefaultBranch, Visibility: p.Visibility, Archived: p.Archived,
		PushedAt: p.LastActivityAt, Organization: p.Namespace.FullPath,
	}
	if p.Description != nil {
		r.Description = *p.Description
	}
	if p.Statistics != nil {
		r.SizeBytes = p.Statistics.RepositorySize
	}
	return r
}

func (p glProject) permission() string {
	level := 0
	if p.Permissions != nil {
		if a := p.Permissions.ProjectAccess; a != nil && a.AccessLevel > level {
			level = a.AccessLevel
		}
		if a := p.Permissions.GroupAccess; a != nil && a.AccessLevel > level {
			level = a.AccessLevel
		}
	}
	switch {
	case level >= 50:
		return "admin"
	case level >= 30:
		return "write"
	case level >= 10:
		return "read"
	}
	return "unknown"
}

func (g *gitLab) ListRepositories(ctx context.Context) ([]RemoteRepo, error) {
	return listAll(ctx, g, RepoQuery{Organization: g.cfg.Owner})
}

func (g *gitLab) ListBranches(ctx context.Context, repo RemoteRepo) ([]string, error) {
	heads, err := g.ListBranchHeads(ctx, repo.Ref())
	if err != nil {
		return nil, err
	}
	out := make([]string, len(heads))
	for i, b := range heads {
		out[i] = b.Name
	}
	return out, nil
}

// ListOrganizations returns the user's namespace and the groups where the
// user has at least Guest access.
func (g *gitLab) ListOrganizations(ctx context.Context) ([]Organization, error) {
	name, id, err := g.user(ctx)
	if err != nil {
		return nil, err
	}
	orgs := []Organization{{ID: "user:" + strconv.FormatInt(id, 10), Name: name, DisplayName: name, Kind: "user"}}
	next := g.root + "/groups?min_access_level=10&per_page=100&order_by=path&sort=asc"
	for pages := 0; next != "" && pages < 20; pages++ {
		var page []struct {
			ID       int64  `json:"id"`
			FullPath string `json:"full_path"`
			FullName string `json:"full_name"`
		}
		resp, err := g.api.get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		for _, gr := range page {
			orgs = append(orgs, Organization{ID: strconv.FormatInt(gr.ID, 10), Name: gr.FullPath, DisplayName: gr.FullName, Kind: "group"})
		}
		next = g.nextLink(resp)
	}
	return orgs, nil
}

func (g *gitLab) ListProjects(context.Context, string) ([]Project, error) {
	return nil, ErrNotSupported
}

// ListRepositoriesPage: /projects?membership=true (no organization),
// /users/{me}/projects (own namespace) or /groups/{path}/projects with
// subgroups; search is server-side (search=).
func (g *gitLab) ListRepositoriesPage(ctx context.Context, q RepoQuery) (RepoPage, error) {
	cur, err := decodeCursor(g.cfg.Provider, q)
	if err != nil {
		return RepoPage{}, err
	}
	size := pageSize(q.PageSize)
	params := url.Values{"per_page": {strconv.Itoa(size)}, "order_by": {"path"}, "sort": {"asc"}}
	if s := strings.TrimSpace(q.Search); s != "" {
		params.Set("search", s)
	}
	var first string
	switch org := q.Organization; {
	case org == "":
		params.Set("membership", "true")
		first = g.root + "/projects?" + params.Encode()
	default:
		me, err := g.cachedUser(ctx)
		if err != nil {
			return RepoPage{}, err
		}
		if strings.EqualFold(me, org) {
			first = g.root + "/users/" + url.PathEscape(me) + "/projects?" + params.Encode()
		} else {
			params.Set("include_subgroups", "true")
			first = g.root + "/groups/" + url.PathEscape(org) + "/projects?" + params.Encode()
		}
	}
	allowed := []string{first, g.root + "/groups/*/projects", g.root + "/users/*/projects"}
	start := first
	if cur.N != "" {
		if start, _ = checkNext(cur.N, allowed...); start == "" {
			return RepoPage{}, ErrInvalidPageToken
		}
	}
	fetch := func(ctx context.Context, u string) ([]RemoteRepo, string, error) {
		var page []glProject
		resp, err := g.api.get(ctx, u, &page)
		if err != nil {
			return nil, "", err
		}
		out := make([]RemoteRepo, len(page))
		for i, p := range page {
			out[i] = p.remote()
		}
		return out, linkHeaderNext(resp), nil
	}
	items, next, err := collectRepos(ctx, start, size, fetch, nil, allowed...)
	if err != nil {
		return RepoPage{}, err
	}
	page := RepoPage{Items: items}
	if next != "" {
		page.NextPageToken = encodeCursor(g.cfg.Provider, q, next, 0)
	}
	return page, nil
}

// projectPath is /projects/{id} or /projects/{url-encoded full path}.
func glProjectPath(ref RepoRef) (string, error) {
	if ref.ExternalID != "" {
		if _, err := strconv.ParseInt(ref.ExternalID, 10, 64); err == nil {
			return "/projects/" + ref.ExternalID, nil
		}
	}
	if _, _, ok := splitFullName(ref.FullName); !ok {
		return "", errors.New("scm: invalid repository name")
	}
	return "/projects/" + url.PathEscape(ref.FullName), nil
}

func (g *gitLab) project(ctx context.Context, ref RepoRef, stats bool) (glProject, error) {
	p, err := glProjectPath(ref)
	if err != nil {
		return glProject{}, err
	}
	if stats {
		p += "?statistics=true"
	}
	var out glProject
	if _, err := g.get(ctx, p, &out); err != nil {
		return glProject{}, err
	}
	return out, nil
}

func (g *gitLab) GetRepository(ctx context.Context, ref RepoRef) (RemoteRepo, error) {
	p, err := g.project(ctx, ref, true)
	if err != nil {
		return RemoteRepo{}, err
	}
	return p.remote(), nil
}

// Permission implements PermissionChecker.
func (g *gitLab) Permission(ctx context.Context, ref RepoRef) (string, error) {
	p, err := g.project(ctx, ref, false)
	if err != nil {
		return "", err
	}
	return p.permission(), nil
}

func (g *gitLab) ListBranchHeads(ctx context.Context, ref RepoRef) ([]Branch, error) {
	p, err := glProjectPath(ref)
	if err != nil {
		return nil, err
	}
	next := g.root + p + "/repository/branches?per_page=100"
	var out []Branch
	for next != "" && len(out) < 1000 {
		var page []struct {
			Name    string `json:"name"`
			Default bool   `json:"default"`
			Commit  struct {
				ID string `json:"id"`
			} `json:"commit"`
		}
		resp, err := g.api.get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		for _, b := range page {
			out = append(out, Branch{Name: b.Name, CommitSHA: b.Commit.ID, Default: b.Default})
		}
		next = g.nextLink(resp)
	}
	return out, nil
}

func (g *gitLab) LatestCommit(ctx context.Context, ref RepoRef, branch string) (Commit, error) {
	p, err := glProjectPath(ref)
	if err != nil {
		return Commit{}, err
	}
	if branch == "" {
		proj, err := g.project(ctx, ref, false)
		if err != nil {
			return Commit{}, err
		}
		branch = proj.DefaultBranch
	}
	var page []struct {
		ID            string     `json:"id"`
		Title         string     `json:"title"`
		Message       string     `json:"message"`
		AuthorName    string     `json:"author_name"`
		CommittedDate *time.Time `json:"committed_date"`
	}
	if _, err := g.get(ctx, p+"/repository/commits?per_page=1&ref_name="+url.QueryEscape(branch), &page); err != nil {
		return Commit{}, err
	}
	if len(page) == 0 {
		return Commit{}, ErrNotFound
	}
	c := page[0]
	msg := c.Title
	if msg == "" {
		msg = c.Message
	}
	return Commit{SHA: c.ID, Message: firstLine(msg), Author: c.AuthorName, CommittedAt: c.CommittedDate}, nil
}

// Languages returns GitLab's percentages, rounded to whole numbers.
func (g *gitLab) Languages(ctx context.Context, ref RepoRef) (map[string]int64, error) {
	p, err := glProjectPath(ref)
	if err != nil {
		return nil, err
	}
	var raw map[string]float64
	if _, err := g.get(ctx, p+"/languages", &raw); err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(raw))
	for k, v := range raw {
		out[k] = int64(math.Round(v))
	}
	return out, nil
}

// Revoke revokes an OAuth access token (POST /oauth/revoke). Access tokens
// (PAT) return nil.
func (g *gitLab) Revoke(ctx context.Context) error {
	oa, ok := g.auth.(*oauthAuth)
	if !ok || g.cfg.OAuth == nil {
		return nil
	}
	tok := oa.accessToken()
	if tok == "" {
		return nil
	}
	form := url.Values{"token": {tok}, "client_id": {g.cfg.OAuth.ClientID}}
	if len(g.cfg.OAuth.ClientSecret) > 0 {
		form.Set("client_secret", string(g.cfg.OAuth.ClientSecret))
	}
	req, err := http.NewRequest(http.MethodPost, g.web+"/oauth/revoke", strings.NewReader(form.Encode()))
	if err != nil {
		return errors.New("scm: invalid base URL")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err = doJSON(ctx, g.cfg.HTTP, req, nil)
	return err
}
