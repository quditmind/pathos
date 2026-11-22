package scm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// gitHub implements FullClient for github.com and GitHub Enterprise Server
// (REST API v3) with PAT, GitHub App and OAuth App authentication.
type gitHub struct {
	cfg  Config
	base *url.URL
	auth authorizer
	api  *api

	mu    sync.Mutex
	login string // authenticated user (PAT / OAuth), cached
}

func newGitHub(cfg Config) (*gitHub, error) {
	base, err := parseBase(cfg.BaseURL)
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
	case AuthGitHubApp:
		if auth, err = newGitHubAppAuth(cfg); err != nil {
			return nil, err
		}
	case AuthOAuth:
		if auth, err = newOAuthAuth(cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("scm: unsupported auth type %q for GitHub", cfg.AuthType)
	}
	g := &gitHub{cfg: cfg, base: base, auth: auth}
	g.api = &api{hc: cfg.HTTP, auth: auth, headers: map[string]string{
		"Accept":               "application/vnd.github+json",
		"X-GitHub-Api-Version": "2022-11-28",
	}}
	return g, nil
}

func (g *gitHub) get(ctx context.Context, path string, out any) (*http.Response, error) {
	return g.api.get(ctx, g.cfg.BaseURL+path, out)
}

// nextLink returns the next page URL if it is on the same origin.
func (g *gitHub) nextLink(resp *http.Response) string {
	u, ok := sameOrigin(g.base, linkHeaderNext(resp))
	if !ok {
		return ""
	}
	return u.String()
}

func (g *gitHub) isApp() bool { return g.cfg.AuthType == AuthGitHubApp }

// CloneCredential implements Client.
func (g *gitHub) CloneCredential(ctx context.Context) (Credential, error) {
	tok, exp, err := g.auth.secret(ctx)
	if err != nil {
		return Credential{}, err
	}
	return Credential{Username: "x-access-token", Token: tok, ExpiresAt: exp}, nil
}

// RepoCloneCredential implements RepoCloner: for a GitHub App, a fresh
// installation token for this one repository with contents:read only. Other
// authentication types fall back to CloneCredential.
func (g *gitHub) RepoCloneCredential(ctx context.Context, fullName string) (Credential, error) {
	app, ok := g.auth.(*githubAppAuth)
	if !ok || !g.isApp() {
		return g.CloneCredential(ctx)
	}
	name := fullName
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return Credential{}, errors.New("scm: repository name required")
	}
	tok, exp, err := app.fetchScoped(ctx, map[string]any{
		"repositories": []string{name},
		"permissions":  map[string]string{"contents": "read"},
	})
	if err != nil {
		return Credential{}, err
	}
	return Credential{Username: "x-access-token", Token: tok, ExpiresAt: &exp}, nil
}

func (g *gitHub) user(ctx context.Context) (string, int64, error) {
	var u struct {
		Login string `json:"login"`
		ID    int64  `json:"id"`
	}
	if _, err := g.get(ctx, "/user", &u); err != nil {
		return "", 0, err
	}
	g.mu.Lock()
	g.login = u.Login
	g.mu.Unlock()
	return u.Login, u.ID, nil
}

func (g *gitHub) cachedLogin(ctx context.Context) (string, error) {
	g.mu.Lock()
	l := g.login
	g.mu.Unlock()
	if l != "" {
		return l, nil
	}
	l, _, err := g.user(ctx)
	return l, err
}

func (g *gitHub) Check(ctx context.Context) (string, error) {
	if g.isApp() {
		var out struct {
			TotalCount int `json:"total_count"`
		}
		if _, err := g.get(ctx, "/installation/repositories?per_page=1", &out); err != nil {
			return "", err
		}
		return fmt.Sprintf("GitHub App installation %d (%d repositories)", g.cfg.InstallationID, out.TotalCount), nil
	}
	login, _, err := g.user(ctx)
	if err != nil {
		return "", err
	}
	return "authenticated as " + login, nil
}

type ghOwner struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Type  string `json:"type"` // User | Organization
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
	Size          int64      `json:"size"` // KiB
	Owner         ghOwner    `json:"owner"`
	Permissions   *struct {
		Admin    bool `json:"admin"`
		Maintain bool `json:"maintain"`
		Push     bool `json:"push"`
		Triage   bool `json:"triage"`
		Pull     bool `json:"pull"`
	} `json:"permissions"`
}

func (r ghRepo) remote() RemoteRepo {
	vis := r.Visibility
	if vis == "" {
		vis = map[bool]string{true: "private", false: "public"}[r.Private]
	}
	out := RemoteRepo{
		ExternalID: strconv.FormatInt(r.ID, 10), FullName: r.FullName, Name: r.Name, URL: r.HTMLURL,
		CloneURL: r.CloneURL, DefaultBranch: r.DefaultBranch, Visibility: vis, Archived: r.Archived, PushedAt: r.PushedAt,
		Organization: r.Owner.Login, SizeBytes: r.Size * 1024,
	}
	if r.Description != nil {
		out.Description = *r.Description
	}
	if r.Language != nil {
		out.Language = *r.Language
	}
	return out
}

func (r ghRepo) permission() string {
	p := r.Permissions
	switch {
	case p == nil:
		return "unknown"
	case p.Admin:
		return "admin"
	case p.Maintain || p.Push:
		return "write"
	case p.Pull || p.Triage:
		return "read"
	}
	return "unknown"
}

// ListRepositories implements Client: everything visible to the
// credential, or cfg.Owner's repositories (organization, else user).
func (g *gitHub) ListRepositories(ctx context.Context) ([]RemoteRepo, error) {
	var path string
	switch {
	case g.isApp():
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
		if g.isApp() {
			var wrapped struct {
				Repositories []ghRepo `json:"repositories"`
			}
			resp, err = g.getPath(ctx, path, &wrapped)
			page = wrapped.Repositories
		} else {
			resp, err = g.getPath(ctx, path, &page)
			if err != nil && g.cfg.Owner != "" && strings.Contains(path, "/orgs/") && errors.Is(err, ErrNotFound) {
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

// getPath accepts a path relative to the base URL or an absolute URL that
// was already validated by nextLink / checkNext.
func (g *gitHub) getPath(ctx context.Context, p string, out any) (*http.Response, error) {
	if strings.HasPrefix(p, "/") {
		return g.get(ctx, p, out)
	}
	return g.api.get(ctx, p, out)
}

func (g *gitHub) ListBranches(ctx context.Context, repo RemoteRepo) ([]string, error) {
	heads, err := g.branches(ctx, repo.FullName, "")
	if err != nil {
		return nil, err
	}
	out := make([]string, len(heads))
	for i, b := range heads {
		out[i] = b.Name
	}
	return out, nil
}

// --- Discoverer --------------------------------------------------------------

func (g *gitHub) ListOrganizations(ctx context.Context) ([]Organization, error) {
	if g.isApp() {
		// An installation belongs to exactly one account.
		var out struct {
			Repositories []ghRepo `json:"repositories"`
		}
		if _, err := g.get(ctx, "/installation/repositories?per_page=100", &out); err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		var orgs []Organization
		for _, r := range out.Repositories {
			if r.Owner.Login == "" || seen[r.Owner.Login] {
				continue
			}
			seen[r.Owner.Login] = true
			orgs = append(orgs, ghOrganization(r.Owner))
		}
		return orgs, nil
	}
	login, id, err := g.user(ctx)
	if err != nil {
		return nil, err
	}
	orgs := []Organization{{ID: strconv.FormatInt(id, 10), Name: login, DisplayName: login, Kind: "user"}}
	next := g.cfg.BaseURL + "/user/orgs?per_page=100"
	for pages := 0; next != "" && pages < 20; pages++ {
		var page []ghOwner
		resp, err := g.api.get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		for _, o := range page {
			o.Type = "Organization"
			orgs = append(orgs, ghOrganization(o))
		}
		next = g.nextLink(resp)
	}
	return orgs, nil
}

func ghOrganization(o ghOwner) Organization {
	kind := "organization"
	if o.Type == "User" {
		kind = "user"
	}
	return Organization{ID: strconv.FormatInt(o.ID, 10), Name: o.Login, DisplayName: o.Login, Kind: kind}
}

func (g *gitHub) ListProjects(context.Context, string) ([]Project, error) {
	return nil, ErrNotSupported
}

// searchTerm strips characters that would let a search term inject GitHub
// search qualifiers.
func searchTerm(s string) string {
	return strings.Join(strings.Fields(strings.NewReplacer(":", " ", `"`, " ").Replace(s)), " ")
}

// ListRepositoriesPage lists one page. Strategy:
//
//   - GitHub App: /installation/repositories, owner and search filtered
//     client-side (the installation API has no filters).
//   - Organization + search: the search API (q=<term> in:name org:<org>
//     fork:true), server-side. It is limited to 1000 results and a lower
//     rate limit, which is acceptable for interactive search.
//   - Organization without search: /orgs/{org}/repos (falls back to
//     /users/{org}/repos for user accounts; the authenticated user's own
//     login uses /user/repos?affiliation=owner to include private repos).
//   - No organization: /user/repos; search filtered client-side.
func (g *gitHub) ListRepositoriesPage(ctx context.Context, q RepoQuery) (RepoPage, error) {
	cur, err := decodeCursor(g.cfg.Provider, q)
	if err != nil {
		return RepoPage{}, err
	}
	size := pageSize(q.PageSize)
	term := strings.TrimSpace(q.Search)
	org := q.Organization
	ps := "per_page=" + strconv.Itoa(size)
	base := g.cfg.BaseURL

	type plan struct {
		first   []string // first-page URLs; [1] is the fallback on 404
		wrapped string   // JSON field holding the items ("" = array)
		keep    func(RemoteRepo) bool
	}
	var p plan
	clientFilter := func(r RemoteRepo) bool {
		return (org == "" || strings.EqualFold(r.Organization, org)) && matchesSearch(r, term)
	}
	switch {
	case g.isApp():
		p = plan{first: []string{base + "/installation/repositories?" + ps}, wrapped: "repositories"}
		if org != "" || term != "" {
			p.keep = clientFilter
		}
	case org != "" && searchTerm(term) != "":
		qual := "org:"
		if login, err := g.cachedLogin(ctx); err == nil && strings.EqualFold(login, org) {
			qual = "user:"
		}
		sq := searchTerm(term) + " in:name fork:true " + qual + org
		p = plan{first: []string{base + "/search/repositories?" + ps + "&q=" + url.QueryEscape(sq)}, wrapped: "items"}
	case org != "":
		login, err := g.cachedLogin(ctx)
		if err != nil {
			return RepoPage{}, err
		}
		if strings.EqualFold(login, org) {
			p = plan{first: []string{base + "/user/repos?" + ps + "&affiliation=owner&sort=full_name"}}
		} else {
			e := url.PathEscape(org)
			p = plan{first: []string{base + "/orgs/" + e + "/repos?" + ps + "&type=all&sort=full_name", base + "/users/" + e + "/repos?" + ps + "&type=owner&sort=full_name"}}
		}
	default:
		p = plan{first: []string{base + "/user/repos?" + ps + "&affiliation=owner,collaborator,organization_member&sort=full_name"}}
		if term != "" {
			p.keep = clientFilter
		}
	}

	fetch := func(ctx context.Context, u string) ([]RemoteRepo, string, error) {
		var raw json.RawMessage
		resp, err := g.api.get(ctx, u, &raw)
		if err != nil {
			return nil, "", err
		}
		var repos []ghRepo
		if p.wrapped != "" {
			var w map[string]json.RawMessage
			if err := json.Unmarshal(raw, &w); err != nil {
				return nil, "", errors.New("scm: invalid response from GitHub")
			}
			raw = w[p.wrapped]
		}
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &repos); err != nil {
				return nil, "", errors.New("scm: invalid response from GitHub")
			}
		}
		out := make([]RemoteRepo, len(repos))
		for i, r := range repos {
			out[i] = r.remote()
		}
		return out, linkHeaderNext(resp), nil
	}

	start := p.first[0]
	if cur.N != "" {
		if start, _ = checkNext(cur.N, p.first...); start == "" {
			return RepoPage{}, ErrInvalidPageToken
		}
	}
	items, next, err := collectRepos(ctx, start, size, fetch, p.keep, p.first...)
	if err != nil && cur.N == "" && len(p.first) > 1 && errors.Is(err, ErrNotFound) {
		items, next, err = collectRepos(ctx, p.first[1], size, fetch, p.keep, p.first...)
	}
	if err != nil {
		return RepoPage{}, err
	}
	page := RepoPage{Items: items}
	if next != "" {
		page.NextPageToken = encodeCursor(g.cfg.Provider, q, next, 0)
	}
	return page, nil
}

// repoPath returns /repositories/{id} or /repos/{owner}/{name}.
func ghRepoPath(ref RepoRef) (string, error) {
	if ref.ExternalID != "" {
		if _, err := strconv.ParseInt(ref.ExternalID, 10, 64); err == nil {
			return "/repositories/" + ref.ExternalID, nil
		}
	}
	return ghFullPath(ref.FullName)
}

func ghFullPath(full string) (string, error) {
	owner, name, ok := strings.Cut(full, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
		return "", errors.New("scm: invalid repository name")
	}
	return "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name), nil
}

func (g *gitHub) repo(ctx context.Context, ref RepoRef) (ghRepo, error) {
	p, err := ghRepoPath(ref)
	if err != nil {
		return ghRepo{}, err
	}
	var r ghRepo
	if _, err := g.get(ctx, p, &r); err != nil {
		return ghRepo{}, err
	}
	return r, nil
}

func (g *gitHub) GetRepository(ctx context.Context, ref RepoRef) (RemoteRepo, error) {
	r, err := g.repo(ctx, ref)
	if err != nil {
		return RemoteRepo{}, err
	}
	return r.remote(), nil
}

// Permission implements PermissionChecker (PAT and OAuth; App tokens do
// not report permissions).
func (g *gitHub) Permission(ctx context.Context, ref RepoRef) (string, error) {
	r, err := g.repo(ctx, ref)
	if err != nil {
		return "", err
	}
	return r.permission(), nil
}

func (g *gitHub) branches(ctx context.Context, fullName, defaultBranch string) ([]Branch, error) {
	p, err := ghFullPath(fullName)
	if err != nil {
		return nil, err
	}
	next := g.cfg.BaseURL + p + "/branches?per_page=100"
	var out []Branch
	for next != "" && len(out) < 1000 {
		var page []struct {
			Name   string `json:"name"`
			Commit struct {
				SHA string `json:"sha"`
			} `json:"commit"`
		}
		resp, err := g.api.get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		for _, b := range page {
			out = append(out, Branch{Name: b.Name, CommitSHA: b.Commit.SHA, Default: b.Name == defaultBranch})
		}
		next = g.nextLink(resp)
	}
	return out, nil
}

func (g *gitHub) ListBranchHeads(ctx context.Context, ref RepoRef) ([]Branch, error) {
	r, err := g.repo(ctx, ref)
	if err != nil {
		return nil, err
	}
	return g.branches(ctx, r.FullName, r.DefaultBranch)
}

func (g *gitHub) LatestCommit(ctx context.Context, ref RepoRef, branch string) (Commit, error) {
	full := ref.FullName
	if branch == "" || full == "" {
		r, err := g.repo(ctx, ref)
		if err != nil {
			return Commit{}, err
		}
		full = r.FullName
		if branch == "" {
			branch = r.DefaultBranch
		}
	}
	p, err := ghFullPath(full)
	if err != nil {
		return Commit{}, err
	}
	var c struct {
		SHA    string `json:"sha"`
		Commit struct {
			Message string `json:"message"`
			Author  struct {
				Name string     `json:"name"`
				Date *time.Time `json:"date"`
			} `json:"author"`
			Committer struct {
				Date *time.Time `json:"date"`
			} `json:"committer"`
		} `json:"commit"`
	}
	if _, err := g.get(ctx, p+"/commits/"+escapeRef(branch), &c); err != nil {
		return Commit{}, err
	}
	at := c.Commit.Committer.Date
	if at == nil {
		at = c.Commit.Author.Date
	}
	return Commit{SHA: c.SHA, Message: firstLine(c.Commit.Message), Author: c.Commit.Author.Name, CommittedAt: at}, nil
}

func (g *gitHub) Languages(ctx context.Context, ref RepoRef) (map[string]int64, error) {
	full := ref.FullName
	if full == "" {
		r, err := g.repo(ctx, ref)
		if err != nil {
			return nil, err
		}
		full = r.FullName
	}
	p, err := ghFullPath(full)
	if err != nil {
		return nil, err
	}
	out := map[string]int64{}
	if _, err := g.get(ctx, p+"/languages", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Revoke deletes an OAuth App token (DELETE /applications/{client_id}/token
// with the app's client credentials). PAT and App credentials have no
// revocation API usable here; nil is returned.
func (g *gitHub) Revoke(ctx context.Context) error {
	oa, ok := g.auth.(*oauthAuth)
	if !ok || g.cfg.OAuth == nil {
		return nil
	}
	tok := oa.accessToken()
	if tok == "" {
		return nil
	}
	body, _ := json.Marshal(map[string]string{"access_token": tok})
	req, err := http.NewRequest(http.MethodDelete, g.cfg.BaseURL+"/applications/"+url.PathEscape(g.cfg.OAuth.ClientID)+"/token", strings.NewReader(string(body)))
	if err != nil {
		return errors.New("scm: invalid base URL")
	}
	req.SetBasicAuth(g.cfg.OAuth.ClientID, string(g.cfg.OAuth.ClientSecret))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if _, err := doJSON(ctx, g.cfg.HTTP, req, nil); err != nil {
		var se *StatusError
		if errors.As(err, &se) && (se.Code == http.StatusNotFound || se.Code == http.StatusUnprocessableEntity) {
			return nil // already revoked
		}
		return err
	}
	return nil
}
