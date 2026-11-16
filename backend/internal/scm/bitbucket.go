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

// bitbucket implements FullClient for Bitbucket Cloud (REST API 2.0,
// https://api.bitbucket.org/2.0). Bitbucket Data Center is not supported.
type bitbucket struct {
	cfg  Config
	root string
	base *url.URL
	auth authorizer
	api  *api

	mu       sync.Mutex
	username string // Bitbucket username (API token clone credential)
}

func newBitbucket(cfg Config) (*bitbucket, error) {
	base, err := parseBase(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	var auth authorizer
	switch cfg.AuthType {
	case AuthPAT: // workspace, project or repository access token
		if len(cfg.Secret) == 0 {
			return nil, errors.New("scm: token required")
		}
		auth = bearerAuth{tok: string(cfg.Secret), k: AuthPAT}
	case AuthAPIToken:
		var c APITokenCredential
		if err := json.Unmarshal(cfg.Secret, &c); err != nil || c.Username == "" || c.Token == "" {
			return nil, errors.New("scm: Bitbucket API token requires the Atlassian account e-mail and the token")
		}
		auth = basicAuth{user: c.Username, pass: c.Token, k: AuthAPIToken}
	case AuthOAuth:
		if auth, err = newOAuthAuth(cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("scm: unsupported auth type %q for Bitbucket", cfg.AuthType)
	}
	return &bitbucket{cfg: cfg, root: cfg.BaseURL, base: base, auth: auth, api: &api{hc: cfg.HTTP, auth: auth}}, nil
}

func (b *bitbucket) get(ctx context.Context, path string, out any) (*http.Response, error) {
	return b.api.get(ctx, b.root+path, out)
}

// userCredential reports whether the credential acts as a user (API token,
// OAuth) rather than a workspace/project/repository access token.
func (b *bitbucket) userCredential() bool { return b.auth.kind() != AuthPAT }

func (b *bitbucket) user(ctx context.Context) (string, string, error) {
	var u struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
	}
	if _, err := b.get(ctx, "/user", &u); err != nil {
		return "", "", err
	}
	b.mu.Lock()
	b.username = u.Username
	b.mu.Unlock()
	return u.Username, u.DisplayName, nil
}

func (b *bitbucket) Check(ctx context.Context) (string, error) {
	if !b.userCredential() {
		if b.cfg.Owner == "" {
			return "", errors.New("scm: set the workspace for a Bitbucket access token")
		}
		var out struct {
			Size int `json:"size"`
		}
		if _, err := b.get(ctx, "/repositories/"+url.PathEscape(b.cfg.Owner)+"?pagelen=1", &out); err != nil {
			return "", err
		}
		return "connected to workspace " + b.cfg.Owner, nil
	}
	name, display, err := b.user(ctx)
	if err != nil {
		return "", err
	}
	if display != "" {
		return "authenticated as " + display + " (" + name + ")", nil
	}
	return "authenticated as " + name, nil
}

// CloneCredential: access tokens and OAuth tokens clone as "x-token-auth";
// API tokens clone with the Bitbucket username (from GET /2.0/user), not
// the e-mail used for the REST API.
func (b *bitbucket) CloneCredential(ctx context.Context) (Credential, error) {
	tok, exp, err := b.auth.secret(ctx)
	if err != nil {
		return Credential{}, err
	}
	if b.auth.kind() != AuthAPIToken {
		return Credential{Username: "x-token-auth", Token: tok, ExpiresAt: exp}, nil
	}
	b.mu.Lock()
	user := b.username
	b.mu.Unlock()
	if user == "" {
		if user, _, err = b.user(ctx); err != nil {
			return Credential{}, err
		}
		if user == "" {
			return Credential{}, errors.New("scm: Bitbucket did not report a username for this API token")
		}
	}
	return Credential{Username: user, Token: tok}, nil
}

type bbRepo struct {
	UUID        string     `json:"uuid"`
	FullName    string     `json:"full_name"`
	Slug        string     `json:"slug"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	IsPrivate   bool       `json:"is_private"`
	Language    string     `json:"language"`
	Size        int64      `json:"size"`
	UpdatedOn   *time.Time `json:"updated_on"`
	MainBranch  *struct {
		Name string `json:"name"`
	} `json:"mainbranch"`
	Links struct {
		HTML struct {
			Href string `json:"href"`
		} `json:"html"`
		Clone []struct {
			Name string `json:"name"`
			Href string `json:"href"`
		} `json:"clone"`
	} `json:"links"`
	Workspace struct {
		Slug string `json:"slug"`
	} `json:"workspace"`
	Project *struct {
		Key string `json:"key"`
	} `json:"project"`
}

func (r bbRepo) remote() RemoteRepo {
	out := RemoteRepo{
		ExternalID: r.UUID, FullName: r.FullName, Name: r.Slug, URL: r.Links.HTML.Href, Description: r.Description,
		Language: r.Language, PushedAt: r.UpdatedOn, Organization: r.Workspace.Slug, SizeBytes: r.Size,
		Visibility: map[bool]string{true: "private", false: "public"}[r.IsPrivate],
	}
	if out.Name == "" {
		out.Name = r.Name
	}
	if r.MainBranch != nil {
		out.DefaultBranch = r.MainBranch.Name
	}
	if r.Project != nil {
		out.Project = r.Project.Key
	}
	for _, c := range r.Links.Clone {
		if c.Name == "https" {
			if u, err := url.Parse(c.Href); err == nil {
				u.User = nil // Bitbucket embeds the username
				out.CloneURL = u.String()
			}
		}
	}
	return out
}

func (b *bitbucket) ListRepositories(ctx context.Context) ([]RemoteRepo, error) {
	if b.cfg.Owner != "" {
		return listAll(ctx, b, RepoQuery{Organization: b.cfg.Owner})
	}
	orgs, err := b.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	var out []RemoteRepo
	for _, o := range orgs {
		repos, err := listAll(ctx, b, RepoQuery{Organization: o.Name})
		if err != nil {
			return nil, err
		}
		out = append(out, repos...)
		if len(out) >= MaxRepositories {
			return out[:MaxRepositories], nil
		}
	}
	return out, nil
}

func (b *bitbucket) ListBranches(ctx context.Context, repo RemoteRepo) ([]string, error) {
	heads, err := b.ListBranchHeads(ctx, repo.Ref())
	if err != nil {
		return nil, err
	}
	out := make([]string, len(heads))
	for i, h := range heads {
		out[i] = h.Name
	}
	return out, nil
}

// bbPage is Bitbucket's paginated envelope; next is a full URL.
type bbPage[T any] struct {
	Values []T    `json:"values"`
	Next   string `json:"next"`
}

// pages follows "next" links (same origin only) up to max pages.
func bbPages[T any](ctx context.Context, b *bitbucket, first string, max int) ([]T, error) {
	var out []T
	next := first
	for i := 0; next != "" && i < max; i++ {
		var p bbPage[T]
		if _, err := b.api.get(ctx, next, &p); err != nil {
			return nil, err
		}
		out = append(out, p.Values...)
		next, _ = checkNext(p.Next, first)
	}
	return out, nil
}

// ListOrganizations returns the workspaces of the user (API token, OAuth)
// or, for an access token, the configured workspace.
func (b *bitbucket) ListOrganizations(ctx context.Context) ([]Organization, error) {
	type ws struct {
		UUID string `json:"uuid"`
		Slug string `json:"slug"`
		Name string `json:"name"`
	}
	if !b.userCredential() {
		if b.cfg.Owner == "" {
			return nil, fmt.Errorf("%w: set the workspace for a Bitbucket access token", ErrNotSupported)
		}
		var w ws
		if _, err := b.get(ctx, "/workspaces/"+url.PathEscape(b.cfg.Owner), &w); err != nil {
			if errors.Is(err, ErrForbidden) || errors.Is(err, ErrAuth) {
				// Project and repository tokens cannot read the workspace.
				return []Organization{{Name: b.cfg.Owner, DisplayName: b.cfg.Owner, Kind: "workspace"}}, nil
			}
			return nil, err
		}
		return []Organization{{ID: w.UUID, Name: w.Slug, DisplayName: w.Name, Kind: "workspace"}}, nil
	}
	perms, err := bbPages[struct {
		Workspace ws `json:"workspace"`
	}](ctx, b, b.root+"/user/permissions/workspaces?pagelen=100", 20)
	if err != nil {
		return nil, err
	}
	orgs := make([]Organization, 0, len(perms))
	for _, p := range perms {
		orgs = append(orgs, Organization{ID: p.Workspace.UUID, Name: p.Workspace.Slug, DisplayName: p.Workspace.Name, Kind: "workspace"})
	}
	return orgs, nil
}

func (b *bitbucket) ListProjects(ctx context.Context, workspace string) ([]Project, error) {
	if workspace == "" {
		workspace = b.cfg.Owner
	}
	if workspace == "" {
		return nil, errors.New("scm: workspace required")
	}
	ps, err := bbPages[struct {
		UUID        string `json:"uuid"`
		Key         string `json:"key"`
		Name        string `json:"name"`
		Description string `json:"description"`
	}](ctx, b, b.root+"/workspaces/"+url.PathEscape(workspace)+"/projects?pagelen=100", 20)
	if err != nil {
		return nil, err
	}
	out := make([]Project, 0, len(ps))
	for _, p := range ps {
		out = append(out, Project{ID: p.UUID, Name: p.Key, DisplayName: p.Name, Description: p.Description})
	}
	return out, nil
}

// bbQuote quotes a value for Bitbucket's query language (BBQL).
func bbQuote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// ListRepositoriesPage lists /repositories/{workspace} with the search
// (name ~ "term") and project (project.key = "KEY") applied server-side.
// A workspace is required unless the credential sees exactly one.
func (b *bitbucket) ListRepositoriesPage(ctx context.Context, q RepoQuery) (RepoPage, error) {
	cur, err := decodeCursor(b.cfg.Provider, q)
	if err != nil {
		return RepoPage{}, err
	}
	ws := q.Organization
	if ws == "" {
		ws = b.cfg.Owner
	}
	if ws == "" {
		orgs, err := b.ListOrganizations(ctx)
		if err != nil {
			return RepoPage{}, err
		}
		if len(orgs) != 1 {
			return RepoPage{}, errors.New("scm: select a Bitbucket workspace")
		}
		ws = orgs[0].Name
	}
	size := pageSize(q.PageSize)
	params := url.Values{"pagelen": {strconv.Itoa(size)}, "sort": {"slug"}}
	var conds []string
	if s := strings.TrimSpace(q.Search); s != "" {
		conds = append(conds, "name ~ "+bbQuote(s))
	}
	if q.Project != "" {
		conds = append(conds, "project.key = "+bbQuote(q.Project))
	}
	if len(conds) > 0 {
		params.Set("q", strings.Join(conds, " AND "))
	}
	first := b.root + "/repositories/" + url.PathEscape(ws) + "?" + params.Encode()
	start := first
	if cur.N != "" {
		if start, _ = checkNext(cur.N, first); start == "" {
			return RepoPage{}, ErrInvalidPageToken
		}
	}
	fetch := func(ctx context.Context, u string) ([]RemoteRepo, string, error) {
		var p bbPage[bbRepo]
		if _, err := b.api.get(ctx, u, &p); err != nil {
			return nil, "", err
		}
		out := make([]RemoteRepo, len(p.Values))
		for i, r := range p.Values {
			out[i] = r.remote()
		}
		return out, p.Next, nil
	}
	items, next, err := collectRepos(ctx, start, size, fetch, nil, first)
	if err != nil {
		return RepoPage{}, err
	}
	page := RepoPage{Items: items}
	if next != "" {
		page.NextPageToken = encodeCursor(b.cfg.Provider, q, next, 0)
	}
	return page, nil
}

// repoPath is /repositories/{workspace}/{uuid} when the UUID and workspace
// are known (stable across renames), else /repositories/{workspace}/{slug}.
func bbRepoPath(ref RepoRef) (string, error) {
	ws, slug, ok := strings.Cut(ref.FullName, "/")
	if ref.Organization != "" {
		ws = ref.Organization
	}
	if ref.ExternalID != "" && strings.HasPrefix(ref.ExternalID, "{") && ws != "" {
		return "/repositories/" + url.PathEscape(ws) + "/" + url.PathEscape(ref.ExternalID), nil
	}
	if !ok || ws == "" || slug == "" || strings.Contains(slug, "/") {
		return "", errors.New("scm: invalid repository name")
	}
	return "/repositories/" + url.PathEscape(ws) + "/" + url.PathEscape(slug), nil
}

func (b *bitbucket) repo(ctx context.Context, ref RepoRef) (bbRepo, string, error) {
	p, err := bbRepoPath(ref)
	if err != nil {
		return bbRepo{}, "", err
	}
	var r bbRepo
	if _, err := b.get(ctx, p, &r); err != nil {
		return bbRepo{}, "", err
	}
	return r, p, nil
}

func (b *bitbucket) GetRepository(ctx context.Context, ref RepoRef) (RemoteRepo, error) {
	r, _, err := b.repo(ctx, ref)
	if err != nil {
		return RemoteRepo{}, err
	}
	return r.remote(), nil
}

// Permission implements PermissionChecker for user credentials (API token,
// OAuth); access tokens report "unknown".
func (b *bitbucket) Permission(ctx context.Context, ref RepoRef) (string, error) {
	if !b.userCredential() {
		return "unknown", nil
	}
	full := ref.FullName
	if full == "" {
		r, _, err := b.repo(ctx, ref)
		if err != nil {
			return "", err
		}
		full = r.FullName
	}
	var out bbPage[struct {
		Permission string `json:"permission"`
	}]
	if _, err := b.get(ctx, "/user/permissions/repositories?q="+url.QueryEscape("repository.full_name = "+bbQuote(full)), &out); err != nil {
		return "", err
	}
	if len(out.Values) == 0 {
		return "unknown", nil
	}
	switch p := out.Values[0].Permission; p {
	case "admin", "write", "read":
		return p, nil
	}
	return "unknown", nil
}

func (b *bitbucket) ListBranchHeads(ctx context.Context, ref RepoRef) ([]Branch, error) {
	r, p, err := b.repo(ctx, ref)
	if err != nil {
		return nil, err
	}
	def := ""
	if r.MainBranch != nil {
		def = r.MainBranch.Name
	}
	bs, err := bbPages[struct {
		Name   string `json:"name"`
		Target struct {
			Hash string `json:"hash"`
		} `json:"target"`
	}](ctx, b, b.root+p+"/refs/branches?pagelen=100", 10)
	if err != nil {
		return nil, err
	}
	out := make([]Branch, 0, len(bs))
	for _, x := range bs {
		out = append(out, Branch{Name: x.Name, CommitSHA: x.Target.Hash, Default: x.Name == def})
	}
	return out, nil
}

func (b *bitbucket) LatestCommit(ctx context.Context, ref RepoRef, branch string) (Commit, error) {
	p, err := bbRepoPath(ref)
	if err != nil {
		return Commit{}, err
	}
	if branch == "" {
		r, _, err := b.repo(ctx, ref)
		if err != nil {
			return Commit{}, err
		}
		if r.MainBranch == nil {
			return Commit{}, ErrNotFound
		}
		branch = r.MainBranch.Name
	}
	var out bbPage[struct {
		Hash    string     `json:"hash"`
		Message string     `json:"message"`
		Date    *time.Time `json:"date"`
		Author  struct {
			Raw  string `json:"raw"`
			User *struct {
				DisplayName string `json:"display_name"`
			} `json:"user"`
		} `json:"author"`
	}]
	if _, err := b.get(ctx, p+"/commits/"+url.PathEscape(branch)+"?pagelen=1", &out); err != nil {
		return Commit{}, err
	}
	if len(out.Values) == 0 {
		return Commit{}, ErrNotFound
	}
	c := out.Values[0]
	author := c.Author.Raw
	if c.Author.User != nil && c.Author.User.DisplayName != "" {
		author = c.Author.User.DisplayName
	} else if i := strings.Index(author, " <"); i > 0 {
		author = author[:i] // drop the e-mail address
	}
	return Commit{SHA: c.Hash, Message: firstLine(c.Message), Author: author, CommittedAt: c.Date}, nil
}

// Languages: Bitbucket reports only a primary language (RemoteRepo.Language),
// not a breakdown, so the map is empty.
func (b *bitbucket) Languages(context.Context, RepoRef) (map[string]int64, error) {
	return map[string]int64{}, nil
}

// Revoke: Bitbucket Cloud has no token revocation endpoint.
func (b *bitbucket) Revoke(context.Context) error { return nil }
