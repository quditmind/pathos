package scm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Azure DevOps addressing. A legacy connection's base URL already contains
// the organization (https://dev.azure.com/<org>, https://<org>.visualstudio.com)
// or, for Server, the collection (https://host/tfs/<collection>); the
// organization of RepoRef / RepoQuery is then ignored. A connection whose
// base URL is the bare Services host (https://dev.azure.com) is
// organization-less: the organization is passed per call.
var (
	// adoServicesHost is the Azure DevOps Services host; a variable only so
	// tests can exercise organization-less addressing.
	adoServicesHost = "dev.azure.com"
	// adoVSSPSBase hosts the profile and accounts APIs used to enumerate
	// the organizations of a user.
	adoVSSPSBase = "https://app.vssps.visualstudio.com"
)

const adoAPIVersion = "7.1"

// The profile and accounts APIs are not released under 7.1; 6.0 is.
const adoVSSPSAPIVersion = "6.0"

var adoNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

// azureDevOps implements FullClient for Azure DevOps Services and Server.
type azureDevOps struct {
	cfg     Config
	base    *url.URL
	auth    authorizer
	api     *api
	orgless bool
	baseOrg string // organization or collection contained in the base URL
}

func newAzureDevOps(cfg Config) (*azureDevOps, error) {
	base, err := parseBase(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	if cfg.Provider == AzureDevOpsServer && cfg.AuthType != AuthPAT {
		return nil, errors.New("scm: Azure DevOps Server supports PAT authentication")
	}
	var auth authorizer
	switch cfg.AuthType {
	case AuthPAT:
		if len(cfg.Secret) == 0 {
			return nil, errors.New("scm: token required")
		}
		auth = basicAuth{pass: string(cfg.Secret), k: AuthPAT}
	case AuthOAuth:
		if auth, err = newOAuthAuth(cfg); err != nil {
			return nil, err
		}
	case AuthServicePrincipal:
		if auth, err = newServicePrincipalAuth(cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("scm: unsupported auth type %q for Azure DevOps", cfg.AuthType)
	}
	a := &azureDevOps{cfg: cfg, base: base, auth: auth, api: &api{hc: cfg.HTTP, auth: auth}}
	path := strings.Trim(base.EscapedPath(), "/")
	switch {
	case cfg.Provider == AzureDevOps && strings.EqualFold(base.Host, adoServicesHost) && path == "":
		a.orgless = true
	case path != "":
		seg := path[strings.LastIndex(path, "/")+1:]
		if s, err := url.PathUnescape(seg); err == nil {
			seg = s
		}
		a.baseOrg = seg
	default:
		host := base.Hostname()
		if h, ok := strings.CutSuffix(strings.ToLower(host), ".visualstudio.com"); ok {
			host = h
		}
		a.baseOrg = host
	}
	return a, nil
}

// call GETs u, adding api-version unless present.
func (a *azureDevOps) call(ctx context.Context, u string, out any) (*http.Response, error) {
	if !strings.Contains(u, "api-version=") {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u += sep + "api-version=" + adoAPIVersion
	}
	return a.api.get(ctx, u, out)
}

// org resolves the organization of a call: the configured single
// organization when none is given.
func (a *azureDevOps) org(org string) string {
	if !a.orgless {
		return a.baseOrg
	}
	if org == "" && len(a.cfg.Organizations) == 1 {
		return a.cfg.Organizations[0]
	}
	return org
}

// orgBase returns the URL prefix for organization-scoped APIs.
func (a *azureDevOps) orgBase(org string) (string, error) {
	if !a.orgless {
		return a.cfg.BaseURL, nil
	}
	org = a.org(org)
	if org == "" {
		return "", errors.New("scm: select an Azure DevOps organization")
	}
	if !adoNameRe.MatchString(org) {
		return "", errors.New("scm: invalid Azure DevOps organization name")
	}
	return a.cfg.BaseURL + "/" + url.PathEscape(org), nil
}

func (a *azureDevOps) profile(ctx context.Context) (string, string, error) {
	var me struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	}
	if _, err := a.api.get(ctx, adoVSSPSBase+"/_apis/profile/profiles/me?api-version="+adoVSSPSAPIVersion, &me); err != nil {
		return "", "", err
	}
	return me.ID, me.DisplayName, nil
}

func (a *azureDevOps) Check(ctx context.Context) (string, error) {
	if !a.orgless {
		var out struct {
			Count int `json:"count"`
		}
		if _, err := a.call(ctx, a.cfg.BaseURL+"/_apis/projects?$top=1", &out); err != nil {
			return "", err
		}
		return "connected to " + a.cfg.BaseURL, nil
	}
	if len(a.cfg.Organizations) > 0 {
		for _, o := range a.cfg.Organizations {
			ob, err := a.orgBase(o)
			if err != nil {
				return "", err
			}
			if _, err := a.call(ctx, ob+"/_apis/projects?$top=1", nil); err != nil {
				return "", fmt.Errorf("organization %s: %w", o, err)
			}
		}
		return fmt.Sprintf("connected to %d Azure DevOps organization(s)", len(a.cfg.Organizations)), nil
	}
	if a.auth.kind() == AuthServicePrincipal {
		return "", errors.New("scm: list the Azure DevOps organizations the service principal was added to")
	}
	_, name, err := a.profile(ctx)
	if err != nil {
		return "", err
	}
	return "authenticated as " + name, nil
}

// CloneCredential: Azure DevOps accepts any username with a PAT or an
// Entra ID access token.
func (a *azureDevOps) CloneCredential(ctx context.Context) (Credential, error) {
	tok, exp, err := a.auth.secret(ctx)
	if err != nil {
		return Credential{}, err
	}
	return Credential{Username: "pathos", Token: tok, ExpiresAt: exp}, nil
}

type adoRepo struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	RemoteURL     string `json:"remoteUrl"`
	WebURL        string `json:"webUrl"`
	DefaultBranch string `json:"defaultBranch"`
	IsDisabled    bool   `json:"isDisabled"`
	Size          int64  `json:"size"`
	Project       struct {
		ID         string `json:"id"`
		Name       string `json:"name"`
		Visibility string `json:"visibility"`
	} `json:"project"`
}

func (r adoRepo) remote(org string) RemoteRepo {
	vis := "private"
	if strings.EqualFold(r.Project.Visibility, "public") {
		vis = "public"
	}
	return RemoteRepo{
		ExternalID: r.ID, FullName: r.Project.Name + "/" + r.Name, Name: r.Name, URL: r.WebURL,
		CloneURL: r.RemoteURL, DefaultBranch: strings.TrimPrefix(r.DefaultBranch, "refs/heads/"),
		Visibility: vis, Archived: r.IsDisabled, Organization: org, Project: r.Project.Name, SizeBytes: r.Size,
	}
}

// listRepos lists the repositories of an organization (all projects, or
// one). Azure DevOps does not paginate or search this API.
func (a *azureDevOps) listRepos(ctx context.Context, org, project string) ([]RemoteRepo, error) {
	ob, err := a.orgBase(org)
	if err != nil {
		return nil, err
	}
	p := ob + "/_apis/git/repositories"
	if project != "" {
		p = ob + "/" + url.PathEscape(project) + "/_apis/git/repositories"
	}
	var out struct {
		Value []adoRepo `json:"value"`
	}
	if _, err := a.call(ctx, p, &out); err != nil {
		return nil, err
	}
	name := a.org(org)
	repos := make([]RemoteRepo, 0, len(out.Value))
	for _, r := range out.Value {
		repos = append(repos, r.remote(name))
		if len(repos) >= MaxRepositories {
			break
		}
	}
	return repos, nil
}

// ListRepositories implements Client. Legacy connections list the base
// URL's organization (cfg.Owner is an optional project); organization-less
// connections list every organization from ListOrganizations.
func (a *azureDevOps) ListRepositories(ctx context.Context) ([]RemoteRepo, error) {
	if !a.orgless {
		return a.listRepos(ctx, "", a.cfg.Owner)
	}
	orgs, err := a.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	var out []RemoteRepo
	for _, o := range orgs {
		repos, err := a.listRepos(ctx, o.Name, "")
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

func (a *azureDevOps) ListBranches(ctx context.Context, repo RemoteRepo) ([]string, error) {
	heads, err := a.refs(ctx, repo.Ref(), "")
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

// ListOrganizations: configured organizations, else the organization in
// the base URL, else (user credentials) the organizations the user is a
// member of via the profile and accounts APIs.
func (a *azureDevOps) ListOrganizations(ctx context.Context) ([]Organization, error) {
	if len(a.cfg.Organizations) > 0 && a.orgless {
		orgs := make([]Organization, 0, len(a.cfg.Organizations))
		for _, o := range a.cfg.Organizations {
			orgs = append(orgs, Organization{Name: o, DisplayName: o, Kind: "organization"})
		}
		return orgs, nil
	}
	if !a.orgless {
		kind := "organization"
		if a.cfg.Provider == AzureDevOpsServer {
			kind = "collection"
		}
		return []Organization{{Name: a.baseOrg, DisplayName: a.baseOrg, Kind: kind}}, nil
	}
	if a.auth.kind() == AuthServicePrincipal {
		return nil, fmt.Errorf("%w: a service principal cannot enumerate organizations; list them in the connection", ErrNotSupported)
	}
	id, _, err := a.profile(ctx)
	if err != nil {
		return nil, err
	}
	var out struct {
		Value []struct {
			AccountID   string `json:"accountId"`
			AccountName string `json:"accountName"`
		} `json:"value"`
	}
	if _, err := a.api.get(ctx, adoVSSPSBase+"/_apis/accounts?memberId="+url.QueryEscape(id)+"&api-version="+adoVSSPSAPIVersion, &out); err != nil {
		return nil, err
	}
	orgs := make([]Organization, 0, len(out.Value))
	for _, v := range out.Value {
		orgs = append(orgs, Organization{ID: v.AccountID, Name: v.AccountName, DisplayName: v.AccountName, Kind: "organization"})
	}
	sort.Slice(orgs, func(i, j int) bool { return strings.ToLower(orgs[i].Name) < strings.ToLower(orgs[j].Name) })
	return orgs, nil
}

func (a *azureDevOps) ListProjects(ctx context.Context, org string) ([]Project, error) {
	ob, err := a.orgBase(org)
	if err != nil {
		return nil, err
	}
	var out []Project
	cont := ""
	for pages := 0; pages < 50; pages++ {
		u := ob + "/_apis/projects?$top=100"
		if cont != "" {
			u += "&continuationToken=" + url.QueryEscape(cont)
		}
		var page struct {
			Value []struct {
				ID          string `json:"id"`
				Name        string `json:"name"`
				Description string `json:"description"`
			} `json:"value"`
		}
		resp, err := a.call(ctx, u, &page)
		if err != nil {
			return nil, err
		}
		for _, p := range page.Value {
			out = append(out, Project{ID: p.ID, Name: p.Name, DisplayName: p.Name, Description: p.Description})
		}
		cont = resp.Header.Get("X-Ms-Continuationtoken")
		if cont == "" || len(page.Value) == 0 {
			break
		}
	}
	return out, nil
}

// ListRepositoriesPage: Azure DevOps has neither pagination nor search on
// the repositories API, so the organization (or project) listing is
// fetched, sorted, filtered client-side and paginated by offset.
func (a *azureDevOps) ListRepositoriesPage(ctx context.Context, q RepoQuery) (RepoPage, error) {
	cur, err := decodeCursor(a.cfg.Provider, q)
	if err != nil {
		return RepoPage{}, err
	}
	if cur.N != "" {
		return RepoPage{}, ErrInvalidPageToken
	}
	project := q.Project
	if project == "" && !a.orgless {
		project = a.cfg.Owner
	}
	all, err := a.listRepos(ctx, q.Organization, project)
	if err != nil {
		return RepoPage{}, err
	}
	sort.Slice(all, func(i, j int) bool { return strings.ToLower(all[i].FullName) < strings.ToLower(all[j].FullName) })
	term := strings.TrimSpace(q.Search)
	filtered := all[:0]
	for _, r := range all {
		if matchesSearch(r, term) {
			filtered = append(filtered, r)
		}
	}
	size := pageSize(q.PageSize)
	if cur.O >= len(filtered) {
		return RepoPage{Items: []RemoteRepo{}}, nil
	}
	end := min(cur.O+size, len(filtered))
	page := RepoPage{Items: filtered[cur.O:end]}
	if end < len(filtered) {
		page.NextPageToken = encodeCursor(a.cfg.Provider, q, "", end)
	}
	return page, nil
}

// repoBase returns the URL of a repository resource.
func (a *azureDevOps) repoBase(ref RepoRef) (string, error) {
	ob, err := a.orgBase(ref.Organization)
	if err != nil {
		return "", err
	}
	project, name := ref.Project, ""
	if p, n, ok := strings.Cut(ref.FullName, "/"); ok {
		if project == "" {
			project = p
		}
		name = n
	}
	id := ref.ExternalID
	if id == "" {
		id = name
	}
	if id == "" {
		return "", errors.New("scm: invalid repository reference")
	}
	if project == "" {
		return ob + "/_apis/git/repositories/" + url.PathEscape(id), nil
	}
	return ob + "/" + url.PathEscape(project) + "/_apis/git/repositories/" + url.PathEscape(id), nil
}

func (a *azureDevOps) repo(ctx context.Context, ref RepoRef) (adoRepo, string, error) {
	rb, err := a.repoBase(ref)
	if err != nil {
		return adoRepo{}, "", err
	}
	var r adoRepo
	if _, err := a.call(ctx, rb, &r); err != nil {
		return adoRepo{}, "", err
	}
	return r, rb, nil
}

func (a *azureDevOps) GetRepository(ctx context.Context, ref RepoRef) (RemoteRepo, error) {
	r, _, err := a.repo(ctx, ref)
	if err != nil {
		return RemoteRepo{}, err
	}
	return r.remote(a.org(ref.Organization)), nil
}

// refs lists branch heads (no default marking).
func (a *azureDevOps) refs(ctx context.Context, ref RepoRef, defaultBranch string) ([]Branch, error) {
	rb, err := a.repoBase(ref)
	if err != nil {
		return nil, err
	}
	var out []Branch
	cont := ""
	for pages := 0; pages < 5; pages++ {
		u := rb + "/refs?filter=heads/&$top=1000"
		if cont != "" {
			u += "&continuationToken=" + url.QueryEscape(cont)
		}
		var page struct {
			Value []struct {
				Name     string `json:"name"`
				ObjectID string `json:"objectId"`
			} `json:"value"`
		}
		resp, err := a.call(ctx, u, &page)
		if err != nil {
			return nil, err
		}
		for _, r := range page.Value {
			name := strings.TrimPrefix(r.Name, "refs/heads/")
			out = append(out, Branch{Name: name, CommitSHA: r.ObjectID, Default: name == defaultBranch})
		}
		cont = resp.Header.Get("X-Ms-Continuationtoken")
		if cont == "" || len(page.Value) == 0 {
			break
		}
	}
	return out, nil
}

func (a *azureDevOps) ListBranchHeads(ctx context.Context, ref RepoRef) ([]Branch, error) {
	r, _, err := a.repo(ctx, ref)
	if err != nil {
		return nil, err
	}
	full := r.remote(a.org(ref.Organization)).Ref()
	full.Organization = ref.Organization
	return a.refs(ctx, full, strings.TrimPrefix(r.DefaultBranch, "refs/heads/"))
}

func (a *azureDevOps) LatestCommit(ctx context.Context, ref RepoRef, branch string) (Commit, error) {
	rb, err := a.repoBase(ref)
	if err != nil {
		return Commit{}, err
	}
	if branch == "" {
		r, _, err := a.repo(ctx, ref)
		if err != nil {
			return Commit{}, err
		}
		branch = strings.TrimPrefix(r.DefaultBranch, "refs/heads/")
		if branch == "" {
			return Commit{}, ErrNotFound
		}
	}
	var out struct {
		Value []struct {
			CommitID string `json:"commitId"`
			Comment  string `json:"comment"`
			Author   struct {
				Name string     `json:"name"`
				Date *time.Time `json:"date"`
			} `json:"author"`
			Committer struct {
				Date *time.Time `json:"date"`
			} `json:"committer"`
		} `json:"value"`
	}
	u := rb + "/commits?searchCriteria.itemVersion.version=" + url.QueryEscape(branch) +
		"&searchCriteria.itemVersion.versionType=branch&searchCriteria.$top=1"
	if _, err := a.call(ctx, u, &out); err != nil {
		return Commit{}, err
	}
	if len(out.Value) == 0 {
		return Commit{}, ErrNotFound
	}
	c := out.Value[0]
	at := c.Committer.Date
	if at == nil {
		at = c.Author.Date
	}
	return Commit{SHA: c.CommitID, Message: firstLine(c.Comment), Author: c.Author.Name, CommittedAt: at}, nil
}

// Languages: Azure DevOps reports language metrics per project only, so
// the per-repository breakdown is empty.
func (a *azureDevOps) Languages(context.Context, RepoRef) (map[string]int64, error) {
	return map[string]int64{}, nil
}

// Revoke: neither PATs nor Entra ID tokens can be revoked through an API
// available to the connection.
func (a *azureDevOps) Revoke(context.Context) error { return nil }
