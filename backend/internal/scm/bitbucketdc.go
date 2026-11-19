package scm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// BitbucketDataCenter is Bitbucket Data Center (formerly Bitbucket Server).
const BitbucketDataCenter = "bitbucket_data_center"

// ErrTokenPermission means a Bitbucket Data Center HTTP access token lacks
// the permission level (read / write) the operation needs. It wraps
// ErrForbidden.
var ErrTokenPermission = fmt.Errorf("%w (the HTTP access token lacks the permission level)", ErrForbidden)

// bitbucketDC implements FullClient for Bitbucket Data Center, REST API
// 1.0 (https://developer.atlassian.com/server/bitbucket/rest/v1000/intro/,
// checked 2026-11-20):
//
//   - base: the instance root (with its context path); the API is
//     <root>/rest/api/1.0.
//   - auth: project and repository HTTP access tokens use
//     "Authorization: Bearer"; user (personal) tokens use Basic with the
//     account user name
//     (https://confluence.atlassian.com/bitbucketserver/http-access-tokens-939515499.html).
//   - paging: start / limit, response isLastPage / nextPageStart / values
//     (default page size 25).
type bitbucketDC struct {
	cfg  Config
	root string // instance root
	api  *api
	auth authorizer
}

func newBitbucketDataCenter(cfg Config) (*bitbucketDC, error) {
	if _, err := parseBase(cfg.BaseURL); err != nil {
		return nil, err
	}
	var auth authorizer
	switch cfg.AuthType {
	case AuthPAT: // project or repository HTTP access token
		if len(cfg.Secret) == 0 {
			return nil, errors.New("scm: token required")
		}
		auth = bearerAuth{tok: string(cfg.Secret), k: AuthPAT}
	case AuthAPIToken: // user HTTP access token: Basic with the user name
		var c APITokenCredential
		if err := json.Unmarshal(cfg.Secret, &c); err != nil || c.Username == "" || c.Token == "" {
			return nil, errors.New("scm: a Bitbucket Data Center user token requires the user name and the token")
		}
		auth = basicAuth{user: c.Username, pass: c.Token, k: AuthAPIToken}
	default:
		return nil, fmt.Errorf("scm: unsupported auth type %q for Bitbucket Data Center", cfg.AuthType)
	}
	root := NormalizeBaseURL(BitbucketDataCenter, cfg.BaseURL)
	return &bitbucketDC{cfg: cfg, root: root, auth: auth, api: &api{hc: cfg.HTTP, auth: auth}}, nil
}

func (b *bitbucketDC) url(path string, q url.Values) string {
	u := b.root + "/rest/api/1.0" + path
	if len(q) > 0 {
		u += "?" + q.Encode()
	}
	return u
}

func (b *bitbucketDC) get(ctx context.Context, path string, q url.Values, out any) error {
	_, err := b.api.get(ctx, b.url(path, q), out)
	if errors.Is(err, ErrForbidden) && !errors.Is(err, ErrRateLimited) && b.auth.kind() == AuthPAT {
		return fmt.Errorf("%w: %w", ErrTokenPermission, err)
	}
	return err
}

type bbsPage[T any] struct {
	Values        []T  `json:"values"`
	IsLastPage    bool `json:"isLastPage"`
	NextPageStart int  `json:"nextPageStart"`
}

type bbsRepo struct {
	ID       int    `json:"id"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Public   bool   `json:"public"`
	Archived bool   `json:"archived"`
	Desc     string `json:"description"`
	Project  struct {
		Key  string `json:"key"`
		Name string `json:"name"`
	} `json:"project"`
	Links struct {
		Clone []struct {
			Href string `json:"href"`
			Name string `json:"name"`
		} `json:"clone"`
		Self []struct {
			Href string `json:"href"`
		} `json:"self"`
	} `json:"links"`
}

func (r bbsRepo) remote() RemoteRepo {
	rr := RemoteRepo{
		ExternalID: strconv.Itoa(r.ID), FullName: r.Project.Key + "/" + r.Slug, Name: r.Name,
		Visibility: "private", Description: r.Desc, Archived: r.Archived,
		Organization: r.Project.Key, Project: r.Project.Key,
	}
	if r.Public {
		rr.Visibility = "public"
	}
	if len(r.Links.Self) > 0 {
		rr.URL = r.Links.Self[0].Href
	}
	for _, c := range r.Links.Clone {
		if c.Name == "http" || c.Name == "https" {
			rr.CloneURL = c.Href
		}
	}
	return rr
}

// ServerVersion reads GET /rest/api/1.0/application-properties.
func (b *bitbucketDC) ServerVersion(ctx context.Context) (VersionInfo, error) {
	var p struct {
		Version     string `json:"version"`
		DisplayName string `json:"displayName"`
	}
	if err := b.get(ctx, "/application-properties", nil, &p); err != nil {
		return VersionInfo{}, err
	}
	vi := judge("Bitbucket Data Center", p.Version, bbdcReleases, nowFunc())
	if !vi.Supported {
		return vi, ErrBBDCVersion
	}
	return vi, nil
}

// Check reads the version and a one-item repository list: the second call
// proves the token is accepted (a rejected token answers 401).
func (b *bitbucketDC) Check(ctx context.Context) (string, error) {
	vi, verr := b.ServerVersion(ctx)
	if verr != nil && !errors.Is(verr, ErrVersionUnsupported) {
		return "", verr
	}
	var page bbsPage[bbsRepo]
	q := url.Values{"limit": {"1"}}
	if b.cfg.Owner != "" {
		if err := b.get(ctx, "/projects/"+url.PathEscape(b.cfg.Owner)+"/repos", q, &page); err != nil {
			return "", err
		}
	} else if err := b.get(ctx, "/repos", q, &page); err != nil {
		return "", err
	}
	msg := "connected to Bitbucket Data Center " + vi.Version
	if b.cfg.Owner != "" {
		msg += ", project " + b.cfg.Owner
	}
	if verr != nil {
		return msg, verr
	}
	return msg, nil
}

func (b *bitbucketDC) ListOrganizations(context.Context) ([]Organization, error) {
	return nil, ErrNotSupported
}

// ListProjects lists the projects the credential can see (up to 1,000).
func (b *bitbucketDC) ListProjects(ctx context.Context, _ string) ([]Project, error) {
	var out []Project
	start := 0
	for pages := 0; pages < 10; pages++ {
		var page bbsPage[struct {
			Key  string `json:"key"`
			Name string `json:"name"`
			Desc string `json:"description"`
		}]
		if err := b.get(ctx, "/projects", url.Values{"start": {strconv.Itoa(start)}, "limit": {"100"}}, &page); err != nil {
			return nil, err
		}
		for _, p := range page.Values {
			out = append(out, Project{ID: p.Key, Name: p.Key, DisplayName: p.Name, Description: p.Desc})
		}
		if page.IsLastPage || page.NextPageStart <= start {
			break
		}
		start = page.NextPageStart
	}
	return out, nil
}

// ListRepositoriesPage lists one page: a project's repositories when
// q.Project (or the connection's project) is set, otherwise every
// repository the credential can read. The page token carries nextPageStart.
func (b *bitbucketDC) ListRepositoriesPage(ctx context.Context, q RepoQuery) (RepoPage, error) {
	if q.Project == "" {
		q.Project = b.cfg.Owner
	}
	cur, err := decodeCursor(BitbucketDataCenter, q)
	if err != nil {
		return RepoPage{}, err
	}
	params := url.Values{"start": {strconv.Itoa(cur.O)}, "limit": {strconv.Itoa(pageSize(q.PageSize))}}
	path := "/repos"
	if q.Project != "" {
		path = "/projects/" + url.PathEscape(q.Project) + "/repos"
	} else if q.Search != "" {
		params.Set("name", q.Search)
	}
	var page bbsPage[bbsRepo]
	if err := b.get(ctx, path, params, &page); err != nil {
		return RepoPage{}, err
	}
	out := RepoPage{Items: []RemoteRepo{}}
	for _, r := range page.Values {
		rr := r.remote()
		if q.Project != "" && !matchesSearch(rr, q.Search) {
			continue
		}
		out.Items = append(out.Items, rr)
	}
	if !page.IsLastPage && page.NextPageStart > cur.O {
		out.NextPageToken = encodeCursor(BitbucketDataCenter, q, "", page.NextPageStart)
	}
	return out, nil
}

func (b *bitbucketDC) refPath(ref RepoRef) (string, error) {
	key, slug, ok := splitFullName(ref.FullName)
	if !ok || strings.Contains(key, "/") {
		return "", fmt.Errorf("%w: Bitbucket Data Center repositories are named PROJECT/slug", ErrNotFound)
	}
	return "/projects/" + url.PathEscape(key) + "/repos/" + url.PathEscape(slug), nil
}

func (b *bitbucketDC) GetRepository(ctx context.Context, ref RepoRef) (RemoteRepo, error) {
	p, err := b.refPath(ref)
	if err != nil {
		return RemoteRepo{}, err
	}
	var r bbsRepo
	if err := b.get(ctx, p, nil, &r); err != nil {
		return RemoteRepo{}, err
	}
	rr := r.remote()
	var def struct {
		DisplayID string `json:"displayId"`
	}
	// An empty repository has no default branch (404): not an error.
	if err := b.get(ctx, p+"/branches/default", nil, &def); err == nil {
		rr.DefaultBranch = def.DisplayID
	} else if !errors.Is(err, ErrNotFound) {
		return RemoteRepo{}, err
	}
	return rr, nil
}

func (b *bitbucketDC) ListBranchHeads(ctx context.Context, ref RepoRef) ([]Branch, error) {
	p, err := b.refPath(ref)
	if err != nil {
		return nil, err
	}
	var out []Branch
	start := 0
	for pages := 0; pages < 10; pages++ {
		var page bbsPage[struct {
			DisplayID    string `json:"displayId"`
			LatestCommit string `json:"latestCommit"`
			Default      bool   `json:"default"`
		}]
		if err := b.get(ctx, p+"/branches", url.Values{"start": {strconv.Itoa(start)}, "limit": {"100"}}, &page); err != nil {
			return nil, err
		}
		for _, br := range page.Values {
			out = append(out, Branch{Name: br.DisplayID, CommitSHA: br.LatestCommit, Default: br.Default})
		}
		if page.IsLastPage || page.NextPageStart <= start {
			break
		}
		start = page.NextPageStart
	}
	return out, nil
}

func (b *bitbucketDC) LatestCommit(ctx context.Context, ref RepoRef, branch string) (Commit, error) {
	p, err := b.refPath(ref)
	if err != nil {
		return Commit{}, err
	}
	q := url.Values{"limit": {"1"}}
	if branch != "" {
		q.Set("until", branch)
	}
	var page bbsPage[struct {
		ID     string `json:"id"`
		Msg    string `json:"message"`
		Author struct {
			Name string `json:"name"`
		} `json:"author"`
		CommitterTimestamp int64 `json:"committerTimestamp"`
	}]
	if err := b.get(ctx, p+"/commits", q, &page); err != nil {
		return Commit{}, err
	}
	if len(page.Values) == 0 {
		return Commit{}, ErrNotFound
	}
	c := page.Values[0]
	out := Commit{SHA: c.ID, Message: firstLine(c.Msg), Author: c.Author.Name}
	if c.CommitterTimestamp > 0 {
		t := time.UnixMilli(c.CommitterTimestamp).UTC()
		out.CommittedAt = &t
	}
	return out, nil
}

// Languages: Bitbucket Data Center has no language API.
func (b *bitbucketDC) Languages(context.Context, RepoRef) (map[string]int64, error) {
	return map[string]int64{}, nil
}

// Revoke: HTTP access tokens are revoked in Bitbucket, not through the API
// PATHOS uses.
func (b *bitbucketDC) Revoke(context.Context) error { return nil }

func (b *bitbucketDC) ListRepositories(ctx context.Context) ([]RemoteRepo, error) {
	return listAll(ctx, b, RepoQuery{})
}

func (b *bitbucketDC) ListBranches(ctx context.Context, repo RemoteRepo) ([]string, error) {
	heads, err := b.ListBranchHeads(ctx, repo.Ref())
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(heads))
	for _, h := range heads {
		out = append(out, h.Name)
	}
	return out, nil
}

// CloneCredential: project and repository tokens clone with
// "Authorization: Bearer" (git http.extraHeader); user tokens with Basic
// user name + token.
func (b *bitbucketDC) CloneCredential(ctx context.Context) (Credential, error) {
	tok, exp, err := b.auth.secret(ctx)
	if err != nil {
		return Credential{}, err
	}
	if ba, ok := b.auth.(basicAuth); ok {
		return Credential{Username: ba.user, Token: tok, ExpiresAt: exp}, nil
	}
	return Credential{Username: "x-token-auth", Token: tok, Scheme: "bearer", ExpiresAt: exp}, nil
}
