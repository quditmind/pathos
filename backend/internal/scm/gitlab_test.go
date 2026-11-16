package scm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func gitlabServer(t *testing.T, valid func(string) bool) *fake {
	project := map[string]any{"id": 11, "name": "API", "path": "api", "path_with_namespace": "acme/backend/api",
		"web_url": "https://gl/acme/backend/api", "http_url_to_repo": "https://gl/acme/backend/api.git", "default_branch": "main",
		"visibility": "internal", "description": "d", "archived": false, "last_activity_at": "2026-02-01T00:00:00Z",
		"namespace":   map[string]any{"full_path": "acme/backend"},
		"permissions": map[string]any{"project_access": nil, "group_access": map[string]int{"access_level": 30}}}
	return newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		p := r.URL.EscapedPath()
		if strings.HasPrefix(p, "/oauth/") {
			_ = r.ParseForm()
			switch {
			case p == "/oauth/token" && r.Form.Get("refresh_token") == "r1":
				jsonResp(w, map[string]any{"access_token": "new", "refresh_token": "r2", "expires_in": 7200, "token_type": "Bearer", "created_at": 1})
			case p == "/oauth/token":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(400)
				_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"secret-body-should-not-leak"}`))
			case p == "/oauth/revoke":
				if r.Form.Get("token") != "new" || r.Form.Get("client_id") != "gcid" || r.Form.Get("client_secret") != "gsec" {
					t.Errorf("revoke form: %v", r.Form)
				}
				jsonResp(w, map[string]any{})
			}
			return
		}
		p, _ = strings.CutPrefix(p, "/api/v4")
		if !valid(bearer(r)) {
			status(w, 401)
			return
		}
		q := r.URL.Query()
		switch {
		case p == "/user":
			jsonResp(w, map[string]any{"id": 3, "username": "ada"})
		case p == "/groups":
			if q.Get("min_access_level") != "10" {
				t.Errorf("groups query: %s", r.URL.RawQuery)
			}
			jsonResp(w, []map[string]any{{"id": 20, "full_path": "acme", "full_name": "Acme"}, {"id": 21, "full_path": "acme/backend", "full_name": "Acme / Backend"}})
		case p == "/groups/acme%2Fbackend/projects" || p == "/groups/21/projects":
			if q.Get("include_subgroups") != "true" || q.Get("search") != "ap" || q.Get("per_page") != "1" {
				t.Errorf("group projects query: %s", r.URL.RawQuery)
			}
			if q.Get("page") == "" {
				// GitLab rewrites the group path to its ID in Link headers.
				w.Header().Set("Link", fmt.Sprintf(`<%s/api/v4/groups/21/projects?include_subgroups=true&page=2&per_page=1&search=ap>; rel="next"`, f.URL))
			}
			jsonResp(w, []any{project})
		case p == "/projects":
			if q.Get("membership") != "true" {
				t.Errorf("projects query: %s", r.URL.RawQuery)
			}
			jsonResp(w, []any{project})
		case p == "/users/ada/projects":
			jsonResp(w, []any{})
		case p == "/projects/11" || p == "/projects/acme%2Fbackend%2Fapi":
			if p == "/projects/11" && q.Get("statistics") == "true" {
				withStats := map[string]any{}
				for k, v := range project {
					withStats[k] = v
				}
				withStats["statistics"] = map[string]int64{"repository_size": 4096}
				jsonResp(w, withStats)
				return
			}
			jsonResp(w, project)
		case p == "/projects/12":
			status(w, 404)
		case p == "/projects/13":
			status(w, 403)
		case p == "/projects/11/repository/branches":
			jsonResp(w, []map[string]any{{"name": "main", "default": true, "commit": map[string]string{"id": "c1"}}, {"name": "dev", "commit": map[string]string{"id": "c2"}}})
		case p == "/projects/11/repository/commits":
			if q.Get("ref_name") != "main" || q.Get("per_page") != "1" {
				t.Errorf("commits query: %s", r.URL.RawQuery)
			}
			jsonResp(w, []map[string]any{{"id": "c1", "title": "Init", "author_name": "Ada", "committed_date": "2026-01-01T00:00:00Z"}})
		case p == "/projects/11/languages":
			jsonResp(w, map[string]float64{"Go": 80.6, "Shell": 19.4})
		default:
			status(w, 404)
		}
	})
}

func TestGitLab(t *testing.T) {
	ctx := context.Background()
	srv := gitlabServer(t, func(tok string) bool { return tok == "glpat" || tok == "new" })
	for _, tc := range []struct {
		name     string
		cfg      Config
		user     string
		storeTok *memStore
	}{
		{name: "pat", cfg: Config{AuthType: AuthPAT, Secret: []byte("glpat")}, user: "pathos"},
		{name: "oauth", cfg: Config{AuthType: AuthOAuth, OAuth: &OAuthApp{Provider: GitLab, BaseURL: "", ClientID: "gcid", ClientSecret: []byte("gsec")}},
			user: "oauth2", storeTok: &memStore{tok: OAuthToken{AccessToken: "old", RefreshToken: "r1", ExpiresAt: future(time.Hour)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Provider, cfg.HTTP = GitLab, srv.Client()
			cfg.BaseURL = srv.URL + "/api/v4" // a trailing /api/v4 is accepted
			if tc.storeTok != nil {
				cfg.Secret = tokenJSON(t, tc.storeTok.tok)
				cfg.Tokens = tc.storeTok
				cfg.OAuth.BaseURL = srv.URL
			}
			c := mustNew(t, cfg)
			if id, err := c.Check(ctx); err != nil || id != "authenticated as ada" {
				t.Fatalf("check: %q %v", id, err)
			}
			orgs, err := c.ListOrganizations(ctx)
			if err != nil || len(orgs) != 3 || orgs[0].Kind != "user" || orgs[2].Name != "acme/backend" || orgs[2].Kind != "group" {
				t.Fatalf("orgs: %+v %v", orgs, err)
			}
			q := RepoQuery{Organization: "acme/backend", Search: "ap", PageSize: 1}
			p1, err := c.ListRepositoriesPage(ctx, q)
			if err != nil || len(p1.Items) != 1 || p1.NextPageToken == "" {
				t.Fatalf("page 1: %+v %v", p1, err)
			}
			r := p1.Items[0]
			if r.ExternalID != "11" || r.FullName != "acme/backend/api" || r.Organization != "acme/backend" || r.Visibility != "internal" || r.PushedAt == nil {
				t.Errorf("mapping: %+v", r)
			}
			q.PageToken = p1.NextPageToken
			if p2, err := c.ListRepositoriesPage(ctx, q); err != nil || p2.NextPageToken != "" {
				t.Fatalf("page 2: %+v %v", p2, err)
			}
			assertInvalidTokens(t, c, GitLab, RepoQuery{Organization: "acme/backend", Search: "ap", PageSize: 1}, srv.URL)
			if p, err := c.ListRepositoriesPage(ctx, RepoQuery{}); err != nil || len(p.Items) != 1 {
				t.Fatalf("membership listing: %+v %v", p, err)
			}
			if p, err := c.ListRepositoriesPage(ctx, RepoQuery{Organization: "ada"}); err != nil || len(p.Items) != 0 {
				t.Fatalf("user namespace: %+v %v", p, err)
			}
			all, err := c.ListRepositories(ctx)
			if err != nil || len(all) != 1 {
				t.Fatalf("list all: %v %v", all, err)
			}
			got, err := c.GetRepository(ctx, RepoRef{ExternalID: "11"})
			if err != nil || got.SizeBytes != 4096 {
				t.Fatalf("get: %+v %v", got, err)
			}
			if _, err := c.GetRepository(ctx, RepoRef{FullName: "acme/backend/api"}); err != nil {
				t.Fatalf("get by path: %v", err)
			}
			if _, err := c.GetRepository(ctx, RepoRef{ExternalID: "12"}); !errors.Is(err, ErrNotFound) {
				t.Errorf("404: %v", err)
			}
			if _, err := c.GetRepository(ctx, RepoRef{ExternalID: "13"}); !errors.Is(err, ErrForbidden) {
				t.Errorf("403: %v", err)
			}
			d, err := Details(ctx, c, RepoRef{ExternalID: "11"})
			if err != nil || d.Permission != "write" || len(d.Branches) != 2 || !d.Branches[0].Default || d.LatestCommit == nil ||
				d.LatestCommit.Message != "Init" || d.Languages["Go"] != 81 {
				t.Fatalf("details: %+v %v", d, err)
			}
			if _, err := c.ListProjects(ctx, "acme"); !errors.Is(err, ErrNotSupported) {
				t.Errorf("projects: %v", err)
			}
			cred, err := c.CloneCredential(ctx)
			if err != nil || cred.Username != tc.user || cred.Token == "" {
				t.Errorf("clone: %+v %v", cred, err)
			}
			if err := c.Revoke(ctx); err != nil {
				t.Errorf("revoke: %v", err)
			}
			if tc.storeTok != nil && (tc.storeTok.tok.AccessToken != "new" || tc.storeTok.tok.RefreshToken != "r2") {
				t.Errorf("refresh token must rotate: %+v", tc.storeTok.tok)
			}
		})
	}
	if n := srv.count("POST /oauth/revoke"); n != 1 {
		t.Errorf("only OAuth tokens are revoked, got %d", n)
	}

	// invalid_grant on refresh → ErrTokenExpired.
	store := &memStore{tok: OAuthToken{AccessToken: "old", RefreshToken: "spent", ExpiresAt: future(-time.Minute)}}
	c := mustNew(t, Config{Provider: GitLab, BaseURL: srv.URL, AuthType: AuthOAuth, Secret: tokenJSON(t, store.tok), Tokens: store,
		OAuth: &OAuthApp{Provider: GitLab, BaseURL: srv.URL, ClientID: "gcid"}, HTTP: srv.Client()})
	_, err := c.Check(ctx)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
	assertNoLeak(t, err, "spent")
	if _, err := New(Config{Provider: GitLab, BaseURL: srv.URL, AuthType: AuthAPIToken, Secret: []byte("x"), HTTP: srv.Client()}); err == nil {
		t.Error("unsupported auth type accepted")
	}
}
