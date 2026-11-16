package scm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func bitbucketServer(t *testing.T) *fake {
	repo := map[string]any{"uuid": "{r-1}", "full_name": "acme/api", "slug": "api", "name": "API", "is_private": true,
		"language": "go", "size": 2048, "updated_on": "2026-03-01T10:00:00.000000+00:00", "mainbranch": map[string]string{"name": "main"},
		"links": map[string]any{"html": map[string]string{"href": "https://bitbucket.org/acme/api"},
			"clone": []map[string]string{{"name": "https", "href": "https://someone@bitbucket.org/acme/api.git"}, {"name": "ssh", "href": "git@bitbucket.org:acme/api.git"}}},
		"workspace": map[string]string{"slug": "acme"}, "project": map[string]string{"key": "CORE"}}
	return newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/site/oauth2/") {
			u, p := basicOf(r)
			_ = r.ParseForm()
			if u != "bcid" || p != "bsec" {
				status(w, 401)
				return
			}
			if r.Form.Get("refresh_token") == "r1" {
				jsonResp(w, map[string]any{"access_token": "new", "refresh_token": "r1", "expires_in": 7200, "scopes": "repository account"})
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
			return
		}
		// Access token / OAuth token: Bearer. API token: Basic e-mail:token.
		u, pw := basicOf(r)
		authed := bearer(r) == "bbat" || bearer(r) == "new" || (u == "ada@example.com" && pw == "atat")
		if !authed {
			status(w, 401)
			return
		}
		userCred := bearer(r) != "bbat"
		q := r.URL.Query()
		p := r.URL.EscapedPath()
		switch {
		case p == "/user" && userCred:
			jsonResp(w, map[string]any{"username": "ada_l", "display_name": "Ada"})
		case p == "/user":
			status(w, 401)
		case p == "/user/permissions/workspaces":
			if q.Get("page") == "" {
				jsonResp(w, map[string]any{"values": []any{map[string]any{"workspace": map[string]string{"uuid": "{w1}", "slug": "acme", "name": "Acme"}}},
					"next": f.URL + "/user/permissions/workspaces?pagelen=100&page=2"})
				return
			}
			jsonResp(w, map[string]any{"values": []any{map[string]any{"workspace": map[string]string{"uuid": "{w2}", "slug": "beta", "name": "Beta"}}},
				"next": "https://evil.example/user/permissions/workspaces?page=3"})
		case p == "/workspaces/acme":
			jsonResp(w, map[string]string{"uuid": "{w1}", "slug": "acme", "name": "Acme"})
		case p == "/workspaces/acme/projects":
			jsonResp(w, map[string]any{"values": []any{map[string]string{"uuid": "{p1}", "key": "CORE", "name": "Core services"}}})
		case p == "/repositories/acme":
			if q.Get("page") == "" {
				if q.Get("q") != `name ~ "a\"p" AND project.key = "CORE"` && q.Get("q") != "" {
					t.Errorf("BBQL: %q", q.Get("q"))
				}
				if q.Get("pagelen") != "1" && q.Get("pagelen") != "100" {
					t.Errorf("pagelen: %s", q.Get("pagelen"))
				}
				next := f.URL + "/repositories/acme?" + q.Encode() + "&page=2"
				jsonResp(w, map[string]any{"values": []any{repo}, "next": next})
				return
			}
			jsonResp(w, map[string]any{"values": []any{}})
		case p == "/repositories/beta":
			jsonResp(w, map[string]any{"values": []any{}})
		case p == "/repositories/acme/api" || p == "/repositories/acme/%7Br-1%7D":
			jsonResp(w, repo)
		case p == "/repositories/acme/missing":
			status(w, 404)
		case p == "/repositories/acme/private":
			status(w, 403)
		case p == "/repositories/acme/api/refs/branches":
			jsonResp(w, map[string]any{"values": []any{
				map[string]any{"name": "main", "target": map[string]string{"hash": "h1"}},
				map[string]any{"name": "dev", "target": map[string]string{"hash": "h2"}}}})
		case p == "/repositories/acme/%7Br-1%7D/refs/branches":
			jsonResp(w, map[string]any{"values": []any{map[string]any{"name": "main", "target": map[string]string{"hash": "h1"}}}})
		case p == "/repositories/acme/%7Br-1%7D/commits/main" || p == "/repositories/acme/api/commits/main":
			jsonResp(w, map[string]any{"values": []any{map[string]any{"hash": "h1", "message": "Ship it\n", "date": "2026-03-01T10:00:00+00:00",
				"author": map[string]any{"raw": "Ada <ada@example.com>"}}}})
		case p == "/user/permissions/repositories":
			if q.Get("q") != `repository.full_name = "acme/api"` {
				t.Errorf("permission q: %q", q.Get("q"))
			}
			jsonResp(w, map[string]any{"values": []any{map[string]string{"permission": "admin"}}})
		default:
			status(w, 404)
		}
	})
}

func TestBitbucket(t *testing.T) {
	ctx := context.Background()
	srv := bitbucketServer(t)
	defer func(old string) { bitbucketWebBase = old }(bitbucketWebBase)
	bitbucketWebBase = srv.URL
	apiTok, _ := json.Marshal(APITokenCredential{Username: "ada@example.com", Token: "atat"})

	for _, tc := range []struct {
		name      string
		cfg       Config
		cloneUser string
		cloneTok  string
		perm      string
		orgs      int
	}{
		{name: "access token", cfg: Config{AuthType: AuthPAT, Secret: []byte("bbat"), Owner: "acme"}, cloneUser: "x-token-auth", cloneTok: "bbat", perm: "unknown", orgs: 1},
		{name: "api token", cfg: Config{AuthType: AuthAPIToken, Secret: apiTok}, cloneUser: "ada_l", cloneTok: "atat", perm: "admin", orgs: 2},
		{name: "oauth", cfg: Config{AuthType: AuthOAuth, OAuth: &OAuthApp{Provider: Bitbucket, ClientID: "bcid", ClientSecret: []byte("bsec")},
			Secret: []byte(`{"access_token":"expired","refresh_token":"r1","expires_at":"2020-01-01T00:00:00Z"}`), Tokens: &memStore{
				tok: OAuthToken{AccessToken: "expired", RefreshToken: "r1", ExpiresAt: future(-time.Hour)}}},
			cloneUser: "x-token-auth", cloneTok: "new", perm: "admin", orgs: 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			cfg.Provider, cfg.HTTP = Bitbucket, srv.Client()
			cfg.BaseURL = srv.URL
			c := mustNew(t, cfg)
			if _, err := c.Check(ctx); err != nil {
				t.Fatalf("check: %v", err)
			}
			orgs, err := c.ListOrganizations(ctx)
			if err != nil || len(orgs) != tc.orgs || orgs[0].Name != "acme" || orgs[0].Kind != "workspace" {
				t.Fatalf("orgs: %+v %v", orgs, err)
			}
			projects, err := c.ListProjects(ctx, "acme")
			if err != nil || len(projects) != 1 || projects[0].Name != "CORE" || projects[0].DisplayName != "Core services" {
				t.Fatalf("projects: %+v %v", projects, err)
			}
			q := RepoQuery{Organization: "acme", Project: "CORE", Search: `a"p`, PageSize: 1}
			p1, err := c.ListRepositoriesPage(ctx, q)
			if err != nil || len(p1.Items) != 1 || p1.NextPageToken == "" {
				t.Fatalf("page 1: %+v %v", p1, err)
			}
			r := p1.Items[0]
			if r.ExternalID != "{r-1}" || r.FullName != "acme/api" || r.Name != "api" || r.Project != "CORE" || r.Organization != "acme" ||
				r.CloneURL != "https://bitbucket.org/acme/api.git" || r.Visibility != "private" || r.SizeBytes != 2048 || r.DefaultBranch != "main" {
				t.Errorf("mapping: %+v", r)
			}
			q.PageToken = p1.NextPageToken
			if p2, err := c.ListRepositoriesPage(ctx, q); err != nil || len(p2.Items) != 0 || p2.NextPageToken != "" {
				t.Fatalf("page 2: %+v %v", p2, err)
			}
			assertInvalidTokens(t, c, Bitbucket, RepoQuery{Organization: "acme", PageSize: 1}, srv.URL)

			if _, err := c.GetRepository(ctx, RepoRef{FullName: "acme/missing"}); !errors.Is(err, ErrNotFound) {
				t.Errorf("404: %v", err)
			}
			if _, err := c.GetRepository(ctx, RepoRef{FullName: "acme/private"}); !errors.Is(err, ErrForbidden) {
				t.Errorf("403: %v", err)
			}
			got, err := c.GetRepository(ctx, RepoRef{ExternalID: "{r-1}", Organization: "acme"})
			if err != nil || got.FullName != "acme/api" {
				t.Fatalf("get by uuid: %+v %v", got, err)
			}
			d, err := Details(ctx, c, RepoRef{FullName: "acme/api"})
			if err != nil || d.Permission != tc.perm || len(d.Branches) != 1 || !d.Branches[0].Default || d.LatestCommit == nil ||
				d.LatestCommit.Author != "Ada" || d.LatestCommit.Message != "Ship it" {
				t.Fatalf("details: %+v %v", d, err)
			}
			heads, err := c.ListBranchHeads(ctx, RepoRef{FullName: "acme/api"})
			if err != nil || len(heads) != 2 || !heads[0].Default || heads[1].CommitSHA != "h2" {
				t.Fatalf("branches: %+v %v", heads, err)
			}
			cred, err := c.CloneCredential(ctx)
			if err != nil || cred.Username != tc.cloneUser || cred.Token != tc.cloneTok {
				t.Errorf("clone: %+v %v", cred, err)
			}
			if err := c.Revoke(ctx); err != nil {
				t.Errorf("revoke: %v", err)
			}
		})
	}

	// Access token without workspace cannot discover organizations.
	c := mustNew(t, Config{Provider: Bitbucket, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("bbat"), HTTP: srv.Client()})
	if _, err := c.ListOrganizations(ctx); !errors.Is(err, ErrNotSupported) {
		t.Errorf("want ErrNotSupported, got %v", err)
	}
	// Multiple workspaces and no organization: the caller must choose.
	c = mustNew(t, Config{Provider: Bitbucket, BaseURL: srv.URL, AuthType: AuthAPIToken, Secret: apiTok, HTTP: srv.Client()})
	if _, err := c.ListRepositoriesPage(ctx, RepoQuery{}); err == nil {
		t.Error("expected a workspace to be required")
	}
	all, err := c.ListRepositories(ctx)
	if err != nil || len(all) != 1 {
		t.Fatalf("list all across workspaces: %v %v", all, err)
	}
	// Refresh rejected.
	store := &memStore{tok: OAuthToken{AccessToken: "x", RefreshToken: "bad", ExpiresAt: future(-time.Hour)}}
	c = mustNew(t, Config{Provider: Bitbucket, BaseURL: srv.URL, AuthType: AuthOAuth, Secret: tokenJSON(t, store.tok), Tokens: store,
		OAuth: &OAuthApp{Provider: Bitbucket, ClientID: "bcid", ClientSecret: []byte("bsec")}, HTTP: srv.Client()})
	if _, err := c.Check(ctx); !errors.Is(err, ErrTokenExpired) {
		t.Errorf("want ErrTokenExpired, got %v", err)
	}
	if _, err := New(Config{Provider: Bitbucket, BaseURL: srv.URL, AuthType: AuthAPIToken, Secret: []byte(`{"username":"a"}`), HTTP: srv.Client()}); err == nil {
		t.Error("API token without token accepted")
	}
}
