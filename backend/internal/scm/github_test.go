package scm

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// githubAPI serves a small GitHub REST API under prefix for token tok.
func githubAPI(t *testing.T, prefix string, valid func(string) bool) *fake {
	return newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		p, ok := strings.CutPrefix(r.URL.Path, prefix)
		if !ok {
			status(w, 404)
			return
		}
		if !valid(bearer(r)) {
			status(w, 401)
			return
		}
		base := f.URL + prefix
		repoA := map[string]any{"id": 1, "full_name": "acme/api", "name": "api", "default_branch": "main", "private": true,
			"language": "Go", "size": 10, "owner": map[string]any{"login": "acme", "id": 50, "type": "Organization"},
			"permissions": map[string]bool{"admin": false, "push": true, "pull": true}}
		repoB := map[string]any{"id": 2, "full_name": "acme/web", "name": "web", "visibility": "internal", "archived": true,
			"owner": map[string]any{"login": "acme"}}
		switch {
		case p == "/user":
			jsonResp(w, map[string]any{"login": "octo", "id": 7})
		case p == "/user/orgs":
			jsonResp(w, []map[string]any{{"login": "acme", "id": 50}})
		case p == "/orgs/acme/repos" && r.URL.Query().Get("page") == "":
			if r.URL.Query().Get("per_page") != "1" {
				t.Errorf("per_page not passed: %s", r.URL.RawQuery)
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/repos?per_page=1&page=2>; rel="next"`, base))
			jsonResp(w, []any{repoA})
		case p == "/orgs/acme/repos":
			w.Header().Set("Link", `<https://evil.example/orgs/acme/repos?page=3>; rel="next"`)
			jsonResp(w, []any{repoB})
		case p == "/orgs/someone/repos":
			status(w, 404)
		case p == "/users/someone/repos":
			jsonResp(w, []any{map[string]any{"id": 3, "full_name": "someone/x", "name": "x", "owner": map[string]any{"login": "someone"}}})
		case p == "/user/repos":
			jsonResp(w, []any{repoA, repoB})
		case p == "/search/repositories":
			if q := r.URL.Query().Get("q"); q != "api in:name fork:true org:acme" {
				t.Errorf("search q = %q", q)
			}
			jsonResp(w, map[string]any{"total_count": 1, "items": []any{repoA}})
		case p == "/repositories/1" || p == "/repos/acme/api":
			jsonResp(w, repoA)
		case p == "/repos/acme/missing":
			status(w, 404)
		case p == "/repos/acme/forbidden":
			status(w, 403)
		case p == "/repos/acme/limited":
			w.Header().Set("X-RateLimit-Remaining", "0")
			status(w, 403)
		case p == "/repos/acme/secondary":
			w.Header().Set("Retry-After", "60")
			status(w, 403)
		case p == "/repos/acme/broken":
			status(w, 502)
		case p == "/repos/acme/api/branches":
			jsonResp(w, []map[string]any{{"name": "main", "commit": map[string]string{"sha": "aaa"}}, {"name": "dev", "commit": map[string]string{"sha": "bbb"}}})
		case p == "/repos/acme/api/commits/main" || p == "/repos/acme/api/commits/feature/x":
			jsonResp(w, map[string]any{"sha": "aaa", "commit": map[string]any{"message": "Fix bug\n\nlong body",
				"author": map[string]any{"name": "Ada", "date": "2026-01-02T03:04:05Z"}, "committer": map[string]any{"date": "2026-01-02T03:04:06Z"}}})
		case p == "/repos/acme/api/languages":
			jsonResp(w, map[string]int64{"Go": 1000, "Shell": 20})
		default:
			status(w, 404)
		}
	})
}

func TestGitHubDiscoveryPAT(t *testing.T) {
	srv := githubAPI(t, "", func(tok string) bool { return tok == "ghp_x" })
	c := mustNew(t, Config{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("ghp_x"), HTTP: srv.Client()})
	ctx := context.Background()

	orgs, err := c.ListOrganizations(ctx)
	if err != nil || len(orgs) != 2 || orgs[0].Name != "octo" || orgs[0].Kind != "user" || orgs[1].Name != "acme" || orgs[1].Kind != "organization" {
		t.Fatalf("orgs: %+v %v", orgs, err)
	}
	if _, err := c.ListProjects(ctx, "acme"); !errors.Is(err, ErrNotSupported) {
		t.Errorf("projects: want ErrNotSupported, got %v", err)
	}

	// Pagination with an opaque token; a cross-host next link ends paging.
	q := RepoQuery{Organization: "acme", PageSize: 1}
	p1, err := c.ListRepositoriesPage(ctx, q)
	if err != nil || len(p1.Items) != 1 || p1.Items[0].FullName != "acme/api" || p1.NextPageToken == "" {
		t.Fatalf("page 1: %+v %v", p1, err)
	}
	if strings.Contains(p1.NextPageToken, "http") {
		t.Error("page token should be opaque")
	}
	r := p1.Items[0]
	if r.ExternalID != "1" || r.Organization != "acme" || r.SizeBytes != 10240 || r.Language != "Go" || r.Visibility != "private" {
		t.Errorf("mapping: %+v", r)
	}
	q.PageToken = p1.NextPageToken
	p2, err := c.ListRepositoriesPage(ctx, q)
	if err != nil || len(p2.Items) != 1 || p2.Items[0].FullName != "acme/web" || p2.NextPageToken != "" {
		t.Fatalf("page 2: %+v %v", p2, err)
	}
	assertInvalidTokens(t, c, GitHub, RepoQuery{Organization: "acme", PageSize: 1}, srv.URL)

	// User account fallback.
	pu, err := c.ListRepositoriesPage(ctx, RepoQuery{Organization: "someone"})
	if err != nil || len(pu.Items) != 1 || pu.Items[0].FullName != "someone/x" {
		t.Fatalf("user fallback: %+v %v", pu, err)
	}
	// Organization + search uses the search API.
	ps, err := c.ListRepositoriesPage(ctx, RepoQuery{Organization: "acme", Search: "api"})
	if err != nil || len(ps.Items) != 1 || ps.Items[0].Name != "api" {
		t.Fatalf("search: %+v %v", ps, err)
	}
	// No organization: client-side filter.
	pa, err := c.ListRepositoriesPage(ctx, RepoQuery{Search: "WEB"})
	if err != nil || len(pa.Items) != 1 || pa.Items[0].Name != "web" {
		t.Fatalf("client search: %+v %v", pa, err)
	}

	// GetRepository and error mapping.
	got, err := c.GetRepository(ctx, RepoRef{ExternalID: "1"})
	if err != nil || got.FullName != "acme/api" {
		t.Fatalf("get: %+v %v", got, err)
	}
	for name, want := range map[string]error{"missing": ErrNotFound, "forbidden": ErrForbidden, "limited": ErrRateLimited, "secondary": ErrRateLimited} {
		_, err := c.GetRepository(ctx, RepoRef{FullName: "acme/" + name})
		if !errors.Is(err, want) {
			t.Errorf("%s: want %v, got %v", name, want, err)
		}
		assertNoLeak(t, err, "ghp_x")
	}
	if _, err := c.GetRepository(ctx, RepoRef{FullName: "acme/limited"}); !IsTransient(err) {
		t.Error("rate limit must be transient")
	}
	if _, err := c.GetRepository(ctx, RepoRef{FullName: "acme/broken"}); !IsTransient(err) || errors.Is(err, ErrAuth) {
		t.Errorf("502 must be transient: %v", err)
	}
	if _, err := c.GetRepository(ctx, RepoRef{FullName: "acme/forbidden"}); IsTransient(err) {
		t.Error("403 must not be transient")
	}
	if _, err := c.GetRepository(ctx, RepoRef{FullName: "nope"}); err == nil {
		t.Error("invalid name accepted")
	}

	br, err := c.ListBranchHeads(ctx, RepoRef{ExternalID: "1"})
	if err != nil || len(br) != 2 || !br[0].Default || br[1].Default || br[0].CommitSHA != "aaa" {
		t.Fatalf("branches: %+v %v", br, err)
	}
	cm, err := c.LatestCommit(ctx, RepoRef{FullName: "acme/api"}, "feature/x")
	if err != nil || cm.SHA != "aaa" || cm.Message != "Fix bug" || cm.Author != "Ada" || cm.CommittedAt == nil || cm.CommittedAt.Second() != 6 {
		t.Fatalf("commit: %+v %v", cm, err)
	}
	langs, err := c.Languages(ctx, RepoRef{FullName: "acme/api"})
	if err != nil || langs["Go"] != 1000 {
		t.Fatalf("languages: %v %v", langs, err)
	}
	d, err := Details(ctx, c, RepoRef{ExternalID: "1"})
	if err != nil || d.Permission != "write" || d.LatestCommit == nil || len(d.Branches) != 2 || d.Languages["Shell"] != 20 {
		t.Fatalf("details: %+v %v", d, err)
	}
	if _, err := Details(ctx, c, RepoRef{FullName: "acme/missing"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("details missing: %v", err)
	}
	cred, err := c.CloneCredential(ctx)
	if err != nil || cred.Username != "x-access-token" || cred.Token != "ghp_x" || cred.ExpiresAt != nil {
		t.Errorf("clone: %+v %v", cred, err)
	}
	if err := c.Revoke(ctx); err != nil {
		t.Errorf("PAT revoke must be a no-op: %v", err)
	}
}

func TestGitHubAppDiscoveryAndCache(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/5/access_tokens":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_1", "expires_at": time.Now().Add(time.Hour)})
		case "/installation/repositories":
			if bearer(r) != "ghs_1" {
				status(w, 401)
				return
			}
			jsonResp(w, map[string]any{"total_count": 2, "repositories": []any{
				map[string]any{"id": 1, "full_name": "acme/api", "name": "api", "owner": map[string]any{"login": "acme", "id": 9, "type": "Organization"}},
				map[string]any{"id": 2, "full_name": "acme/web", "name": "web", "owner": map[string]any{"login": "acme", "id": 9, "type": "Organization"}},
			}})
		default:
			status(w, 404)
		}
	})
	cfg := Config{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthGitHubApp, Secret: pemKey, AppID: 3, InstallationID: 5, HTTP: srv.Client()}
	c := mustNew(t, cfg)
	ctx := context.Background()
	orgs, err := c.ListOrganizations(ctx)
	if err != nil || len(orgs) != 1 || orgs[0].Name != "acme" || orgs[0].ID != "9" {
		t.Fatalf("orgs: %+v %v", orgs, err)
	}
	p, err := c.ListRepositoriesPage(ctx, RepoQuery{Organization: "acme", Search: "we"})
	if err != nil || len(p.Items) != 1 || p.Items[0].Name != "web" {
		t.Fatalf("app page: %+v %v", p, err)
	}
	// A second client for the same app/installation/key shares the token.
	c2 := mustNew(t, cfg)
	cred, err := c2.CloneCredential(ctx)
	if err != nil || cred.Token != "ghs_1" || cred.ExpiresAt == nil {
		t.Fatalf("clone: %+v %v", cred, err)
	}
	if n := srv.count("POST /app/installations/5/access_tokens"); n != 1 {
		t.Errorf("installation token must be cached process-wide, got %d token requests", n)
	}
}

func TestGitHubOAuthRefresh(t *testing.T) {
	var refreshForms []string
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			if r.Header.Get("Accept") != "application/json" {
				t.Error("GitHub token endpoint needs Accept: application/json")
			}
			_ = r.ParseForm()
			refreshForms = append(refreshForms, r.Form.Encode())
			if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("client_id") != "cid" || r.Form.Get("client_secret") != "csecret" {
				t.Errorf("refresh form: %v", r.Form)
			}
			switch r.Form.Get("refresh_token") {
			case "r1":
				jsonResp(w, map[string]any{"access_token": "new", "refresh_token": "r2", "expires_in": 28800, "token_type": "bearer"})
			default: // GitHub reports errors with HTTP 200
				jsonResp(w, map[string]any{"error": "bad_refresh_token", "error_description": "secret-body-should-not-leak"})
			}
		case "/api/v3/user":
			if bearer(r) != "new" {
				status(w, 401)
				return
			}
			jsonResp(w, map[string]any{"login": "octo"})
		case "/api/v3/applications/cid/token":
			u, p := basicOf(r)
			body, _ := io.ReadAll(r.Body)
			if r.Method != http.MethodDelete || u != "cid" || p != "csecret" || !strings.Contains(string(body), `"access_token":"new"`) {
				t.Errorf("revoke request: %s %s:%s %s", r.Method, u, p, body)
			}
			w.WriteHeader(204)
		default:
			status(w, 404)
		}
	})
	app := &OAuthApp{Provider: GitHubEnterprise, BaseURL: srv.URL + "/api/v3", ClientID: "cid", ClientSecret: []byte("csecret")}
	ctx := context.Background()
	newClient := func(tok OAuthToken, store TokenStore) FullClient {
		return mustNew(t, Config{Provider: GitHubEnterprise, BaseURL: srv.URL + "/api/v3", AuthType: AuthOAuth,
			Secret: tokenJSON(t, tok), OAuth: app, Tokens: store, HTTP: srv.Client()})
	}

	// 401 → one refresh through the store → retry succeeds.
	store := &memStore{tok: OAuthToken{AccessToken: "old", RefreshToken: "r1"}}
	c := newClient(store.tok, store)
	if id, err := c.Check(ctx); err != nil || !strings.Contains(id, "octo") {
		t.Fatalf("check after refresh: %q %v", id, err)
	}
	if store.tok.AccessToken != "new" || store.tok.RefreshToken != "r2" || store.tok.ExpiresAt == nil || store.calls != 1 {
		t.Fatalf("store not updated: %+v calls=%d", store.tok, store.calls)
	}
	if _, err := c.Check(ctx); err != nil || store.invoked != 1 {
		t.Errorf("refreshed token should be reused: %v invoked=%d", err, store.invoked)
	}
	if err := c.Revoke(ctx); err != nil {
		t.Errorf("revoke: %v", err)
	}

	// Proactive refresh of an expired token (no 401 needed).
	store = &memStore{tok: OAuthToken{AccessToken: "stale", RefreshToken: "r1", ExpiresAt: future(-time.Minute)}}
	if _, err := newClient(store.tok, store).Check(ctx); err != nil || store.tok.AccessToken != "new" {
		t.Fatalf("proactive refresh: %v %+v", err, store.tok)
	}
	if n := srv.count("GET /api/v3/user"); n != 4 {
		t.Errorf("proactive refresh should avoid a 401 round trip; /user calls = %d", n)
	}

	// Refresh rejected → ErrTokenExpired (and ErrAuth), no body in message.
	store = &memStore{tok: OAuthToken{AccessToken: "old", RefreshToken: "rt-zz9"}}
	_, err := newClient(store.tok, store).Check(ctx)
	if !errors.Is(err, ErrTokenExpired) || !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrTokenExpired, got %v", err)
	}
	assertNoLeak(t, err, "rt-zz9", "old")

	// Without a refresh token a 401 means the authorization is gone.
	store = &memStore{tok: OAuthToken{AccessToken: "old"}}
	if _, err := newClient(store.tok, store).Check(ctx); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("401 without refresh token: %v", err)
	}
	// No store (tests, one-off checks): token used as is; expired and not
	// refreshable → ErrTokenExpired before any request.
	if _, err := newClient(OAuthToken{AccessToken: "new"}, nil).Check(ctx); err != nil {
		t.Fatalf("nil store: %v", err)
	}
	if _, err := newClient(OAuthToken{AccessToken: "x", ExpiresAt: future(-time.Hour)}, nil).Check(ctx); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired: %v", err)
	}
	if len(refreshForms) != 3 {
		t.Errorf("refresh calls: %d", len(refreshForms))
	}
	if _, err := New(Config{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthOAuth, Secret: []byte("{"), HTTP: srv.Client()}); err == nil {
		t.Error("invalid stored token accepted")
	}
}

func TestIsTransient(t *testing.T) {
	cases := map[error]bool{
		nil:                                false,
		ErrRateLimited:                     true,
		&StatusError{Code: 503, Host: "x"}: true,
		&StatusError{Code: 404, kind: ErrNotFound}:      false,
		&transportError{host: "x", err: io.EOF}:         true,
		context.DeadlineExceeded:                        true,
		context.Canceled:                                false,
		ErrAuth:                                         false,
		fmt.Errorf("wrap: %w", ErrBlockedAddress):       false,
		&transportError{err: ErrBlockedAddress}:         false,
		fmt.Errorf("x: %w", io.ErrUnexpectedEOF):        true,
		&OAuthError{Code: "invalid_grant", Status: 400}: false,
	}
	for err, want := range cases {
		if got := IsTransient(err); got != want {
			t.Errorf("IsTransient(%v) = %v, want %v", err, got, want)
		}
	}
}

// Workers get an installation token limited to the scanned repository with
// contents:read, not the installation-wide cached token.
func TestGitHubAppRepoCloneCredentialIsScoped(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	var bodies []map[string]any
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app/installations/7/access_tokens" {
			status(w, 404)
			return
		}
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		bodies = append(bodies, b)
		tok := "ghs_wide"
		if b != nil {
			tok = "ghs_scoped"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"token": tok, "expires_at": time.Now().Add(time.Hour)})
	})
	c := mustNew(t, Config{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthGitHubApp, Secret: pemKey, AppID: 3, InstallationID: 7, HTTP: srv.Client()})
	rc, ok := c.(RepoCloner)
	if !ok {
		t.Fatal("the GitHub client must implement RepoCloner")
	}
	cred, err := rc.RepoCloneCredential(context.Background(), "acme/api")
	if err != nil || cred.Token != "ghs_scoped" || cred.Username != "x-access-token" || cred.ExpiresAt == nil {
		t.Fatalf("scoped clone: %+v %v", cred, err)
	}
	if len(bodies) != 1 {
		t.Fatalf("want one token request, got %d", len(bodies))
	}
	repos, _ := bodies[0]["repositories"].([]any)
	perms, _ := bodies[0]["permissions"].(map[string]any)
	if len(repos) != 1 || repos[0] != "api" || len(perms) != 1 || perms["contents"] != "read" {
		t.Fatalf("token request not scoped to one repository with contents:read: %v", bodies[0])
	}
}

// PAT connections keep their credential (no scoping is possible).
func TestGitHubPATRepoCloneCredentialFallsBack(t *testing.T) {
	c := mustNew(t, Config{Provider: GitHub, BaseURL: "https://api.github.com", AuthType: AuthPAT, Secret: []byte("ghp_x"), HTTP: http.DefaultClient})
	cred, err := c.(RepoCloner).RepoCloneCredential(context.Background(), "acme/api")
	if err != nil || cred.Token != "ghp_x" {
		t.Fatalf("PAT fallback: %+v %v", cred, err)
	}
}
