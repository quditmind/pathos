package scm

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOAuthAuthorizeURLs(t *testing.T) {
	defer func(a, b string) { entraLoginBase, bitbucketWebBase = a, b }(entraLoginBase, bitbucketWebBase)
	entraLoginBase, bitbucketWebBase = "https://login.microsoftonline.com", "https://bitbucket.org"
	verifier, challenge, err := NewPKCE()
	if err != nil || len(verifier) < 43 || challenge != PKCEChallenge(verifier) || challenge == verifier {
		t.Fatalf("PKCE: %q %q %v", verifier, challenge, err)
	}
	redirect := "https://pathos.example/api/v1/scm-oauth/callback"
	for _, tc := range []struct {
		provider string
		app      OAuthApp
		prefix   string
		scope    string
		pkce     bool
	}{
		{GitHub, OAuthApp{ClientID: "c"}, "https://github.com/login/oauth/authorize?", "repo read:org", false},
		{GitHubEnterprise, OAuthApp{ClientID: "c", BaseURL: "https://ghe.example.com/api/v3"}, "https://ghe.example.com/login/oauth/authorize?", "repo read:org", false},
		{GitLab, OAuthApp{ClientID: "c"}, "https://gitlab.com/oauth/authorize?", "read_api read_repository", true},
		{GitLab, OAuthApp{ClientID: "c", BaseURL: "https://git.example.com/gitlab/", Scopes: "read_api"}, "https://git.example.com/gitlab/oauth/authorize?", "read_api", true},
		{Bitbucket, OAuthApp{ClientID: "c"}, "https://bitbucket.org/site/oauth2/authorize?", "", false},
		{AzureDevOps, OAuthApp{ClientID: "c", TenantID: "contoso.onmicrosoft.com"}, "https://login.microsoftonline.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize?",
			"499b84ac-1321-427f-aa17-267ca6975798/.default offline_access", true},
		{AzureDevOps, OAuthApp{ClientID: "c"}, "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize?",
			"499b84ac-1321-427f-aa17-267ca6975798/.default offline_access", true},
	} {
		ex, err := OAuthFor(tc.provider)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := ex.AuthorizeURL(tc.app, redirect, "st4te", challenge)
		if err != nil {
			t.Fatalf("%s: %v", tc.provider, err)
		}
		if !strings.HasPrefix(raw, tc.prefix) {
			t.Errorf("%s: %s", tc.provider, raw)
		}
		u, _ := url.Parse(raw)
		q := u.Query()
		if q.Get("client_id") != "c" || q.Get("state") != "st4te" || q.Get("redirect_uri") != redirect || q.Get("scope") != tc.scope {
			t.Errorf("%s: query %v", tc.provider, q)
		}
		if got := q.Get("code_challenge"); (got == challenge) != tc.pkce || (tc.pkce && q.Get("code_challenge_method") != "S256") {
			t.Errorf("%s: PKCE %v", tc.provider, q)
		}
		if _, err := ex.AuthorizeURL(OAuthApp{ClientID: "c"}, redirect, "", challenge); err == nil {
			t.Errorf("%s: missing state accepted", tc.provider)
		}
	}
	if ex, _ := OAuthFor(GitLab); ex != nil {
		if _, err := ex.AuthorizeURL(OAuthApp{ClientID: "c"}, redirect, "s", ""); err == nil {
			t.Error("GitLab without PKCE challenge accepted")
		}
	}
	if ex, _ := OAuthFor(AzureDevOps); ex != nil {
		if _, err := ex.AuthorizeURL(OAuthApp{ClientID: "c", TenantID: "a/b"}, redirect, "s", "x"); err == nil {
			t.Error("invalid tenant accepted")
		}
	}
	if _, err := OAuthFor(AzureDevOpsServer); err == nil {
		t.Error("Azure DevOps Server has no OAuth")
	}
	if _, err := (githubOAuth{}).AuthorizeURL(OAuthApp{ClientID: "c", BaseURL: "https://u:p@ghe.example.com"}, redirect, "s", ""); err == nil {
		t.Error("base URL with credentials accepted")
	}
}

func TestOAuthExchangeAndRefresh(t *testing.T) {
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form := r.Form
		ok := func(cond bool) {
			if !cond {
				t.Errorf("%s: unexpected form %v", r.URL.Path, form)
			}
		}
		switch r.URL.Path {
		case "/login/oauth/access_token": // GitHub
			ok(r.Header.Get("Accept") == "application/json" && form.Get("code_verifier") == "" && form.Get("client_secret") == "sec")
			if form.Get("code") == "bad" {
				jsonResp(w, map[string]string{"error": "bad_verification_code", "error_description": "secret-body-should-not-leak"})
				return
			}
			jsonResp(w, map[string]any{"access_token": "gho_1", "token_type": "bearer", "scope": "repo,read:org"})
		case "/gitlab/oauth/token":
			if form.Get("grant_type") == "authorization_code" {
				ok(form.Get("code_verifier") == "ver" && form.Get("redirect_uri") == "https://r" && form.Get("code") == "code")
			}
			jsonResp(w, map[string]any{"access_token": "gl_1", "refresh_token": "gl_r2", "expires_in": 7200})
		case "/site/oauth2/access_token": // Bitbucket
			u, p := basicOf(r)
			ok(u == "c" && p == "sec" && form.Get("client_secret") == "")
			jsonResp(w, map[string]any{"access_token": "bb_1", "refresh_token": "bb_r", "expires_in": "7200", "scopes": "repository"})
		case "/login/common/oauth2/v2.0/token": // Entra
			ok(form.Get("scope") == DefaultScopes(AzureDevOps) && form.Get("client_id") == "c")
			if form.Get("grant_type") == "authorization_code" {
				ok(form.Get("code_verifier") == "ver")
			}
			if form.Get("grant_type") == "refresh_token" {
				// Entra may omit a new refresh token; the old one is kept.
				jsonResp(w, map[string]any{"access_token": "aad_2", "expires_in": 3600})
				return
			}
			jsonResp(w, map[string]any{"access_token": "aad_1", "refresh_token": "aad_r", "expires_in": 3600})
		case "/fail/oauth/token":
			w.WriteHeader(503)
		default:
			w.WriteHeader(404)
		}
	})
	defer func(a, b string) { entraLoginBase, bitbucketWebBase = a, b }(entraLoginBase, bitbucketWebBase)
	entraLoginBase, bitbucketWebBase = srv.URL+"/login", srv.URL
	ctx, hc := context.Background(), srv.Client()
	sec := []byte("sec")
	start := time.Now()

	for _, tc := range []struct {
		provider string
		app      OAuthApp
		access   string
		refresh  string
		expires  bool
	}{
		{GitHubEnterprise, OAuthApp{ClientID: "c", ClientSecret: sec, BaseURL: srv.URL + "/api/v3"}, "gho_1", "", false},
		{GitLab, OAuthApp{ClientID: "c", ClientSecret: sec, BaseURL: srv.URL + "/gitlab"}, "gl_1", "gl_r2", true},
		{Bitbucket, OAuthApp{ClientID: "c", ClientSecret: sec}, "bb_1", "bb_r", true},
		{AzureDevOps, OAuthApp{ClientID: "c", ClientSecret: sec, TenantID: "common"}, "aad_1", "aad_r", true},
	} {
		ex, _ := OAuthFor(tc.provider)
		tok, err := ex.Exchange(ctx, hc, tc.app, "https://r", "code", "ver")
		if err != nil || tok.AccessToken != tc.access || tok.RefreshToken != tc.refresh || (tok.ExpiresAt != nil) != tc.expires {
			t.Fatalf("%s exchange: %+v %v", tc.provider, tok, err)
		}
		if tc.expires && (tok.ExpiresAt.Before(start.Add(time.Hour)) || tok.ExpiresAt.After(time.Now().Add(3*time.Hour))) {
			t.Errorf("%s: expires_at %v", tc.provider, tok.ExpiresAt)
		}
		if tc.refresh != "" {
			nt, err := ex.Refresh(ctx, hc, tc.app, tok)
			if err != nil || nt.AccessToken == "" || nt.RefreshToken == "" {
				t.Fatalf("%s refresh: %+v %v", tc.provider, nt, err)
			}
			if tc.provider == AzureDevOps && (nt.AccessToken != "aad_2" || nt.RefreshToken != "aad_r") {
				t.Errorf("entra refresh must keep the refresh token: %+v", nt)
			}
		}
	}
	gh, _ := OAuthFor(GitHub)
	_, err := gh.Exchange(ctx, hc, OAuthApp{ClientID: "c", ClientSecret: sec, BaseURL: srv.URL + "/api/v3"}, "https://r", "bad", "")
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "bad_verification_code" || !errors.Is(err, ErrAuth) {
		t.Fatalf("GitHub error with HTTP 200: %v", err)
	}
	assertNoLeak(t, err, "sec")
	gl, _ := OAuthFor(GitLab)
	_, err = gl.Refresh(ctx, hc, OAuthApp{ClientID: "c", BaseURL: srv.URL + "/fail"}, OAuthToken{RefreshToken: "r"})
	if !IsTransient(err) || errors.Is(err, ErrAuth) {
		t.Errorf("5xx from token endpoint must be transient: %v", err)
	}
}

func TestOAuthConcurrentRefreshUsesStoredToken(t *testing.T) {
	// Another process refreshed already: the stored token differs from the
	// one that failed and is valid, so no refresh request is made.
	refreshes := 0
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			refreshes++
			jsonResp(w, map[string]any{"access_token": "x"})
		case "/api/v4/user":
			if bearer(r) != "fresh" {
				status(w, 401)
				return
			}
			jsonResp(w, map[string]any{"username": "ada"})
		}
	})
	store := &memStore{tok: OAuthToken{AccessToken: "fresh", RefreshToken: "r2", ExpiresAt: future(time.Hour)}}
	stale := OAuthToken{AccessToken: "stale", RefreshToken: "r1", ExpiresAt: future(time.Hour)}
	c := mustNew(t, Config{Provider: GitLab, BaseURL: srv.URL, AuthType: AuthOAuth, Secret: tokenJSON(t, stale), Tokens: store,
		OAuth: &OAuthApp{ClientID: "c", BaseURL: srv.URL}, HTTP: srv.Client()})
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if refreshes != 0 || store.invoked != 1 {
		t.Errorf("refreshes=%d invoked=%d", refreshes, store.invoked)
	}
}

func TestProvidersCatalog(t *testing.T) {
	allowed := map[string]bool{"token": true, "private_key": true, "github_app_id": true, "github_installation_id": true, "username": true,
		"tenant_id": true, "client_id": true, "client_secret": true, "certificate_pem": true, "private_key_pem": true, "organizations": true}
	seen := map[string]bool{}
	for _, p := range Providers() {
		seen[p.Key] = true
		if len(p.AuthMethods) == 0 || p.Label == "" {
			t.Errorf("%s: incomplete", p.Key)
		}
		for _, m := range p.AuthMethods {
			if m.OAuth != (m.Key == AuthOAuth) || m.DocsURL == "" || !strings.HasPrefix(m.DocsURL, "https://") {
				t.Errorf("%s/%s: oauth flag or docs", p.Key, m.Key)
			}
			if m.OAuth && len(m.Fields) != 0 {
				t.Errorf("%s: OAuth methods take no secret fields", p.Key)
			}
			if m.OAuth {
				if _, err := OAuthFor(p.Key); err != nil {
					t.Errorf("%s: OAuth listed but not implemented", p.Key)
				}
			}
			for _, f := range m.Fields {
				if !allowed[f.Name] {
					t.Errorf("%s/%s: unknown field %q", p.Key, m.Key, f.Name)
				}
			}
			// Every listed method must be constructible by New.
			if _, ok := AuthMethodFor(p.Key, m.Key); !ok {
				t.Errorf("AuthMethodFor(%s, %s)", p.Key, m.Key)
			}
		}
	}
	for _, k := range []string{GitHub, GitHubEnterprise, GitLab, Bitbucket, AzureDevOps, AzureDevOpsServer} {
		if !seen[k] {
			t.Errorf("provider %s missing", k)
		}
	}
	if _, ok := AuthMethodFor(AzureDevOpsServer, AuthOAuth); ok {
		t.Error("Azure DevOps Server must not offer OAuth")
	}
}

func TestGitLabAndBitbucketWebhooks(t *testing.T) {
	secret := []byte("hook-secret")
	if VerifyGitLabToken(secret, "hook-secret") != nil {
		t.Error("valid GitLab token rejected")
	}
	for _, h := range []string{"", "hook-secre", "hook-secret ", "HOOK-SECRET"} {
		if VerifyGitLabToken(secret, h) == nil {
			t.Errorf("GitLab token %q accepted", h)
		}
	}
	if VerifyGitLabToken(nil, "") == nil {
		t.Error("empty secret must never verify")
	}

	ev, id, err := ParseGitLabEvent("Push Hook", []byte(`{"object_kind":"push","ref":"refs/heads/main","after":"abc","project_id":15,"project":{"id":15}}`))
	if err != nil || ev.Kind != "push" || ev.Ref != "main" || ev.CommitSHA != "abc" || id != "15" || ev.ExternalID != "15" {
		t.Errorf("gitlab push: %+v %q %v", ev, id, err)
	}
	ev, _, _ = ParseGitLabEvent("Push Hook", []byte(`{"ref":"refs/heads/old","after":"0000000000000000000000000000000000000000","project_id":15}`))
	if ev.Kind != "ignored" {
		t.Errorf("branch deletion should be ignored: %+v", ev)
	}
	ev, _, _ = ParseGitLabEvent("Merge Request Hook", []byte(`{"project":{"id":15},"object_attributes":{"iid":4,"action":"merge","state":"merged",
		"source_branch":"feat","target_branch":"main","merge_commit_sha":"m1","last_commit":{"id":"h1"}}}`))
	if ev.Kind != "merge" || ev.Ref != "main" || ev.CommitSHA != "m1" || ev.PullRequest != 4 {
		t.Errorf("gitlab merge: %+v", ev)
	}
	ev, _, _ = ParseGitLabEvent("Merge Request Hook", []byte(`{"project":{"id":15},"object_attributes":{"iid":4,"action":"update",
		"source_branch":"feat","target_branch":"main","last_commit":{"id":"h2"}}}`))
	if ev.Kind != "pull_request" || ev.Ref != "feat" || ev.CommitSHA != "h2" {
		t.Errorf("gitlab mr update: %+v", ev)
	}
	ev, _, _ = ParseGitLabEvent("Merge Request Hook", []byte(`{"project":{"id":15},"object_attributes":{"iid":4,"action":"close"}}`))
	if ev.Kind != "ignored" {
		t.Errorf("closed MR should be ignored: %+v", ev)
	}
	if _, _, err := ParseGitLabEvent("Push Hook", []byte("{")); err == nil {
		t.Error("invalid JSON accepted")
	}

	body := []byte(`{"repository":{"uuid":"{r-1}"},"push":{"changes":[{"new":{"type":"tag","name":"v1","target":{"hash":"t"}}},
		{"new":{"type":"branch","name":"main","target":{"hash":"b1"}}}]}}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if VerifyBitbucketSignature(secret, body, sig) != nil {
		t.Error("valid Bitbucket signature rejected")
	}
	if VerifyBitbucketSignature(secret, append(body, ' '), sig) == nil || VerifyBitbucketSignature(secret, body, "") == nil || VerifyBitbucketSignature(nil, body, sig) == nil {
		t.Error("invalid Bitbucket signature accepted")
	}
	ev, id, err = ParseBitbucketEvent("repo:push", body)
	if err != nil || ev.Kind != "push" || ev.Ref != "main" || ev.CommitSHA != "b1" || id != "{r-1}" {
		t.Errorf("bitbucket push: %+v %q %v", ev, id, err)
	}
	ev, _, _ = ParseBitbucketEvent("repo:push", []byte(`{"repository":{"uuid":"{r-1}"},"push":{"changes":[{"new":null,"old":{"type":"branch"}}]}}`))
	if ev.Kind != "ignored" {
		t.Errorf("branch deletion should be ignored: %+v", ev)
	}
	pr := `{"repository":{"uuid":"{r-1}"},"pullrequest":{"id":9,"state":"%s","source":{"branch":{"name":"feat"},"commit":{"hash":"s1"}},
		"destination":{"branch":{"name":"main"},"commit":{"hash":"d1"}},"merge_commit":{"hash":"m9"}}}`
	ev, _, _ = ParseBitbucketEvent("pullrequest:created", []byte(strings.Replace(pr, "%s", "OPEN", 1)))
	if ev.Kind != "pull_request" || ev.Ref != "feat" || ev.CommitSHA != "s1" || ev.PullRequest != 9 {
		t.Errorf("bitbucket pr: %+v", ev)
	}
	ev, _, _ = ParseBitbucketEvent("pullrequest:fulfilled", []byte(strings.Replace(pr, "%s", "MERGED", 1)))
	if ev.Kind != "merge" || ev.Ref != "main" || ev.CommitSHA != "m9" {
		t.Errorf("bitbucket merge: %+v", ev)
	}
	ev, _, _ = ParseBitbucketEvent("pullrequest:updated", []byte(strings.Replace(pr, "%s", "DECLINED", 1)))
	if ev.Kind != "ignored" {
		t.Errorf("declined PR should be ignored: %+v", ev)
	}
}
