package scm

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestNetPolicy(t *testing.T) {
	strict := NetPolicy{}
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "10.1.2.3", "192.168.1.1", "::1", "fd00:ec2::254", "0.0.0.0", "100.64.0.1", "::ffff:127.0.0.1"} {
		if strict.Allowed(netip.MustParseAddr(ip)) {
			t.Errorf("%s must be blocked by default", ip)
		}
	}
	if !strict.Allowed(netip.MustParseAddr("140.82.112.3")) {
		t.Error("public address must be allowed")
	}
	private := NetPolicy{AllowPrivate: true}
	if !private.Allowed(netip.MustParseAddr("10.1.2.3")) {
		t.Error("AllowPrivate should permit RFC 1918")
	}
	if private.Allowed(netip.MustParseAddr("169.254.169.254")) || private.Allowed(netip.MustParseAddr("127.0.0.1")) {
		t.Error("metadata and loopback must stay blocked even with AllowPrivate")
	}

	for _, u := range []string{"http://github.example.com", "https://user:pw@ghe.example.com", "https://169.254.169.254/", "ftp://x", "https://x/?a=1", "not a url"} {
		if _, err := strict.ValidateBaseURL(u); err == nil {
			t.Errorf("%q should be rejected", u)
		}
	}
	if _, err := strict.ValidateBaseURL("https://ghe.example.com/api/v3"); err != nil {
		t.Error(err)
	}
	if _, err := (NetPolicy{AllowHTTP: true}).ValidateBaseURL("http://ado.local/tfs"); err != nil {
		t.Error("AllowHTTP should permit http")
	}
}

func TestSafeClientBlocksAtDialTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	_, err := NetPolicy{}.Client().Get(srv.URL) // 127.0.0.1
	if err == nil || !errors.Is(err, ErrBlockedAddress) {
		t.Fatalf("dial to loopback must be blocked, got %v", err)
	}
}

func jsonResp(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestGitHubPATPagination(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer ghp_test" {
			w.WriteHeader(401)
			return
		}
		switch {
		case r.URL.Path == "/user":
			jsonResp(w, map[string]string{"login": "octo"})
		case r.URL.Path == "/orgs/acme/repos" && r.URL.Query().Get("page") == "":
			w.Header().Set("Link", fmt.Sprintf(`<%s/orgs/acme/repos?page=2>; rel="next"`, srv.URL))
			jsonResp(w, []map[string]any{{"id": 1, "full_name": "acme/a", "name": "a", "default_branch": "main", "private": true, "language": "Go"}})
		case r.URL.Path == "/orgs/acme/repos":
			// A next link pointing at another host must not be followed.
			w.Header().Set("Link", `<https://evil.example/steal>; rel="next"`)
			jsonResp(w, []map[string]any{{"id": 2, "full_name": "acme/b", "name": "b", "visibility": "internal", "archived": true}})
		case r.URL.Path == "/repos/acme/a/branches":
			jsonResp(w, []map[string]string{{"name": "main"}, {"name": "dev"}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c, err := New(Config{Provider: GitHub, BaseURL: srv.URL, AuthType: "pat", Owner: "acme", Secret: []byte("ghp_test"), HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if id, err := c.Check(ctx); err != nil || !strings.Contains(id, "octo") {
		t.Fatalf("check: %q %v", id, err)
	}
	repos, err := c.ListRepositories(ctx)
	if err != nil || len(repos) != 2 {
		t.Fatalf("want 2 repos across pages, got %d %v", len(repos), err)
	}
	if repos[0].ExternalID != "1" || repos[0].Visibility != "private" || repos[0].Language != "Go" {
		t.Errorf("unexpected mapping %+v", repos[0])
	}
	if repos[1].Visibility != "internal" || !repos[1].Archived {
		t.Errorf("unexpected mapping %+v", repos[1])
	}
	br, err := c.ListBranches(ctx, repos[0])
	if err != nil || len(br) != 2 {
		t.Fatalf("branches: %v %v", br, err)
	}

	bad, _ := New(Config{Provider: GitHub, BaseURL: srv.URL, AuthType: "pat", Secret: []byte("wrong"), HTTP: srv.Client()})
	if _, err := bad.Check(ctx); !errors.Is(err, ErrAuth) {
		t.Fatalf("want ErrAuth, got %v", err)
	}
}

func TestGitHubApp(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tokenCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/42/access_tokens":
			tokenCalls++
			jwt := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			parts := strings.Split(jwt, ".")
			if len(parts) != 3 {
				w.WriteHeader(401)
				return
			}
			claims, _ := base64.RawURLEncoding.DecodeString(parts[1])
			if !strings.Contains(string(claims), `"iss":"7"`) {
				w.WriteHeader(401)
				return
			}
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			if rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, sum[:], sig) != nil {
				w.WriteHeader(401)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(201)
			_ = json.NewEncoder(w).Encode(map[string]any{"token": "ghs_inst", "expires_at": "2099-01-01T00:00:00Z"})
		case "/installation/repositories":
			if r.Header.Get("Authorization") != "Bearer ghs_inst" {
				w.WriteHeader(401)
				return
			}
			jsonResp(w, map[string]any{"total_count": 1, "repositories": []map[string]any{{"id": 9, "full_name": "acme/app", "name": "app"}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c, err := New(Config{Provider: GitHub, BaseURL: srv.URL, AuthType: "github_app", Secret: pemKey, AppID: 7, InstallationID: 42, HTTP: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	repos, err := c.ListRepositories(context.Background())
	if err != nil || len(repos) != 1 || repos[0].FullName != "acme/app" {
		t.Fatalf("%v %v", repos, err)
	}
	if _, err := c.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if tokenCalls != 1 {
		t.Errorf("installation token should be cached, got %d token calls", tokenCalls)
	}
	if _, err := New(Config{Provider: GitHub, BaseURL: srv.URL, AuthType: "github_app", Secret: []byte("nope"), AppID: 1, InstallationID: 1, HTTP: srv.Client()}); err == nil {
		t.Error("invalid PEM must be rejected")
	}
}

func TestAzureDevOps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api-version") != "7.1" {
			w.WriteHeader(400)
			return
		}
		user, pass, _ := r.BasicAuth()
		if user != "" || pass != "adopat" {
			// Azure DevOps answers with an HTML sign-in page.
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(203)
			return
		}
		switch r.URL.Path {
		case "/_apis/projects":
			jsonResp(w, map[string]any{"count": 1})
		case "/_apis/git/repositories":
			jsonResp(w, map[string]any{"value": []map[string]any{{"id": "guid-1", "name": "api", "remoteUrl": "https://x/_git/api",
				"webUrl": "https://x/_git/api", "defaultBranch": "refs/heads/main", "project": map[string]string{"name": "Shop", "visibility": "private"}}}})
		case "/Shop/_apis/git/repositories/guid-1/refs":
			jsonResp(w, map[string]any{"value": []map[string]string{{"name": "refs/heads/main"}, {"name": "refs/heads/release"}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	c, _ := New(Config{Provider: AzureDevOps, BaseURL: srv.URL, AuthType: "pat", Secret: []byte("adopat"), HTTP: srv.Client()})
	ctx := context.Background()
	if _, err := c.Check(ctx); err != nil {
		t.Fatal(err)
	}
	repos, err := c.ListRepositories(ctx)
	if err != nil || len(repos) != 1 || repos[0].FullName != "Shop/api" || repos[0].DefaultBranch != "main" {
		t.Fatalf("%+v %v", repos, err)
	}
	br, err := c.ListBranches(ctx, repos[0])
	if err != nil || strings.Join(br, ",") != "main,release" {
		t.Fatalf("%v %v", br, err)
	}
	bad, _ := New(Config{Provider: AzureDevOps, BaseURL: srv.URL, AuthType: "pat", Secret: []byte("x"), HTTP: srv.Client()})
	if _, err := bad.Check(ctx); !errors.Is(err, ErrAuth) {
		t.Fatalf("HTML sign-in page must map to ErrAuth, got %v", err)
	}
}

func TestWebhookVerification(t *testing.T) {
	secret, body := []byte("s3cret"), []byte(`{"ref":"refs/heads/main"}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if VerifyGitHubSignature(secret, body, good) != nil {
		t.Error("valid signature rejected")
	}
	for _, h := range []string{"", "sha1=abc", "sha256=zz", "sha256=" + strings.Repeat("0", 64)} {
		if VerifyGitHubSignature(secret, body, h) == nil {
			t.Errorf("signature %q accepted", h)
		}
	}
	if VerifyGitHubSignature(secret, append(body, ' '), good) == nil {
		t.Error("tampered body accepted")
	}
	ok := "Basic " + base64.StdEncoding.EncodeToString([]byte("pathos:s3cret"))
	if VerifyAzureBasicAuth(secret, ok) != nil {
		t.Error("valid basic auth rejected")
	}
	if VerifyAzureBasicAuth(secret, "Basic "+base64.StdEncoding.EncodeToString([]byte("pathos:nope"))) == nil {
		t.Error("wrong password accepted")
	}
}

func TestParseEvents(t *testing.T) {
	ev, _ := ParseGitHubEvent("push", []byte(`{"ref":"refs/heads/main","after":"abc","repository":{"id":5}}`))
	if ev.Kind != "push" || ev.Ref != "main" || ev.CommitSHA != "abc" || ev.ExternalID != "5" {
		t.Errorf("push: %+v", ev)
	}
	ev, _ = ParseGitHubEvent("push", []byte(`{"ref":"refs/tags/v1","after":"abc","repository":{"id":5}}`))
	if ev.Kind != "ignored" {
		t.Errorf("tag push should be ignored: %+v", ev)
	}
	ev, _ = ParseGitHubEvent("pull_request", []byte(`{"action":"closed","number":3,"repository":{"id":5},
		"pull_request":{"merged":true,"merge_commit_sha":"m1","base":{"ref":"main"},"head":{"ref":"feat","sha":"h1"}}}`))
	if ev.Kind != "merge" || ev.Ref != "main" || ev.CommitSHA != "m1" || ev.PullRequest != 3 {
		t.Errorf("merge: %+v", ev)
	}
	ev, _ = ParseGitHubEvent("pull_request", []byte(`{"action":"synchronize","number":3,"repository":{"id":5},
		"pull_request":{"head":{"ref":"feat","sha":"h2"}}}`))
	if ev.Kind != "pull_request" || ev.CommitSHA != "h2" {
		t.Errorf("pr: %+v", ev)
	}
	ev, id, _ := ParseAzureEvent([]byte(`{"id":"d1","eventType":"git.push","resource":{"repository":{"id":"g1"},
		"refUpdates":[{"name":"refs/heads/main","newObjectId":"c0ffee"}]}}`))
	if ev.Kind != "push" || ev.Ref != "main" || id != "d1" || ev.ExternalID != "g1" {
		t.Errorf("ado push: %+v", ev)
	}
	ev, _, _ = ParseAzureEvent([]byte(`{"eventType":"git.push","resource":{"refUpdates":[{"name":"refs/heads/old","newObjectId":"0000000000"}]}}`))
	if ev.Kind != "ignored" {
		t.Errorf("branch deletion should be ignored: %+v", ev)
	}
}
