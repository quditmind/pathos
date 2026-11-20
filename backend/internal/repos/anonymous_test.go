package repos

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

func diagOf(err error) string {
	var he *httpx.Error
	if errors.As(err, &he) {
		return he.Diag
	}
	return ""
}

func TestParsePublicURL(t *testing.T) {
	cases := []struct {
		in, provider, url, diag string
		parts                   []string
	}{
		{"https://github.com/owner/repo", AnonGitHub, "https://github.com/owner/repo", "", []string{"owner", "repo"}},
		{"https://github.com/owner/repo.git", AnonGitHub, "https://github.com/owner/repo", "", []string{"owner", "repo"}},
		{"https://www.github.com/owner/repo/tree/main/src", AnonGitHub, "https://github.com/owner/repo", "", []string{"owner", "repo"}},
		{"https://gitlab.com/group/sub/project/-/tree/main", AnonGitLab, "https://gitlab.com/group/sub/project", "", []string{"group", "sub", "project"}},
		{"https://bitbucket.org/ws/repo.git", AnonBitbucket, "https://bitbucket.org/ws/repo", "", []string{"ws", "repo"}},
		{"https://org@dev.azure.com/org/My%20Project/_git/repo", AnonAzure, "https://dev.azure.com/org/My%20Project/_git/repo", "", []string{"org", "My Project", "repo"}},
		{"https://git.example.org/scm/team/repo.git", AnonGit, "https://git.example.org/scm/team/repo.git", "", []string{"scm", "team", "repo.git"}},
		{"http://github.com/owner/repo", "", "", DiagAnonInvalidURL, nil},
		{"https://user:secret@github.com/owner/repo", "", "", DiagAnonInvalidURL, nil},
		{"https://github.com/owner", "", "", DiagAnonInvalidURL, nil},
		{"https://github.com/owner/repo?x=1", "", "", DiagAnonInvalidURL, nil},
		{"https://dev.azure.com/org/project", "", "", DiagAnonInvalidURL, nil},
		{"https://127.0.0.1/repo.git", "", "", DiagAnonBlocked, nil},
		{"https://169.254.169.254/latest", "", "", DiagAnonBlocked, nil},
		{"git@github.com:owner/repo.git", "", "", DiagAnonInvalidURL, nil},
		{"https://git.example.org/../etc", "", "", DiagAnonInvalidURL, nil},
	}
	for _, c := range cases {
		got, err := parsePublicURL(c.in, false)
		if c.diag != "" {
			if diagOf(err) != c.diag {
				t.Errorf("%s: want %s, got %v", c.in, c.diag, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", c.in, err)
			continue
		}
		if got.Provider != c.provider || got.URL.String() != c.url || strings.Join(got.Parts, "|") != strings.Join(c.parts, "|") {
			t.Errorf("%s: got %s %s %v", c.in, got.Provider, got.URL, got.Parts)
		}
	}
}

// fakeProviders answers like the public APIs to anonymous callers.
func fakeProviders(t *testing.T, rateLimited *bool) (*httptest.Server, *PublicProbe) {
	t.Helper()
	mux := http.NewServeMux()
	json := func(w http.ResponseWriter, status int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = fmt.Fprint(w, body)
	}
	mux.HandleFunc("/gh/repos/{o}/{r}", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("anonymous probe sent a credential")
		}
		if *rateLimited {
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("Retry-After", "120")
			json(w, 403, `{"message":"API rate limit exceeded"}`)
			return
		}
		switch r.PathValue("r") {
		case "public":
			json(w, 200, `{"id":42,"full_name":"acme/public","name":"public","html_url":"https://github.com/acme/public",
				"clone_url":"https://github.com/acme/public.git","default_branch":"main","private":false,"visibility":"public",
				"language":"Go","owner":{"login":"acme"}}`)
		case "flagged":
			json(w, 200, `{"id":43,"full_name":"acme/flagged","name":"flagged","clone_url":"https://github.com/acme/flagged.git","private":true}`)
		case "evil":
			json(w, 200, `{"id":44,"full_name":"acme/evil","name":"evil","clone_url":"https://attacker.example/evil.git","private":false}`)
		default:
			json(w, 404, `{"message":"Not Found"}`)
		}
	})
	mux.HandleFunc("/gl/projects/{p}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("p") {
		case "group/sub/public":
			json(w, 200, `{"id":7,"path_with_namespace":"group/sub/public","name":"public","web_url":"https://gitlab.com/group/sub/public",
				"http_url_to_repo":"https://gitlab.com/group/sub/public.git","default_branch":"develop","visibility":"public","namespace":{"full_path":"group/sub"}}`)
		case "group/internal":
			json(w, 200, `{"id":8,"path_with_namespace":"group/internal","name":"internal","visibility":"internal","http_url_to_repo":"https://gitlab.com/group/internal.git"}`)
		default:
			json(w, 404, `{"message":"404 Project Not Found"}`)
		}
	})
	mux.HandleFunc("/bb/repositories/{w}/{r}", func(w http.ResponseWriter, r *http.Request) {
		switch r.PathValue("r") {
		case "public":
			json(w, 200, `{"uuid":"{abc}","full_name":"ws/public","name":"public","is_private":false,"mainbranch":{"name":"master"},
				"links":{"html":{"href":"https://bitbucket.org/ws/public"},"clone":[{"name":"https","href":"https://someone@bitbucket.org/ws/public.git"}]},
				"workspace":{"slug":"ws"}}`)
		default:
			json(w, 403, `{"type":"error","error":{"message":"Access denied"}}`)
		}
	})
	mux.HandleFunc("/ado/{org}/{project}/_apis/git/repositories/{repo}", func(w http.ResponseWriter, r *http.Request) {
		if r.PathValue("project") == "Private" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(203)
			_, _ = fmt.Fprint(w, "<html>sign in</html>")
			return
		}
		json(w, 200, `{"id":"r-1","name":"`+r.PathValue("repo")+`","remoteUrl":"https://org@dev.azure.com/org/Public/_git/`+r.PathValue("repo")+`",
			"webUrl":"https://dev.azure.com/org/Public/_git/`+r.PathValue("repo")+`","defaultBranch":"refs/heads/main","project":{"name":"Public","visibility":"public"}}`)
	})
	mux.HandleFunc("/git/public.git/info/refs", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("service") != "git-upload-pack" {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/x-git-upload-pack-advertisement")
		_, _ = fmt.Fprint(w, "001e# service=git-upload-pack\n0000")
		line := "1111111111111111111111111111111111111111 HEAD\x00multi_ack symref=HEAD:refs/heads/trunk agent=git/2\n"
		_, _ = fmt.Fprintf(w, "%04x%s0000", len(line)+4, line)
	})
	mux.HandleFunc("/git/private.git/info/refs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
		w.WriteHeader(401)
	})
	mux.HandleFunc("/git/login/info/refs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, "<html>please sign in</html>")
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &PublicProbe{HTTP: srv.Client(), Net: scm.NetPolicy{AllowHTTP: true},
		GitHubAPI: srv.URL + "/gh", GitLabAPI: srv.URL + "/gl", BitbucketAPI: srv.URL + "/bb", AzureBase: srv.URL + "/ado"}
}

func TestPublicProbe(t *testing.T) {
	limited := false
	srv, p := fakeProviders(t, &limited)
	ctx := t.Context()

	r, err := p.Probe(ctx, "https://github.com/acme/public")
	if err != nil || r.Provider != AnonGitHub || r.CloneURL != "https://github.com/acme/public.git" || r.DefaultBranch != "main" || r.ExternalID != "42" || r.Language != "Go" {
		t.Fatalf("github public: %+v %v", r, err)
	}
	for _, u := range []string{"https://github.com/acme/private", "https://github.com/acme/flagged"} {
		if _, err := p.Probe(ctx, u); diagOf(err) != DiagAnonNotPublic {
			t.Errorf("%s must be refused as not public: %v", u, err)
		}
	}
	if _, err := p.Probe(ctx, "https://github.com/acme/evil"); err == nil {
		t.Error("a clone URL on another host must be refused")
	}
	limited = true
	_, err = p.Probe(ctx, "https://github.com/acme/public")
	var he *httpx.Error
	if diagOf(err) != DiagAnonRateLimited || !errors.As(err, &he) || he.Status != 429 || he.Details.(map[string]any)["retry_after_seconds"] != 120 {
		t.Errorf("rate limit: %v %+v", err, he)
	}
	limited = false

	r, err = p.Probe(ctx, "https://gitlab.com/group/sub/public.git")
	if err != nil || r.Provider != AnonGitLab || r.DefaultBranch != "develop" || r.Organization != "group/sub" {
		t.Fatalf("gitlab public: %+v %v", r, err)
	}
	for _, u := range []string{"https://gitlab.com/group/internal", "https://gitlab.com/group/private"} {
		if _, err := p.Probe(ctx, u); diagOf(err) != DiagAnonNotPublic {
			t.Errorf("%s: %v", u, err)
		}
	}

	r, err = p.Probe(ctx, "https://bitbucket.org/ws/public")
	if err != nil || r.CloneURL != "https://bitbucket.org/ws/public.git" || r.DefaultBranch != "master" {
		t.Fatalf("bitbucket public (user info stripped): %+v %v", r, err)
	}
	if _, err := p.Probe(ctx, "https://bitbucket.org/ws/private"); diagOf(err) != DiagAnonNotPublic {
		t.Errorf("bitbucket private: %v", err)
	}

	r, err = p.Probe(ctx, "https://dev.azure.com/org/Public/_git/app")
	if err != nil || r.CloneURL != "https://dev.azure.com/org/Public/_git/app" || r.DefaultBranch != "main" || r.Project != "Public" {
		t.Fatalf("azure public: %+v %v", r, err)
	}
	if _, err := p.Probe(ctx, "https://dev.azure.com/org/Private/_git/app"); diagOf(err) != DiagAnonNotPublic {
		t.Errorf("azure private (203 sign-in page): %v", err)
	}

	// Generic git server, smart HTTP (localhost: not a literal loopback IP).
	base := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
	r, err = p.Probe(ctx, base+"/git/public.git")
	if err != nil || r.Provider != AnonGit || r.DefaultBranch != "trunk" || !strings.HasSuffix(r.CloneURL, "/git/public.git") {
		t.Fatalf("generic public: %+v %v", r, err)
	}
	for _, u := range []string{base + "/git/private.git", base + "/git/login", base + "/git/missing.git"} {
		if _, err := p.Probe(ctx, u); diagOf(err) != DiagAnonNotPublic {
			t.Errorf("%s must be refused: %v", u, err)
		}
	}
}

func TestAdvertisedHead(t *testing.T) {
	line := "abc HEAD\x00symref=HEAD:refs/heads/main\n"
	body := "001e# service=git-upload-pack\n0000" + fmt.Sprintf("%04x%s", len(line)+4, line) + "0000"
	if b, ok := advertisedHead([]byte(body)); !ok || b != "main" {
		t.Errorf("symref: %q %v", b, ok)
	}
	if _, ok := advertisedHead([]byte("<html>")); ok {
		t.Error("HTML is not an advertisement")
	}
	// Empty repository: service line and flush only.
	if b, ok := advertisedHead([]byte("001e# service=git-upload-pack\n0000")); !ok || b != "" {
		t.Errorf("empty repository: %q %v", b, ok)
	}
}
