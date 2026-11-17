package scm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestContentArgsValidation(t *testing.T) {
	for _, p := range []string{"", "/etc/passwd", "a/../b", "a//b", "a\\b", "./a", "a/\x00b"} {
		if ValidRepoPath(p) {
			t.Errorf("%q must be rejected", p)
		}
	}
	for _, p := range []string{"src/main.go", "a/b c/d.txt", ".github/workflows/ci.yml"} {
		if !ValidRepoPath(p) {
			t.Errorf("%q must be accepted", p)
		}
	}
	for _, c := range []string{"main", "abc", "zzzzzzz", "abcdef1;rm"} {
		if ValidCommit(c) {
			t.Errorf("commit %q must be rejected", c)
		}
	}
	if !ValidCommit("0123abc") || !ValidCommit(strings.Repeat("a", 40)) {
		t.Error("SHAs must be accepted")
	}
}

func TestProviderFileAtCommit(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	content := "package main\n\nfunc main() {}\n"
	enc := base64.StdEncoding.EncodeToString([]byte(content))
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		// GitHub
		case r.URL.Path == "/repos/acme/api/contents/src/main.go" && r.URL.Query().Get("ref") == sha:
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "file", "encoding": "base64", "content": enc, "size": len(content)})
		case r.URL.Path == "/repos/acme/api/commits" && r.URL.Query().Get("sha") == sha && r.URL.Query().Get("path") == "src/main.go":
			_ = json.NewEncoder(w).Encode([]map[string]any{{"sha": sha, "commit": map[string]any{"message": "init\nbody", "author": map[string]any{"name": "Dana"}}}})
		// GitLab
		case r.URL.EscapedPath() == "/api/v4/projects/7/repository/files/src%2Fmain.go" && r.URL.Query().Get("ref") == sha:
			_ = json.NewEncoder(w).Encode(map[string]any{"encoding": "base64", "content": enc, "size": len(content)})
		// Bitbucket
		case r.URL.Path == "/repositories/acme/api/src/"+sha+"/src/main.go" && r.URL.Query().Get("format") == "meta":
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "commit_file", "size": len(content)})
		case r.URL.Path == "/repositories/acme/api/src/"+sha+"/src/main.go":
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(content))
		default:
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	gh := mustNew(t, Config{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("t"), HTTP: srv.Client()})
	cr := gh.(ContentReader)
	b, err := cr.FileAt(ctx, RepoRef{FullName: "acme/api"}, sha, "src/main.go")
	if err != nil || string(b) != content {
		t.Fatalf("github FileAt: %q %v", b, err)
	}
	if _, err := cr.FileAt(ctx, RepoRef{FullName: "acme/api"}, sha, "missing.go"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing file: %v", err)
	}
	if _, err := cr.FileAt(ctx, RepoRef{FullName: "acme/api"}, sha, "../x"); err == nil {
		t.Error("path traversal must be rejected before any request")
	}
	hist, err := cr.FileHistory(ctx, RepoRef{FullName: "acme/api"}, sha, "src/main.go", 5)
	if err != nil || len(hist) != 1 || hist[0].Message != "init" || hist[0].Author != "Dana" {
		t.Fatalf("github history: %+v %v", hist, err)
	}

	gl := mustNew(t, Config{Provider: GitLab, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("t"), HTTP: srv.Client()})
	if b, err := gl.(ContentReader).FileAt(ctx, RepoRef{ExternalID: "7", FullName: "acme/api"}, sha, "src/main.go"); err != nil || string(b) != content {
		t.Fatalf("gitlab FileAt: %q %v", b, err)
	}

	bb := mustNew(t, Config{Provider: Bitbucket, BaseURL: srv.URL, AuthType: AuthAPIToken,
		Secret: []byte(`{"username":"a@b.c","token":"t"}`), HTTP: srv.Client()})
	if b, err := bb.(ContentReader).FileAt(ctx, RepoRef{FullName: "acme/api"}, sha, "src/main.go"); err != nil || string(b) != content {
		t.Fatalf("bitbucket FileAt: %q %v", b, err)
	}
}
