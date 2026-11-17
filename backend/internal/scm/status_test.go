package scm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestSetCommitStatus(t *testing.T) {
	const sha = "0123456789abcdef0123456789abcdef01234567"
	var mu sync.Mutex
	got := map[string]map[string]any{}
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		var body map[string]any
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &body)
		mu.Lock()
		got[r.URL.Path] = body
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	})
	ctx := context.Background()
	st := CommitStatus{State: CommitFailure, Context: "PATHOS / security", Description: strings.Repeat("x", 200), TargetURL: "https://pathos.example/pr/1"}
	ref := RepoRef{ExternalID: "7", FullName: "acme/api", Project: "acme"}
	for _, cfg := range []Config{
		{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("t")},
		{Provider: GitLab, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("t")},
		{Provider: Bitbucket, BaseURL: srv.URL, AuthType: AuthAPIToken, Secret: []byte(`{"username":"a@b.c","token":"t"}`)},
		{Provider: AzureDevOps, BaseURL: srv.URL + "/org", AuthType: AuthPAT, Secret: []byte("t")},
	} {
		cfg.HTTP = srv.Client()
		c := mustNew(t, cfg).(StatusWriter)
		r := ref
		if cfg.Provider == GitHub {
			r.ExternalID = ""
		}
		if err := c.SetCommitStatus(ctx, r, sha, st); err != nil {
			t.Fatalf("%s: %v", cfg.Provider, err)
		}
		if err := c.SetCommitStatus(ctx, r, "not-a-sha", st); err == nil {
			t.Errorf("%s: invalid commit accepted", cfg.Provider)
		}
		if err := c.SetCommitStatus(ctx, r, sha, CommitStatus{State: "weird", Context: "x"}); err == nil {
			t.Errorf("%s: invalid state accepted", cfg.Provider)
		}
	}
	check := func(path, key, want string) {
		t.Helper()
		b, ok := got[path]
		if !ok {
			t.Fatalf("no request to %s (got %v)", path, srv.requests())
		}
		if v, _ := b[key].(string); v != want {
			t.Errorf("%s %s = %q, want %q", path, key, v, want)
		}
	}
	check("/repos/acme/api/statuses/"+sha, "state", "failure")
	check("/repos/acme/api/statuses/"+sha, "context", "PATHOS / security")
	if d := got["/repos/acme/api/statuses/"+sha]["description"].(string); len([]rune(d)) != 140 {
		t.Errorf("description clipped to 140: %d", len([]rune(d)))
	}
	check("/api/v4/projects/7/statuses/"+sha, "state", "failed")
	check("/repositories/acme/api/commit/"+sha+"/statuses/build", "state", "FAILED")
	check("/repositories/acme/api/commit/"+sha+"/statuses/build", "url", "https://pathos.example/pr/1")
	var azure string
	for p := range got {
		if strings.Contains(p, "/_apis/git/repositories/") && strings.HasSuffix(p, "/commits/"+sha+"/statuses") {
			azure = p
		}
	}
	if azure == "" {
		t.Fatalf("no Azure DevOps status request: %v", srv.requests())
	}
	check(azure, "state", "failed")
}
