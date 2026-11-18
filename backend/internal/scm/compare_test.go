package scm

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestPushDiffGitHub(t *testing.T) {
	const before = "1111111111111111111111111111111111111111"
	const c1 = "2222222222222222222222222222222222222222"
	const c2 = "3333333333333333333333333333333333333333"
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/repos/acme/api/compare/" + before + "..." + c2, "/repos/acme/api/compare/main..." + c2:
			_, _ = w.Write([]byte(`{"total_commits":2,"commits":[{"sha":"` + c1 + `"},{"sha":"` + c2 + `"}],"files":[]}`))
		case "/repos/acme/api/commits/" + c1:
			_, _ = w.Write([]byte(`{"files":[{"filename":"a.txt","status":"added","patch":"@@ -0,0 +1 @@\n+hello"},{"filename":"gone.txt","status":"removed","patch":"-x"}]}`))
		case "/repos/acme/api/commits/" + c2:
			_, _ = w.Write([]byte(`{"files":[{"filename":"b.txt","status":"modified","patch":"@@ -1 +1 @@\n-a\n+b"}]}`))
		case "/repos/acme/api":
			_, _ = w.Write([]byte(`{"id":1,"full_name":"acme/api","default_branch":"main","owner":{"login":"acme"}}`))
		default:
			status(w, http.StatusNotFound)
		}
	})
	c := mustNew(t, Config{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("t"), HTTP: srv.Client()}).(DiffReader)
	ref := RepoRef{FullName: "acme/api"}
	d, err := c.PushDiff(context.Background(), ref, before, c2)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Commits) != 2 || d.Commits[0].SHA != c1 || len(d.Commits[0].Files) != 1 || d.Commits[0].Files[0].Path != "a.txt" || d.Truncated {
		t.Fatalf("unexpected diff %+v", d)
	}
	// New branch: compared with the default branch.
	d, err = c.PushDiff(context.Background(), ref, strings.Repeat("0", 40), c2)
	if err != nil || len(d.Commits) != 2 {
		t.Fatalf("new branch: %+v %v", d, err)
	}
	if _, err := c.PushDiff(context.Background(), ref, before, "not a sha"); err == nil {
		t.Error("invalid commit accepted")
	}
	if _, err := c.PushDiff(context.Background(), RepoRef{FullName: "acme/missing"}, before, c2); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestPushDiffGitHubTooManyCommits(t *testing.T) {
	const before = "1111111111111111111111111111111111111111"
	const head = "4444444444444444444444444444444444444444"
	var commits []string
	for i := 0; i < MaxPushCommits+1; i++ {
		commits = append(commits, `{"sha":"`+strings.Repeat("5", 40)+`"}`)
	}
	big := strings.Repeat("x", MaxPatchBytes+10)
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/compare/") {
			_, _ = w.Write([]byte(`{"total_commits":51,"commits":[` + strings.Join(commits, ",") + `],"files":[{"filename":"big.txt","status":"added","patch":"` + big + `"}]}`))
			return
		}
		status(w, http.StatusNotFound)
	})
	c := mustNew(t, Config{Provider: GitHub, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("t"), HTTP: srv.Client()}).(DiffReader)
	d, err := c.PushDiff(context.Background(), RepoRef{FullName: "acme/api"}, before, head)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Truncated || len(d.Commits) != 1 || d.Commits[0].SHA != head || len(d.Commits[0].Files[0].Patch) != MaxPatchBytes {
		t.Fatalf("aggregate diff expected: truncated=%v commits=%d", d.Truncated, len(d.Commits))
	}
	if n := srv.count("GET /repos/acme/api/commits/"); n != 0 {
		t.Errorf("per-commit requests beyond the limit: %d", n)
	}
}

func TestPushDiffGitLab(t *testing.T) {
	const before = "1111111111111111111111111111111111111111"
	const c1 = "2222222222222222222222222222222222222222"
	srv := newFake(t, func(f *fake, w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v4/projects/7/repository/compare":
			if r.URL.Query().Get("from") != before || r.URL.Query().Get("to") != c1 {
				status(w, http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"commits":[{"id":"` + c1 + `"}],"diffs":[]}`))
		case "/api/v4/projects/7/repository/commits/" + c1 + "/diff":
			_, _ = w.Write([]byte(`[{"new_path":"cfg.env","diff":"@@ -0,0 +1 @@\n+X=1"},{"new_path":"old","diff":"-y","deleted_file":true}]`))
		default:
			status(w, http.StatusNotFound)
		}
	})
	c := mustNew(t, Config{Provider: GitLab, BaseURL: srv.URL, AuthType: AuthPAT, Secret: []byte("t"), HTTP: srv.Client()}).(DiffReader)
	d, err := c.PushDiff(context.Background(), RepoRef{ExternalID: "7", FullName: "acme/api"}, before, c1)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Commits) != 1 || len(d.Commits[0].Files) != 1 || d.Commits[0].Files[0].Path != "cfg.env" {
		t.Fatalf("unexpected diff %+v", d)
	}
}

func TestPushDiffNotImplemented(t *testing.T) {
	for _, cfg := range []Config{
		{Provider: Bitbucket, BaseURL: "https://api.bitbucket.org/2.0", AuthType: AuthAPIToken, Secret: []byte(`{"username":"a@b.c","token":"t"}`)},
		{Provider: AzureDevOps, BaseURL: "https://dev.azure.com/org", AuthType: AuthPAT, Secret: []byte("t")},
	} {
		cfg.HTTP = http.DefaultClient
		if _, ok := mustNew(t, cfg).(DiffReader); ok {
			t.Errorf("%s unexpectedly implements DiffReader", cfg.Provider)
		}
	}
}

func TestWebhookBefore(t *testing.T) {
	ev, _ := ParseGitHubEvent("push", []byte(`{"ref":"refs/heads/main","before":"aaa","after":"bbb","repository":{"id":5}}`))
	if ev.Before != "aaa" || ev.CommitSHA != "bbb" {
		t.Errorf("github before: %+v", ev)
	}
	ev, _, _ = ParseGitLabEvent("Push Hook", []byte(`{"ref":"refs/heads/main","before":"ccc","after":"ddd","project_id":15}`))
	if ev.Before != "ccc" || ev.CommitSHA != "ddd" {
		t.Errorf("gitlab before: %+v", ev)
	}
}
