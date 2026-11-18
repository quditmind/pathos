package worker

import (
	"context"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitAs(t *testing.T, dir, author string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME="+author, "GIT_AUTHOR_EMAIL=private@example.invalid", "GIT_COMMITTER_NAME=c", "GIT_COMMITTER_EMAIL=c@example.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// changeRepo builds a repository with three commits and returns its base
// directory (holding repo.git) and the first and last commit.
func changeRepo(t *testing.T) (base, first, last string) {
	base = t.TempDir()
	work := filepath.Join(base, "work")
	_ = os.MkdirAll(filepath.Join(work, "app"), 0o700)
	gitAs(t, work, "Init", "init", "-q", "-b", "main")
	_ = os.WriteFile(filepath.Join(work, "app", "server.js"), []byte("const app = express();\n"), 0o600)
	gitAs(t, work, "Init", "add", ".")
	gitAs(t, work, "Init", "commit", "-q", "-m", "first")
	first = gitAs(t, work, "Init", "rev-parse", "HEAD")
	_ = os.WriteFile(filepath.Join(work, "app", "server.js"), []byte("const app = express();\napp.post('/api/pay', pay);\n"), 0o600)
	gitAs(t, work, "Alice Example", "commit", "-q", "-am", "add payment endpoint")
	_ = os.MkdirAll(filepath.Join(work, ".github", "workflows"), 0o700)
	_ = os.WriteFile(filepath.Join(work, ".github", "workflows", "ci.yml"), []byte("on: pull_request_target\n"), 0o600)
	gitAs(t, work, "Bob Example", "add", ".")
	gitAs(t, work, "Bob Example", "commit", "-q", "-m", "ci")
	last = gitAs(t, work, "Bob Example", "rev-parse", "HEAD")
	gitAs(t, base, "x", "clone", "-q", "--bare", work, filepath.Join(base, "repo.git"))
	return base, first, last
}

func checkReport(t *testing.T, rep *ChangeReport, wantCommits bool) {
	t.Helper()
	if rep.Status != "computed" {
		t.Fatalf("status %s: %s", rep.Status, rep.Reason)
	}
	rules := map[string]bool{}
	for _, c := range rep.Changes {
		rules[c.RuleID+" "+c.FilePath] = true
	}
	for _, want := range []string{"endpoint.express app/server.js", "cicd.pipeline .github/workflows/ci.yml", "cicd.dangerous-trigger .github/workflows/ci.yml"} {
		if !rules[want] {
			t.Errorf("missing %s in %+v", want, rep.Changes)
		}
	}
	if rep.FilesChanged != 2 {
		t.Errorf("files changed %d", rep.FilesChanged)
	}
	if !wantCommits {
		if len(rep.Commits) != 0 {
			t.Errorf("commits collected without consent: %+v", rep.Commits)
		}
		return
	}
	if !rep.CommitsComplete || len(rep.Commits) != 2 {
		t.Fatalf("commits %+v complete=%v", rep.Commits, rep.CommitsComplete)
	}
	if rep.Commits[0].AuthorName != "Bob Example" || rep.Commits[1].AuthorName != "Alice Example" ||
		len(rep.Commits[1].Files) != 1 || rep.Commits[1].Files[0] != "app/server.js" {
		t.Errorf("commits %+v", rep.Commits)
	}
}

func TestDetectChangesFullHistory(t *testing.T) {
	base, first, last := changeRepo(t)
	job := Job{FullHistory: true, PreviousCommitSHA: first, CollectAuthors: true}
	rep := detectChanges(context.Background(), job, last, filepath.Join(base, "repo.git"), t.TempDir())
	checkReport(t, rep, true)
}

func TestDetectChangesShallowFetch(t *testing.T) {
	backend := ""
	for _, p := range []string{"/usr/lib/git-core/git-http-backend", "/usr/libexec/git-core/git-http-backend"} {
		if _, err := os.Stat(p); err == nil {
			backend = p
		}
	}
	if backend == "" {
		t.Skip("git-http-backend not installed")
	}
	base, first, last := changeRepo(t)
	srv := httptest.NewServer(&cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + base, "GIT_HTTP_EXPORT_ALL=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}})
	defer srv.Close()
	for _, authors := range []bool{false, true} {
		job := Job{CloneURL: srv.URL + "/repo.git", PreviousCommitSHA: first, CollectAuthors: authors}
		rep := detectChanges(context.Background(), job, last, "", filepath.Join(t.TempDir(), "changes"))
		checkReport(t, rep, authors)
	}
}

func TestDetectChangesStates(t *testing.T) {
	sha := strings.Repeat("a", 40)
	if r := detectChanges(context.Background(), Job{}, sha, "", ""); r.Status != "baseline" {
		t.Errorf("first scan: %+v", r)
	}
	if r := detectChanges(context.Background(), Job{PreviousCommitSHA: sha}, sha, "", ""); r.Status != "unchanged" {
		t.Errorf("same commit: %+v", r)
	}
	if r := detectChanges(context.Background(), Job{PreviousCommitSHA: "abc"}, sha, "", ""); r.Status != "unavailable" {
		t.Errorf("short id: %+v", r)
	}
	base, first, _ := changeRepo(t)
	missing := strings.Repeat("b", 40)
	r := detectChanges(context.Background(), Job{FullHistory: true, PreviousCommitSHA: missing}, first, filepath.Join(base, "repo.git"), "")
	if r.Status != "unavailable" || !strings.Contains(r.Reason, "rewritten history") {
		t.Errorf("missing base: %+v", r)
	}
}

func TestParseCommitLog(t *testing.T) {
	sha := strings.Repeat("c", 40)
	in := "\x1e" + sha + "\x1fAda\x07 Lovelace\x1f2026-11-01T10:00:00+01:00\n\nsrc/a.go\nsrc/b.go\n\x1ebad\x1fx\x1fy\n"
	got := parseCommitLog(in)
	if len(got) != 1 || got[0].AuthorName != "Ada Lovelace" || len(got[0].Files) != 2 || got[0].AuthoredAt.IsZero() {
		t.Fatalf("%+v", got)
	}
}
