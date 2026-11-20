package worker

import (
	"context"
	"errors"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// TestShallowCloneReportsCommit uses git's smart HTTP backend (shallow
// clones need it) through net/http/cgi.
func TestShallowCloneReportsCommit(t *testing.T) {
	backend := ""
	for _, p := range []string{"/usr/lib/git-core/git-http-backend", "/usr/libexec/git-core/git-http-backend"} {
		if _, err := os.Stat(p); err == nil {
			backend = p
		}
	}
	if backend == "" {
		t.Skip("git-http-backend not installed")
	}
	base := t.TempDir()
	work := filepath.Join(base, "work")
	_ = os.MkdirAll(work, 0o700)
	gitRun(t, work, "init", "-q", "-b", "main")
	_ = os.WriteFile(filepath.Join(work, "a.txt"), []byte("1"), 0o600)
	gitRun(t, work, "add", ".")
	gitRun(t, work, "commit", "-q", "-m", "first")
	_ = os.WriteFile(filepath.Join(work, "a.txt"), []byte("2"), 0o600)
	gitRun(t, work, "commit", "-q", "-am", "second")
	head := gitRun(t, work, "rev-parse", "HEAD")
	gitRun(t, base, "clone", "-q", "--bare", work, filepath.Join(base, "repo.git"))
	srv := httptest.NewServer(&cgi.Handler{Path: backend, Env: []string{"GIT_PROJECT_ROOT=" + base, "GIT_HTTP_EXPORT_ALL=1",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1"}})
	defer srv.Close()

	ws := t.TempDir()
	src := filepath.Join(ws, "src")
	commit, err := clone(context.Background(), Job{CloneURL: srv.URL + "/repo.git", Ref: "main"}, src, filepath.Join(ws, "git"), 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	if commit != head {
		t.Fatalf("commit %s, want %s", commit, head)
	}
	if _, err := os.Lstat(filepath.Join(src, ".git")); err == nil {
		t.Fatal(".git must be removed after a shallow clone")
	}
	if _, err := os.Stat(filepath.Join(ws, "git")); err == nil {
		t.Fatal("no separate git dir expected for a shallow clone")
	}
	if b, _ := os.ReadFile(filepath.Join(src, "a.txt")); string(b) != "2" {
		t.Fatalf("working tree %q", b)
	}
}

func TestAnonymousCloneError(t *testing.T) {
	err := anonymousCloneError(errors.New("fatal: could not read Username for 'https://github.com': terminal prompts disabled"))
	if !strings.Contains(err.Error(), "PTH-ONB-1102") {
		t.Errorf("refused anonymous clone: %v", err)
	}
	other := errors.New("fatal: unable to access: Could not resolve host")
	if anonymousCloneError(other) != other {
		t.Error("network errors are not reported as private repositories")
	}
}
