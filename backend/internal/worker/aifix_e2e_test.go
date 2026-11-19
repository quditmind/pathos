//go:build sandbox_e2e

package worker

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAIFixSandboxE2E runs the AI fix test step (pathos-fixtest) through the
// real sandbox runner of the built worker-fuzz image, on the samples in
// workers/fuzz/test/fixtest: a change that keeps the tests passing and one
// that breaks them, for Go and Python. Run it with
//
//	SANDBOX_E2E_RUN='^TestAIFixSandboxE2E$' workers/fuzz/test/sandbox-e2e.sh [image]
func TestAIFixSandboxE2E(t *testing.T) {
	testDir := os.Getenv("E2E_TEST_DIR")
	if testDir == "" {
		t.Skip("run workers/fuzz/test/sandbox-e2e.sh")
	}
	s, err := OpenSandbox(os.Getenv(SandboxDirEnv))
	if err != nil {
		t.Fatal(err)
	}
	a := &Agent{cfg: Config{WorkDir: t.TempDir()}, log: slog.New(slog.NewTextHandler(io.Discard, nil)), sandbox: s}
	checkout := func(sample string) string {
		src := filepath.Join(t.TempDir(), "src")
		files := map[string][]byte{}
		entries, err := os.ReadDir(filepath.Join(testDir, "fixtest", sample))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			b, err := os.ReadFile(filepath.Join(testDir, "fixtest", sample, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			files[e.Name()] = b
		}
		if err := writeTree(src, files); err != nil {
			t.Fatal(err)
		}
		return src
	}
	for _, c := range []struct {
		runner, sample, file, old, new, want string
	}{
		{"go", "go-ok", "calc.go", "func Add(a, b int) int { return a + b }", "func Add(a, b int) int { return b + a }", "passed"},
		{"go", "go-ok", "calc.go", "func Add(a, b int) int { return a + b }", "func Add(a, b int) int { return a - b }", "failed"},
		{"python", "py-ok", "calc.py", "def add(a, b): return a + b", "def add(a, b): return b + a", "passed"},
		{"python", "py-ok", "calc.py", "def add(a, b): return a + b", "def add(a, b): return a * b", "failed"},
	} {
		job := AIFixJob{Phase: "test", FilePath: c.file, TestRunner: c.runner,
			Diff: "--- a/" + c.file + "\n+++ b/" + c.file + "\n@@ -1 +1 @@\n-" + c.old + "\n+" + c.new + "\n"}
		rep := a.testAIFix(t.Context(), job, checkout(c.sample), filepath.Join(t.TempDir(), "ws"), aiFixReport{Phase: "test", Status: "failed"})
		t.Logf("%s %s -> %s: %s %s\n%s", c.runner, c.new, rep.Status, stepStatus(rep, "tests"), rep.FailureReason, rep.TestLog)
		if stepStatus(rep, "tests") != c.want {
			t.Errorf("%s %q: tests step %s, want %s (%s)", c.runner, c.new, stepStatus(rep, "tests"), c.want, rep.FailureReason)
		}
		if c.want == "failed" && !strings.Contains(rep.FailureReason, "fail with it") {
			t.Errorf("%s: reason %q", c.runner, rep.FailureReason)
		}
	}
}
