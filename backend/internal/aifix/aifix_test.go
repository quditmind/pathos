package aifix

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const appPy = `import subprocess
from flask import request


def run():
    cmd = request.args["cmd"]
    return subprocess.call(cmd, shell=True)


def ok():
    return 1
`

const goodDiff = "Here is the fix:\n```diff\n--- a/app/views.py\n+++ b/app/views.py\n@@ -5,3 +5,4 @@ def run():\n def run():\n     cmd = request.args[\"cmd\"]\n-    return subprocess.call(cmd, shell=True)\n+    import shlex\n+    return subprocess.call(shlex.split(cmd), shell=False)\n```\n"

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestParseAndApply(t *testing.T) {
	d, err := Parse(goodDiff)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Files) != 1 || d.Files[0].Path != "app/views.py" || d.Added != 2 || d.Removed != 1 {
		t.Fatalf("parsed: %+v", d)
	}
	if err := (Policy{FindingFile: "app/views.py"}).Check(d); err != nil {
		t.Fatal(err)
	}
	// The hunk header says line 5, but the file has one extra line above:
	// the hunk is placed where its context matches.
	root := writeTree(t, map[string]string{"app/views.py": "# header\n" + appPy})
	res, err := Apply(root, d)
	if err != nil {
		t.Fatal(err)
	}
	got := string(res[0].Patched)
	if !strings.Contains(got, "shlex.split(cmd), shell=False)\n") || strings.Contains(got, "shell=True") || !strings.HasSuffix(got, "return 1\n") {
		t.Fatalf("patched:\n%s", got)
	}
	// Line 8 (the shell=True call, shifted by the header) maps to the hunk's
	// new lines; lines after the hunk shift by one.
	if from, to := res[0].MapLine(8); from != 6 || to != 9 {
		t.Errorf("MapLine(8) = %d..%d", from, to)
	}
	if from, _ := res[0].MapLine(12); from != 13 {
		t.Errorf("MapLine(12) = %d", from)
	}
	if from, _ := res[0].MapLine(1); from != 1 {
		t.Errorf("MapLine(1) = %d", from)
	}
}

func TestApplyRedactedContext(t *testing.T) {
	src := "package cfg\n\nconst token = \"not-a-real-token-value\"\n\nfunc Token() string { return token }\n"
	diff := "--- a/cfg/cfg.go\n+++ b/cfg/cfg.go\n@@ -1,5 +1,7 @@\n package cfg\n \n-const token = \"[REDACTED]\"\n+import \"os\"\n+\n+var token = os.Getenv(\"CFG_TOKEN\")\n \n func Token() string { return token }\n"
	d, err := Parse(diff)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Apply(writeTree(t, map[string]string{"cfg/cfg.go": src}), d)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(res[0].Patched); strings.Contains(got, "not-a-real") || !strings.Contains(got, `os.Getenv("CFG_TOKEN")`) {
		t.Fatalf("patched:\n%s", got)
	}
	// The placeholder must never be written into the code.
	bad, _ := Parse(strings.Replace(diff, `os.Getenv("CFG_TOKEN")`, `"[REDACTED]"`, 1))
	if err := (Policy{FindingFile: "cfg/cfg.go"}).Check(bad); err == nil || !strings.Contains(err.Error(), "placeholder") {
		t.Errorf("placeholder in added lines: %v", err)
	}
}

func TestApplyMismatchAndLinks(t *testing.T) {
	d, _ := Parse(goodDiff)
	root := writeTree(t, map[string]string{"app/views.py": strings.Replace(appPy, `request.args["cmd"]`, `request.form["cmd"]`, 1)})
	if _, err := Apply(root, d); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Errorf("context mismatch: %v", err)
	}
	root = writeTree(t, map[string]string{"real.py": appPy})
	if err := os.MkdirAll(filepath.Join(root, "app"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real.py"), filepath.Join(root, "app", "views.py")); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(root, d); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Errorf("symlink: %v", err)
	}
	if _, err := Apply(writeTree(t, map[string]string{}), d); err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("missing file: %v", err)
	}
}

func TestParseRefusals(t *testing.T) {
	for name, diff := range map[string]string{
		"traversal": "--- a/../etc/passwd\n+++ b/../etc/passwd\n@@ -1 +1 @@\n-a\n+b\n",
		"absolute":  "--- /etc/passwd\n+++ /etc/passwd\n@@ -1 +1 @@\n-a\n+b\n",
		"new file":  "--- /dev/null\n+++ b/x.py\n@@ -0,0 +1 @@\n+a\n",
		"delete":    "--- a/x.py\n+++ /dev/null\n@@ -1 +0,0 @@\n-a\n",
		"rename":    "--- a/x.py\n+++ b/y.py\n@@ -1 +1 @@\n-a\n+b\n",
		"mode":      "diff --git a/x.sh b/x.sh\nold mode 100644\nnew mode 100755\n",
		"binary":    "diff --git a/x.bin b/x.bin\nGIT binary patch\nliteral 1\n",
		"empty":     "I cannot fix this.",
		"no hunk":   "--- a/x.py\n+++ b/x.py\n",
		"no ctx":    "--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+a\n",
		"too big":   "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+" + strings.Repeat("b", MaxDiffBytes) + "\n",
	} {
		if _, err := Parse(diff); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var many strings.Builder
	many.WriteString("--- a/x.py\n+++ b/x.py\n@@ -1 +1,300 @@\n a\n")
	for i := 0; i < MaxChangedLines+1; i++ {
		many.WriteString("+x\n")
	}
	if _, err := Parse(many.String()); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("too many changed lines: %v", err)
	}
}

func TestPolicy(t *testing.T) {
	p := Policy{FindingFile: "app/views.py"}
	diff := func(paths ...string) Diff {
		var b strings.Builder
		for _, p := range paths {
			b.WriteString("--- a/" + p + "\n+++ b/" + p + "\n@@ -1 +1 @@\n-old\n+new\n")
		}
		d, err := Parse(b.String())
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if err := p.Check(diff("app/views.py", "app/helpers.py")); err != nil {
		t.Errorf("a file next to the finding: %v", err)
	}
	for name, d := range map[string]Diff{
		"other directory": diff("app/views.py", "lib/util.py"),
		"CI file":         diff("app/views.py", ".github/workflows/ci.yml"),
		"manifest":        diff("app/views.py", "app/requirements.txt"),
		"build script":    diff("app/views.py", "app/Makefile"),
		"not the finding": diff("app/helpers.py"),
		"too many files":  diff("app/views.py", "app/a.py", "app/b.py", "app/c.py"),
	} {
		if err := p.Check(d); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The finding's own file may be protected: that is where the finding is.
	if err := (Policy{FindingFile: ".github/workflows/ci.yml"}).Check(diff(".github/workflows/ci.yml")); err != nil {
		t.Errorf("finding in a CI file: %v", err)
	}
	ws, _ := Parse("--- a/app/views.py\n+++ b/app/views.py\n@@ -1 +1 @@\n-x = 1\n+x  =  1\n")
	if err := p.Check(ws); err == nil {
		t.Error("whitespace-only change accepted")
	}
	for path, want := range map[string]string{
		"Jenkinsfile": ci, ".gitlab-ci.yml": ci, "svc/go.mod": manifest, "web/package-lock.json": manifest, "Dockerfile.prod": build,
		"src/app.csproj": manifest, "requirements-dev.txt": manifest, ".git/config": control, "app/views.py": "",
	} {
		if got := Protected(path); got != want {
			t.Errorf("Protected(%s) = %q, want %q", path, got, want)
		}
	}
}

func TestCompare(t *testing.T) {
	target := Target{RuleID: "py.shell-true", File: "app/views.py", Line: 7}
	before := []Result{{RuleID: "py.shell-true", File: "app/views.py", Line: 7}, {RuleID: "py.debug", File: "app/views.py", Line: 2}}
	d, _ := Parse(goodDiff)
	res, err := Apply(writeTree(t, map[string]string{"app/views.py": appPy}), d)
	if err != nil {
		t.Fatal(err)
	}
	a := &res[0]

	// Correct fix: the result is gone, the unrelated one moved but stays.
	v := Compare(before, []Result{{RuleID: "py.debug", File: "app/views.py", Line: 2}}, target, a)
	if !v.Verified() {
		t.Errorf("correct fix: %+v", v)
	}
	// Wrong fix: the scanner still reports the rule on the fixed lines.
	v = Compare(before, []Result{{RuleID: "py.shell-true", File: "app/views.py", Line: 8}, {RuleID: "py.debug", File: "app/views.py", Line: 2}}, target, a)
	if v.Verified() || v.Removed || !strings.Contains(v.Reason, "still reports") {
		t.Errorf("wrong fix: %+v", v)
	}
	// New finding introduced by the fix.
	v = Compare(before, []Result{{RuleID: "py.debug", File: "app/views.py", Line: 2}, {RuleID: "py.shlex", File: "app/views.py", Line: 7}}, target, a)
	if v.Verified() || len(v.New) != 1 || v.New[0].RuleID != "py.shlex" || !strings.Contains(v.Reason, "new scanner result") {
		t.Errorf("new finding: %+v", v)
	}
	// Not reproduced on the original: cannot verify.
	v = Compare(nil, nil, target, a)
	if v.Verified() || v.Reproduced || !strings.Contains(v.Reason, "cannot be verified") {
		t.Errorf("not reproduced: %+v", v)
	}
	// Two results of the rule; the fix removed the other one, not the target.
	two := []Result{{RuleID: "py.shell-true", File: "app/views.py", Line: 7}, {RuleID: "py.shell-true", File: "app/views.py", Line: 11}}
	v = Compare(two, []Result{{RuleID: "py.shell-true", File: "app/views.py", Line: 8}}, target, a)
	if v.Verified() {
		t.Errorf("other instance removed: %+v", v)
	}
}
