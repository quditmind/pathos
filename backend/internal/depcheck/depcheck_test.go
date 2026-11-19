package depcheck

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOneEdit(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"requests", "requests", false}, {"reqests", "requests", true}, {"requestss", "requests", true}, {"requesst", "requests", true},
		{"rqeuests", "requests", true}, {"reuqests", "requests", true}, {"requets", "requests", true}, {"request", "requests", true},
		{"reqursts", "requests", true}, {"rqeuesst", "requests", false}, {"lodash", "ldoahs", false}, {"lodahs", "lodash", true},
		{"abc", "xyz", false}, {"", "a", true}, {"ab", "ba", true},
	} {
		if got := oneEdit(c.a, c.b); got != c.want {
			t.Errorf("oneEdit(%q, %q) = %v", c.a, c.b, got)
		}
	}
}

func TestSimilar(t *testing.T) {
	p := NewPopular("# comment\nrequests\nurllib3\npython-dateutil\nflask\nabc\nrareone\n", 5)
	for name, want := range map[string]string{
		"requests":        "",                // popular itself
		"Requests":        "",                // case-insensitive
		"reqeusts":        "requests",        // transposition
		"urlib3":          "urllib3",         // deletion
		"python_dateutil": "python-dateutil", // separator
		"pythondateutil":  "python-dateutil",
		"flsk":            "flask",
		"abd":             "", // short
		"rareon":          "", // rareone is popular but not among the compared top 5
		"rareone":         "", // and is popular itself
		"totally-unique":  "",
	} {
		if got := p.Similar(name); got != want {
			t.Errorf("Similar(%q) = %q, want %q", name, got, want)
		}
	}
	if p.Len() != 6 {
		t.Errorf("Len %d", p.Len())
	}
}

func TestEmbeddedLists(t *testing.T) {
	c := Default()
	if c.NPM.Len() < 1000 || c.PyPI.Len() < 1000 {
		t.Fatalf("popular lists: npm %d, pypi %d", c.NPM.Len(), c.PyPI.Len())
	}
	if c.NPM.Similar("lodahs") != "lodash" || c.PyPI.Similar("reqeusts") != "requests" || c.PyPI.Similar("numpy") != "" {
		t.Error("embedded lists")
	}
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestScan(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "web/package.json", `{
  "name": "web",
  "dependencies": {
    "lodahs": "^4.17.21",
    "express": "^4.19.0",
    "@acme/ui": "1.2.3",
    "@corp/auth": "2.0.0",
    "local-lib": "file:../lib"
  },
  "devDependencies": { "@types/node": "^22.0.0" }
}`)
	write(t, dir, "web/.npmrc", "@acme:registry=https://npm.acme.internal/\n")
	write(t, dir, "requirements.txt", "# app\n--extra-index-url https://pypi.acme.internal/simple\nreqeusts==2.31.0\nflask>=3.0  # web\n-e .\n")
	write(t, dir, "svc/pyproject.toml", "[project]\nname = \"svc\"\ndependencies = [\n  \"djnago>=5.0\",\n  \"numpy\",\n]\n\n[tool.poetry.dependencies]\npython = \"^3.12\"\nurlib3 = \"^2\"\n")
	write(t, dir, "node_modules/x/package.json", `{"dependencies": {"lodahs": "1"}}`)
	fs, err := Default().Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs = Sorted(fs)
	type key struct {
		rule, file, pkg, similar string
		line                     int
	}
	want := []key{
		{"DEPCHECK-PIP-EXTRA-INDEX", "requirements.txt", "", "", 2},
		{"DEPCHECK-TYPOSQUAT-PYPI", "requirements.txt", "reqeusts", "requests", 3},
		{"DEPCHECK-TYPOSQUAT-PYPI", "svc/pyproject.toml", "djnago", "django", 4},
		{"DEPCHECK-TYPOSQUAT-PYPI", "svc/pyproject.toml", "urlib3", "urllib3", 10},
		{"DEPCHECK-TYPOSQUAT-NPM", "web/package.json", "lodahs", "lodash", 4},
		{"DEPCHECK-NPM-UNMAPPED-SCOPE", "web/package.json", "@corp/auth", "", 7},
		{"DEPCHECK-NPM-UNMAPPED-SCOPE", "web/package.json", "@types/node", "", 10},
	}
	if len(fs) != len(want) {
		t.Fatalf("findings: %+v", fs)
	}
	for i, w := range want {
		f := fs[i]
		if (key{f.RuleID, f.File, f.Package, f.SimilarTo, f.Line}) != w {
			t.Errorf("finding %d: %+v, want %+v", i, f, w)
		}
		if f.Title == "" || f.Message == "" || f.Severity == "" || f.CWE == "" {
			t.Errorf("finding %d incomplete: %+v", i, f)
		}
	}
}

func TestScanWithoutPrivateRegistry(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "package.json", `{"dependencies": {"@corp/auth": "1.0.0"}}`)
	write(t, dir, ".npmrc", "@corp:registry=https://registry.npmjs.org/\n")
	fs, err := Default().Scan(dir)
	if err != nil || len(fs) != 0 {
		t.Errorf("no private registry, no scope finding: %+v %v", fs, err)
	}
}
