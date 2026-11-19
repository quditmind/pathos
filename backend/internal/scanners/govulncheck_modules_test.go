package scanners

import (
	"os"
	"strings"
	"testing"
)

// The worker runs govulncheck per Go module and records the module's
// directory in each run's config message. Regression (benchmark
// 2026-11-19): every finding was located in "go.mod", so in a repository
// with several modules findings pointed to the wrong file.
func TestGovulncheckModuleDirectories(t *testing.T) {
	raw, err := os.ReadFile("testdata/imports/govulncheck.json")
	if err != nil {
		t.Fatal(err)
	}
	one, err := ParseImport("govulncheck", "govulncheck", raw)
	if err != nil || len(one) == 0 {
		t.Fatalf("%v %d", err, len(one))
	}
	for _, f := range one {
		if f.FilePath != "go.mod" && f.FilePath != "" {
			t.Errorf("without a module directory the file is go.mod: %q", f.FilePath)
		}
	}
	mod := func(dir string) string {
		return strings.Replace(string(raw), `"scanner_name"`, `"pathos_module_dir": "`+dir+`", "scanner_name"`, 1)
	}
	two, err := ParseImport("govulncheck", "govulncheck", []byte(mod("services/api")+"\n"+mod("../../etc/web")))
	if err != nil {
		t.Fatal(err)
	}
	if len(two) != 2*len(one) {
		t.Fatalf("the same vulnerability in two modules is two findings: %d, want %d", len(two), 2*len(one))
	}
	files := map[string]int{}
	fps := map[string]bool{}
	for _, f := range two {
		files[f.FilePath]++
		fps[f.Fingerprint] = true
	}
	n := 0
	for _, f := range one {
		if f.FilePath != "" {
			n++
		}
	}
	if files["services/api/go.mod"] != n || files["etc/web/go.mod"] != n {
		t.Errorf("files: %v", files)
	}
	if len(fps) != len(two)-(len(one)-n) {
		t.Errorf("distinct fingerprints per module: %d of %d", len(fps), len(two))
	}
}
