package scanners

import (
	"os"
	"strings"
	"testing"
)

func TestImportKeys(t *testing.T) {
	k, err := ImportKey("sast", "Snyk Code!")
	if err != nil || k != "import-sast-snyk-code" || !IsImportKey(k) {
		t.Fatalf("%q %v", k, err)
	}
	if _, err := ImportKey("bogus", "x"); err == nil {
		t.Error("unknown category")
	}
	if _, err := ImportKey("sast", "  !!  "); err == nil {
		t.Error("empty tool")
	}
	long, _ := ImportKey("dast", strings.Repeat("a", 60))
	if !IsImportKey(long) || len(long) > 40 {
		t.Errorf("long tool name: %q", long)
	}
	sc, ok := Resolve("import-dast-zap")
	if !ok || sc.FindingCategory() != "dast" || sc.Family != "import" {
		t.Errorf("resolve: %+v", sc)
	}
	if _, ok := Resolve("import-nope"); ok {
		t.Error("invalid import key must not resolve")
	}
}

func TestImportedFormats(t *testing.T) {
	sarif, _ := os.ReadFile("testdata/opengrep.sarif")
	fs, err := Parse("import-sast-semgrep", sarif)
	if err != nil || len(fs) == 0 || fs[0].ScannerKey != "import-sast-semgrep" || fs[0].Category != "sast" {
		t.Fatalf("sarif import: %v %+v", err, fs)
	}
	// Same tool output under another tool name is a different finding.
	native, _ := ParseSARIF(Opengrep, sarif)
	if native[0].Fingerprint == fs[0].Fingerprint {
		t.Error("imported findings keep their own provenance")
	}
	grype, _ := os.ReadFile("testdata/grype.json")
	if g, err := Parse("import-sca-grype-ci", grype); err != nil || len(g) == 0 || g[0].ScannerKey != "import-sca-grype-ci" {
		t.Errorf("grype import: %v", err)
	}
	generic := []byte(`{"tool":"fuzzer","findings":[
		{"rule_id":"crash-1","title":"Heap overflow in parse()","severity":"high","file_path":"src/parse.c","start_line":42,"cwe":["CWE-122"],"fingerprint":"abc"},
		{"title":"Exposed admin","cvss":9.1,"url":"https://app.example/admin"}]}`)
	g, err := Parse("import-dast-burp", generic)
	if err != nil || len(g) != 2 || g[0].Severity != "high" || g[1].Severity != "critical" || g[1].Category != "dast" {
		t.Fatalf("generic: %v %+v", err, g)
	}
	again, _ := Parse("import-dast-burp", generic)
	if again[0].Fingerprint != g[0].Fingerprint {
		t.Error("stable fingerprints")
	}
	loc, err := Locate("import-dast-burp", generic, g[0].Fingerprint)
	if err != nil || !strings.Contains(string(loc.Raw), "crash-1") {
		t.Errorf("locate generic: %v", err)
	}
	for _, bad := range []string{`{"findings":[{"title":"x","severity":"urgent"}]}`, `{"findings":[{"severity":"low"}]}`, `{"findings":[{"title":"x","severity":"low","extra":1}]}`, `<html>`, `{"other":1}`} {
		if _, err := Parse("import-other-x", []byte(bad)); err == nil {
			t.Errorf("%s: expected an error", bad)
		}
	}
	if DetectImportFormat(sarif) != "sarif" || DetectImportFormat(grype) != "grype" || DetectImportFormat(generic) != "pathos" {
		t.Error("format detection")
	}
}
