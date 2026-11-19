package scanners

import (
	"os"
	"strings"
	"testing"
)

func load(t *testing.T, key string) []Finding {
	t.Helper()
	name := key + ".sarif"
	if key == Grype {
		name = "grype.json"
	}
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Parse(key, raw)
	if err != nil {
		t.Fatalf("%s: %v", key, err)
	}
	return fs
}

func TestCatalog(t *testing.T) {
	// catalog.go lists 55 scanner integrations; the family packs
	// (catalog_<family>.go) replace some of them and add more.
	if len(Catalog) < 97 {
		t.Errorf("SCANNER_CATALOG lists at least 97 scanner integrations, got %d", len(Catalog))
	}
	seen := map[string]bool{}
	mandatory := 0
	for _, sc := range Catalog {
		if seen[sc.Key] {
			t.Errorf("duplicate key %s", sc.Key)
		}
		seen[sc.Key] = true
		if sc.Mandatory {
			mandatory++
			if !sc.AdapterAvailable {
				t.Errorf("mandatory scanner %s must be runnable", sc.Key)
			}
		}
		if sc.RequiresBuild && sc.DefaultEnabled {
			t.Errorf("%s requires a build and must not be enabled by default", sc.Key)
		}
	}
	if mandatory != 1 || !seen[Gitleaks] {
		t.Error("exactly Gitleaks must be mandatory")
	}
}

func TestParseFixtures(t *testing.T) {
	cases := []struct {
		key      string
		min      int
		category string
	}{
		{Gitleaks, 1, "secrets"}, {Opengrep, 3, "sast"}, {TrivyFS, 4, "sca"}, {Grype, 4, "sca"}, {OSVScanner, 4, "sca"}, {Checkov, 5, "iac"},
	}
	for _, c := range cases {
		fs := load(t, c.key)
		if len(fs) < c.min {
			t.Errorf("%s: want >= %d findings, got %d", c.key, c.min, len(fs))
		}
		for _, f := range fs {
			if f.Category != c.category || f.Fingerprint == "" || f.RuleID == "" || f.Title == "" {
				t.Errorf("%s: incomplete finding %+v", c.key, f)
			}
			if strings.HasPrefix(f.FilePath, "/") || strings.Contains(f.FilePath, "work/") {
				t.Errorf("%s: path not normalized: %q", c.key, f.FilePath)
			}
		}
	}
}

func TestSecretsAreRedactedAndHigh(t *testing.T) {
	for _, f := range load(t, Gitleaks) {
		if f.Severity != "high" || f.RuleID != "github-pat" || f.FilePath != "config.py" {
			t.Errorf("unexpected gitleaks finding %+v", f)
		}
		if strings.Contains(f.Description, "ghp_") || strings.Contains(f.Title, "ghp_") {
			t.Error("secret value must never be stored")
		}
	}
}

func TestOpengrepNormalization(t *testing.T) {
	for _, f := range load(t, Opengrep) {
		if !strings.HasPrefix(f.RuleID, "pathos.python.") {
			t.Errorf("rule id prefix not stripped: %s", f.RuleID)
		}
		if strings.HasPrefix(f.Title, "Opengrep Finding") || len(f.CWE) == 0 || f.StartLine == nil {
			t.Errorf("title/CWE/line not extracted: %+v", f)
		}
	}
}

func TestCrossToolSCADeduplication(t *testing.T) {
	byTool := map[string]string{}
	for _, key := range []string{TrivyFS, Grype, OSVScanner} {
		for _, f := range load(t, key) {
			if f.CVE == "CVE-2021-23337" {
				if f.PackageName != "lodash" || f.PackageVersion != "4.17.20" {
					t.Errorf("%s: package not extracted: %+v", key, f)
				}
				byTool[key] = f.Fingerprint
			}
		}
	}
	if len(byTool) != 3 {
		t.Fatalf("CVE-2021-23337 should be reported by all three SCA tools, got %v", byTool)
	}
	if byTool[TrivyFS] != byTool[Grype] || byTool[Grype] != byTool[OSVScanner] {
		t.Errorf("the same vulnerability must fingerprint identically across tools: %v", byTool)
	}
}

func TestGrypeEnrichment(t *testing.T) {
	for _, f := range load(t, Grype) {
		if f.PackageName == "lodash" && f.CVE == "CVE-2021-23337" {
			if f.FixedVersion != "4.17.21" || f.CVSS == nil || !strings.Contains(f.Title, "GHSA-35jh-r3h4-6jhm") {
				t.Errorf("grype enrichment missing: %+v", f)
			}
			return
		}
	}
	t.Error("lodash CVE-2021-23337 not found in grype output")
}

func TestFingerprintIgnoresLineNumbers(t *testing.T) {
	a := Finding{ScannerKey: Opengrep, Category: "sast", RuleID: "r1", FilePath: "/work/abc/src/app/x.py"}
	b := a
	b.FilePath = "app/x.py"
	l1, l2 := 10, 99
	a.StartLine, b.StartLine = &l1, &l2
	if Fingerprint(a, "snip") != Fingerprint(b, "snip") {
		t.Error("fingerprint must not depend on line numbers or workspace paths")
	}
	if Fingerprint(a, "snip") == Fingerprint(a, "other") {
		t.Error("different code must give different fingerprints")
	}
}

func TestSeverity(t *testing.T) {
	cases := map[float64]string{9.8: "critical", 7.5: "high", 5: "medium", 1: "low", 0: "info"}
	for score, want := range cases {
		if got := FromScore(score); got != want {
			t.Errorf("FromScore(%v) = %s, want %s", score, got, want)
		}
	}
	if SeverityRank("critical") <= SeverityRank("high") || SeverityRank("info") != 0 {
		t.Error("severity ranking broken")
	}
}

func TestExclusions(t *testing.T) {
	globs := []string{"node_modules/**", "**/testdata/**", "docs/", "*.min.js"}
	for p, want := range map[string]bool{
		"node_modules/lodash/index.js": true, "src/a/testdata/x.go": true, "docs/readme.md": true,
		"app.min.js": true, "src/app.min.js": false, "src/main.go": false, "nodemodules/x": false,
	} {
		if got := Excluded(p, globs); got != want {
			t.Errorf("Excluded(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestMalformedInput(t *testing.T) {
	if _, err := Parse(Gitleaks, []byte("not json")); err == nil {
		t.Error("invalid SARIF must error")
	}
	if _, err := Parse(Grype, []byte("{")); err == nil {
		t.Error("invalid grype JSON must error")
	}
	if fs, err := Parse(Checkov, []byte(`{"runs":[]}`)); err != nil || len(fs) != 0 {
		t.Error("empty SARIF is valid")
	}
}
