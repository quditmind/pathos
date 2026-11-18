package scanners

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func readImport(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/imports/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// parseTwice parses a fixture and checks detection, stable fingerprints and
// that every finding can be located with its raw record.
func parseTwice(t *testing.T, key, format string, raw []byte) []Finding {
	t.Helper()
	if got := DetectImportFormat(raw); !SameImportParser(got, format) {
		t.Fatalf("detected %q, want %q", got, format)
	}
	fs, err := ParseImport(key, format, raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	again, _ := ParseImport(key, "", raw)
	if len(again) != len(fs) {
		t.Fatalf("detected parse differs: %d vs %d", len(again), len(fs))
	}
	for i := range fs {
		if fs[i].Fingerprint != again[i].Fingerprint || fs[i].Fingerprint == "" {
			t.Errorf("finding %d: unstable fingerprint", i)
		}
		if fs[i].ScannerKey != key || !slices.Contains(Severities, fs[i].Severity) || fs[i].Title == "" || fs[i].CWE == nil {
			t.Errorf("finding %d not normalised: %+v", i, fs[i])
		}
		loc, err := LocateImport(key, format, raw, fs[i].Fingerprint)
		if err != nil || len(loc.Raw) < 3 {
			t.Errorf("finding %d: locate: %v", i, err)
		}
	}
	return fs
}

func TestImportGitleaks(t *testing.T) {
	raw := readImport(t, "gitleaks.json")
	clean := SanitizeImport("gitleaks", raw)
	for _, secret := range []string{"ghp_EXAMPLEexampleEXAMPLEexample0123456", "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFi"} {
		if strings.Contains(string(clean), secret) {
			t.Fatal("sanitised report still contains a secret")
		}
	}
	fs := parseTwice(t, "import-secrets-gitleaks", "gitleaks", clean)
	if len(fs) != 2 || fs[0].Severity != "high" || fs[0].FilePath != "config/settings.py" || *fs[0].StartLine != 12 ||
		fs[0].CWE[0] != "CWE-798" || fs[0].Category != "secrets" || !strings.Contains(fs[0].Description, "3f2a9c1d") {
		t.Fatalf("%+v", fs)
	}
	// Identity does not depend on the secret: the unsanitised report gives
	// the same fingerprints.
	orig, _ := ParseImport("import-secrets-gitleaks", "gitleaks", raw)
	if orig[0].Fingerprint != fs[0].Fingerprint {
		t.Error("fingerprint depends on the secret value")
	}
	loc, _ := LocateImport("import-secrets-gitleaks", "gitleaks", raw, fs[0].Fingerprint)
	if strings.Contains(string(loc.Raw), "ghp_") {
		t.Error("located record exposes the secret")
	}
}

func TestImportTrivy(t *testing.T) {
	raw := SanitizeImport("trivy", readImport(t, "trivy.json"))
	if strings.Contains(string(raw), "AKIAEXAMPLEEXAMPLE12") {
		t.Fatal("secret kept")
	}
	if !strings.Contains(string(raw), "command injection") {
		t.Fatal("vulnerability text lost")
	}
	// Category "other": each record keeps its own category.
	fs := parseTwice(t, "import-other-trivy", "trivy", raw)
	if len(fs) != 4 { // 2 vulnerabilities, 1 failed misconfiguration (PASS skipped), 1 secret
		t.Fatalf("%d findings: %+v", len(fs), fs)
	}
	v := fs[0]
	if v.Category != "sca" || v.CVE != "CVE-2021-23337" || v.PackageName != "lodash" || v.PackageVersion != "4.17.20" || v.FixedVersion != "4.17.21" ||
		v.Severity != "high" || v.CVSS == nil || *v.CVSS != 7.2 || v.CVSSVersion != "3.1" || v.CWE[0] != "CWE-94" || v.FilePath != "package-lock.json" {
		t.Errorf("vulnerability: %+v", v)
	}
	if fs[1].FixedVersion != "4.17.21" || fs[1].CVE != "" || fs[1].Severity != "medium" {
		t.Errorf("ghsa: %+v", fs[1])
	}
	m := fs[2]
	if m.Category != "iac" || m.RuleID != "AVD-KSV-0001" || *m.StartLine != 21 || *m.EndLine != 40 || m.FilePath != "deploy/k8s/deployment.yaml" {
		t.Errorf("misconfiguration: %+v", m)
	}
	if s := fs[3]; s.Category != "secrets" || s.Severity != "critical" || *s.StartLine != 7 {
		t.Errorf("secret: %+v", s)
	}
	// A declared category applies to all records.
	img, _ := ParseImport("import-container-trivy", "trivy", raw)
	if img[0].Category != "container" || img[2].Category != "container" {
		t.Errorf("declared category: %+v", img[0])
	}
}

func TestImportSemgrep(t *testing.T) {
	fs := parseTwice(t, "import-sast-semgrep", "semgrep", readImport(t, "semgrep.json"))
	if len(fs) != 2 {
		t.Fatal(len(fs))
	}
	if f := fs[0]; f.RuleID != "sql-injection-using-raw.sql-injection-using-raw" && !strings.HasSuffix(f.RuleID, "sql-injection-using-raw") {
		t.Errorf("rule: %q", f.RuleID)
	}
	if f := fs[0]; f.Severity != "high" || f.Confidence != "high" || f.CWE[0] != "CWE-89" || *f.StartLine != 42 || f.FilePath != "app/views.py" ||
		f.Title != "Detected user input used in a raw SQL query." {
		t.Errorf("%+v", f)
	}
	if f := fs[1]; f.Severity != "medium" || f.Confidence != "low" || f.CWE[0] != "CWE-79" {
		t.Errorf("%+v", f)
	}
}

func TestImportNuclei(t *testing.T) {
	raw := readImport(t, "nuclei.jsonl")
	fs := parseTwice(t, "import-dast-nuclei", "nuclei", raw)
	native, _ := ParseNucleiJSONL(raw)
	if len(fs) != len(native) || fs[1].Severity != "critical" || fs[1].CWE[0] != "CWE-89" || !strings.HasPrefix(fs[1].FilePath, "https://") {
		t.Fatalf("%+v", fs)
	}
	if fs[0].Fingerprint == native[0].Fingerprint {
		t.Error("imported findings keep their own provenance")
	}
}

func TestImportCSV(t *testing.T) {
	fs := parseTwice(t, "import-other-pentest", "csv", readImport(t, "csv.csv"))
	if len(fs) != 3 {
		t.Fatalf("%d: %+v", len(fs), fs)
	}
	if f := fs[0]; f.Category != "dast" || f.Severity != "high" || f.FilePath != "https://app.example/comments" || f.Confidence != "high" || f.CWE[0] != "CWE-79" {
		t.Errorf("%+v", f)
	}
	if f := fs[1]; f.Category != "sca" || f.Severity != "critical" || f.CVE != "CVE-2024-5535" || f.PackageName != "openssl" || f.PackageVersion != "3.0.13" || f.FixedVersion != "3.0.14" {
		t.Errorf("%+v", f)
	}
	if f := fs[2]; f.Category != "other" || f.FilePath != "src/db/conn.go" || *f.StartLine != 17 || !slices.Equal(f.CWE, []string{"CWE-798", "CWE-259"}) {
		t.Errorf("%+v", f)
	}
	semi := []byte("name;risk;file\nWeak cipher;Low;nginx.conf\n")
	if DetectImportFormat(semi) != "csv" {
		t.Error("semicolon CSV")
	}
	if g, err := ParseImport("import-other-x", "csv", semi); err != nil || len(g) != 1 || g[0].Severity != "low" {
		t.Errorf("semicolon: %v %+v", err, g)
	}
	for _, bad := range []string{"title,severity\nx,urgent-ish\n", "title,severity\n,low\n", "file,line\na,1\n"} {
		if _, err := ParseImport("import-other-x", "csv", []byte(bad)); err == nil {
			t.Errorf("%q: expected an error", bad)
		}
	}
}

func TestImportFormatRegistry(t *testing.T) {
	ids := map[string]bool{}
	for _, f := range ImportFormats() {
		if ids[f.ID] || f.Label == "" || f.Media == "" {
			t.Errorf("format %+v", f)
		}
		ids[f.ID] = true
		if f.ID != "sarif" && f.ID != "pathos" && f.ID != "csv" && f.Tool == "" {
			t.Errorf("%s: tool-specific formats name their tool", f.ID)
		}
		if f.Parser == "" && f.parse == nil && !slices.Contains([]string{"sarif", "grype", "pathos"}, f.ID) {
			t.Errorf("%s has no parser", f.ID)
		}
		if FormatFromContentType(ImportContentType(f.ID)) != f.ID {
			t.Errorf("%s: content type round trip", f.ID)
		}
	}
	if _, ok := LookupImportFormat("SEMGREP"); !ok {
		t.Error("lookup is case-insensitive")
	}
	if _, err := ParseImport("import-other-x", "nope", []byte("{}")); err == nil {
		t.Error("unknown format")
	}
	if DetectImportFormat([]byte("[]")) != "" || DetectImportFormat([]byte("hello world")) != "" {
		t.Error("ambiguous content is not detected")
	}
	// An empty report of a named format is a valid, complete result.
	if fs, err := ParseImport("import-secrets-gitleaks", "gitleaks", []byte("[]")); err != nil || len(fs) != 0 {
		t.Errorf("empty gitleaks: %v", err)
	}
	if normSeverity("BLOCKER") != "critical" || normSeverity("Moderate") != "medium" || normSeverity("?") != "" {
		t.Error("severity vocabulary")
	}
	if got := normCWEs([]string{"CWE-079", "79", "cwe-89: SQL", "x"}); !slices.Equal(got, []string{"CWE-79", "CWE-89"}) {
		t.Errorf("cwes: %v", got)
	}
}

func TestLocateArtifactUsesContentType(t *testing.T) {
	raw := []byte("[]")
	if _, err := LocateArtifact("import-secrets-gitleaks", ImportContentType("gitleaks"), raw, "x"); err != ErrNotLocated {
		t.Errorf("empty report: %v", err)
	}
	g := readImport(t, "gitleaks.json")
	fs, _ := ParseImport("import-secrets-gitleaks", "gitleaks", g)
	if loc, err := LocateArtifact("import-secrets-gitleaks", "application/json; pathos-format=gitleaks", g, fs[1].Fingerprint); err != nil || !strings.Contains(string(loc.Raw), "generic-api-key") {
		t.Errorf("locate: %v", err)
	}
}
