package scanners

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// want is the expected mapping of one finding.
type want struct {
	sev, cve, cwe, file string
	line, endLine       int
	pkg, ver, fixed     string
	rule                string
}

func TestImportJSONFormats(t *testing.T) {
	cases := []struct {
		file, format string
		count        int
		checks       map[int]want
	}{
		{"snyk.json", "snyk", 2, map[int]want{
			0: {sev: "high", cve: "CVE-2021-23337", cwe: "CWE-94", file: "package-lock.json", pkg: "lodash", ver: "4.17.20", fixed: "4.17.21", rule: "SNYK-JS-LODASH-1018905"},
			1: {sev: "low", cwe: "CWE-1321", pkg: "minimist", ver: "1.2.5"},
		}},
		{"snyk-all-projects.json", "snyk", 1, map[int]want{
			0: {sev: "medium", cve: "CVE-2023-32681", cwe: "CWE-200", file: "services/api/requirements.txt", pkg: "requests", ver: "2.28.1", fixed: "2.31.0"},
		}},
		{"sonarqube.json", "sonarqube", 2, map[int]want{
			0: {sev: "high", file: "src/main/java/com/acme/OrderDao.java", line: 42, endLine: 44, rule: "javasecurity:S3649"},
			1: {sev: "medium", file: "src/main/java/com/acme/Cart.java", line: 17},
		}},
		{"sonarqube-hotspots.json", "sonarqube", 1, map[int]want{
			0: {sev: "high", file: "src/main/resources/application.properties", line: 7, rule: "java:S2068"},
		}},
		{"bandit.json", "bandit", 2, map[int]want{
			0: {sev: "high", cwe: "CWE-78", file: "app/views.py", line: 15, rule: "B602"},
			1: {sev: "low", cwe: "CWE-502", file: "app/cache.py", line: 3},
		}},
		{"gosec.json", "gosec", 2, map[int]want{
			0: {sev: "medium", cwe: "CWE-22", file: "src/internal/files/read.go", line: 24, rule: "G304"},
			1: {sev: "high", cwe: "CWE-89", file: "src/internal/store/orders.go", line: 40, endLine: 41},
		}},
		{"eslint.json", "eslint", 2, map[int]want{
			0: {sev: "medium", file: "home/runner/work/web/src/server/render.js", line: 18, rule: "security/detect-eval-with-expression"},
			1: {sev: "low", line: 31},
		}},
		{"npm-audit.json", "npm-audit", 2, map[int]want{
			0: {sev: "critical", cwe: "CWE-1321", file: "package-lock.json", pkg: "minimist", fixed: "0.2.4", rule: "GHSA-xvch-5gv4-984h"},
			1: {sev: "high", cwe: "CWE-1333", pkg: "semver", rule: "GHSA-c2qf-rxjj-qqgw"},
		}},
		{"npm-audit-v1.json", "npm-audit", 2, map[int]want{
			0: {sev: "low", cve: "CVE-2019-10744", cwe: "CWE-471", pkg: "lodash", ver: "4.17.15", fixed: "4.17.19", rule: "GHSA-p6mc-m468-83gw"},
			1: {ver: "4.17.11"},
		}},
		{"pip-audit.json", "pip-audit", 3, map[int]want{
			0: {sev: "medium", cve: "CVE-2024-22195", pkg: "jinja2", ver: "3.1.2", fixed: "3.1.3", rule: "GHSA-h5c8-rqwp-cp95"},
			1: {cve: "CVE-2023-43804", pkg: "urllib3", fixed: "1.26.17"},
		}},
		{"osv-scanner.json", "osv-scanner", 2, map[int]want{
			0: {sev: "high", cve: "CVE-2023-45288", cwe: "CWE-400", file: "src/go.mod", pkg: "golang.org/x/net", ver: "0.17.0", fixed: "0.23.0", rule: "GHSA-4v7x-pqxf-cx7m"},
			1: {sev: "high", cve: "CVE-2024-4068", file: "src/web/package-lock.json", pkg: "braces", fixed: "3.0.3"},
		}},
		{"dependency-check.json", "dependency-check", 2, map[int]want{
			0: {sev: "critical", cve: "CVE-2021-44228", cwe: "CWE-20", file: "build/target/lib/log4j-core-2.14.1.jar", pkg: "log4j-core", ver: "2.14.1"},
			1: {sev: "critical", cve: "CVE-2022-42889", pkg: "commons-text", ver: "1.9"},
		}},
		{"checkov.json", "checkov", 3, map[int]want{
			0: {sev: "medium", file: "infra/s3.tf", line: 14, endLine: 22, rule: "CKV_AWS_20"},
			1: {sev: "high", file: "infra/network.tf", line: 3},
			2: {sev: "medium", file: "Dockerfile", rule: "CKV_DOCKER_3"},
		}},
		{"trufflehog.jsonl", "trufflehog", 2, map[int]want{
			0: {sev: "critical", cwe: "CWE-798", file: "config/settings.py", line: 12, rule: "AWS"},
			1: {sev: "high", file: "deploy/.env.example", line: 3, rule: "URI"},
		}},
		{"snyk-code.sarif", "snyk-code", 2, map[int]want{
			0: {sev: "high", cwe: "CWE-79", file: "src/components/Banner.js", line: 27, rule: "javascript/DOMXSS"},
			1: {sev: "low", cwe: "CWE-547", file: "src/config.js", line: 4},
		}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "imports", c.file))
			if err != nil {
				t.Fatal(err)
			}
			if got := DetectImportFormat(raw); !SameImportParser(got, c.format) {
				t.Fatalf("detected %q, want %q", got, c.format)
			}
			f, _ := LookupImportFormat(c.format)
			cat := f.Category
			if cat == "" {
				cat = "other"
			}
			key := "import-" + cat + "-x"
			fs, err := ParseImport(key, c.format, raw)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if len(fs) != c.count {
				t.Fatalf("%d findings, want %d: %+v", len(fs), c.count, fs)
			}
			for i, w := range c.checks {
				g := fs[i]
				check := func(name, got, want string) {
					if want != "" && got != want {
						t.Errorf("finding %d %s = %q, want %q", i, name, got, want)
					}
				}
				check("severity", g.Severity, w.sev)
				check("cve", g.CVE, w.cve)
				check("file", g.FilePath, w.file)
				check("package", g.PackageName, w.pkg)
				check("version", g.PackageVersion, w.ver)
				check("fixed", g.FixedVersion, w.fixed)
				check("rule", g.RuleID, w.rule)
				if w.cwe != "" && !slices.Contains(g.CWE, w.cwe) {
					t.Errorf("finding %d CWE = %v, want %s", i, g.CWE, w.cwe)
				}
				if w.line > 0 && (g.StartLine == nil || *g.StartLine != w.line) {
					t.Errorf("finding %d line = %v, want %d", i, g.StartLine, w.line)
				}
				if w.endLine > 0 && (g.EndLine == nil || *g.EndLine != w.endLine) {
					t.Errorf("finding %d end line = %v, want %d", i, g.EndLine, w.endLine)
				}
			}
			for _, g := range fs {
				if g.ScannerKey != key || g.Fingerprint == "" || g.Title == "" || !slices.Contains(Severities, g.Severity) {
					t.Errorf("incomplete finding %+v", g)
				}
			}
			again, _ := ParseImport(key, "", raw)
			for i := range fs {
				if i >= len(again) || again[i].Fingerprint != fs[i].Fingerprint {
					t.Fatalf("fingerprint %d not stable (detected vs explicit format)", i)
				}
			}
			stored := SanitizeImport(c.format, raw)
			for _, g := range fs {
				loc, err := LocateImport(key, c.format, stored, g.Fingerprint)
				if err != nil || len(loc.Raw) < 3 {
					t.Fatalf("locate %s: %v", g.Title, err)
				}
			}
		})
	}
}

func TestTrufflehogSecretsAreRemoved(t *testing.T) {
	raw, err := os.ReadFile("testdata/imports/trufflehog.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{"fake-aws-key-id-for-tests", "fake-aws-secret-for-tests", "not-a-real-pass"}
	stored := SanitizeImport("trufflehog", raw)
	orig, _ := ParseImport("import-secrets-th", "trufflehog", raw)
	clean, err := ParseImport("import-secrets-th", "", stored)
	if err != nil || len(clean) != len(orig) {
		t.Fatalf("sanitized report: %v %d", err, len(clean))
	}
	for i := range orig {
		if orig[i].Fingerprint != clean[i].Fingerprint {
			t.Error("identity must not depend on the secret")
		}
		for _, src := range [][]byte{raw, stored} {
			loc, err := LocateImport("import-secrets-th", "trufflehog", src, orig[i].Fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range secrets {
				if strings.Contains(string(loc.Raw), s) {
					t.Errorf("secret %q in located record", s)
				}
			}
		}
		for _, s := range secrets {
			if strings.Contains(orig[i].Title+orig[i].Description, s) {
				t.Errorf("secret %q in finding text", s)
			}
		}
	}
	for _, s := range secrets {
		if strings.Contains(string(stored), s) {
			t.Errorf("secret %q in the stored report", s)
		}
	}
	if !strings.Contains(string(stored), "config/settings.py") {
		t.Error("non-secret fields are kept")
	}
}

// TestImportFixturesDetectOnlyAsTheirFormat checks every fixture in
// testdata/imports (named <format>.<ext> or <format>-<variant>.<ext>) is
// detected as its own format and nothing else.
func TestImportFixturesDetectOnlyAsTheirFormat(t *testing.T) {
	entries, err := os.ReadDir("testdata/imports")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, f := range ImportFormats() {
		ids = append(ids, f.ID)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		stem := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		want := ""
		for _, id := range ids {
			if (stem == id || strings.HasPrefix(stem, id+"-")) && len(id) > len(want) {
				want = id
			}
		}
		if want == "" {
			t.Errorf("%s: no format named by the file name", e.Name())
			continue
		}
		raw, err := os.ReadFile(filepath.Join("testdata", "imports", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		got := DetectImportFormat(raw)
		if !SameImportParser(got, want) {
			t.Errorf("%s: detected as %q, want %q", e.Name(), got, want)
			continue
		}
		fs, err := ParseImport("import-other-x", "", raw)
		if err != nil || len(fs) == 0 {
			t.Errorf("%s: parse: %d findings, %v", e.Name(), len(fs), err)
		}
	}
}

func TestImportEmptyAndAmbiguous(t *testing.T) {
	// An empty array is ambiguous: detection fails, an explicit format works.
	if DetectImportFormat([]byte(`[]`)) != "" {
		t.Error("[] must not be detected")
	}
	for _, f := range []string{"eslint", "checkov", "pip-audit", "snyk"} {
		if fs, err := ParseImport("import-other-x", f, []byte(`[]`)); err != nil || len(fs) != 0 {
			t.Errorf("%s: empty report: %v %d", f, err, len(fs))
		}
	}
	// Empty reports with the tool's envelope are detected.
	for doc, f := range map[string]string{
		`{"errors":[],"generated_at":"x","metrics":{},"results":[]}`:                  "bandit",
		`{"Golang errors":{},"Issues":[],"Stats":{}}`:                                 "gosec",
		`{"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}`:                 "npm-audit",
		`{"dependencies":[],"fixes":[]}`:                                              "pip-audit",
		`{"reportSchema":"1.1","dependencies":[]}`:                                    "dependency-check",
		`{"check_type":"terraform","results":{"failed_checks":[]}}`:                   "checkov",
		`{"vulnerabilities":[],"ok":true,"dependencyCount":3,"packageManager":"npm"}`: "snyk",
	} {
		if got := DetectImportFormat([]byte(doc)); got != f {
			t.Errorf("%s: detected %q, want %q", doc, got, f)
		}
		if fs, err := ParseImport("import-other-x", f, []byte(doc)); err != nil || len(fs) != 0 {
			t.Errorf("%s: %v %d", f, err, len(fs))
		}
	}
	// Malformed records are errors, not silently skipped.
	for f, doc := range map[string]string{
		"gosec":  `{"Issues":[{"severity":"HIGH"}],"Stats":{}}`,
		"bandit": `{"results":[{"filename":"a.py"}],"metrics":{},"generated_at":"x"}`,
		"snyk":   `{"vulnerabilities":[{"title":"x"}],"packageManager":"npm"}`,
	} {
		if _, err := ParseImport("import-other-x", f, []byte(doc)); err == nil {
			t.Errorf("%s: malformed record accepted", f)
		}
	}
}

func TestImportNaturalCategory(t *testing.T) {
	raw, _ := os.ReadFile("testdata/imports/sonarqube.json")
	fs, err := ParseImport("import-other-sonar", "sonarqube", raw)
	if err != nil || fs[0].Category != "sast" || fs[1].Category != "other" {
		t.Fatalf("categories: %v %+v", err, fs)
	}
	fs, _ = ParseImport("import-sast-sonar", "sonarqube", raw)
	if fs[1].Category != "sast" {
		t.Error("an explicit import category applies to every finding")
	}
}

func TestPurlNameVersion(t *testing.T) {
	for purl, nv := range map[string][2]string{
		"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1": {"log4j-core", "2.14.1"},
		"pkg:npm/%40babel/core@7.24.0?arch=x":                  {"core", "7.24.0"},
		"pkg:pypi/django@4.2":                                  {"django", "4.2"},
		"cpe:2.3:a:x":                                          {"", ""},
	} {
		if n, v := purlNameVersion(purl); n != nv[0] || v != nv[1] {
			t.Errorf("%s: %s %s", purl, n, v)
		}
	}
}
