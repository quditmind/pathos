package scanners

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// importCase is one fixture of a native import format and the expected
// mapping of some of its findings (see TestImportJSONFormats).
type importCase struct {
	file, format string
	count        int
	checks       map[int]want
	// cats are the expected natural categories of the findings when the
	// import category is "other" (nil: not checked).
	cats map[int]string
	// secrets must not appear in the stored report, the located records or
	// the finding text.
	secrets []string
}

// runImportCases checks detection, the mapping, stable fingerprints,
// locating every finding in the stored (sanitised) report and secret
// removal for each case.
func runImportCases(t *testing.T, cases []importCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join("testdata", "imports", c.file))
			if err != nil {
				t.Fatal(err)
			}
			if got := DetectImportFormat(raw); !SameImportParser(got, c.format) {
				t.Fatalf("detected %q, want %q", got, c.format)
			}
			f, ok := LookupImportFormat(c.format)
			if !ok {
				t.Fatalf("format %q not registered", c.format)
			}
			cat := f.Category
			if cat == "" {
				cat = "other"
			}
			key := "import-" + cat + "-x"
			stored := SanitizeImport(c.format, raw)
			fs, err := ParseImport(key, c.format, stored)
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
			if c.cats != nil {
				other, err := ParseImport("import-other-x", c.format, stored)
				if err != nil {
					t.Fatal(err)
				}
				for i, want := range c.cats {
					if other[i].Category != want {
						t.Errorf("finding %d category = %q, want %q", i, other[i].Category, want)
					}
				}
			}
			for _, g := range fs {
				if g.ScannerKey != key || g.Fingerprint == "" || g.Title == "" || !slices.Contains(Severities, g.Severity) || g.CWE == nil {
					t.Errorf("incomplete finding %+v", g)
				}
			}
			again, _ := ParseImport(key, "", stored)
			for i := range fs {
				if i >= len(again) || again[i].Fingerprint != fs[i].Fingerprint {
					t.Fatalf("fingerprint %d not stable (detected vs explicit format)", i)
				}
			}
			// Identity never depends on removed secret values.
			if orig, _ := ParseImport(key, c.format, raw); len(orig) == len(fs) {
				for i := range fs {
					if orig[i].Fingerprint != fs[i].Fingerprint {
						t.Errorf("finding %d: fingerprint depends on sanitised values", i)
					}
				}
			} else {
				t.Errorf("unsanitised report: %d findings, want %d", len(orig), len(fs))
			}
			for _, g := range fs {
				for _, src := range [][]byte{raw, stored} {
					loc, err := LocateImport(key, c.format, src, g.Fingerprint)
					if err != nil || len(loc.Raw) < 3 {
						t.Fatalf("locate %s: %v", g.Title, err)
					}
					for _, s := range c.secrets {
						if strings.Contains(string(loc.Raw), s) {
							t.Errorf("secret %q in the located record", s)
						}
					}
				}
				for _, s := range c.secrets {
					if strings.Contains(g.Title+g.Description, s) {
						t.Errorf("secret %q in finding text", s)
					}
				}
			}
			for _, s := range c.secrets {
				if strings.Contains(string(stored), s) {
					t.Errorf("secret %q in the stored report", s)
				}
			}
		})
	}
}
