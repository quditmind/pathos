package scanners

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// The worker-sca wrapper runs npm, yarn, pnpm and Composer audit and
// pip-audit once per lockfile or requirements file and stores the reports
// in a PATHOS envelope. Regression (benchmark 2026-11-19): npm audit read
// only the root lockfile and pip-audit refused a package pinned in two
// requirements files, so monorepos got no findings from either.
func TestPathosEnvelope(t *testing.T) {
	for _, c := range []struct{ format, fixture, file string }{
		{"npm-audit", "npm-audit.json", "package-lock.json"},
		{"pip-audit", "pip-audit.json", "requirements.txt"},
		{"composer-audit", "composer-audit.json", "composer.lock"},
		{"pnpm-audit", "pnpm-audit.json", "pnpm-lock.yaml"},
		{"yarn-audit", "yarn-audit.jsonl", "yarn.lock"},
	} {
		raw, err := os.ReadFile("testdata/imports/" + c.fixture)
		if err != nil {
			t.Fatal(err)
		}
		single, err := ParseImport(c.format, c.format, raw)
		if err != nil || len(single) == 0 {
			t.Fatalf("%s: %v %d", c.format, err, len(single))
		}
		entry := func(file string) map[string]any {
			if c.format == "yarn-audit" {
				return map[string]any{"file": file, "report_text": string(raw)}
			}
			return map[string]any{"file": file, "report": json.RawMessage(raw)}
		}
		env, _ := json.Marshal(map[string]any{"pathos_reports": []any{entry("services/a/" + c.file), entry("services/b/" + c.file)}})
		fs, err := ParseImport(c.format, c.format, env)
		if err != nil || len(fs) != 2*len(single) {
			t.Fatalf("%s: %v: %d findings, want %d", c.format, err, len(fs), 2*len(single))
		}
		files := map[string]int{}
		fps := map[string]bool{}
		for _, f := range fs {
			files[f.FilePath]++
			fps[f.Fingerprint] = true
		}
		if files["services/a/"+c.file] != len(single) || files["services/b/"+c.file] != len(single) {
			t.Errorf("%s: files %v", c.format, files)
		}
		if len(fps) != len(fs) {
			t.Errorf("%s: the same vulnerability in two projects is two findings (%d fingerprints for %d findings)", c.format, len(fps), len(fs))
		}
		// Evidence is located in the stored envelope.
		if loc, err := LocateImport(c.format, c.format, env, fs[len(fs)-1].Fingerprint); err != nil || loc == nil {
			t.Errorf("%s: locate: %v", c.format, err)
		}
		// An unchanged envelope is stored as it came.
		if string(SanitizeImport(c.format, env)) != string(env) {
			t.Errorf("%s: sanitizing rewrote a report without secrets", c.format)
		}
	}
	// An empty envelope has no findings and no error; a broken one fails.
	if fs, err := ParseImport("npm-audit", "npm-audit", []byte(`{"pathos_reports": []}`)); err != nil || len(fs) != 0 {
		t.Errorf("empty envelope: %v %d", err, len(fs))
	}
	if _, err := ParseImport("npm-audit", "npm-audit", []byte(`{"pathos_reports": [}`)); err == nil {
		t.Error("broken envelope accepted")
	}
}

// Findings located in a new file keep a legacy fingerprint with the file
// PATHOS 2.0 used, so stored findings are re-keyed, not replaced.
func TestLegacyPathFingerprints(t *testing.T) {
	raw, _ := os.ReadFile("testdata/imports/pip-audit.json")
	old, _ := ParseImport("pip-audit", "pip-audit", raw)
	env, _ := json.Marshal(map[string]any{"pathos_reports": []any{map[string]any{"file": "svc/requirements.txt", "report": json.RawMessage(raw)}}})
	cur, _ := ParseImport("pip-audit", "pip-audit", env)
	if len(old) == 0 || len(cur) != len(old) {
		t.Fatalf("%d %d", len(old), len(cur))
	}
	for i := range cur {
		if cur[i].Fingerprint == old[i].Fingerprint || !cur[i].Matches(LegacyFingerprint(old[i], "")) {
			t.Errorf("%s: legacy fingerprint must be the 2.0 one", cur[i].Title)
		}
	}
	gv, _ := os.ReadFile("testdata/imports/govulncheck.json")
	o, _ := ParseImport("govulncheck", "govulncheck", gv)
	withDir := strings.Replace(string(gv), `"scanner_name"`, `"pathos_module_dir": "svc", "scanner_name"`, 1)
	n, _ := ParseImport("govulncheck", "govulncheck", []byte(withDir))
	for i := range n {
		if o[i].FilePath == "" {
			continue
		}
		if n[i].FilePath != "svc/go.mod" || !n[i].Matches(LegacyFingerprint(o[i], "")) {
			t.Errorf("govulncheck %s: %q legacy %v", n[i].RuleID, n[i].FilePath, n[i].Matches(LegacyFingerprint(o[i], "")))
		}
	}
}
