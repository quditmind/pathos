package worker

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestWriteCustomRules(t *testing.T) {
	dir, err := writeCustomRules([]byte(`{"custom_rules":[{"name":"../../etc/passwd","content":"rules: []"}]}`))
	if err != nil || dir == "" {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	files, _ := filepath.Glob(filepath.Join(dir, "*"))
	if len(files) != 1 || filepath.Base(files[0]) != "custom-000.yml" {
		t.Errorf("file names are generated, never taken from the server: %v", files)
	}
	if d, err := writeCustomRules([]byte(`{}`)); d != "" || err != nil {
		t.Errorf("no rules: %q %v", d, err)
	}
}

// The framework configuration rules (workers/rules/pathos-misconfig-*.yml)
// are complete: every rule has a message, CWE, references, severity and
// the misconfiguration category, and at least one positive test fixture
// in workers/rules-tests (scripts/test-opengrep-rules.py runs them).
func TestMisconfigurationRules(t *testing.T) {
	files, _ := filepath.Glob("../../../workers/rules/pathos-misconfig-*.yml")
	if len(files) < 3 {
		t.Fatalf("expected the Spring, Django and Express rule files, got %v", files)
	}
	var fixtures strings.Builder
	_ = filepath.WalkDir("../../../workers/rules-tests", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p) // #nosec G304 -- test fixtures in the repository
			fixtures.Write(b)
		}
		return nil
	})
	annotated := fixtures.String()
	seen := map[string]bool{}
	frameworks := map[string]int{}
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- rule files in the repository
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []map[string]any `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, r := range doc.Rules {
			id, _ := r["id"].(string)
			if !strings.HasPrefix(id, "pathos.misconfig.") || seen[id] {
				t.Errorf("%s: rule id %q must be unique and start with pathos.misconfig.", f, id)
			}
			seen[id] = true
			if msg, _ := r["message"].(string); len(msg) < 40 {
				t.Errorf("%s: message too short", id)
			}
			switch r["severity"] {
			case "ERROR", "WARNING", "INFO":
			default:
				t.Errorf("%s: severity %v", id, r["severity"])
			}
			if langs, _ := r["languages"].([]any); len(langs) == 0 {
				t.Errorf("%s: no languages", id)
			}
			meta, _ := r["metadata"].(map[string]any)
			if meta["category"] != "misconfiguration" || meta["license"] != "Apache-2.0" {
				t.Errorf("%s: metadata category/license: %v", id, meta)
			}
			if cwe, _ := meta["cwe"].([]any); len(cwe) == 0 || !strings.HasPrefix(cwe[0].(string), "CWE-") {
				t.Errorf("%s: CWE missing", id)
			}
			if refs, _ := meta["references"].([]any); len(refs) == 0 || !strings.HasPrefix(refs[0].(string), "https://") {
				t.Errorf("%s: references missing", id)
			}
			fw, _ := meta["framework"].(string)
			frameworks[fw]++
			hasPattern := false
			for _, k := range []string{"pattern", "patterns", "pattern-either", "pattern-regex"} {
				hasPattern = hasPattern || r[k] != nil
			}
			if !hasPattern {
				t.Errorf("%s: no pattern", id)
			}
			if !strings.Contains(annotated, "ruleid: "+id) && !strings.Contains(annotated, ", "+id) {
				t.Errorf("%s: no positive test fixture in workers/rules-tests", id)
			}
		}
	}
	for _, fw := range []string{"spring", "django", "express"} {
		if frameworks[fw] < 4 {
			t.Errorf("%s: only %d rules", fw, frameworks[fw])
		}
	}
}

// The PATHOS rule packs for cryptography, database security, AI/LLM
// applications and CI/CD pipelines (workers/rules/pathos-<pack>.yml) are
// complete: every rule has an id pathos.<pack>.*, a message, CWE,
// references, severity, the pack's metadata category, and both a positive
// ("ruleid:") and a negative ("ok:") test case in workers/rules-tests
// (scripts/test-opengrep-rules.py runs them with Opengrep).
func TestRulePacks(t *testing.T) {
	var fixtures strings.Builder
	_ = filepath.WalkDir("../../../workers/rules-tests", func(p string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			b, _ := os.ReadFile(p) // #nosec G304 -- test fixtures in the repository
			fixtures.Write(b)
			fixtures.WriteByte('\n')
		}
		return nil
	})
	annotated := fixtures.String()
	annotatedAs := func(kind, id string) bool {
		for _, l := range strings.Split(annotated, "\n") {
			_, rest, ok := strings.Cut(l, kind+": ")
			if !ok {
				continue
			}
			for _, r := range strings.Split(rest, ",") {
				if strings.TrimSpace(r) == id {
					return true
				}
			}
		}
		return false
	}
	seen := map[string]bool{}
	for _, pack := range []string{"crypto", "database", "ai", "cicd"} {
		file := "../../../workers/rules/pathos-" + pack + ".yml"
		raw, err := os.ReadFile(file) // #nosec G304 -- rule files in the repository
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Rules []map[string]any `yaml:"rules"`
		}
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		if len(doc.Rules) < 8 {
			t.Errorf("%s: only %d rules", pack, len(doc.Rules))
		}
		for _, r := range doc.Rules {
			id, _ := r["id"].(string)
			if !strings.HasPrefix(id, "pathos."+pack+".") || seen[id] {
				t.Errorf("%s: rule id %q must be unique and start with pathos.%s.", pack, id, pack)
			}
			seen[id] = true
			if msg, _ := r["message"].(string); len(msg) < 60 {
				t.Errorf("%s: message too short", id)
			}
			switch r["severity"] {
			case "ERROR", "WARNING", "INFO":
			default:
				t.Errorf("%s: severity %v", id, r["severity"])
			}
			if langs, _ := r["languages"].([]any); len(langs) == 0 {
				t.Errorf("%s: no languages", id)
			}
			meta, _ := r["metadata"].(map[string]any)
			if meta["category"] != pack || meta["license"] != "Apache-2.0" {
				t.Errorf("%s: metadata category/license: %v", id, meta)
			}
			if cwe, _ := meta["cwe"].([]any); len(cwe) == 0 || !strings.HasPrefix(cwe[0].(string), "CWE-") {
				t.Errorf("%s: CWE missing", id)
			}
			if refs, _ := meta["references"].([]any); len(refs) == 0 || !strings.HasPrefix(refs[0].(string), "https://") {
				t.Errorf("%s: references missing", id)
			}
			hasPattern := false
			for _, k := range []string{"pattern", "patterns", "pattern-either", "pattern-regex", "pattern-sinks"} {
				hasPattern = hasPattern || r[k] != nil
			}
			if !hasPattern {
				t.Errorf("%s: no pattern", id)
			}
			if !annotatedAs("ruleid", id) || !annotatedAs("ok", id) {
				t.Errorf("%s: needs a positive (ruleid:) and a negative (ok:) test case in workers/rules-tests", id)
			}
		}
	}
}
