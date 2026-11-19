package scanners

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func TestSASTPackCatalog(t *testing.T) {
	shipped := map[string]string{
		"gosec": "sast", "flawfinder": "sast", "cppcheck": "sast", "psalm": "sast", "phpstan": "code-quality", "ruff": "sast",
		"eslint-security": "sast", "semgrep-ce": "sast", "bearer": "sast", "trufflehog": "secrets", "detect-secrets": "secrets",
		"kingfisher": "secrets", "talisman": "secrets", "pylint": "code-quality", "golangci-lint": "code-quality",
	}
	for key, cat := range shipped {
		sc, ok := Lookup(key)
		if !ok || !sc.AdapterAvailable || sc.Family != "sast" || sc.Category != cat || sc.License == "" || sc.DefaultEnabled || sc.Network != "none" {
			t.Errorf("%s: %+v", key, sc)
		}
		if !ManifestRouted(key) || len(ScanTypesOf(key)) == 0 {
			t.Errorf("%s: routed %v, scan types %v", key, ManifestRouted(key), ScanTypesOf(key))
		}
	}
	// Licences that restrict use: Bearer (Elastic-2.0) and Semgrep CE (rules)
	// are optional; Brakeman is not bundled.
	for key, decision := range map[string]string{"bearer": "optional", "semgrep-ce": "optional", "brakeman": "restricted"} {
		if sc, _ := Lookup(key); sc.Decision != decision {
			t.Errorf("%s: decision %s", key, sc.Decision)
		}
	}
	for _, key := range []string{"brakeman", "sobelow", "pmd", "horusec", "devskim", "noseyparker", "whispers"} {
		if sc, ok := Lookup(key); !ok || sc.AdapterAvailable || !strings.HasPrefix(sc.Notes, "Not bundled") {
			t.Errorf("%s is catalogued as not bundled: %+v", key, sc)
		}
	}
	// Entries of catalog.go are replaced in place, never duplicated.
	seen := map[string]bool{}
	for _, sc := range Catalog {
		if seen[sc.Key] {
			t.Errorf("duplicate %s", sc.Key)
		}
		seen[sc.Key] = true
	}
	if Catalog[0].Key != Gitleaks {
		t.Error("catalog order")
	}
	for id, key := range map[string]string{"sast": "bearer", "secrets": "talisman", "code-quality": "golangci-lint", "crypto": Opengrep,
		"database": Opengrep, "ai": Opengrep, "cicd": Opengrep} {
		st, _ := LookupScanType(id)
		if !slices.Contains(st.Tools, key) {
			t.Errorf("scan type %s: %v", id, st.Tools)
		}
	}
	if st, _ := LookupScanType("cicd"); !strings.Contains(st.Note, "zizmor") || !strings.Contains(st.Note, "pathos.cicd") {
		t.Errorf("cicd note keeps the zizmor mapping and adds the rules: %q", st.Note)
	}
}

// The PATHOS rule packs are recorded in their own finding categories. The
// fixture is real Opengrep 2.0.0 output of the four packs on their test
// fixtures (workers/rules-tests), mounted at /work/fixture/src.
func TestRulePackCategories(t *testing.T) {
	raw, err := os.ReadFile("testdata/opengrep-packs.sarif")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{Opengrep, SemgrepCE} {
		fs, err := Parse(key, raw)
		if err != nil || len(fs) < 50 {
			t.Fatalf("%s: %v %d", key, err, len(fs))
		}
		cats := map[string]int{}
		for _, f := range fs {
			pack := strings.Split(f.RuleID, ".")[1]
			want := map[string]string{"crypto": "crypto", "database": "database", "ai": "ai", "cicd": "cicd"}[pack]
			if !strings.HasPrefix(f.RuleID, "pathos.") || f.Category != want || strings.HasPrefix(f.FilePath, "/") || f.Title == "" {
				t.Errorf("%s: %s %s %s", key, f.RuleID, f.Category, f.FilePath)
			}
			cats[f.Category]++
			if secretRuleRe.MatchString(f.RuleID) && f.Snippet != "" {
				t.Errorf("%s: hard-coded secret kept in the code context", f.RuleID)
			}
		}
		for _, c := range []string{"crypto", "database", "ai", "cicd"} {
			if cats[c] == 0 {
				t.Errorf("%s: no %s findings", key, c)
			}
		}
	}
	for id, want := range map[string]string{"x.rules.pathos.crypto.go.weak-hash": "crypto", "pathos.database.connection-string-tls-disabled": "database",
		"pathos.python.eval-injection": "", "pathos.cryptography.x": "", "custom.rule": ""} {
		if got := ruleCategory(id, nil); got != want {
			t.Errorf("%s: %q, want %q", id, got, want)
		}
	}
	if ruleCategory("custom.rule", map[string]any{"tags": []any{"security", "CICD"}}) != "cicd" {
		t.Error("administrator rules opt in with a metadata category")
	}
}
