package scanners

import (
	"slices"
	"testing"
)

func TestCheckKinds(t *testing.T) {
	if len(CheckKinds) != 20 {
		t.Fatalf("%d kinds of check, want 20", len(CheckKinds))
	}
	// Every scan type belongs to exactly one kind (20 kinds or outside
	// group), and no scan type is removed.
	for _, st := range ScanTypes {
		n := 0
		for _, k := range append(append([]CheckKind{}, CheckKinds...), OutsideKinds...) {
			if slices.Contains(k.ScanTypes, st.ID) {
				n++
			}
		}
		if n != 1 {
			t.Errorf("scan type %s is in %d kinds", st.ID, n)
		}
	}
	for _, k := range CheckKinds {
		if len(k.Tools) != ToolsPerKind {
			t.Errorf("%s: %d tools, want %d (the §7 table)", k.ID, len(k.Tools), ToolsPerKind)
		}
		for _, tool := range k.Tools {
			switch tool.Source {
			case "catalog":
				if _, ok := Lookup(tool.Key); !ok {
					t.Errorf("%s: %s (%s) is not catalogued", k.ID, tool.Name, tool.Key)
				}
			case "gap":
				if tool.Key != "" && tool.Mode == "" {
					t.Errorf("%s: gap %s has a key but no mode", k.ID, tool.Name)
				}
			case "feed", "pathos":
			default:
				t.Errorf("%s: %s has source %q", k.ID, tool.Name, tool.Source)
			}
		}
		if len(k.ListedKeys()) > ToolsPerKind {
			t.Errorf("%s lists more than %d catalogued tools", k.ID, ToolsPerKind)
		}
	}
	// Every catalogued tool that a worker image runs belongs to a kind.
	for _, sc := range append(append([]Scanner{}, Catalog...), SyftUtility) {
		if sc.AdapterAvailable && len(KindsOfTool(sc.Key)) == 0 {
			t.Errorf("%s belongs to no kind of check", sc.Key)
		}
	}
	// Every finding category has a kind.
	for _, c := range FindingCategories {
		if _, ok := LookupKind(KindOfCategory(c)); !ok {
			t.Errorf("category %s: unknown kind %s", c, KindOfCategory(c))
		}
	}
	if KindOfScanType("iac") != "iac" || KindOfScanType("ai") != "ai" || KindOfScanType("license-policy") != "license" {
		t.Error("KindOfScanType")
	}
}

func TestKindOfFinding(t *testing.T) {
	cases := []struct {
		cat  string
		keys []string
		want string
	}{
		{"sast", []string{"opengrep"}, "sast-deep"},
		{"sast", []string{"bandit"}, "sast-language"},
		{"sast", []string{"bandit", "opengrep"}, "sast-deep"},
		{"sast", []string{"import-sast-gosec"}, "sast-language"},
		{"sast", nil, "sast-deep"},
		{"code-quality", []string{"pmd"}, "sast-language"},
		{"misconfiguration", []string{"testssl"}, "web-api"},
		{"misconfiguration", []string{"opengrep"}, "sast-deep"},
		{"sca", []string{"trivy-fs", "grype"}, "dependencies"},
		{"eol", []string{"endoflife"}, "dependencies"},
		{"ai", []string{"modelscan"}, "ai"},
		{"other", []string{"import-other-x"}, "other"},
		{"runtime", nil, "cloud-kubernetes"},
	}
	for _, c := range cases {
		if got := KindOfFinding(c.cat, c.keys); got != c.want {
			t.Errorf("KindOfFinding(%s, %v) = %s, want %s", c.cat, c.keys, got, c.want)
		}
	}
	if KindSQL("f") == "" || !slices.Contains(kindOverrides[0].Tools, "bandit") {
		t.Error("KindSQL / overrides")
	}
}

func TestEngines(t *testing.T) {
	cases := []struct {
		keys []string
		want int
	}{
		{nil, 0},
		{[]string{"trivy-fs"}, 1},
		{[]string{"trivy-fs", "import-sca-trivy", "sarif-trivy"}, 1},
		{[]string{"trivy-fs", "grype", "osv-scanner"}, 3},
		{[]string{"zap", "zap-baseline", "import-dast-zap"}, 1},
		{[]string{"import-supply-chain-scorecard", "scorecard"}, 1},
		{[]string{"gitleaks", "trufflehog", "import-secrets-trufflehog-v2"}, 2},
	}
	for _, c := range cases {
		if got := EnginesCount(c.keys); got != c.want {
			t.Errorf("EnginesCount(%v) = %d, want %d", c.keys, got, c.want)
		}
	}
}
