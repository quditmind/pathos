package scanners

import (
	"bytes"
	"slices"
	"testing"
)

func TestScanTypeRegistry(t *testing.T) {
	want := []string{"sast", "dast", "sca", "secrets", "iac", "container", "api", "iast", "mobile", "fuzzing", "license", "sbom", "malware",
		"code-quality", "supply-chain", "crypto", "configuration", "cicd", "binary", "ai", "runtime", "compliance", "license-policy",
		"database", "manual"}
	if len(ScanTypes) != 25 {
		t.Fatalf("%d scan types", len(ScanTypes))
	}
	var ids []string
	for _, st := range ScanTypes {
		ids = append(ids, st.ID)
		if st.Name == "" || st.Description == "" || st.Categories == nil {
			t.Errorf("incomplete scan type %+v", st)
		}
		for _, c := range st.Categories {
			if !IsFindingCategory(c) {
				t.Errorf("%s: unknown category %s", st.ID, c)
			}
		}
		for _, k := range st.Tools {
			if _, ok := Lookup(k); !ok && k != LicensePolicy {
				t.Errorf("%s: tool %s is not in the catalog", st.ID, k)
			}
		}
		for _, f := range st.ImportFormats {
			if _, ok := LookupImportFormat(f); !ok {
				t.Errorf("%s: import format %s is not registered", st.ID, f)
			}
		}
		if _, ok := LookupScanType(st.ID); !ok {
			t.Errorf("lookup %s", st.ID)
		}
	}
	slices.Sort(want)
	slices.Sort(ids)
	if !slices.Equal(ids, want) {
		t.Errorf("scan types: %v", ids)
	}
	// Every new finding category belongs to a scan type.
	for _, c := range FindingCategories {
		if c == "other" {
			continue
		}
		if !slices.ContainsFunc(ScanTypes, func(st ScanType) bool { return slices.Contains(st.Categories, c) }) {
			t.Errorf("category %s has no scan type", c)
		}
	}
	// Every available catalog tool covers at least one scan type, except
	// CodeGraph discovery and reverse engineering (they build graphs, they
	// are not kinds of check).
	for _, sc := range Catalog {
		if sc.AdapterAvailable && len(ScanTypesOf(sc.Key)) == 0 && !IsGraphTool(sc.Key) && !IsREATool(sc.Key) {
			t.Errorf("%s covers no scan type", sc.Key)
		}
	}
	if !slices.Contains(ScanTypesOf("bandit"), "sast") || !slices.Contains(ScanTypesOf("shellcheck"), "code-quality") {
		t.Error("ScanTypesOf")
	}
	sast, _ := LookupScanType("sast")
	formats := ScanTypeImportFormats(sast)
	if !slices.ContainsFunc(formats, func(f ImportFormat) bool { return f.ID == "bandit" }) ||
		slices.ContainsFunc(formats, func(f ImportFormat) bool { return f.ID == "sarif" }) {
		t.Errorf("sast formats: %v", formats)
	}
	if !slices.ContainsFunc(GenericImportFormats(), func(f ImportFormat) bool { return f.ID == "sarif" }) {
		t.Error("SARIF is a generic format")
	}
	if got := WithScanTypes(Scanner{Key: Gitleaks}).ScanTypes; !slices.Equal(got, []string{"secrets"}) {
		t.Errorf("WithScanTypes: %v", got)
	}
}

func TestTargetsOf(t *testing.T) {
	cases := map[string][]string{
		Gitleaks: {"repository"}, TrivyImage: {"image"}, Nuclei: {"url", "api"}, BinaryHardening: {"repository"},
		EndpointCheck: {"url"}, Cosign: {"image", "binary"}, "zap": {"url", "api"},
	}
	for k, want := range cases {
		sc, _ := Lookup(k)
		if got := TargetsOf(sc); !slices.Equal(got, want) {
			t.Errorf("%s: %v, want %v", k, got, want)
		}
	}
	for _, sc := range append(append([]Scanner{}, Catalog...), Builtins...) {
		if sc.Network != "none" && sc.Network != "target" && sc.Network != "registry" {
			t.Errorf("%s: network %q", sc.Key, sc.Network)
		}
		if sc.Intrusive && sc.Network != "target" {
			t.Errorf("%s: intrusive tools contact the target", sc.Key)
		}
	}
}

// TestImportFormatCategories checks the default category of the import
// formats of the PATHOS 2.0 categories, the natural category of their
// findings (import category "other") and the formats of each scan type.
func TestImportFormatCategories(t *testing.T) {
	defaults := map[string]string{
		"schemathesis": "api", "restler": "api", "42crunch": "api",
		"mobsf": "mobile", "apkleaks": "mobile", "nowsecure": "mobile",
		"clusterfuzzlite": "fuzz", "libfuzzer": "fuzz", "gl-coverage-fuzzing": "fuzz",
		"garak": "ai", "promptfoo": "ai", "modelscan": "ai",
		"falco": "runtime", "tetragon": "runtime", "tracee": "runtime",
		"contrast": "iast",
		"prowler":  "compliance", "prowler-csv": "compliance", "scoutsuite": "compliance", "defender-cloud": "compliance",
		"cloudsploit": "compliance", "kube-bench": "compliance",
		"poutine": "cicd", "legitify": "cicd", "scorecard": "supply-chain",
		"testssl": "misconfiguration", "sslyze": "misconfiguration", "sslscan": "misconfiguration",
		"phpstan": "code-quality", "shellcheck": "code-quality",
		// Per finding: each finding keeps its own category.
		"asff": "", "gcp-scc": "", "gitlab": "", "psalm": "", "ruff": "", "pylint": "", "golangci-lint": "", "codacy": "",
		"spotbugs": "", "pmd": "", "cppcheck": "", "coverity": "", "klocwork": "", "polaris": "",
	}
	for id, want := range defaults {
		f, ok := LookupImportFormat(id)
		if !ok || f.Category != want {
			t.Errorf("%s: default category %q, want %q", id, f.Category, want)
		}
	}
	natural := []struct{ file, format, cat string }{
		{"garak.jsonl", "garak", "ai"}, {"promptfoo.json", "promptfoo", "ai"},
		{"falco.jsonl", "falco", "runtime"}, {"tetragon.jsonl", "tetragon", "runtime"}, {"tracee.jsonl", "tracee", "runtime"},
		{"contrast.csv", "contrast", "iast"}, {"kube-bench.json", "kube-bench", "compliance"},
		{"poutine.json", "poutine", "cicd"}, {"legitify.json", "legitify", "cicd"}, {"scorecard.json", "scorecard", "supply-chain"},
		{"testssl.json", "testssl", "misconfiguration"}, {"sslyze.json", "sslyze", "misconfiguration"}, {"sslscan.xml", "sslscan", "misconfiguration"},
		{"libfuzzer.log", "libfuzzer", "fuzz"}, {"gl-coverage-fuzzing.json", "gitlab", "fuzz"},
		{"phpstan.json", "phpstan", "code-quality"}, {"shellcheck.json", "shellcheck", "code-quality"},
	}
	for _, c := range natural {
		raw := readImportFixture(t, c.file)
		for _, key := range []string{"import-other-x", "import-" + firstNonEmpty(defaults[c.format], "other") + "-x"} {
			fs, err := ParseImport(key, c.format, raw)
			if err != nil || len(fs) == 0 {
				t.Fatalf("%s: %v (%d findings)", c.file, err, len(fs))
			}
			for i, f := range fs {
				if f.Category != c.cat {
					t.Errorf("%s (%s): finding %d category %q, want %q", c.file, key, i, f.Category, c.cat)
				}
			}
		}
	}
	// GitLab API fuzzing reports are api findings.
	api := bytes.ReplaceAll(readImportFixture(t, "gl-coverage-fuzzing.json"), []byte(`"coverage_fuzzing"`), []byte(`"api_fuzzing"`))
	if fs, err := ParseImport("import-other-x", "gitlab", api); err != nil || len(fs) == 0 || fs[0].Category != "api" {
		t.Errorf("gitlab api_fuzzing: %v %+v", err, fs)
	}
	// Every scan type that has import formats lists them.
	want := map[string][]string{
		"api": {"schemathesis", "restler", "42crunch", "zap", "nuclei"}, "iast": {"contrast"}, "mobile": {"mobsf", "apkleaks", "nowsecure", "mobsfscan"},
		"fuzzing": {"clusterfuzzlite", "libfuzzer", "gl-coverage-fuzzing"}, "ai": {"garak", "promptfoo", "modelscan"},
		"runtime": {"falco", "tetragon", "tracee", "gcp-scc", "asff"}, "compliance": {"prowler", "prowler-csv", "scoutsuite", "asff", "defender-cloud", "gcp-scc", "cloudsploit", "kube-bench"},
		"cicd": {"poutine", "legitify"}, "supply-chain": {"scorecard"}, "configuration": {"testssl", "sslyze", "sslscan"}, "crypto": {"testssl", "sslyze", "sslscan"},
		"code-quality": {"phpstan", "psalm", "shellcheck", "ruff", "pylint", "golangci-lint", "codacy", "spotbugs", "pmd", "cppcheck", "coverity", "klocwork", "polaris"},
		"sast":         {"bandit", "psalm", "ruff", "coverity", "gitlab"}, "secrets": {"gitleaks", "trivy"}, "manual": {"hackerone", "hackerone-csv", "bugcrowd", "intigriti"},
	}
	for id, formats := range want {
		st, _ := LookupScanType(id)
		got := ScanTypeImportFormats(st)
		for _, f := range formats {
			if !slices.ContainsFunc(got, func(g ImportFormat) bool { return g.ID == f }) {
				t.Errorf("%s: import format %s not listed", id, f)
			}
		}
	}
	// API security lists API tools, not every DAST tool; CI/CD not every IaC tool.
	for id, f := range map[string]string{"api": "nikto", "cicd": "checkov"} {
		st, _ := LookupScanType(id)
		if slices.ContainsFunc(ScanTypeImportFormats(st), func(g ImportFormat) bool { return g.ID == f }) {
			t.Errorf("%s lists %s", id, f)
		}
	}
	// Formats with per-finding categories are listed by their scan types, not as generic formats.
	for _, f := range GenericImportFormats() {
		if f.ID != "sarif" && f.ID != "pathos" && f.ID != "csv" {
			t.Errorf("generic format %s", f.ID)
		}
	}
}
