package scanners

import (
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
	// Every available catalog tool covers at least one scan type.
	for _, sc := range Catalog {
		if sc.AdapterAvailable && len(ScanTypesOf(sc.Key)) == 0 {
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
