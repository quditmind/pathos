package scanners

import (
	"slices"
	"testing"
)

func TestMobileBinaryAIFuzzCatalog(t *testing.T) {
	for key, want := range map[string]struct {
		family, category string
		scanTypes        []string
		targets          []string
		network          string
		intrusive, build bool
	}{
		"mobsfscan":     {"mobile", "mobile", []string{"mobile"}, []string{"mobile-app"}, "none", false, false},
		"apkleaks":      {"mobile", "mobile", []string{"secrets", "mobile"}, []string{"mobile-app"}, "none", false, false},
		"quark-engine":  {"mobile", "malware", []string{"mobile", "malware"}, []string{"mobile-app"}, "none", false, false},
		MobileAppChecks: {"mobile", "mobile", []string{"mobile"}, []string{"mobile-app"}, "none", false, false},
		"cve-bin-tool":  {"binary", "sca", []string{"sca", "binary"}, []string{"binary"}, "none", false, false},
		"capa":          {"binary", "binary", []string{"malware", "binary"}, []string{"binary"}, "none", false, false},
		"yara-x":        {"binary", "malware", []string{"malware", "binary"}, []string{"repository", "binary", "mobile-app"}, "none", false, false},
		"modelscan":     {"ai", "ai", []string{"ai"}, []string{"repository", "model"}, "none", false, false},
		"garak":         {"ai", "ai", []string{"ai"}, []string{"llm-endpoint"}, "target", true, false},
		"promptfoo":     {"ai", "ai", []string{"ai"}, []string{"llm-endpoint"}, "target", true, false},
		"go-fuzz":       {"fuzz", "fuzz", []string{"fuzzing"}, []string{"repository"}, "none", false, true},
		"atheris":       {"fuzz", "fuzz", []string{"fuzzing"}, []string{"repository"}, "none", false, true},
	} {
		sc, ok := Lookup(key)
		if !ok || !sc.AdapterAvailable || sc.Family != want.family || sc.Category != want.category || sc.License == "" || sc.DefaultEnabled {
			t.Errorf("%s: %+v", key, sc)
			continue
		}
		if !ManifestRouted(key) {
			t.Errorf("%s is run by a family image manifest", key)
		}
		if got := ScanTypesOf(key); !slices.Equal(got, want.scanTypes) {
			t.Errorf("%s scan types %v, want %v", key, got, want.scanTypes)
		}
		if got := TargetsOf(sc); !slices.Equal(got, want.targets) {
			t.Errorf("%s targets %v, want %v", key, got, want.targets)
		}
		if sc.Network != want.network || sc.Intrusive != want.intrusive || sc.RequiresBuild != want.build {
			t.Errorf("%s network %s intrusive %v build %v", key, sc.Network, sc.Intrusive, sc.RequiresBuild)
		}
	}
	// Jazzer is catalogued but not shipped.
	if sc, ok := Lookup("jazzer"); !ok || sc.AdapterAvailable || !slices.Contains(ScanTypesOf("jazzer"), "fuzzing") {
		t.Errorf("jazzer: %+v", sc)
	}
	// The AI-BOM is a built-in inventory of the core worker.
	if sc, ok := Lookup(AIBOM); !ok || sc.Family != "core" || sc.Category != "sbom" || !slices.Contains(ScanTypesOf(AIBOM), "ai") ||
		!slices.Contains(ScanTypesOf(AIBOM), "sbom") || ManifestRouted(AIBOM) {
		t.Errorf("ai-bom: %+v", sc)
	}
	if !slices.Equal(TargetScanners["mobile-app"], []string{BinaryHardening, Cosign}) {
		t.Errorf("mobile app target scanners: %v", TargetScanners["mobile-app"])
	}
}
