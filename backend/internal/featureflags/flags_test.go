package featureflags

import (
	"testing"

	"pathos/internal/platform/diag"
)

func TestKnownFlags(t *testing.T) {
	want := []string{"connectors", "onboarding", "codegraph", "threat_models", "reverse_engineering", "remediation_workspace", "continuous_monitoring", "lifecycle_overview", "scan_profile_tiers"}
	for _, n := range want {
		if !IsKnown(n) {
			t.Errorf("flag %s missing", n)
		}
	}
	if IsKnown("nope") {
		t.Error("unknown flag accepted")
	}
	seen := map[string]bool{}
	for _, f := range Known {
		if seen[f.Name] || f.Description == "" || f.Milestone == "" {
			t.Errorf("flag %+v: duplicate or incomplete", f)
		}
		seen[f.Name] = true
	}
}

func TestDisabledError(t *testing.T) {
	e := Disabled("codegraph")
	if e.Status != 404 || e.Code != "feature_disabled" || e.DiagCode() != "PTH-PLAT-1007" {
		t.Fatalf("%+v %s", e, e.DiagCode())
	}
	if _, ok := diag.Lookup(e.DiagCode()); !ok {
		t.Fatal("code not in catalogue")
	}
}
