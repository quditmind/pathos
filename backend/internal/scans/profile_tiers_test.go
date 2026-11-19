package scans

import (
	"slices"
	"testing"

	"pathos/internal/scanners"
)

func TestTierSettings(t *testing.T) {
	sizes := map[string]int{}
	var prev []string
	for _, tier := range Tiers {
		st := TierSettings(tier)
		req := profileRequest{ProfileSettings: st}
		if err := req.validate(); err != nil {
			t.Fatalf("%s: seeded settings do not validate: %v", tier.ID, err)
		}
		keys := []string{}
		for _, ps := range req.Scanners {
			keys = append(keys, ps.Key)
			sc, ok := scanners.Lookup(ps.Key)
			if !ok {
				t.Fatalf("%s: unknown %s", tier.ID, ps.Key)
			}
			if tier.CoreOnly && sc.Family != "core" {
				t.Errorf("quick: %s is not a core tool", ps.Key)
			}
			if sc.Decision != "use" {
				t.Errorf("%s: seeds %s (decision %s)", tier.ID, ps.Key, sc.Decision)
			}
		}
		if !slices.Contains(keys, scanners.Gitleaks) {
			t.Errorf("%s: mandatory Gitleaks missing", tier.ID)
		}
		// A larger tier never has fewer tools.
		if len(keys) < len(prev) {
			t.Errorf("%s has %d tools, fewer than the previous tier (%d)", tier.ID, len(keys), len(prev))
		}
		prev = keys
		sizes[tier.ID] = len(keys)
	}
	// Comprehensive: every eligible catalogued tool.
	comp := TierSettings(Tiers[2])
	for _, sc := range scanners.Catalog {
		if profileEligible(sc) && !slices.ContainsFunc(comp.Scanners, func(ps ProfileScanner) bool { return ps.Key == sc.Key }) {
			t.Errorf("comprehensive misses %s", sc.Key)
		}
	}
	if sizes["quick"] >= sizes["standard"] || sizes["standard"] >= sizes["comprehensive"] {
		t.Errorf("tier sizes %v", sizes)
	}
	t.Logf("tier sizes %v", sizes)
}

func TestKindProgressOf(t *testing.T) {
	st := []Stage{
		{Key: "source"},
		{Scanner: "checkov", KindOfCheck: "iac", KindOfCheckName: "Infrastructure as code", Status: "succeeded"},
		{Scanner: "kics", KindOfCheck: "iac", KindOfCheckName: "Infrastructure as code", Status: "running"},
		{Scanner: "tflint", KindOfCheck: "iac", KindOfCheckName: "Infrastructure as code", Status: "failed"},
		{Scanner: "gitleaks", KindOfCheck: "secrets", KindOfCheckName: "Secrets", Status: "pending"},
	}
	got := KindProgressOf(st)
	if len(got) != 2 || got[0].ID != "secrets" || got[1].ID != "iac" {
		t.Fatalf("%+v", got)
	}
	if iac := got[1]; iac.Total != 3 || iac.Finished != 2 || iac.Failed != 1 || iac.Running != 1 {
		t.Fatalf("%+v", iac)
	}
}
