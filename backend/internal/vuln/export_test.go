package vuln

import (
	"testing"
	"time"
)

func TestExportRoundTrip(t *testing.T) {
	zero, one, two := 0, 1, 2
	comps := []invComponent{
		{Ref: "app", Name: "app", Version: "1.0.0", Type: "application", Depth: &zero},
		{Ref: "lodash", Name: "lodash", Version: "4.17.20", PURL: "pkg:npm/lodash@4.17.20", Licenses: []string{"MIT"}, Depth: &one},
		{Ref: "qs", Name: "@hapi/qs", Version: "6.0.0", PURL: "pkg:npm/%40hapi/qs@6.0.0", Licenses: []string{"BSD 3 clause (custom)"}, Depth: &two},
	}
	edges := map[string][]string{"app": {"lodash"}, "lodash": {"qs"}}
	now := time.Date(2026, 11, 18, 2, 0, 0, 0, time.UTC)

	spdx, err := SPDXDocument("acme/api", comps, edges, now)
	if err != nil {
		t.Fatal(err)
	}
	if DetectSBOM(spdx) != "spdx" {
		t.Fatal("not detected as SPDX")
	}
	got, aliases, err := parseSPDX(spdx)
	if err != nil || len(got) != 3 || len(aliases) != 0 {
		t.Fatalf("SPDX parse: %v %d", err, len(got))
	}
	for _, c := range got {
		if c.Name == "@hapi/qs" && len(c.Licenses) != 0 {
			t.Errorf("a non-SPDX licence becomes NOASSERTION: %v", c.Licenses)
		}
		if c.Name == "lodash" && (len(c.Licenses) != 1 || c.Licenses[0] != "MIT" || c.PURL != "pkg:npm/lodash@4.17.20") {
			t.Errorf("lodash: %+v", c)
		}
	}
	g := ParseGraph(spdx)
	d := Depths(g)
	if len(g.Edges) != 2 || len(d) != 3 {
		t.Errorf("SPDX graph: %+v %v", g.Edges, d)
	}

	cdx, err := CycloneDXDocument("acme/api", comps, edges, now)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := ParseCycloneDX(cdx)
	if err != nil || len(cc) != 3 {
		t.Fatalf("CycloneDX parse: %v %d", err, len(cc))
	}
	if g := ParseGraph(cdx); len(g.Edges) != 2 {
		t.Errorf("CycloneDX graph: %+v", g.Edges)
	}
	if spdxLicense([]string{"MIT", "Apache-2.0"}) != "(MIT) AND (Apache-2.0)" || spdxLicense(nil) != "NOASSERTION" {
		t.Error("licence expressions")
	}
}
