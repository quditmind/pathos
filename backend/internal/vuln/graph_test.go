package vuln

import (
	"os"
	"testing"
)

func TestCycloneDXGraph(t *testing.T) {
	raw, err := os.ReadFile("../scanners/testdata/syft.cdx.json")
	if err != nil {
		t.Fatal(err)
	}
	comps, aliases, err := parseCycloneDX(raw)
	if err != nil || len(comps) == 0 || comps[0].Ref == "" || len(aliases) != 0 {
		t.Fatalf("components: %v %+v %v", err, comps, aliases)
	}
	g := ParseGraph(raw)
	if len(g.Edges) != 2 {
		t.Fatalf("edges: %+v", g.Edges)
	}
	d := Depths(g)
	demo, lodash := "pkg:npm/demo@1.0.0?package-id=22fd847526de0651", "pkg:npm/lodash@4.17.20?package-id=b6861faac7bb3c22"
	// metadata.component (the scanned directory) has no dependencies, so the
	// project package is the root.
	if d[demo] != 0 || d[lodash] != 1 {
		t.Errorf("depths: %v", d)
	}
}

func TestDepthsTransitiveAndCycles(t *testing.T) {
	g := Graph{Edges: []Edge{{"app", "a"}, {"a", "b"}, {"b", "c"}, {"c", "a"}, {"app", "c"}}}
	d := Depths(g)
	if d["app"] != 0 || d["a"] != 1 || d["c"] != 1 || d["b"] != 2 {
		t.Errorf("shortest depths with a cycle: %v", d)
	}
	if _, ok := d["unrelated"]; ok {
		t.Error("unknown refs have no depth")
	}
	// A declared root with dependencies wins over inferred roots.
	g2 := Graph{Roots: []string{"x"}, Edges: []Edge{{"x", "y"}, {"z", "y"}}}
	if d2 := Depths(g2); d2["x"] != 0 || d2["y"] != 1 {
		t.Errorf("declared root: %v", d2)
	}
}

func TestSPDXGraphAndAliases(t *testing.T) {
	raw := []byte(`{"spdxVersion":"SPDX-2.3","documentDescribes":["SPDXRef-app"],
	 "packages":[{"SPDXID":"SPDXRef-app","name":"app","versionInfo":"1"},
	   {"SPDXID":"SPDXRef-lib","name":"lib","versionInfo":"2"},
	   {"SPDXID":"SPDXRef-lib-dup","name":"lib","versionInfo":"2"},
	   {"SPDXID":"SPDXRef-deep","name":"deep","versionInfo":"3"}],
	 "relationships":[
	   {"spdxElementId":"SPDXRef-app","relationshipType":"DEPENDS_ON","relatedSpdxElement":"SPDXRef-lib"},
	   {"spdxElementId":"SPDXRef-deep","relationshipType":"RUNTIME_DEPENDENCY_OF","relatedSpdxElement":"SPDXRef-lib-dup"},
	   {"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"CONTAINS","relatedSpdxElement":"SPDXRef-deep"}]}`)
	comps, aliases, err := parseSPDX(raw)
	if err != nil || len(comps) != 3 || aliases["SPDXRef-lib-dup"] != "SPDXRef-lib" {
		t.Fatalf("%v %d %v", err, len(comps), aliases)
	}
	g := ParseGraph(raw)
	if len(g.Edges) != 2 || g.Roots[0] != "SPDXRef-app" {
		t.Fatalf("CONTAINS must not be an edge: %+v", g)
	}
	// Resolve aliases as storeGraph does.
	for i, e := range g.Edges {
		if a, ok := aliases[e.Parent]; ok {
			g.Edges[i].Parent = a
		}
	}
	d := Depths(g)
	if d["SPDXRef-app"] != 0 || d["SPDXRef-lib"] != 1 || d["SPDXRef-deep"] != 2 {
		t.Errorf("depths: %v", d)
	}
}
