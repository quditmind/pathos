package reach

import "testing"

func set(vs ...string) map[string]bool {
	m := map[string]bool{}
	for _, v := range vs {
		m[v] = true
	}
	return m
}

func TestDecide(t *testing.T) {
	comps := []component{
		{"app", "goof", "1.0.0", "npm"},
		{"express", "express", "4.0.0", "npm"},
		{"qs", "qs", "6.0.0", "npm"},           // dependency of express
		{"ejs", "ejs", "1.0.0", "npm"},         // only named in a string (view engine)
		{"nodemon", "nodemon", "2.0.0", "npm"}, // dev tool: not used by the code
		{"yaml", "PyYAML", "6.0", "pypi"},      // imported as yaml
		{"req", "requests", "2.0", "pypi"},     // not imported: Python stays unknown
		{"gin", "github.com/gin-gonic/gin", "v1.9.0", "go"},
		{"maven", "jackson-databind", "2.0", ""}, // other ecosystem
	}
	edges := map[string][]string{"app": {"express", "ejs", "nodemon"}, "express": {"qs"}}
	inv := Inventory{
		Imports: map[string]map[string]bool{"npm": set("express"), "pypi": set("yaml"), "go": set("github.com/gin-gonic/gin/binding")},
		Strings: map[string]map[string]bool{"npm": set("ejs")},
	}
	d := Decide(comps, edges, inv, true)
	want := map[string]string{
		"express@4.0.0": "reachable", "qs@6.0.0": "reachable", "ejs@1.0.0": "reachable", "nodemon@2.0.0": "not_reachable",
		"pyyaml@6.0": "reachable", "requests@2.0": "unknown", "github.com/gin-gonic/gin@v1.9.0": "reachable", "jackson-databind@2.0": "unknown",
		"goof@1.0.0": "not_reachable",
	}
	for k, w := range want {
		if d[k].Reachability != w {
			t.Errorf("%s: %s (%s), want %s", k, d[k].Reachability, d[k].Basis, w)
		}
	}
	if d["qs@6.0.0"].Basis != "a dependency of express, which the code uses" {
		t.Errorf("basis: %q", d["qs@6.0.0"].Basis)
	}
	// Without a dependency graph nothing is declared unreachable.
	d2 := Decide(comps, map[string][]string{}, inv, true)
	if d2["nodemon@2.0.0"].Reachability != "unknown" || d2["express@4.0.0"].Reachability != "reachable" {
		t.Errorf("no graph: %v %v", d2["nodemon@2.0.0"], d2["express@4.0.0"])
	}
	// Without a code inventory, no decision at all.
	if len(Decide(comps, edges, inv, false)) != 0 {
		t.Error("no inventory: no decisions")
	}
}
