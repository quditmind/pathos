package reach

import (
	"slices"
	"strings"
	"testing"

	"pathos/internal/reachscan"
	"pathos/internal/scanners"
)

func TestSymMatch(t *testing.T) {
	for _, c := range []struct {
		use, vs string
		want    bool
	}{
		{"template", "template", true},
		{"Template.render", "environment.Template.render", true}, // re-exported class
		{"Template", "environment.Template", true},               // a module path before it
		{"urlize", "utils.urlize", true},
		{"render", "Template.render", false}, // a function is not a class's method
		{"zip", "zipObjectDeep", false},
		{"sandbox.SandboxedEnvironment", "SandboxedEnvironment", true},
		{"loader.load", "load", true},
		{"Loader.load", "load", false},
	} {
		if got := symMatch(c.use, c.vs); got != c.want {
			t.Errorf("symMatch(%q, %q) = %v", c.use, c.vs, got)
		}
	}
}

func TestModuleSymbols(t *testing.T) {
	got := moduleSymbols("npm", "lodash", []string{"lodash.template", "lodash/zipObjectDeep", "merge()", "Lodash#chain"})
	if !slices.Equal(got["lodash"], []string{"template", "zipObjectDeep", "merge", "Lodash.chain"}) {
		t.Errorf("npm: %v", got)
	}
	got = moduleSymbols("npm", "lodash.template", []string{"lodash.template"})
	if !slices.Equal(got["lodash.template"], []string{"default"}) {
		t.Errorf("npm module itself: %v", got)
	}
	got = moduleSymbols("pypi", "PyYAML", []string{"yaml.load", "yaml:full_load"})
	if !slices.Equal(got["yaml"], []string{"load", "full_load"}) {
		t.Errorf("pypi: %v", got)
	}
	got = moduleSymbols("maven", "org.apache.commons:commons-text", []string{"org.apache.commons.text.StringSubstitutor#replace",
		"org.apache.commons.text.lookup.StringLookupFactory.<init>", "replace"})
	if !slices.Equal(got["org.apache.commons.text"], []string{"StringSubstitutor.replace"}) ||
		!slices.Equal(got["org.apache.commons.text.lookup"], []string{"StringLookupFactory"}) || len(got) != 2 {
		t.Errorf("maven: %v", got)
	}
}

func npmReport(uses []reachscan.Use, methods []reachscan.MethodUse, dyn []reachscan.Dynamic, imported ...string) Reports {
	r := &reachscan.Report{Schema: reachscan.Schema, Tool: "pathos-reach", Languages: map[string]*reachscan.LangStats{"npm": {Files: 3}},
		Uses: uses, Methods: methods, Dynamic: dyn}
	for _, m := range imported {
		r.Imports = append(r.Imports, reachscan.Import{Ecosystem: "npm", Module: m, Files: 1})
	}
	return Reports{Reach: r}
}

var site = reachscan.Frame{File: "a.js", Line: 3, Function: "f"}

func TestDecideSymbols(t *testing.T) {
	adv := Advisory{IDs: []string{"GHSA-x"}, Ecosystem: "npm", Symbols: []string{"lodash.template"}}
	call := reachscan.Use{Ecosystem: "npm", Module: "lodash", Symbol: "template", Kind: "call", Sites: []reachscan.Frame{site},
		Paths: [][]reachscan.Frame{{site}}}
	for _, c := range []struct {
		name  string
		r     Reports
		adv   Advisory
		want  string
		basis string
		ok    bool
	}{
		{"called", npmReport([]reachscan.Use{call}, nil, nil, "lodash"), adv, "reachable", "lodash.template at a.js:3", true},
		{"imported, not called", npmReport(nil, nil, nil, "lodash"), adv, "not_reachable", "calls none of its vulnerable functions", true},
		{"test code only", npmReport([]reachscan.Use{{Ecosystem: "npm", Module: "lodash", Symbol: "template", Kind: "call", Test: true,
			Sites: []reachscan.Frame{{File: "a.test.js", Line: 1}}}}, nil, nil, "lodash"), adv, "not_reachable", "only test code", true},
		{"computed member", npmReport(nil, nil, []reachscan.Dynamic{{Ecosystem: "npm", Module: "lodash", Reason: "member selected by a computed name",
			File: "a.js", Line: 9}}, "lodash"), adv, "unknown", "dynamic use", true},
		{"dynamic require anywhere", npmReport(nil, nil, []reachscan.Dynamic{{Ecosystem: "npm", Reason: "require() of a computed module name",
			File: "b.js", Line: 2}}, "lodash"), adv, "unknown", "any module", true},
		{"dynamic in test code only", npmReport(nil, nil, []reachscan.Dynamic{{Ecosystem: "npm", Module: "lodash", Reason: "x", Test: true}}, "lodash"),
			adv, "not_reachable", "", true},
		{"truncated", func() Reports { r := npmReport(nil, nil, nil, "lodash"); r.Reach.Truncated = true; return r }(), adv, "unknown", "limit", true},
		{"not imported: package level stands", npmReport(nil, nil, nil, "express"), adv, "", "", false},
		{"no symbols", npmReport(nil, nil, nil, "lodash"), Advisory{IDs: []string{"x"}, Ecosystem: "npm"}, "", "", false},
		{"no report for the language", Reports{Reach: &reachscan.Report{Schema: 1, Languages: map[string]*reachscan.LangStats{}}}, adv, "", "", false},
		{"untyped method of a class", npmReport(nil, []reachscan.MethodUse{{Ecosystem: "npm", Name: "render", Sites: []reachscan.Frame{site}}}, nil, "tpl"),
			Advisory{IDs: []string{"x"}, Ecosystem: "npm", Symbols: []string{"tpl.Template.render"}}, "unknown", "method named render", true},
		{"method of a value from the module", npmReport([]reachscan.Use{{Ecosystem: "npm", Module: "tpl", Symbol: "render", Kind: "method",
			Sites: []reachscan.Frame{site}, Paths: [][]reachscan.Frame{{site}}}}, nil, nil, "tpl"),
			Advisory{IDs: []string{"x"}, Ecosystem: "npm", Symbols: []string{"tpl.Template.render"}}, "reachable", "class is not resolved", true},
	} {
		d, ok := DecideFunction("lodash", c.adv, c.r)
		if c.adv.Symbols != nil && strings.HasPrefix(c.adv.Symbols[0], "tpl.") {
			d, ok = DecideFunction("tpl", c.adv, c.r)
		}
		if ok != c.ok || d.Reachability != c.want || !strings.Contains(d.Basis, c.basis) {
			t.Errorf("%s: %v %s (%s)", c.name, ok, d.Reachability, d.Basis)
			continue
		}
		if ok && (d.Method != MethodSymbolCalls || d.Evidence == nil || d.Evidence.Tool != ToolPathosReach || d.Evidence.Limits == "") {
			t.Errorf("%s: method %s evidence %+v", c.name, d.Method, d.Evidence)
		}
		if d.Reachability == "reachable" && len(d.Evidence.Paths) == 0 {
			t.Errorf("%s: reachable without a path", c.name)
		}
	}
}

// A package the code does not import, with a dynamic import somewhere, is
// unknown but does not override a package-level "reachable" (a dependency
// of a used package).
func TestDynamicSoftForTransitive(t *testing.T) {
	adv := Advisory{IDs: []string{"x"}, Ecosystem: "npm", Symbols: []string{"minimist"}}
	d, ok := DecideFunction("minimist", adv, npmReport(nil, nil, []reachscan.Dynamic{{Ecosystem: "npm", Reason: "require() of a computed module name"}}, "express"))
	if !ok || d.Reachability != "unknown" || !d.soft {
		t.Fatalf("%v %+v", ok, d)
	}
}

func TestDecideGo(t *testing.T) {
	res := []scanners.GovulnResult{
		{OSV: "GO-1", Aliases: []string{"CVE-1"}, Module: "golang.org/x/text", Level: 3, Packages: []string{"golang.org/x/text/language"},
			Symbols: []string{"golang.org/x/text/language.Parse"},
			Traces:  [][]scanners.GovulnFrame{{{File: "main.go", Line: 9, Function: "example.com/m.main"}, {File: "language/parse.go", Line: 3, Function: "golang.org/x/text/language.Parse"}}}},
		{OSV: "GO-2", Module: "golang.org/x/text", Level: 2, Packages: []string{"golang.org/x/text/unicode/norm"}},
		{OSV: "GO-3", Module: "golang.org/x/text", Level: 1},
	}
	r := Reports{Go: res, HaveGo: true}
	for _, c := range []struct {
		ids        []string
		want, part string
	}{
		{[]string{"CVE-1"}, "reachable", "main.go:9 calls golang.org/x/text/language.Parse"},
		{[]string{"GO-2"}, "not_reachable", "norm is imported"},
		{[]string{"GO-3"}, "not_reachable", "none of its vulnerable packages is imported"},
	} {
		d, ok := DecideFunction("golang.org/x/text", Advisory{IDs: c.ids}, r)
		if !ok || d.Reachability != c.want || !strings.Contains(d.Basis, c.part) || d.Method != MethodCallGraph {
			t.Errorf("%v: %v %+v", c.ids, ok, d)
		}
		if c.want == "not_reachable" && !strings.Contains(d.Evidence.Limits, "pathos-reach did not run") {
			t.Errorf("limits: %s", d.Evidence.Limits)
		}
	}
	if _, ok := DecideFunction("golang.org/x/net", Advisory{IDs: []string{"GO-2"}}, r); ok {
		t.Error("another module is not decided by these results")
	}
	// reflection in a package that imports the module
	r.Reach = &reachscan.Report{Schema: 1, Languages: map[string]*reachscan.LangStats{"go": {Files: 1}},
		Dynamic: []reachscan.Dynamic{{Ecosystem: "go", Module: "golang.org/x/text/unicode/norm", Reason: "methods called through reflect (MethodByName)", File: "main.go", Line: 4}}}
	d, _ := DecideFunction("golang.org/x/text", Advisory{IDs: []string{"GO-2"}}, r)
	if d.Reachability != "unknown" || len(d.Evidence.Dynamic) != 1 {
		t.Errorf("reflection: %+v", d)
	}
}
