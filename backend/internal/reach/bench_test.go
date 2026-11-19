package reach_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"pathos/internal/intel"
	"pathos/internal/reach"
	"pathos/internal/reachscan"
	"pathos/internal/scanners"
)

// The reachability benchmark: one sample project per language
// (internal/reachscan/testdata/bench) with a vulnerable function the code
// calls, one it does not call, and a project where the call happens
// through dynamic dispatch or reflection, which must come out unknown,
// never "not reachable".
//
//	JavaScript  js/app: lodash.template called through a re-export under
//	            another name (util/strings.js) -> reachable;
//	            lodash.zipObjectDeep never called -> not reachable.
//	            js/dynamic: underscore[op](...) -> unknown.
//	Python      python/app: yaml.load through "import yaml as y" ->
//	            reachable; jinja2.utils.urlize never called (Template is)
//	            -> not reachable. python/dynamic: getattr(requests, name)
//	            -> unknown.
//	Java        java/app: StringSubstitutor.replace on a typed field ->
//	            reachable; InvokerTransformer.transform never called
//	            (CollectionUtils is) -> not reachable. java/dynamic:
//	            Class.forName + getMethod with computed names -> unknown.
//	Go          go/app: language.ParseAcceptLanguage (GO-2022-1059) ->
//	            reachable; unicode/norm (GO-2026-5970) not imported -> not
//	            reachable. go/dynamic: a norm.Form method called through
//	            reflect.Value.MethodByName -> unknown.
//
// The advisories for npm, PyPI and Maven (testdata/bench/osv-advisories.json)
// are real advisory identifiers with the vulnerable functions written into
// the OSV fields PATHOS reads (database_specific/ecosystem_specific
// vulnerable_functions, affected_functions): the public OSV exports of
// these ecosystems rarely name functions. The Go results are real
// govulncheck 1.10.0 output from the worker-sca image on go/app and
// go/dynamic (with network access for the module and the vulnerability
// database), reduced to the config, finding and matching osv messages.
//
// The "package level" column is what the import inventory alone answers
// (reach.Decide): reachable for every imported npm, PyPI and Go package,
// unknown for Maven (not covered at package level), for comparison.

type benchCase struct {
	lang, sample, pkg, vuln, want string
}

var benchCases = []benchCase{
	{"JavaScript", "js/app", "lodash", "GHSA-35jh-r3h4-6jhm", "reachable"},
	{"JavaScript", "js/app", "lodash", "GHSA-p6mc-m468-83gw", "not_reachable"},
	{"JavaScript", "js/dynamic", "underscore", "GHSA-cf4h-3jhx-xvhq", "unknown"},
	{"Python", "python/app", "PyYAML", "GHSA-8q59-q68h-6hv4", "reachable"},
	{"Python", "python/app", "Jinja2", "GHSA-g3rq-g295-4j3m", "not_reachable"},
	{"Python", "python/dynamic", "requests", "GHSA-j8r2-6x86-q33q", "unknown"},
	{"Java", "java/app", "org.apache.commons:commons-text", "GHSA-599f-7c49-w659", "reachable"},
	{"Java", "java/app", "commons-collections:commons-collections", "GHSA-fjq5-5j5f-mvxh", "not_reachable"},
	{"Java", "java/dynamic", "org.apache.commons:commons-text", "GHSA-599f-7c49-w659", "unknown"},
	{"Go", "go/app", "golang.org/x/text", "GO-2022-1059", "reachable"},
	{"Go", "go/app", "golang.org/x/text", "GO-2026-5970", "not_reachable"},
	{"Go", "go/dynamic", "golang.org/x/text", "GO-2026-5970", "unknown"},
}

const benchDir = "../reachscan/testdata/bench"

func benchAdvisories(t *testing.T) map[string]intel.Vuln {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(benchDir, "osv-advisories.json"))
	if err != nil {
		t.Fatal(err)
	}
	vs, err := intel.ParseOSV(raw, "osv-file")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]intel.Vuln{}
	for _, v := range vs {
		out[v.ID] = v
	}
	return out
}

func benchReports(t *testing.T, sample string) reach.Reports {
	t.Helper()
	rep, err := reachscan.Scan(filepath.Join(benchDir, sample))
	if err != nil {
		t.Fatal(err)
	}
	r := reach.Reports{Reach: rep}
	if lang, name, _ := strings.Cut(sample, "/"); lang == "go" {
		raw, err := os.ReadFile(filepath.Join(benchDir, "go", "govulncheck-"+name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if r.Go, err = scanners.GovulncheckResults(raw); err != nil {
			t.Fatal(err)
		}
		r.HaveGo = true
	}
	return r
}

func TestReachabilityBenchmark(t *testing.T) {
	advisories := benchAdvisories(t)
	type row struct {
		c                benchCase
		got, method, why string
		paths            int
	}
	var rows []row
	for _, c := range benchCases {
		r := benchReports(t, c.sample)
		adv := reach.Advisory{IDs: []string{c.vuln}}
		if v, ok := advisories[c.vuln]; ok {
			adv.IDs = append(adv.IDs, v.Aliases...)
			for _, a := range v.Affected {
				if strings.EqualFold(a.Package, c.pkg) {
					adv.Ecosystem, adv.Symbols = a.Ecosystem, a.Symbols
				}
			}
			if len(adv.Symbols) == 0 {
				t.Fatalf("%s: no vulnerable functions for %s", c.vuln, c.pkg)
			}
		}
		d, ok := reach.DecideFunction(c.pkg, adv, r)
		if !ok {
			d = reach.Decision{Reachability: "unknown", Basis: "no function-level decision"}
		}
		paths := 0
		if d.Evidence != nil {
			paths = len(d.Evidence.Paths)
		}
		rows = append(rows, row{c, d.Reachability, d.Method, d.Basis, paths})
		if d.Reachability != c.want {
			t.Errorf("%s %s %s: got %s (%s), want %s", c.lang, c.sample, c.vuln, d.Reachability, d.Basis, c.want)
		}
		// Every reachable answer carries a call path ending at the call.
		if d.Reachability == "reachable" && paths == 0 {
			t.Errorf("%s %s: reachable without a call path", c.sample, c.vuln)
		}
	}
	// The results table (go test -v -run TestReachabilityBenchmark).
	var b strings.Builder
	fmt.Fprintf(&b, "\n| Language | Sample | Advisory | Expected | Function level | Method | Package level | Paths |\n|---|---|---|---|---|---|---|---|\n")
	correct := map[string]int{}
	for _, r := range rows {
		pkgLevel := "reachable"
		if r.c.lang == "Java" {
			pkgLevel = "unknown"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s | %s | %s | %d |\n", r.c.lang, r.c.sample, r.c.vuln, r.c.want, r.got, r.method, pkgLevel, r.paths)
		if r.got == r.c.want {
			correct[r.c.want]++
		}
	}
	count := func(w string) int {
		return len(slices.DeleteFunc(slices.Clone(benchCases), func(c benchCase) bool { return c.want != w }))
	}
	fmt.Fprintf(&b, "\nreachable %d/%d, not reachable %d/%d, unknown (dynamic) %d/%d; false \"not reachable\": %d\n",
		correct["reachable"], count("reachable"), correct["not_reachable"], count("not_reachable"), correct["unknown"], count("unknown"),
		len(slices.DeleteFunc(slices.Clone(rows), func(r row) bool { return !(r.got == "not_reachable" && r.c.want != "not_reachable") })))
	t.Log(b.String())
}

// The call path of a reachable answer names the real call sites.
func TestReachabilityBenchmarkPaths(t *testing.T) {
	advisories := benchAdvisories(t)
	cases := []struct {
		sample, pkg, vuln string
		frames            []string // file:line of each frame, outermost first
	}{
		{"js/app", "lodash", "GHSA-35jh-r3h4-6jhm", []string{"src/index.js:12", "src/index.js:8", "src/views.js:5"}},
		{"python/app", "PyYAML", "GHSA-8q59-q68h-6hv4", []string{"app/main.py:13", "app/main.py:8", "app/loader.py:7"}},
		{"java/app", "org.apache.commons:commons-text", "GHSA-599f-7c49-w659",
			[]string{"src/main/java/com/example/App.java:25", "src/main/java/com/example/App.java:13"}},
		{"go/app", "golang.org/x/text", "GO-2022-1059", []string{"main.go:19", "main.go:14", "language/parse.go:158"}},
	}
	for _, c := range cases {
		adv := reach.Advisory{IDs: []string{c.vuln}}
		if v, ok := advisories[c.vuln]; ok {
			adv.Ecosystem, adv.Symbols = v.Affected[0].Ecosystem, v.Affected[0].Symbols
		}
		d, _ := reach.DecideFunction(c.pkg, adv, benchReports(t, c.sample))
		if d.Evidence == nil || len(d.Evidence.Paths) == 0 {
			t.Fatalf("%s: no path (%+v)", c.sample, d)
		}
		var got []string
		for _, f := range d.Evidence.Paths[0] {
			got = append(got, fmt.Sprintf("%s:%d", f.File, f.Line))
		}
		if !slices.Equal(got, c.frames) {
			t.Errorf("%s: path %v, want %v", c.sample, got, c.frames)
		}
	}
}
