package posture

import (
	"slices"
	"testing"
)

func f(v float64) *float64 { return &v }

func TestRollup(t *testing.T) {
	if s, _ := rollup(nil, 0); s != 0 {
		t.Error("no open findings, no risk")
	}
	if s, b := rollup(f(82), 1); s != 82 || b.Uplift != 0 {
		t.Errorf("single finding: %v %+v", s, b)
	}
	if s, b := rollup(f(82), 6); s != 87 || b.OtherHighRisk != 5 {
		t.Errorf("five more high-risk findings add five points: %v %+v", s, b)
	}
	if s, _ := rollup(f(95), 40); s != 100 {
		t.Errorf("capped at 100: %v", s)
	}
	if s, _ := rollup(f(30), 200); s != 30 {
		t.Errorf("many low-risk findings never add up: %v", s)
	}
}

func TestPaths(t *testing.T) {
	g := repoGraph{byRef: map[string]int{}, parents: map[string][]string{}}
	for _, e := range []edge{{"app", "a"}, {"app", "b"}, {"a", "x"}, {"b", "c"}, {"c", "x"}, {"x", "y"}, {"y", "x"}} {
		g.edges = append(g.edges, e)
		g.parents[e.Child] = append(g.parents[e.Child], e.Parent)
	}
	ps := g.paths("x", 5)
	if len(ps) == 0 || !slices.Equal(ps[0], []string{"app", "a", "x"}) {
		t.Fatalf("shortest path first: %v", ps)
	}
	for _, p := range ps {
		if p[0] != "app" || p[len(p)-1] != "x" {
			t.Errorf("paths run from a root to the component: %v", p)
		}
	}
	if len(g.paths("app", 5)) != 1 {
		t.Error("a root is its own path")
	}
}

func TestRelation(t *testing.T) {
	zero, one, two := 0, 1, 4
	for _, c := range []struct {
		d    *int
		want string
	}{{nil, "unknown"}, {&zero, "root"}, {&one, "direct"}, {&two, "transitive"}} {
		if got := relation(c.d); got != c.want {
			t.Errorf("%v: %s", c.d, got)
		}
	}
	if !cveParam.MatchString("CVE-2021-44906") || !cveParam.MatchString("GHSA-xvch-5gv4-984h") || cveParam.MatchString("CVE-1' OR 1=1") {
		t.Error("cve parameter validation")
	}
}
