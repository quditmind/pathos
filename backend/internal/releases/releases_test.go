package releases

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestStatementMapping(t *testing.T) {
	until := time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC)
	fs := []VEXFinding{
		{Vulnerability: "CVE-2024-1", PackageName: "lodash", PackageVersion: "4.17.20", PURL: "pkg:npm/lodash@4.17.20", Status: "false_positive", Reachability: "not_reachable", Reason: "only used at build time"},
		{Vulnerability: "CVE-2024-2", PackageName: "requests", PackageVersion: "2.0", Status: "accepted_risk", Reason: "internal only", AcceptedUntil: &until},
		{Vulnerability: "CVE-2024-3", PackageName: "a", PackageVersion: "1", FixedVersion: "1.2", Status: "open"},
		{Vulnerability: "CVE-2024-4", PackageName: "b", PackageVersion: "1", Status: "fixed"},
		{Vulnerability: "CVE-2024-5", PackageName: "c", PackageVersion: "1", Status: "needs_review"},
		{Vulnerability: "", PackageName: "d", Status: "open"},
	}
	st := Statements(fs)
	if len(st) != 5 {
		t.Fatalf("statements without a vulnerability are dropped: %d", len(st))
	}
	want := map[string]string{"CVE-2024-1": VEXNotAffected, "CVE-2024-2": VEXAffected, "CVE-2024-3": VEXAffected, "CVE-2024-4": VEXFixed, "CVE-2024-5": VEXUnderInvestigation}
	for _, s := range st {
		if s.Status != want[s.Vulnerability] {
			t.Errorf("%s: %s, want %s", s.Vulnerability, s.Status, want[s.Vulnerability])
		}
	}
	if st[0].Justification != "vulnerable_code_not_in_execute_path" || st[0].ImpactStatement != "only used at build time" {
		t.Errorf("not_affected: %+v", st[0])
	}
	if !strings.Contains(st[1].ActionStatement, "2027-01-02") || st[1].Products[0] != "pkg:generic/requests@2.0" {
		t.Errorf("accepted risk: %+v", st[1])
	}
	if !strings.Contains(st[2].ActionStatement, "1.2") {
		t.Errorf("open: %+v", st[2])
	}
	// The most conservative status wins for the same product.
	dup := Statements([]VEXFinding{
		{Vulnerability: "CVE-1", PackageName: "x", PackageVersion: "1", Status: "false_positive"},
		{Vulnerability: "cve-1", PackageName: "x", PackageVersion: "1", Status: "open"},
	})
	if len(dup) != 1 || dup[0].Status != VEXAffected {
		t.Errorf("dedupe: %+v", dup)
	}
}

func TestOpenVEXRoundTrip(t *testing.T) {
	st := Statements([]VEXFinding{
		{Vulnerability: "CVE-2024-1", PackageName: "lodash", PackageVersion: "4.17.20", PURL: "pkg:npm/lodash@4.17.20", Status: "false_positive"},
		{Vulnerability: "CVE-2024-4", PackageName: "b", PackageVersion: "1", PURL: "pkg:pypi/b@1", Status: "fixed"},
	})
	raw, err := OpenVEXDocument("PATHOS", "https://pathos.local/vex/1", st, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.Unmarshal(raw, &doc)
	if doc["@context"] != "https://openvex.dev/ns/v0.2.0" || doc["author"] != "PATHOS" || len(doc["statements"].([]any)) != 2 {
		t.Fatalf("document: %s", raw)
	}
	s0 := doc["statements"].([]any)[0].(map[string]any)
	if s0["vulnerability"].(map[string]any)["name"] != "CVE-2024-1" || s0["products"].([]any)[0].(map[string]any)["@id"] != "pkg:npm/lodash@4.17.20" {
		t.Errorf("statement: %v", s0)
	}
	format, author, parsed, err := ParseVEX(raw)
	if err != nil || format != "openvex" || author != "PATHOS" || len(parsed) != 2 || parsed[0].Status != VEXNotAffected {
		t.Fatalf("parse: %s %s %+v %v", format, author, parsed, err)
	}
	if _, err := OpenVEXDocument("a", "b", []Statement{{Vulnerability: "X", Products: []string{"p"}, Status: VEXNotAffected}}, time.Now()); err == nil {
		t.Error("not_affected without justification or impact must be rejected")
	}
}

func TestCycloneDXRoundTrip(t *testing.T) {
	st := Statements([]VEXFinding{
		{Vulnerability: "CVE-2024-1", PackageName: "lodash", PackageVersion: "4.17.20", PURL: "pkg:npm/lodash@4.17.20", Status: "false_positive", Reachability: "not_reachable", Reason: "x"},
		{Vulnerability: "CVE-2024-2", PackageName: "lodash", PackageVersion: "4.17.20", PURL: "pkg:npm/lodash@4.17.20", Status: "accepted_risk"},
		{Vulnerability: "CVE-2024-3", PackageName: "a", PackageVersion: "1", PURL: "pkg:npm/a@1", Status: "fixed"},
	})
	raw, err := CycloneDXVEXDocument("Payments", "2.3.1", st, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BOMFormat       string           `json:"bomFormat"`
		SpecVersion     string           `json:"specVersion"`
		Components      []map[string]any `json:"components"`
		Vulnerabilities []struct {
			ID       string              `json:"id"`
			Analysis map[string]any      `json:"analysis"`
			Affects  []map[string]string `json:"affects"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BOMFormat != "CycloneDX" || doc.SpecVersion != "1.6" || len(doc.Components) != 2 || len(doc.Vulnerabilities) != 3 {
		t.Fatalf("doc: %s", raw)
	}
	v := doc.Vulnerabilities[0]
	if v.Analysis["state"] != "not_affected" || v.Analysis["justification"] != "code_not_reachable" || v.Affects[0]["ref"] != "pkg:npm/lodash@4.17.20" {
		t.Errorf("not affected: %+v", v)
	}
	if doc.Vulnerabilities[1].Analysis["state"] != "exploitable" || doc.Vulnerabilities[1].Analysis["response"].([]any)[0] != "will_not_fix" {
		t.Errorf("accepted risk: %+v", doc.Vulnerabilities[1])
	}
	if doc.Vulnerabilities[2].Analysis["state"] != "resolved" {
		t.Errorf("fixed: %+v", doc.Vulnerabilities[2])
	}
	format, _, parsed, err := ParseVEX(raw)
	if err != nil || format != "cyclonedx" || len(parsed) != 3 {
		t.Fatalf("parse: %v %+v", err, parsed)
	}
	if parsed[0].Status != VEXNotAffected || parsed[0].Justification != "vulnerable_code_not_in_execute_path" || parsed[0].Products[0] != "pkg:npm/lodash@4.17.20" {
		t.Errorf("parsed: %+v", parsed[0])
	}
	if parsed[2].Status != VEXFixed {
		t.Errorf("parsed fixed: %+v", parsed[2])
	}
}

func TestParseVEXErrors(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":   "{",
		"unknown":    `{"hello":1}`,
		"bad status": `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{"name":"CVE-1"},"status":"maybe"}]}`,
		"no vuln":    `{"@context":"https://openvex.dev/ns/v0.2.0","statements":[{"vulnerability":{},"status":"fixed"}]}`,
		"bad state":  `{"bomFormat":"CycloneDX","vulnerabilities":[{"id":"CVE-1","analysis":{"state":"nope"}}]}`,
	} {
		if _, _, _, err := ParseVEX([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// OpenVEX v0.0.x: vulnerability as a string, subcomponents as products.
	_, _, st, err := ParseVEX([]byte(`{"@context":"https://openvex.dev/ns","statements":[{"vulnerability":"CVE-9","status":"not_affected",
		"justification":"component_not_present","products":[{"@id":"pkg:oci/app","subcomponents":[{"@id":"pkg:golang/github.com/x/y@v1.2.0"}]}]}]}`))
	if err != nil || st[0].Vulnerability != "CVE-9" || st[0].Products[0] != "pkg:golang/github.com/x/y@v1.2.0" {
		t.Errorf("legacy: %+v %v", st, err)
	}
}

func TestStatementMatches(t *testing.T) {
	c := Candidate{Vulnerability: "CVE-2024-1", PackageName: "lodash", PackageVersion: "4.17.20", PURLs: []string{"pkg:npm/lodash@4.17.20"}}
	cases := []struct {
		st   Statement
		want bool
	}{
		{Statement{Vulnerability: "cve-2024-1"}, true},
		{Statement{Vulnerability: "GHSA-x", Aliases: []string{"CVE-2024-1"}}, true},
		{Statement{Vulnerability: "CVE-2024-2"}, false},
		{Statement{Vulnerability: "CVE-2024-1", Products: []string{"pkg:npm/lodash"}}, true},
		{Statement{Vulnerability: "CVE-2024-1", Products: []string{"pkg:npm/lodash@4.17.20?x=1"}}, true},
		{Statement{Vulnerability: "CVE-2024-1", Products: []string{"pkg:npm/lodash@4.17.21"}}, false},
		{Statement{Vulnerability: "CVE-2024-1", Products: []string{"pkg:npm/underscore@1"}}, false},
		{Statement{Vulnerability: "CVE-2024-1", Products: []string{"not-a-purl"}}, false},
	}
	for i, tc := range cases {
		if got := tc.st.Matches(c); got != tc.want {
			t.Errorf("case %d: %v, want %v", i, got, tc.want)
		}
	}
	// Without an inventory purl, names are compared (Maven group:artifact).
	m := Candidate{Vulnerability: "CVE-1", PackageName: "org.apache.logging.log4j:log4j-core", PackageVersion: "2.14.1"}
	if !(Statement{Vulnerability: "CVE-1", Products: []string{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}).Matches(m) {
		t.Error("maven name match")
	}
	if (Statement{Vulnerability: "CVE-1", Products: []string{"pkg:maven/x/other@2.14.1"}}).Matches(m) {
		t.Error("different name must not match")
	}
}

func TestComponentPolicyEvaluate(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	old := now.AddDate(-3, 0, 0)
	pol := func(kind string, p PolicyParams) ComponentPolicy {
		x := ComponentPolicy{Name: "p", ConditionKind: kind, Params: p}
		if err := x.Validate(); err != nil {
			t.Fatal(err)
		}
		return x
	}
	type tc struct {
		p              ComponentPolicy
		c              CompFacts
		bad, evaluated bool
	}
	for i, x := range []tc{
		{pol(CondLicense, PolicyParams{Licenses: []string{"GPL-3.0-only"}}), CompFacts{Licenses: []string{"gpl-3.0-only"}}, true, true},
		{pol(CondLicense, PolicyParams{Licenses: []string{"GPL-3.0-only"}}), CompFacts{Licenses: []string{"MIT"}}, false, true},
		{pol(CondLicense, PolicyParams{IncludeUnknown: true}), CompFacts{Licenses: []string{"NOASSERTION"}}, true, true},
		{pol(CondVulnSeverity, PolicyParams{MinSeverity: "high"}), CompFacts{WorstOpenSeverity: "critical", OpenVulns: 2}, true, true},
		{pol(CondVulnSeverity, PolicyParams{MinSeverity: "high"}), CompFacts{WorstOpenSeverity: "medium", OpenVulns: 1}, false, true},
		{pol(CondOutdated, PolicyParams{}), CompFacts{Version: "1.2.0", HasHealth: true, LatestVersion: "1.3.0"}, true, true},
		{pol(CondOutdated, PolicyParams{}), CompFacts{Version: "v1.3.0", HasHealth: true, LatestVersion: "1.3.0"}, false, true},
		{pol(CondOutdated, PolicyParams{}), CompFacts{Version: "1.2.0"}, false, false},
		{pol(CondOutdated, PolicyParams{VersionsBehind: "major"}), CompFacts{Version: "1.9.0", HasHealth: true, LatestVersion: "1.10.0"}, false, true},
		{pol(CondOutdated, PolicyParams{VersionsBehind: "major"}), CompFacts{Version: "1.9.0", HasHealth: true, LatestVersion: "3.0.0"}, true, true},
		{pol(CondComponentAge, PolicyParams{MaxDays: 365}), CompFacts{HasHealth: true, LatestPublished: &old}, true, true},
		{pol(CondComponentAge, PolicyParams{MaxDays: 365}), CompFacts{}, false, false},
	} {
		bad, ev, _ := Evaluate(x.p, x.c, now)
		if bad != x.bad || ev != x.evaluated {
			t.Errorf("case %d: violates=%v evaluated=%v, want %v %v", i, bad, ev, x.bad, x.evaluated)
		}
	}
	for _, bad := range []ComponentPolicy{
		{Name: "x", ConditionKind: "weird"},
		{Name: "", ConditionKind: CondLicense, Params: PolicyParams{Licenses: []string{"MIT"}}},
		{Name: "x", ConditionKind: CondLicense},
		{Name: "x", ConditionKind: CondComponentAge},
		{Name: "x", ConditionKind: CondVulnSeverity, Params: PolicyParams{MinSeverity: "urgent"}},
		{Name: "x", ConditionKind: CondOutdated, ViolationState: "panic"},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("accepted %+v", bad)
		}
	}
}
