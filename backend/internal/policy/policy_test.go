package policy

import (
	"strings"
	"testing"
)

func ptr[T any](v T) *T { return &v }

func TestNormalize(t *testing.T) {
	c := Conditions{MinSeverity: " HIGH ", CWE: []string{"89", "cwe-79"}}
	a := Actions{Block: true}
	if err := Normalize(&c, &a); err != nil {
		t.Fatal(err)
	}
	if c.MinSeverity != "high" || c.CWE[0] != "CWE-89" || c.CWE[1] != "CWE-79" {
		t.Errorf("normalized: %+v", c)
	}
	for name, tc := range map[string]struct {
		c Conditions
		a Actions
	}{
		"no condition":      {Conditions{}, Actions{Block: true}},
		"no action":         {Conditions{KEV: ptr(true)}, Actions{}},
		"bad severity":      {Conditions{MinSeverity: "urgent"}, Actions{Notify: true}},
		"bad category":      {Conditions{Categories: []string{"secret"}}, Actions{Notify: true}},
		"bad risk":          {Conditions{MinRisk: ptr(101)}, Actions{Notify: true}},
		"bad sla":           {Conditions{KEV: ptr(true)}, Actions{SLADays: ptr(0)}},
		"bad repository id": {Conditions{RepositoryIDs: []string{"x'; drop table findings; --"}}, Actions{Notify: true}},
		"bad scope key":     {Conditions{ComplianceScopes: []string{"PCI DSS"}}, Actions{Notify: true}},
	} {
		if err := Normalize(&tc.c, &tc.a); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestWhere(t *testing.T) {
	c := Conditions{MinSeverity: "high", Categories: []string{"sca"}, KEV: ptr(true), MinRisk: ptr(50), ComplianceScopes: []string{"pci_dss"},
		RepositoryIDs: []string{"01a1eb24-4ef3-72e0-9468-62ff7c5a349d"}}
	args := []any{"org", "policy"}
	sql, err := Where(c, FindingColumns, &args)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"f.severity = ANY($3::text[])", "f.category = ANY($4::text[])", "COALESCE(f.risk_score, 0) >= $5",
		"(f.kev) = $6", "cs.scope_key = ANY($7::text[])", "r.id = ANY($8::uuid[])"} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q in %s", want, sql)
		}
	}
	if len(args) != 8 || args[2].([]string)[1] != "high" || len(args[2].([]string)) != 2 {
		t.Errorf("args: %v", args)
	}
	// Values never reach the SQL text.
	if strings.Contains(sql, "pci_dss") || strings.Contains(sql, "01a1eb24") {
		t.Error("values must be bound parameters")
	}
	// Branch-only conditions are refused for pull requests.
	args = nil
	if _, err := Where(c, PRColumns, &args); err == nil {
		t.Error("risk is not available on pull request findings")
	}
	if !c.BranchOnly() || (Conditions{KEV: ptr(true)}).BranchOnly() {
		t.Error("BranchOnly")
	}
	args = nil
	sql, err = Where(Conditions{Malicious: ptr(true), CWE: []string{"CWE-89"}}, PRColumns, &args)
	if err != nil || !strings.Contains(sql, "pf.cwe && $1::text[]") || !strings.Contains(sql, "MAL-") {
		t.Errorf("PR columns: %v %s", err, sql)
	}
}
