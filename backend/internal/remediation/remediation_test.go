package remediation

import (
	"testing"

	"github.com/google/uuid"

	"pathos/internal/aifix"
)

func TestTransitions(t *testing.T) {
	for _, from := range Statuses {
		if CanTransition(from, "closed") && from != "closed" {
			t.Errorf("%s → closed must not be allowed by hand", from)
		}
		if from != "verifying" && CanTransition("verifying", from) {
			t.Errorf("verifying → %s must wait for the verification", from)
		}
	}
	for _, ok := range [][2]string{{"open", "in_progress"}, {"in_progress", "fix_submitted"}, {"closed", "open"}, {"wont_fix", "open"}, {"open", "wont_fix"}} {
		if !CanTransition(ok[0], ok[1]) {
			t.Errorf("%s → %s", ok[0], ok[1])
		}
	}
}

func TestKindAndPriority(t *testing.T) {
	if KindFor("sca") != "dependency_upgrade" || KindFor("iac") != "configuration" || KindFor("sast") != "code_fix" || KindFor("secrets") != "code_fix" {
		t.Error("kinds")
	}
	if PriorityFor("info") != "low" || PriorityFor("critical") != "critical" {
		t.Error("priorities")
	}
}

func res(rule, file string, line int) aifix.Result {
	return aifix.Result{RuleID: rule, File: file, Line: line}
}

func TestDecide(t *testing.T) {
	f1, f2 := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	targets := []target{
		{FindingID: f1, RuleID: "sqli", File: "a.go", Line: 10, ScannerKey: "opengrep", Status: "open"},
		{FindingID: f2, RuleID: "G101", File: "b.go", Line: 3, ScannerKey: "gosec", Status: "open"},
	}
	before := map[string]Results{
		"opengrep": {Before: []aifix.Result{res("sqli", "a.go", 10)}, After: []aifix.Result{}},
		"gosec":    {Before: []aifix.Result{res("G101", "b.go", 3), res("G104", "b.go", 9)}, After: []aifix.Result{res("G104", "b.go", 8)}},
	}
	if r, ev := Decide(targets, before); r != "fixed" || len(ev.Regressions) != 0 || !ev.Findings[0].Removed || !ev.Findings[1].Removed {
		t.Fatalf("fixed: %s %+v", r, ev)
	}
	// Still reported after the fix.
	still := map[string]Results{"opengrep": before["opengrep"], "gosec": {Before: before["gosec"].Before, After: before["gosec"].Before}}
	if r, _ := Decide(targets, still); r != "still_present" {
		t.Fatalf("still present: %s", r)
	}
	// Gone, but a new result in an affected file: reported, not closed.
	reg := map[string]Results{"opengrep": {Before: before["opengrep"].Before, After: []aifix.Result{res("xss", "a.go", 22)}}, "gosec": before["gosec"]}
	r, ev := Decide(targets, reg)
	if r != "regressed" || len(ev.Regressions) != 1 || ev.Regressions[0].RuleID != "xss" {
		t.Fatalf("regressed: %s %+v", r, ev.Regressions)
	}
	// Not reproduced before: absence proves nothing.
	inc := map[string]Results{"opengrep": {Before: []aifix.Result{}, After: []aifix.Result{}}, "gosec": before["gosec"]}
	if r, _ := Decide(targets, inc); r != "inconclusive" {
		t.Fatalf("inconclusive: %s", r)
	}
	// Missing scanner results count as not reproduced.
	if r, _ := Decide(targets, map[string]Results{}); r != "inconclusive" {
		t.Fatalf("no results: %s", r)
	}
}

func TestRegressionsAreMultisets(t *testing.T) {
	got := Regressions(map[string]Results{"x": {
		Before: []aifix.Result{res("r1", "a", 1), res("r1", "a", 5)},
		After:  []aifix.Result{res("r1", "a", 2), res("r1", "a", 6), res("r1", "a", 9), res("r2", "a", 1)},
	}})
	if len(got) != 2 {
		t.Fatalf("one more r1 and a new r2: %+v", got)
	}
}

func TestJSONText(t *testing.T) {
	if jsonText([]byte(`{"secure_code":"use prepared statements","fix":"  ","n":3}`)) != "secure code: use prepared statements" {
		t.Error(jsonText([]byte(`{"secure_code":"use prepared statements"}`)))
	}
	if jsonText(nil) != "" || jsonText([]byte(`[]`)) != "" {
		t.Error("empty")
	}
}
