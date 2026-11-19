package scans

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"pathos/internal/gates"
)

// The pull request check keeps its wording with the gates engine.
func TestPRDecisionOutcome(t *testing.T) {
	sev := map[string]int{"high": 2, "low": 1}
	pol := gates.PolicyRef{ID: uuid.Must(uuid.NewV7()), Name: "No secrets"}
	managed := gates.GateResult{Managed: true, Effect: gates.OutcomeBlock, Count: 2, Policy: gates.PolicyRef{ID: uuid.Must(uuid.NewV7()), Name: "Pull request gate: x"}}
	cases := []struct {
		name, scan string
		gates      []gates.GateResult
		status     string
		prefix     string
	}{
		{"pass, no policy", "succeeded", nil, "passed", "Passed: 3 new"},
		{"threshold block", "succeeded", []gates.GateResult{managed}, "failed", "Blocked: 3 new: 2 high, 1 low (gate: high and above)"},
		{"threshold warn", "succeeded", []gates.GateResult{{Managed: true, Effect: gates.OutcomeWarn, Policy: managed.Policy}}, "passed", "Passed with warnings (policy Pull request gate: x): 3 new"},
		{"security policy", "succeeded", []gates.GateResult{{Effect: gates.OutcomeBlock, Policy: pol}}, "failed", "Blocked by policy No secrets: 3 new"},
		{"approval", "succeeded", []gates.GateResult{{Effect: gates.OutcomeApproval, Policy: pol}}, "failed", "Approval required by policy No secrets"},
		{"exception", "succeeded", []gates.GateResult{{Managed: true, Effect: gates.OutcomeExceptionApplied, Policy: managed.Policy}}, "passed", "Passed by approved exception"},
		{"partial without block", "partial", nil, "error", "Incomplete scan"},
		{"partial with block", "partial", []gates.GateResult{managed}, "failed", "Blocked: "},
	}
	for _, c := range cases {
		st, sum := prDecisionOutcome(c.scan, "high", 3, sev, gates.Decision{Gates: c.gates})
		if st != c.status || !strings.HasPrefix(sum, c.prefix) {
			t.Errorf("%s: %s %q", c.name, st, sum)
		}
	}
}
