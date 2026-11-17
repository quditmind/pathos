package scans

import "testing"

func TestPROutcome(t *testing.T) {
	for _, c := range []struct {
		scan, gate      string
		n, blocking     int
		sev             map[string]int
		status, summary string
	}{
		{"succeeded", "high", 0, 0, nil, "passed", "Passed: no new findings"},
		{"succeeded", "high", 2, 0, map[string]int{"medium": 2}, "passed", "Passed: 2 new: 2 medium"},
		{"succeeded", "high", 3, 1, map[string]int{"critical": 1, "low": 2}, "failed", "Blocked: 3 new: 1 critical, 2 low (gate: high and above)"},
		{"partial", "high", 1, 1, map[string]int{"high": 1}, "failed", "Blocked: 1 new: 1 high (gate: high and above) (some scanners failed)"},
		{"partial", "high", 0, 0, nil, "error", "Incomplete scan: no new findings (some scanners failed)"},
		{"failed", "high", 0, 0, nil, "error", "The security scan could not run"},
	} {
		st, sum := prOutcome(c.scan, c.gate, c.n, c.blocking, c.sev)
		if st != c.status || sum != c.summary {
			t.Errorf("%+v: got %s %q", c, st, sum)
		}
	}
}
