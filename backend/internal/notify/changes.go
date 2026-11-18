package notify

import (
	"encoding/json"
	"fmt"
	"strings"
)

// ScanChanges is the change summary of a push or merge scan: new and
// fixed findings since the previous scanned commit.
type ScanChanges struct {
	BaseCommit, HeadCommit string
	BaseShort, HeadShort   string
	New, Fixed             map[string]int
	NewTotal, FixedTotal   int
	// NewText and FixedText list the counts by severity ("1 critical, 2 high").
	NewText, FixedText string
}

// parseChanges reads scan_jobs.change_summary (nil when absent).
func parseChanges(raw []byte) *ScanChanges {
	if len(raw) == 0 {
		return nil
	}
	var cs struct {
		BaseCommit string         `json:"base_commit"`
		HeadCommit string         `json:"head_commit"`
		New        map[string]int `json:"new"`
		Fixed      map[string]int `json:"fixed"`
		NewTotal   int            `json:"new_total"`
		FixedTotal int            `json:"fixed_total"`
	}
	if json.Unmarshal(raw, &cs) != nil {
		return nil
	}
	return newScanChanges(cs.BaseCommit, cs.HeadCommit, cs.New, cs.Fixed, cs.NewTotal, cs.FixedTotal)
}

func newScanChanges(base, head string, newBy, fixedBy map[string]int, newTotal, fixedTotal int) *ScanChanges {
	c := &ScanChanges{BaseCommit: base, HeadCommit: head, BaseShort: short(base), HeadShort: short(head), New: newBy, Fixed: fixedBy,
		NewTotal: newTotal, FixedTotal: fixedTotal}
	c.NewText, c.FixedText = bySeverity(newBy), bySeverity(fixedBy)
	return c
}

func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}

func bySeverity(m map[string]int) string {
	var parts []string
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		if n := m[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}
