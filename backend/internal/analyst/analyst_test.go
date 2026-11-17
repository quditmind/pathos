package analyst

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestKeywords(t *testing.T) {
	k := keywords("Which repos are affected by cve-2021-44906 and GHSA-XVCH-5GV4-984H in the lodash package?")
	for _, want := range []string{"CVE-2021-44906", "GHSA-xvch-5gv4-984h", "lodash"} {
		if !slices.Contains(k, want) {
			t.Errorf("%s missing: %v", want, k)
		}
	}
	for _, not := range []string{"which", "the", "package", "repos"} {
		if slices.Contains(k, not) {
			t.Errorf("stopword %s kept: %v", not, k)
		}
	}
}

func TestNarrativeAndMarkdown(t *testing.T) {
	if _, err := validNarrative([]byte(`{"summary":"","key_risks":[],"recommendations":[]}`)); err == nil {
		t.Error("an empty summary is refused")
	}
	if _, err := validNarrative([]byte(`{"summary":"x","key_risks":[],"recommendations":[],"extra":1}`)); err == nil {
		t.Error("unknown fields are refused")
	}
	n, err := validNarrative([]byte(`{"summary":"Fine.","key_risks":["a","b","c","d","e","f","g"],"recommendations":[" "]}`))
	if err != nil || len(n.KeyRisks) != 6 || len(n.Recommendations) != 0 {
		t.Fatalf("bounded: %v %+v", err, n)
	}
	risk := 91.0
	md := Markdown(Report{Title: "Executive security summary: Organization", Model: "m", Narrative: n,
		Facts: Facts{GeneratedAt: time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC), Open: map[string]int{"critical": 1}, KEV: 1,
			TopFindings: []FindingRef{{Title: "A | B", Severity: "critical", Risk: &risk, KEV: true, Repository: "acme/api"}}}})
	for _, want := range []string{"# Executive security summary", "## Summary", "| Open critical / high / medium / low | 1 / 0 / 0 / 0 |", "A \\| B", "Mean time to fix | not available"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown lacks %q:\n%s", want, md)
		}
	}
}
