package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// kube-bench JSON (`kube-bench run --json`): Controls[] (one per CIS
// benchmark section: id, version, text, node_type) with tests[] groups and
// their results[] (test_number, test_desc, status PASS/FAIL/WARN/INFO,
// scored, remediation, audit, expected_result, actual_value), and Totals.
// kube-bench has no severity: FAIL is medium; WARN (a check that needs
// manual verification) is low with low confidence. PASS and INFO are not
// findings. The checks audit a cluster node's configuration, not a file in
// a repository; findings use the "other" category.

type kubeBenchResult struct {
	TestNumber     string `json:"test_number"`
	TestDesc       string `json:"test_desc"`
	Status         string `json:"status"`
	Scored         bool   `json:"scored"`
	Remediation    string `json:"remediation"`
	ExpectedResult string `json:"expected_result"`
	ActualValue    string `json:"actual_value"`
	Reason         string `json:"reason"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "kube-bench", Label: "kube-bench JSON", Tool: "kube-bench", Category: "other", Media: "json", Order: 271,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("Controls") && (p.has("Totals") || hasKeys(p.firstOf("Controls"), "tests", "node_type"))
		},
		parse: parseKubeBench})
}

func parseKubeBench(raw []byte) ([]importRecord, error) {
	var doc struct {
		Controls []struct {
			ID       string `json:"id"`
			Version  string `json:"version"`
			Text     string `json:"text"`
			NodeType string `json:"node_type"`
			Tests    []struct {
				Section string            `json:"section"`
				Desc    string            `json:"desc"`
				Results []json.RawMessage `json:"results"`
			} `json:"tests"`
		} `json:"Controls"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("kube-bench: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, c := range doc.Controls {
		for _, t := range c.Tests {
			for i, rr := range t.Results {
				var r kubeBenchResult
				if err := json.Unmarshal(rr, &r); err != nil || r.TestNumber == "" {
					return out, fmt.Errorf("kube-bench: section %s: result %d: expected an object with test_number", t.Section, i+1)
				}
				st := strings.ToUpper(r.Status)
				if st != "FAIL" && st != "WARN" {
					continue
				}
				f := Finding{Category: "other", RuleID: "CIS " + r.TestNumber, Title: r.TestDesc, Severity: "medium",
					Description: joinText(r.TestDesc, fmt.Sprintf("%s %s, %s: %s (node type %s)", c.Version, c.ID, t.Section, t.Desc, c.NodeType),
						"Expected: "+r.ExpectedResult, "Actual: "+r.ActualValue, r.Reason, "Remediation: "+r.Remediation)}
				if st == "WARN" {
					f.Severity, f.Confidence = "low", "low"
					f.Description = joinText(f.Description, "kube-bench could not verify this check automatically (WARN); it needs a manual review.")
				}
				out = append(out, importRecord{F: f, SnippetKey: hashOf(c.Version + "|" + c.NodeType), Raw: rr})
			}
		}
	}
	return out, nil
}
