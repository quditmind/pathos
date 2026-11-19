package scanners

import (
	"encoding/json"
	"fmt"
)

// Terrascan JSON (`terrascan scan -o json`): results {violations[],
// skipped_violations[], scan_errors[], scan_summary}. Violations carry
// rule_id, rule_name, description, severity, category, resource_name,
// resource_type, file and line. Skipped violations (waived in the code) are
// imported with low confidence and the waiver in the description.

type terrascanViolation struct {
	RuleName     string `json:"rule_name"`
	Description  string `json:"description"`
	RuleID       string `json:"rule_id"`
	Severity     string `json:"severity"`
	Category     string `json:"category"`
	ResourceName string `json:"resource_name"`
	ResourceType string `json:"resource_type"`
	File         string `json:"file"`
	Line         int    `json:"line"`
	SkipComment  string `json:"skip_comment"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "terrascan", Label: "Terrascan JSON", Tool: "Terrascan", Category: "iac", Media: "json", Order: 262,
		match: func(p *importProbe) bool {
			var res map[string]json.RawMessage
			return p.kind == "object" && p.has("results") && json.Unmarshal(p.keys["results"], &res) == nil &&
				hasKeys(res, "violations", "scan_summary")
		},
		parse: parseTerrascan})
}

func parseTerrascan(raw []byte) ([]importRecord, error) {
	var doc struct {
		Results struct {
			Violations        []json.RawMessage `json:"violations"`
			SkippedViolations []json.RawMessage `json:"skipped_violations"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("terrascan: invalid JSON: %w", err)
	}
	var out []importRecord
	for set, items := range [][]json.RawMessage{doc.Results.Violations, doc.Results.SkippedViolations} {
		for i, it := range items {
			var v terrascanViolation
			if err := json.Unmarshal(it, &v); err != nil || v.RuleID == "" {
				return out, fmt.Errorf("terrascan: violation %d: expected an object with rule_id", i+1)
			}
			f := Finding{Category: "iac", RuleID: v.RuleID, Title: firstNonEmpty(v.Description, v.RuleName), Severity: v.Severity,
				FilePath: NormalizePath(v.File), StartLine: intPtr(v.Line),
				Description: joinText(v.Description, fmt.Sprintf("Rule: %s (%s); category: %s", v.RuleName, v.RuleID, v.Category),
					fmt.Sprintf("Resource: %s %s", v.ResourceType, v.ResourceName))}
			if set == 1 {
				f.Confidence = "low"
				f.Description = joinText(f.Description, "Skipped in the code ("+firstNonEmpty(v.SkipComment, "no comment")+"); imported for triage.")
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(v.ResourceType + "|" + v.ResourceName), Raw: it})
		}
	}
	return out, nil
}
