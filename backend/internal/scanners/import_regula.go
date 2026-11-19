package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Regula JSON (`regula run <paths> --format json`): rule_results[] with
// rule_id, rule_name, rule_summary, rule_description, rule_severity
// (Critical, High, Medium, Low, Informational, Unknown), rule_result
// (PASS, FAIL, WAIVED), resource_id, resource_type, filepath,
// source_location (path, line), controls and rule_remediation_doc, and a
// summary. FAIL results are findings, WAIVED ones are kept with low
// confidence, PASS results are not findings.

func init() {
	registerImportFormat(ImportFormat{ID: "regula", Label: "Regula JSON", Tool: "Regula", Category: "iac", Media: "json", Order: 710,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("rule_results"), "rule_id", "rule_result")
		},
		parse: parseRegula})
}

func parseRegula(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "rule_results")
	if err != nil {
		return nil, fmt.Errorf("regula: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r struct {
			RuleID      string   `json:"rule_id"`
			RuleName    string   `json:"rule_name"`
			Summary     string   `json:"rule_summary"`
			Description string   `json:"rule_description"`
			Severity    string   `json:"rule_severity"`
			Result      string   `json:"rule_result"`
			Message     string   `json:"rule_message"`
			ResourceID  string   `json:"resource_id"`
			Type        string   `json:"resource_type"`
			FilePath    string   `json:"filepath"`
			Controls    []string `json:"controls"`
			Doc         string   `json:"rule_remediation_doc"`
			Locations   []struct {
				Path string `json:"path"`
				Line int    `json:"line"`
			} `json:"source_location"`
		}
		if err := json.Unmarshal(it, &r); err != nil || r.RuleID == "" {
			return out, fmt.Errorf("regula: result %d: expected rule_id", i+1)
		}
		res := strings.ToUpper(r.Result)
		if res != "FAIL" && res != "WAIVED" {
			continue
		}
		f := Finding{Category: "iac", RuleID: r.RuleID, Title: firstNonEmpty(r.Summary, r.RuleName), Severity: firstNonEmpty(normSeverity(r.Severity), "medium"),
			FilePath:    NormalizePath(r.FilePath),
			Description: joinText(r.Description, r.Message, fmt.Sprintf("Resource %s (%s).", r.ResourceID, r.Type), labeled("Controls", strings.Join(r.Controls, ", ")), r.Doc)}
		if len(r.Locations) > 0 {
			f.StartLine = intPtr(r.Locations[0].Line)
		}
		if res == "WAIVED" {
			f.Confidence = "low"
			f.Description = joinText(f.Description, "Regula verdict: waived.")
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(r.ResourceID), Raw: it})
	}
	return out, nil
}
