package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// cfn_nag JSON (`cfn_nag_scan --output-format json`): an array of
// {filename, file_results: {failure_count, violations[]}}; each violation
// has id (F... failing, W... warning), name, type (FAIL or WARN), message,
// logical_resource_ids and line_numbers (parallel arrays). One finding per
// violation and resource. FAIL is high, WARN medium.

type cfnNagViolation struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Type               string   `json:"type"`
	Message            string   `json:"message"`
	LogicalResourceIDs []string `json:"logical_resource_ids"`
	LineNumbers        []int    `json:"line_numbers"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "cfn-nag", Label: "cfn_nag JSON", Tool: "cfn_nag", Category: "iac", Media: "json", Order: 266,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("filename", "file_results")
		},
		parse: parseCfnNag})
}

func parseCfnNag(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("cfn_nag: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, it := range items {
		var file struct {
			Filename    string `json:"filename"`
			FileResults struct {
				Violations []json.RawMessage `json:"violations"`
			} `json:"file_results"`
		}
		if err := json.Unmarshal(it, &file); err != nil {
			return out, fmt.Errorf("cfn_nag: invalid file result: %w", err)
		}
		for i, vr := range file.FileResults.Violations {
			var v cfnNagViolation
			if err := json.Unmarshal(vr, &v); err != nil || v.ID == "" {
				return out, fmt.Errorf("cfn_nag: %s: violation %d: expected an object with id", file.Filename, i+1)
			}
			sev := "medium"
			if strings.EqualFold(v.Type, "FAIL") {
				sev = "high"
			}
			ids := v.LogicalResourceIDs
			if len(ids) == 0 {
				ids = []string{""}
			}
			for j, res := range ids {
				line := 0
				if j < len(v.LineNumbers) {
					line = v.LineNumbers[j]
				}
				title := v.Message
				if res != "" {
					title += " (" + res + ")"
				}
				f := Finding{Category: "iac", RuleID: v.ID, Title: title, Severity: sev, FilePath: NormalizePath(file.Filename),
					StartLine: intPtr(line), Description: joinText(v.Message, "Rule: "+v.Name+" ("+v.ID+")", "Resource: "+res)}
				out = append(out, importRecord{F: f, SnippetKey: hashOf(res), Raw: vr})
			}
		}
	}
	return out, nil
}
