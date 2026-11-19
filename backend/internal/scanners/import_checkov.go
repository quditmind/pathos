package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Checkov JSON (`checkov -o json`): one object per framework
// ({check_type, results: {failed_checks, passed_checks, skipped_checks}}),
// or an array of them when several frameworks ran. Only failed checks are
// findings (passed are not, skipped were waived in the code). Checkov
// reports a severity only with a Prisma Cloud API key; without one it is
// null and the finding is medium.

type checkovCheck struct {
	CheckID       string `json:"check_id"`
	BCCheckID     string `json:"bc_check_id"`
	CheckName     string `json:"check_name"`
	FilePath      string `json:"file_path"`
	RepoFilePath  string `json:"repo_file_path"`
	FileLineRange []int  `json:"file_line_range"`
	Resource      string `json:"resource"`
	Severity      string `json:"severity"`
	Guideline     string `json:"guideline"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "checkov", Label: "Checkov JSON", Category: "iac", Media: "json", Order: 50,
		match: func(p *importProbe) bool {
			return (p.kind == "object" || p.kind == "array") && p.has("check_type", "results")
		},
		parse: parseCheckov})
}

func parseCheckov(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("checkov: invalid JSON: %w", err)
	}
	if items == nil {
		items = []json.RawMessage{json.RawMessage(raw)}
	}
	var out []importRecord
	for _, it := range items {
		var fw struct {
			CheckType string `json:"check_type"`
			Results   struct {
				FailedChecks []json.RawMessage `json:"failed_checks"`
			} `json:"results"`
		}
		if err := json.Unmarshal(it, &fw); err != nil {
			return out, fmt.Errorf("checkov: invalid report: %w", err)
		}
		for _, cr := range fw.Results.FailedChecks {
			var c checkovCheck
			if err := json.Unmarshal(cr, &c); err != nil || c.CheckID == "" {
				return out, fmt.Errorf("checkov: failed check without check_id")
			}
			f := Finding{Category: "iac", RuleID: c.CheckID, Title: firstNonEmpty(c.CheckName, c.CheckID),
				Severity: firstNonEmpty(normSeverity(c.Severity), "medium"),
				FilePath: NormalizePath(firstNonEmpty(c.RepoFilePath, c.FilePath))}
			if len(c.FileLineRange) > 0 {
				f.StartLine = intPtr(c.FileLineRange[0])
				f.EndLine = intPtr(c.FileLineRange[len(c.FileLineRange)-1])
			}
			desc := []string{c.CheckName, "Resource: " + c.Resource, "Framework: " + fw.CheckType}
			if c.BCCheckID != "" {
				desc = append(desc, "Prisma Cloud ID: "+c.BCCheckID)
			}
			if c.Guideline != "" {
				desc = append(desc, c.Guideline)
			}
			f.Description = strings.Join(desc, "\n")
			out = append(out, importRecord{F: f, SnippetKey: hashOf(c.Resource), Raw: cr})
		}
	}
	return out, nil
}
