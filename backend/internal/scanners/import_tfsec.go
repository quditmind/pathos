package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// tfsec JSON (`tfsec --format json`): results[] with rule_id (AVD id),
// long_id, rule_description, severity, resource and location {filename,
// start_line, end_line}. status 0 is a failed check, 1 passed (only with
// --include-passed; not a finding), 2 ignored by an inline tfsec:ignore
// comment (imported with low confidence, the waiver in the description).

type tfsecResult struct {
	RuleID          string   `json:"rule_id"`
	LongID          string   `json:"long_id"`
	RuleDescription string   `json:"rule_description"`
	Impact          string   `json:"impact"`
	Resolution      string   `json:"resolution"`
	Links           []string `json:"links"`
	Description     string   `json:"description"`
	Severity        string   `json:"severity"`
	Status          *int     `json:"status"`
	Resource        string   `json:"resource"`
	Location        struct {
		Filename  string `json:"filename"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	} `json:"location"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "tfsec", Label: "tfsec JSON", Tool: "tfsec", Category: "iac", Media: "json", Order: 261,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("results") && (hasKeys(p.firstOf("results"), "rule_id", "long_id", "location") ||
				(len(p.keys) == 1 && string(p.keys["results"]) == "null"))
		},
		parse: parseTfsec})
}

func parseTfsec(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("tfsec: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r tfsecResult
		if err := json.Unmarshal(it, &r); err != nil || (r.RuleID == "" && r.LongID == "") {
			return out, fmt.Errorf("tfsec: result %d: expected an object with rule_id", i+1)
		}
		status := 0
		if r.Status != nil {
			status = *r.Status
		}
		if status == 1 {
			continue
		}
		f := Finding{Category: "iac", RuleID: firstNonEmpty(r.RuleID, r.LongID), Title: firstNonEmpty(r.RuleDescription, r.LongID),
			Severity: r.Severity, FilePath: NormalizePath(r.Location.Filename), StartLine: intPtr(r.Location.StartLine),
			EndLine: intPtr(r.Location.EndLine),
			Description: joinText(r.Description, "Resource: "+r.Resource, "Check: "+r.LongID, "Impact: "+r.Impact,
				"Resolution: "+r.Resolution, strings.Join(r.Links, "\n"))}
		if status == 2 {
			f.Confidence = "low"
			f.Description = joinText(f.Description, "Ignored in the code (tfsec:ignore); imported for triage.")
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(r.Resource), Raw: it})
	}
	return out, nil
}
