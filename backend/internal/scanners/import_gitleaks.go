package scanners

import (
	"encoding/json"
	"fmt"
)

// Gitleaks JSON (`gitleaks detect --report-format json`): an array of
// leaks. The secret values (Secret, Match, Line) are removed before the
// report is stored; identity is the rule, file, commit and line.

type gitleaksLeak struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	Author      string   `json:"Author"`
	Date        string   `json:"Date"`
	Tags        []string `json:"Tags"`
	Fingerprint string   `json:"Fingerprint"`
}

var gitleaksSecretKeys = []string{"Secret", "Match", "Line"}

func init() {
	registerImportFormat(ImportFormat{ID: "gitleaks", Label: "Gitleaks JSON", Category: "secrets", Media: "json", Order: 30,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("RuleID", "File") && p.hasAny("Secret", "Match", "Fingerprint", "StartLine")
		},
		parse:    parseGitleaksJSON,
		sanitize: func(raw []byte) []byte { return redactKeys(raw, gitleaksSecretKeys...) },
	})
}

func parseGitleaksJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("gitleaks: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var l gitleaksLeak
		if err := json.Unmarshal(it, &l); err != nil || l.RuleID == "" {
			return out, fmt.Errorf("gitleaks: leak %d: expected an object with RuleID", i+1)
		}
		f := Finding{Category: "secrets", RuleID: l.RuleID, Title: firstNonEmpty(l.Description, l.RuleID) + " (" + l.RuleID + ")",
			Description: fmt.Sprintf("Gitleaks rule %s matched a secret in %s", l.RuleID, l.File), Severity: "high",
			FilePath: NormalizePath(l.File), StartLine: intPtr(l.StartLine), EndLine: intPtr(l.EndLine), CWE: []string{"CWE-798"}}
		if l.Commit != "" {
			f.Description += " (commit " + l.Commit + ")"
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(l.Commit + "|" + fmt.Sprint(l.StartLine)), Raw: redactKeys(it, gitleaksSecretKeys...)})
	}
	return out, nil
}
