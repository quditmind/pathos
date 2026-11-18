package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Bandit JSON (`bandit -f json`): results[] with test_id, issue_severity,
// issue_confidence, issue_cwe, filename, line_number and line_range.

type banditResult struct {
	Code            string `json:"code"`
	Filename        string `json:"filename"`
	IssueConfidence string `json:"issue_confidence"`
	IssueSeverity   string `json:"issue_severity"`
	IssueCWE        struct {
		ID int `json:"id"`
	} `json:"issue_cwe"`
	IssueText  string `json:"issue_text"`
	LineNumber int    `json:"line_number"`
	LineRange  []int  `json:"line_range"`
	MoreInfo   string `json:"more_info"`
	TestID     string `json:"test_id"`
	TestName   string `json:"test_name"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "bandit", Label: "Bandit JSON", Category: "sast", Media: "json", Order: 11,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("results") && (hasKeys(p.firstOf("results"), "test_id", "issue_severity") ||
				(p.firstOf("results") == nil && p.has("generated_at", "metrics")))
		},
		parse: parseBanditJSON})
}

// lineNumberPrefix matches the "12 " / "12: " prefixes Bandit and gosec put
// in front of code lines.
var lineNumberPrefix = regexp.MustCompile(`(?m)^\s*\d+:?\s?`)

// codeIdentity is a finding's code without line numbers and whitespace, so
// its identity survives the code moving.
func codeIdentity(code string) string {
	return strings.Join(strings.Fields(lineNumberPrefix.ReplaceAllString(code, "")), " ")
}

func parseBanditJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("bandit: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r banditResult
		if err := json.Unmarshal(it, &r); err != nil || r.TestID == "" {
			return out, fmt.Errorf("bandit: result %d: expected an object with test_id", i+1)
		}
		f := Finding{Category: "sast", RuleID: r.TestID, Title: firstNonEmpty(r.IssueText, r.TestName),
			Description: strings.TrimSpace(r.IssueText + "\n\n" + r.MoreInfo), Severity: r.IssueSeverity,
			Confidence: strings.ToLower(r.IssueConfidence), FilePath: NormalizePath(r.Filename), StartLine: intPtr(r.LineNumber)}
		if n := len(r.LineRange); n > 0 {
			f.EndLine = intPtr(r.LineRange[n-1])
		}
		if r.IssueCWE.ID > 0 {
			f.CWE = []string{fmt.Sprintf("CWE-%d", r.IssueCWE.ID)}
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(firstNonEmpty(codeIdentity(r.Code), r.IssueText)), Raw: it})
	}
	return out, nil
}
