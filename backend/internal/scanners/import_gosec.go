package scanners

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// gosec JSON (`gosec -fmt json`): Issues[] with severity, confidence, cwe,
// rule_id, details, file, code and line ("12" or a range "12-14").

type gosecIssue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	CWE        struct {
		ID string `json:"id"`
	} `json:"cwe"`
	RuleID  string `json:"rule_id"`
	Details string `json:"details"`
	File    string `json:"file"`
	Code    string `json:"code"`
	Line    string `json:"line"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "gosec", Label: "gosec JSON", Category: "sast", Media: "json", Order: 12,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("Issues") && p.hasAny("Stats", "Golang errors", "GosecVersion")
		},
		parse: parseGosecJSON})
}

func parseGosecJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "Issues")
	if err != nil {
		return nil, fmt.Errorf("gosec: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r gosecIssue
		if err := json.Unmarshal(it, &r); err != nil || r.RuleID == "" {
			return out, fmt.Errorf("gosec: issue %d: expected an object with rule_id", i+1)
		}
		f := Finding{Category: "sast", RuleID: r.RuleID, Title: firstNonEmpty(r.Details, r.RuleID), Description: r.Details,
			Severity: r.Severity, Confidence: strings.ToLower(r.Confidence), FilePath: NormalizePath(r.File)}
		if r.CWE.ID != "" {
			f.CWE = []string{"CWE-" + r.CWE.ID}
		}
		a, b, _ := strings.Cut(r.Line, "-")
		if n, err := strconv.Atoi(strings.TrimSpace(a)); err == nil {
			f.StartLine = intPtr(n)
		}
		if n, err := strconv.Atoi(strings.TrimSpace(b)); err == nil {
			f.EndLine = intPtr(n)
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(firstNonEmpty(codeIdentity(r.Code), r.Details)), Raw: it})
	}
	return out, nil
}
