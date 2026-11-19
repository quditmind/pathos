package scanners

import (
	"encoding/json"
	"fmt"
)

// Hadolint JSON (`hadolint -f json`): an array of {code, column, file,
// level, line, message}. Codes are DLxxxx (Hadolint rules) or SCxxxx
// (ShellCheck rules applied to RUN instructions, as strings); levels are
// error, warning, info and style. ShellCheck's own JSON has numeric codes
// and endLine, which tells the two apart.

type hadolintResult struct {
	Code    string `json:"code"`
	Column  int    `json:"column"`
	File    string `json:"file"`
	Level   string `json:"level"`
	Line    int    `json:"line"`
	Message string `json:"message"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "hadolint", Label: "Hadolint JSON", Tool: "Hadolint", Category: "iac", Media: "json", Order: 267,
		match: func(p *importProbe) bool {
			var code string
			return p.kind == "array" && p.has("code", "level", "line", "message", "file") && !p.hasAny("endLine", "endColumn") &&
				json.Unmarshal(p.keys["code"], &code) == nil
		},
		parse: parseHadolint})
}

func parseHadolint(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("hadolint: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r hadolintResult
		if err := json.Unmarshal(it, &r); err != nil || r.Code == "" {
			return out, fmt.Errorf("hadolint: result %d: expected an object with code", i+1)
		}
		sev := normSeverity(r.Level)
		if r.Level == "style" {
			sev = "info"
		}
		f := Finding{Category: "iac", RuleID: r.Code, Title: r.Message, Severity: sev, FilePath: NormalizePath(r.File),
			StartLine: intPtr(r.Line), Description: joinText(r.Message, "Rule: "+r.Code)}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprint(r.Line)), Raw: it})
	}
	return out, nil
}
