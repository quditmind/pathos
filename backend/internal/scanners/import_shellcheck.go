package scanners

import (
	"encoding/json"
	"fmt"
)

// ShellCheck JSON (`shellcheck -f json1`: {"comments": [...]}, or the older
// `-f json`: the array of comments). Each comment has file, line, endLine,
// column, level (error, warning, info, style), code (SC number) and
// message. ShellCheck finds shell bugs, not vulnerabilities: findings are
// "other" (code quality), error medium, warning low, info and style info.
// The report has no code, so identity is the code, file, line and column.

type shellcheckComment struct {
	File      string `json:"file"`
	Line      int    `json:"line"`
	EndLine   int    `json:"endLine"`
	Column    int    `json:"column"`
	EndColumn int    `json:"endColumn"`
	Level     string `json:"level"`
	Code      int    `json:"code"`
	Message   string `json:"message"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "shellcheck", Label: "ShellCheck JSON", Tool: "ShellCheck", Media: "json", Order: 160,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				return len(p.keys) == 1 && p.has("comments")
			case "array":
				// ShellCheck codes are numbers (Hadolint reports them as "SCnnnn").
				var code float64
				return p.has("file", "line", "column", "level", "code", "message") && json.Unmarshal(p.keys["code"], &code) == nil
			}
			return false
		},
		parse: parseShellCheck})
}

func parseShellCheck(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "comments")
	if err != nil {
		return nil, fmt.Errorf("shellcheck: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var c shellcheckComment
		if err := json.Unmarshal(it, &c); err != nil || c.Code == 0 {
			return out, fmt.Errorf("shellcheck: comment %d: expected an object with code", i+1)
		}
		sev := "info"
		switch c.Level {
		case "error":
			sev = "medium"
		case "warning":
			sev = "low"
		}
		rule := fmt.Sprintf("SC%d", c.Code)
		f := Finding{Category: "other", RuleID: rule, Title: c.Message, Severity: sev, FilePath: NormalizePath(c.File),
			StartLine: intPtr(c.Line), EndLine: intPtr(c.EndLine),
			Description: joinText(c.Message, "https://www.shellcheck.net/wiki/"+rule)}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%d:%d", c.Line, c.Column)), Raw: it})
	}
	return out, nil
}
