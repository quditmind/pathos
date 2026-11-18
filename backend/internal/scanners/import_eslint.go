package scanners

import (
	"encoding/json"
	"fmt"
)

// ESLint JSON (`eslint -f json`, typically with eslint-plugin-security or a
// similar plugin): an array of files with messages. Whether a rule is
// security relevant cannot be decided from the report, so every rule
// message is imported (severity 2 medium, 1 low). Messages without a ruleId
// are parser or configuration diagnostics (fatal parse errors, unused
// disable directives), not rule findings, and are not imported.

type eslintFile struct {
	FilePath string            `json:"filePath"`
	Messages []json.RawMessage `json:"messages"`
}

type eslintMessage struct {
	RuleID   *string `json:"ruleId"`
	Severity int     `json:"severity"`
	Message  string  `json:"message"`
	Line     int     `json:"line"`
	EndLine  int     `json:"endLine"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "eslint", Label: "ESLint JSON", Category: "sast", Media: "json", Order: 13,
		match: func(p *importProbe) bool { return p.kind == "array" && p.has("filePath", "messages") },
		parse: parseESLintJSON})
}

func parseESLintJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("eslint: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, it := range items {
		var file eslintFile
		if err := json.Unmarshal(it, &file); err != nil {
			return out, fmt.Errorf("eslint: invalid file entry: %w", err)
		}
		for _, mr := range file.Messages {
			var m eslintMessage
			if err := json.Unmarshal(mr, &m); err != nil {
				return out, fmt.Errorf("eslint: invalid message in %s: %w", file.FilePath, err)
			}
			if m.RuleID == nil || *m.RuleID == "" {
				continue
			}
			sev := "low"
			if m.Severity >= 2 {
				sev = "medium"
			}
			f := Finding{Category: "sast", RuleID: *m.RuleID, Title: firstNonEmpty(m.Message, *m.RuleID), Description: m.Message,
				Severity: sev, FilePath: NormalizePath(file.FilePath), StartLine: intPtr(m.Line), EndLine: intPtr(m.EndLine)}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(m.Message),
				Raw: rawJSON(map[string]any{"filePath": file.FilePath, "message": mr})})
		}
	}
	return out, nil
}
