package scanners

import (
	"encoding/json"
	"fmt"
)

// Pylint JSON: `--output-format=json` (an array of messages with type,
// path, line, endLine, symbol, message and message-id) and
// `--output-format=json2` ({"messages": [...], "statistics": {...}} with
// messageId and confidence). Pylint is a linter: eval-used and exec-used
// (code injection) are sast findings; everything else is "other" (code
// quality): fatal and error low, other types info. The report has no
// code, so identity is the symbol, file, object, message and line.

type pylintMessage struct {
	Type       string `json:"type"`
	Path       string `json:"path"`
	Obj        string `json:"obj"`
	Line       int    `json:"line"`
	EndLine    *int   `json:"endLine"`
	Column     int    `json:"column"`
	Symbol     string `json:"symbol"`
	Message    string `json:"message"`
	MessageID  string `json:"message-id"`
	MessageID2 string `json:"messageId"`
	Confidence string `json:"confidence"`
}

// pylintSecurity are the Pylint checks that find code injection.
var pylintSecurity = map[string]string{"eval-used": "CWE-95", "exec-used": "CWE-95"}

func init() {
	registerImportFormat(ImportFormat{ID: "pylint", Label: "Pylint JSON (json or json2)", Tool: "Pylint", Media: "json", Order: 162,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "array":
				return p.has("symbol", "message-id", "path", "type")
			case "object":
				return p.has("messages", "statistics") && (hasKeys(p.firstOf("messages"), "symbol", "messageId") ||
					(p.firstOf("messages") == nil && hasKeys(pylintStats(p), "messageTypeCount")))
			}
			return false
		},
		parse: parsePylint})
}

func pylintStats(p *importProbe) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	_ = json.Unmarshal(p.keys["statistics"], &m)
	return m
}

func parsePylint(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "messages")
	if err != nil {
		return nil, fmt.Errorf("pylint: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var m pylintMessage
		if err := json.Unmarshal(it, &m); err != nil || m.Symbol == "" {
			return out, fmt.Errorf("pylint: message %d: expected an object with symbol", i+1)
		}
		id := firstNonEmpty(m.MessageID, m.MessageID2)
		f := Finding{Category: "other", RuleID: m.Symbol, Title: m.Message, Severity: "info", FilePath: NormalizePath(m.Path),
			StartLine: intPtr(m.Line), Description: joinText(m.Message, id+" "+m.Symbol)}
		if m.EndLine != nil {
			f.EndLine = intPtr(*m.EndLine)
		}
		switch m.Type {
		case "fatal", "error":
			f.Severity = "low"
		}
		if cwe, ok := pylintSecurity[m.Symbol]; ok {
			f.Category, f.Severity, f.CWE = "sast", "medium", []string{cwe}
		}
		switch m.Confidence {
		case "HIGH":
			f.Confidence = "high"
		case "INFERENCE", "INFERENCE_FAILURE":
			f.Confidence = "medium"
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%s|%s|%d", m.Obj, m.Message, m.Line)), Raw: it})
	}
	return out, nil
}
