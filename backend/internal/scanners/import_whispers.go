package scanners

import (
	"encoding/json"
	"fmt"
)

// Whispers JSON (`whispers -o report.json <path>`): an array of {key,
// value, file, line, rule_id, message, severity (Critical, High, Medium,
// Low, Info)}. value is the secret (or, for the file-known rule, the file
// name); it is removed before the report is stored, and identity is the
// rule, file, key and line. Whispers' own severity is kept.

var whispersSecretKeys = []string{"value"}

type whispersResult struct {
	Key      string `json:"key"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	RuleID   string `json:"rule_id"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "whispers", Label: "Whispers JSON", Tool: "Whispers", Category: "secrets", Media: "json", Order: 184,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("rule_id", "key", "value", "file", "severity")
		},
		parse:    parseWhispers,
		sanitize: func(raw []byte) []byte { return redactKeys(raw, whispersSecretKeys...) },
	})
}

func parseWhispers(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("whispers: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r whispersResult
		if err := json.Unmarshal(it, &r); err != nil || r.RuleID == "" {
			return out, fmt.Errorf("whispers: result %d: expected an object with rule_id", i+1)
		}
		path := NormalizePath(r.File)
		f := Finding{Category: "secrets", RuleID: r.RuleID, Title: fmt.Sprintf("%s: %s", firstNonEmpty(r.Message, r.RuleID), r.Key),
			Severity: firstNonEmpty(normSeverity(r.Severity), "high"), CWE: []string{"CWE-798"}, FilePath: path, StartLine: intPtr(r.Line),
			Description: fmt.Sprintf("Whispers rule %s (%s) matched %q in %s", r.RuleID, r.Message, r.Key, path)}
		if r.RuleID == "file-known" {
			// A file that usually holds secrets (keys, .env), not a secret.
			f.CWE, f.Title = []string{"CWE-538"}, firstNonEmpty(r.Message, r.RuleID)
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%s|%d", r.Key, r.Line)), Raw: redactKeys(it, whispersSecretKeys...)})
	}
	return out, nil
}
