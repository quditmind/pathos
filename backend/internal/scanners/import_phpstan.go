package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// PHPStan JSON (`phpstan analyse --error-format=json`): totals, files (a map
// from file path to its messages: message, line, identifier, tip) and
// errors (analysis errors without a file, which are not findings, like
// ESLint parse errors). PHPStan is a type checker: it has no
// severity and no security rules, so every message is a low "other"
// (code quality) finding. The report has no code, so identity is the
// identifier, file, message and line.

type phpstanMessage struct {
	Message    string `json:"message"`
	Line       int    `json:"line"`
	Identifier string `json:"identifier"`
	Tip        string `json:"tip"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "phpstan", Label: "PHPStan JSON", Tool: "PHPStan", Media: "json", Order: 150,
		match: func(p *importProbe) bool { return p.kind == "object" && p.has("totals", "files") },
		parse: parsePHPStan})
}

func parsePHPStan(raw []byte) ([]importRecord, error) {
	var doc struct {
		Files json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("phpstan: invalid JSON: %w", err)
	}
	// PHP encodes an empty files map as [].
	var byFile map[string]struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if b := bytes.TrimSpace(doc.Files); len(b) > 0 && b[0] == '{' {
		if err := json.Unmarshal(b, &byFile); err != nil {
			return nil, fmt.Errorf("phpstan: invalid files: %w", err)
		}
	}
	files := make([]string, 0, len(byFile))
	for f := range byFile {
		files = append(files, f)
	}
	slices.Sort(files)
	var out []importRecord
	for _, file := range files {
		for i, it := range byFile[file].Messages {
			var m phpstanMessage
			if err := json.Unmarshal(it, &m); err != nil || m.Message == "" {
				return out, fmt.Errorf("phpstan: %s: message %d: expected an object with message", file, i+1)
			}
			rule := firstNonEmpty(m.Identifier, "phpstan")
			f := Finding{Category: "other", RuleID: rule, Title: m.Message, Description: joinText(m.Message, m.Tip),
				Severity: "low", FilePath: NormalizePath(file), StartLine: intPtr(m.Line)}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%s|%d", m.Message, m.Line)), Raw: it})
		}
	}
	return out, nil
}
