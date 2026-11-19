package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Kingfisher JSON (`kingfisher scan --format json`): {"findings": [{rule
// {id, name, description}, finding {snippet, path, line, confidence,
// validation {status, outcome}, ...}}], "audit": ...,
// "metadata": {kingfisher_version, ...}}; Kingfisher prints a summary
// object on the next line, which is ignored. The secret is in snippet,
// dependent_captures, validate_command, blast_radius_command and the
// validation response; they are removed before the report is stored, and
// identity is the rule, file and line. Secrets validated as active are
// critical, others high.

var kingfisherSecretKeys = []string{"snippet", "dependent_captures", "validate_command", "blast_radius_command", "response"}

type kingfisherFinding struct {
	Rule struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"rule"`
	Finding struct {
		Path       string `json:"path"`
		Line       int    `json:"line"`
		Confidence string `json:"confidence"`
		Validation struct {
			Status  string `json:"status"`
			Outcome string `json:"outcome"`
		} `json:"validation"`
	} `json:"finding"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "kingfisher", Label: "Kingfisher JSON", Tool: "Kingfisher", Category: "secrets", Media: "json", Order: 181,
		match: func(p *importProbe) bool {
			return (p.kind == "object" || p.kind == "jsonl") && p.has("findings") &&
				(bytes.Contains(p.keys["metadata"], []byte(`"kingfisher_version"`)) || bytes.Contains(p.keys["audit"], []byte(`"kingfisher.`)) ||
					hasKeys(p.firstOf("findings"), "rule", "finding"))
		},
		parse:    parseKingfisher,
		sanitize: sanitizeKingfisher,
	})
}

// kingfisherReport returns the report object (the first JSON value) and
// what follows it (the summary).
func kingfisherReport(raw []byte) (json.RawMessage, []byte, error) {
	raw = bytes.TrimPrefix(raw, utf8BOM)
	var doc json.RawMessage
	d := json.NewDecoder(bytes.NewReader(raw))
	if err := d.Decode(&doc); err != nil {
		return nil, nil, err
	}
	return doc, raw[d.InputOffset():], nil
}

// sanitizeKingfisher removes the secrets from the report object and keeps
// the summary that follows it.
func sanitizeKingfisher(raw []byte) []byte {
	doc, rest, err := kingfisherReport(raw)
	if err != nil {
		return raw
	}
	return append(redactKeys(doc, kingfisherSecretKeys...), rest...)
}

func parseKingfisher(raw []byte) ([]importRecord, error) {
	doc, _, err := kingfisherReport(raw)
	if err != nil {
		return nil, fmt.Errorf("kingfisher: invalid JSON: %w", err)
	}
	items, err := jsonArray(doc, "findings")
	if err != nil {
		return nil, fmt.Errorf("kingfisher: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r kingfisherFinding
		if err := json.Unmarshal(it, &r); err != nil || r.Rule.ID == "" {
			return out, fmt.Errorf("kingfisher: finding %d: expected an object with rule.id", i+1)
		}
		fd := r.Finding
		name := firstNonEmpty(r.Rule.Name, r.Rule.ID)
		f := Finding{Category: "secrets", RuleID: r.Rule.ID, Severity: "high", CWE: []string{"CWE-798"}, FilePath: NormalizePath(fd.Path),
			StartLine: intPtr(fd.Line), Confidence: strings.ToLower(fd.Confidence)}
		state := firstNonEmpty(fd.Validation.Status, fd.Validation.Outcome, "not validated")
		switch strings.ToLower(fd.Validation.Outcome) {
		case "active", "valid":
			f.Severity, f.Confidence = "critical", "high"
		}
		f.Title = fmt.Sprintf("%s (%s)", name, strings.ToLower(state))
		f.Description = joinText(r.Rule.Description, fmt.Sprintf("Kingfisher rule %s, validation: %s", r.Rule.ID, state))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprint(fd.Line)), Raw: redactKeys(it, kingfisherSecretKeys...)})
	}
	return out, nil
}
