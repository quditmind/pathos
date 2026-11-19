package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
)

// Bearer CLI JSON (`bearer scan --format json`): an object keyed by
// severity (critical, high, medium, low, warning), each an array of
// findings with id (the rule), title, description, cwe_ids, filename,
// line_number, source/sink positions, code_extract and fingerprint.
// Identity is Bearer's fingerprint (it numbers repeats of a rule in a
// file _0, _1, ...). The "warning" level is imported as low. Findings of
// hard-coded secret rules (CWE-798, CWE-259, CWE-321, or a rule id naming
// a secret, password, credential, token or gitleaks) quote the secret in
// code_extract and sink.content; both are removed before the report is
// stored, and they are secrets findings.

type bearerFinding struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	DocumentationURL string   `json:"documentation_url"`
	CWEIDs           []string `json:"cwe_ids"`
	LineNumber       int      `json:"line_number"`
	Filename         string   `json:"filename"`
	FullFilename     string   `json:"full_filename"`
	Source           struct {
		Start int `json:"start"`
		End   int `json:"end"`
	} `json:"source"`
	Fingerprint string `json:"fingerprint"`
	CodeExtract string `json:"code_extract"`
}

var bearerSeverities = []string{"critical", "high", "medium", "low", "warning"}

func init() {
	registerImportFormat(ImportFormat{ID: "bearer", Label: "Bearer CLI JSON", Tool: "Bearer", Media: "json", Order: 106,
		match: func(p *importProbe) bool {
			if p.kind != "object" || len(p.keys) == 0 {
				return false
			}
			found := false
			for k := range p.keys {
				if !slices.Contains(bearerSeverities, k) {
					return false
				}
				if m := p.firstOf(k); m != nil {
					if !hasKeys(m, "id", "cwe_ids", "fingerprint") {
						return false
					}
					found = true
				}
			}
			return found
		},
		parse: parseBearerJSON, sanitize: sanitizeBearer})
}

func parseBearerJSON(raw []byte) ([]importRecord, error) {
	var doc map[string][]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("bearer: invalid JSON: expected an object of severity arrays: %w", err)
	}
	var out []importRecord
	for _, sev := range bearerSeverities {
		for i, it := range doc[sev] {
			var b bearerFinding
			if err := json.Unmarshal(it, &b); err != nil || b.ID == "" {
				return out, fmt.Errorf("bearer: %s finding %d: expected an object with id", sev, i+1)
			}
			s := sev
			if s == "warning" {
				s = "low"
			}
			cwes := make([]string, len(b.CWEIDs))
			for j, c := range b.CWEIDs {
				cwes[j] = "CWE-" + c
			}
			f := Finding{Category: "sast", RuleID: b.ID, Title: firstNonEmpty(b.Title, b.ID), Severity: s, CWE: cwes,
				Description: joinText(b.Description, labelled("Documentation", b.DocumentationURL)),
				FilePath:    NormalizePath(firstNonEmpty(b.Filename, b.FullFilename)), StartLine: intPtr(bearerFirstPositive(b.Source.Start, b.LineNumber)),
				EndLine: intPtr(b.Source.End)}
			key, rec := b.Fingerprint, it
			var m map[string]any
			if json.Unmarshal(it, &m) == nil && bearerIsSecret(m) {
				f.Category = "secrets"
				rec = redactKeys(it, "code_extract", "content")
			} else if key == "" {
				key = codeIdentity(b.CodeExtract)
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf("bearer|" + key), Raw: rec})
		}
	}
	return out, nil
}

func bearerFirstPositive(v ...int) int {
	for _, n := range v {
		if n > 0 {
			return n
		}
	}
	return 0
}

var bearerSecretRule = regexp.MustCompile(`(?i)secret|password|credential|token|gitleaks`)

// bearerIsSecret reports whether a finding quotes a hard-coded secret.
func bearerIsSecret(m map[string]any) bool {
	if id, _ := m["id"].(string); bearerSecretRule.MatchString(id) {
		return true
	}
	cwes, _ := m["cwe_ids"].([]any)
	for _, c := range cwes {
		if c == "798" || c == "259" || c == "321" {
			return true
		}
	}
	return false
}

// sanitizeBearer removes the quoted code of hard-coded secret findings.
func sanitizeBearer(raw []byte) []byte {
	var doc map[string][]map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	for _, items := range doc {
		for _, m := range items {
			if !bearerIsSecret(m) {
				continue
			}
			if m["code_extract"] != nil && m["code_extract"] != "" {
				m["code_extract"] = "[REDACTED]"
			}
			if sink, ok := m["sink"].(map[string]any); ok && sink["content"] != nil && sink["content"] != "" {
				sink["content"] = "[REDACTED]"
			}
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return b
}
