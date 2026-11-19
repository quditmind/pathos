package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
)

// detect-secrets JSON (`detect-secrets scan`, the .secrets.baseline file):
// results maps each file to its secrets {type, filename, line_number,
// hashed_secret, is_verified, is_secret}. The report holds no secret in
// plain text, but hashed_secret is an unsalted SHA-1 of the secret (weak
// passwords can be recovered from it), so it is removed before the report
// is stored; identity is the detector type, file and line. Verified
// secrets are critical, others high; secrets audited as false positives
// (is_secret false) are imported with low confidence.

var detectSecretsKeys = []string{"hashed_secret"}

type detectSecretsResult struct {
	Type       string `json:"type"`
	Filename   string `json:"filename"`
	LineNumber int    `json:"line_number"`
	IsVerified bool   `json:"is_verified"`
	IsSecret   *bool  `json:"is_secret"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "detect-secrets", Label: "detect-secrets JSON (baseline)", Tool: "detect-secrets", Category: "secrets",
		Media: "json", Order: 180,
		match:    func(p *importProbe) bool { return p.kind == "object" && p.has("results", "plugins_used") },
		parse:    parseDetectSecrets,
		sanitize: func(raw []byte) []byte { return redactKeys(raw, detectSecretsKeys...) },
	})
}

func parseDetectSecrets(raw []byte) ([]importRecord, error) {
	var doc struct {
		Results map[string][]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("detect-secrets: invalid JSON: %w", err)
	}
	files := make([]string, 0, len(doc.Results))
	for f := range doc.Results {
		files = append(files, f)
	}
	slices.Sort(files)
	var out []importRecord
	for _, file := range files {
		for i, it := range doc.Results[file] {
			var r detectSecretsResult
			if err := json.Unmarshal(it, &r); err != nil || r.Type == "" {
				return out, fmt.Errorf("detect-secrets: %s: secret %d: expected an object with type", file, i+1)
			}
			path := NormalizePath(firstNonEmpty(r.Filename, file))
			f := Finding{Category: "secrets", RuleID: r.Type, Title: r.Type + " (detect-secrets)", Severity: "high", CWE: []string{"CWE-798"},
				FilePath: path, StartLine: intPtr(r.LineNumber), Description: fmt.Sprintf("detect-secrets found a %s in %s", r.Type, path)}
			if r.IsVerified {
				f.Severity, f.Confidence = "critical", "high"
				f.Description += " (verified)"
			}
			if r.IsSecret != nil && !*r.IsSecret {
				f.Confidence = "low"
				f.Description += "; audited as not a secret"
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprint(r.LineNumber)), Raw: redactKeys(it, detectSecretsKeys...)})
		}
	}
	return out, nil
}
