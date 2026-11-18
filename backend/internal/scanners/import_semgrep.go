package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Semgrep (and Opengrep) JSON (`semgrep scan --json`): results[] with
// check_id, path, start/end and extra (message, severity, metadata with
// cwe, confidence, impact).

type semgrepResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	End struct {
		Line int `json:"line"`
	} `json:"end"`
	Extra struct {
		Message     string         `json:"message"`
		Severity    string         `json:"severity"`
		Lines       string         `json:"lines"`
		Fingerprint string         `json:"fingerprint"`
		Metadata    map[string]any `json:"metadata"`
	} `json:"extra"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "semgrep", Label: "Semgrep / Opengrep JSON", Category: "sast", Media: "json", Order: 10,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("results") && (hasKeys(p.firstOf("results"), "check_id") ||
				(p.hasAny("errors", "paths") && p.firstOf("results") == nil && p.hasAny("version", "skipped_rules", "interfile_languages_used")))
		},
		parse: parseSemgrepJSON})
}

func parseSemgrepJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("semgrep: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r semgrepResult
		if err := json.Unmarshal(it, &r); err != nil || r.CheckID == "" {
			return out, fmt.Errorf("semgrep: result %d: expected an object with check_id", i+1)
		}
		md := r.Extra.Metadata
		rule := opengrepPrefix.ReplaceAllString(r.CheckID, "")
		title := strings.TrimSpace(r.Extra.Message)
		if j := strings.Index(title, ". "); j > 0 {
			title = title[:j+1]
		}
		f := Finding{Category: "sast", RuleID: rule, Title: firstNonEmpty(title, rule), Description: r.Extra.Message,
			Severity: semgrepSeverity(r.Extra.Severity, md), FilePath: NormalizePath(r.Path),
			StartLine: intPtr(r.Start.Line), EndLine: intPtr(r.End.Line), CWE: stringsOf(md["cwe"]),
			Confidence: strings.ToLower(fmt.Sprint(md["confidence"]))}
		// The matched lines identify the finding; "requires login" is what
		// Semgrep prints for them without an account, which is no identity.
		snip := strings.Join(strings.Fields(r.Extra.Lines), " ")
		if snip == "" || snip == "requires login" {
			snip = r.Extra.Message
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(snip), Raw: it})
	}
	return out, nil
}

// semgrepSeverity prefers the rule's impact metadata (newer registry
// rules) over the coarse ERROR/WARNING/INFO severity.
func semgrepSeverity(sev string, md map[string]any) string {
	if s, ok := md["impact"].(string); ok && normSeverity(s) != "" {
		return normSeverity(s)
	}
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return "critical"
	case "ERROR", "HIGH":
		return "high"
	case "WARNING", "MEDIUM":
		return "medium"
	case "INFO", "LOW":
		return "low"
	}
	return "medium"
}

// stringsOf returns a JSON string or array of strings as a slice.
func stringsOf(v any) []string {
	switch t := v.(type) {
	case string:
		return []string{t}
	case []any:
		var out []string
		for _, x := range t {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
