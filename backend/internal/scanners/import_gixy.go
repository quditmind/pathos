package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Gixy JSON (`gixy -f json <nginx.conf>`, gixy and gixy-ng): an array of
// issues with plugin, summary, description, reason, severity (HIGH,
// MEDIUM, LOW, UNSPECIFIED), reference, path and config (the nginx
// configuration block concerned). Gixy reports no line numbers; findings
// are located at the configuration file.

func init() {
	registerImportFormat(ImportFormat{ID: "gixy", Label: "Gixy nginx configuration JSON", Tool: "Gixy", Category: "misconfiguration", Media: "json", Order: 709,
		match: func(p *importProbe) bool {
			return p.kind == "array" && hasKeys(p.keys, "plugin", "summary", "severity", "config")
		},
		parse: parseGixy})
}

func parseGixy(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("gixy: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var g struct {
			Plugin      string `json:"plugin"`
			Summary     string `json:"summary"`
			Description string `json:"description"`
			Reason      string `json:"reason"`
			Severity    string `json:"severity"`
			Reference   string `json:"reference"`
			Path        string `json:"path"`
			Config      string `json:"config"`
		}
		if err := json.Unmarshal(it, &g); err != nil || g.Plugin == "" {
			return out, fmt.Errorf("gixy: issue %d: expected plugin", i+1)
		}
		f := Finding{Category: "misconfiguration", RuleID: g.Plugin, Title: firstNonEmpty(g.Summary, g.Plugin), Severity: firstNonEmpty(normSeverity(g.Severity), "medium"),
			FilePath: NormalizePath(g.Path), Description: joinText(g.Reason, g.Description, labeled("Configuration", strings.TrimSpace(g.Config)), g.Reference)}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.Join(strings.Fields(g.Config), " ") + "|" + g.Reason), Raw: it})
	}
	return out, nil
}
