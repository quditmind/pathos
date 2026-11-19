package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Dockle JSON (`dockle -f json`): CIS Docker Benchmark and best-practice
// checks of a container image. Every detail with level FATAL (high), WARN
// (medium) or INFO (info) is a finding; SKIP, PASS and IGNORE are not.
// Dockle masks credential values itself; alerts are redacted again.

type dockleDetail struct {
	Code   string   `json:"code"`
	Title  string   `json:"title"`
	Level  string   `json:"level"`
	Alerts []string `json:"alerts"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "dockle", Label: "Dockle JSON", Tool: "Dockle", Category: "container", Media: "json", Order: 334,
		match: func(p *importProbe) bool {
			if p.kind != "object" || !p.has("summary", "details") {
				return false
			}
			var s map[string]json.RawMessage
			return json.Unmarshal(p.keys["summary"], &s) == nil && hasKeys(s, "fatal", "warn", "pass")
		},
		parse:    parseDockle,
		sanitize: sanitizeHTTPJSON})
}

func parseDockle(raw []byte) ([]importRecord, error) {
	var doc struct {
		Image   string         `json:"image"`
		Details []dockleDetail `json:"details"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("dockle: invalid JSON: %w", err)
	}
	image := firstNonEmpty(doc.Image, "container image")
	var out []importRecord
	for i, d := range doc.Details {
		if d.Code == "" {
			return out, fmt.Errorf("dockle: detail %d: missing code", i+1)
		}
		sev := map[string]string{"FATAL": "high", "WARN": "medium", "INFO": "info"}[strings.ToUpper(d.Level)]
		if sev == "" {
			continue
		}
		alerts := make([]string, len(d.Alerts))
		for j, a := range d.Alerts {
			alerts[j] = redactHTTP(a)
		}
		d.Alerts = alerts
		f := Finding{Category: "container", RuleID: d.Code, Title: firstNonEmpty(d.Title, d.Code), Severity: sev, FilePath: image, Confidence: "high",
			Description: joinText(fmt.Sprintf("Dockle %s %s: %s", d.Level, d.Code, d.Title), strings.Join(alerts, "\n"))}
		if d.Code == "CIS-DI-0010" {
			f.CWE = []string{"CWE-798"}
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(d.Code), Raw: rawJSON(d)})
	}
	return out, nil
}
