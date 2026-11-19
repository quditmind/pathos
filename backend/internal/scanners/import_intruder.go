package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Intruder issues JSON (API v1 /issues/ with their occurrences): {"count",
// "results": [...]} of issues (id, title, severity, description,
// remediation, cvss_score, snoozed, snooze_reason) whose occurrences[]
// (occurrence_id, target, port, protocol, cves, cvss_score, snoozed,
// snooze_reason, first_seen_at) are the findings. In the API an issue's
// occurrences are a separate request; an issue without an occurrence list
// is one finding. Snoozed issues and occurrences (false positive,
// accepted risk, mitigating controls) are kept with low confidence.

type intruderOccurrence struct {
	ID       json.Number `json:"occurrence_id"`
	Target   string      `json:"target"`
	Port     looseString `json:"port"`
	Protocol string      `json:"protocol"`
	CVEs     []string    `json:"cves"`
	CVSS     float64     `json:"cvss_score"`
	Snoozed  bool        `json:"snoozed"`
	Reason   string      `json:"snooze_reason"`
	First    string      `json:"first_seen_at"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "intruder", Label: "Intruder issues and occurrences JSON (API v1)", Tool: "Intruder", Category: "other", Media: "json", Order: 620,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("count", "results") && hasKeys(p.firstOf("results"), "id", "title", "severity", "occurrences")
		},
		parse: parseIntruder})
}

func parseIntruder(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("intruder: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var is struct {
			ID          json.Number     `json:"id"`
			Title       string          `json:"title"`
			Severity    string          `json:"severity"`
			Description string          `json:"description"`
			Remediation string          `json:"remediation"`
			CVSS        float64         `json:"cvss_score"`
			Snoozed     bool            `json:"snoozed"`
			Reason      string          `json:"snooze_reason"`
			Occurrences json.RawMessage `json:"occurrences"`
		}
		if err := json.Unmarshal(it, &is); err != nil || is.Title == "" {
			return out, fmt.Errorf("intruder: issue %d: expected title", i+1)
		}
		var occs []intruderOccurrence
		_ = json.Unmarshal(is.Occurrences, &occs)
		if len(occs) == 0 {
			occs = []intruderOccurrence{{Target: "intruder issue " + is.ID.String()}}
		}
		for _, o := range occs {
			f := Finding{Category: "misconfiguration", RuleID: "intruder-" + is.ID.String(), Title: is.Title, Severity: firstNonEmpty(normSeverity(is.Severity), "info"),
				CVSS: floatPtr(firstScore(o.CVSS, is.CVSS)), FilePath: hostLocation(o.Target, string(o.Port), o.Protocol),
				Description: joinText(is.Description, labeled("Remediation", is.Remediation), labeled("CVEs", strings.Join(o.CVEs, ", ")), labeled("First seen", o.First))}
			if len(o.CVEs) > 0 {
				f.Category, f.CVE = "sca", o.CVEs[0]
			}
			if is.Snoozed || o.Snoozed {
				f.Confidence = "low"
				f.Description = joinText(f.Description, "Intruder verdict: snoozed ("+firstNonEmpty(o.Reason, is.Reason)+").")
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(o.ID.String()), Raw: it})
		}
	}
	return out, nil
}
