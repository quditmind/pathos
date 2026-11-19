package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GitGuardian ggshield JSON (`ggshield secret scan path|repo|docker|ci
// --json`): entities_with_incidents[] (a file or commit: mode, filename,
// incidents[]), each incident with type (the detector), policy, validity,
// ignore_sha, known_secret, incident_url and occurrences[] (match, the
// secret; match_type, line_start, line_end). Commit-range scans nest the
// same object per commit in scans[]. One finding per incident and file.
// match is removed before the report is stored; identity is the detector,
// file, commit (scan id) and first line. Valid secrets are critical,
// others high.

var ggshieldSecretKeys = []string{"match"}

type ggshieldIncident struct {
	Type        string `json:"type"`
	Policy      string `json:"policy"`
	Validity    string `json:"validity"`
	IncidentURL string `json:"incident_url"`
	KnownSecret bool   `json:"known_secret"`
	Occurrences []struct {
		MatchType string `json:"match_type"`
		LineStart int    `json:"line_start"`
		LineEnd   int    `json:"line_end"`
	} `json:"occurrences"`
	IgnoreReason *struct {
		Kind string `json:"kind"`
	} `json:"ignore_reason"`
}

type ggshieldScan struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Entities []struct {
		Mode      string            `json:"mode"`
		Filename  string            `json:"filename"`
		Incidents []json.RawMessage `json:"incidents"`
	} `json:"entities_with_incidents"`
	Scans []ggshieldScan `json:"scans"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "ggshield", Label: "GitGuardian ggshield JSON", Tool: "ggshield", Category: "secrets", Media: "json", Order: 183,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("total_incidents", "total_occurrences") && p.hasAny("entities_with_incidents", "scans", "secrets_engine_version")
		},
		parse:    parseGGShield,
		sanitize: func(raw []byte) []byte { return redactKeys(raw, ggshieldSecretKeys...) },
	})
}

func parseGGShield(raw []byte) ([]importRecord, error) {
	var doc ggshieldScan
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("ggshield: invalid JSON: %w", err)
	}
	var out []importRecord
	var walk func(s ggshieldScan, depth int) error
	walk = func(s ggshieldScan, depth int) error {
		commit := ""
		if s.Type == "commit" || depth > 0 {
			commit = s.ID
		}
		for _, e := range s.Entities {
			for i, it := range e.Incidents {
				var r ggshieldIncident
				if err := json.Unmarshal(it, &r); err != nil || r.Type == "" {
					return fmt.Errorf("ggshield: %s: incident %d: expected an object with type", e.Filename, i+1)
				}
				f := Finding{Category: "secrets", RuleID: r.Type, Severity: "high", CWE: []string{"CWE-798"}, FilePath: NormalizePath(e.Filename)}
				var kinds []string
				for _, o := range r.Occurrences {
					if f.StartLine == nil || (o.LineStart > 0 && o.LineStart < *f.StartLine) {
						f.StartLine = intPtr(o.LineStart)
					}
					if f.EndLine == nil || o.LineEnd > *f.EndLine {
						f.EndLine = intPtr(o.LineEnd)
					}
					kinds = append(kinds, o.MatchType)
				}
				validity := firstNonEmpty(r.Validity, "unknown")
				if validity == "valid" {
					f.Severity, f.Confidence = "critical", "high"
				}
				f.Title = fmt.Sprintf("%s (%s)", r.Type, validity)
				f.Description = fmt.Sprintf("ggshield (%s) found a %s secret in %s, validity %s", firstNonEmpty(r.Policy, "Secrets detection"), r.Type, f.FilePath, validity)
				if len(kinds) > 0 {
					f.Description += "; parts: " + strings.Join(kinds, ", ")
				}
				if commit != "" {
					f.Description += " (commit " + commit + ")"
				}
				if r.KnownSecret {
					f.Description += "; already known to GitGuardian"
				}
				if r.IncidentURL != "" {
					f.Description += "\n\n" + r.IncidentURL
				}
				if r.IgnoreReason != nil && r.IgnoreReason.Kind != "" {
					f.Confidence = "low"
					f.Description += "; ignored: " + r.IgnoreReason.Kind
				}
				out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%s|%d", commit, derefInt(f.StartLine))), Raw: redactKeys(it, ggshieldSecretKeys...)})
			}
		}
		if depth > 4 {
			return nil
		}
		for _, sub := range s.Scans {
			if err := walk(sub, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk(doc, 0)
	return out, err
}
