package scanners

import (
	"encoding/json"
	"fmt"
)

// kubesec JSON (`kubesec scan <file>`): an array of scanned objects
// (object, valid, fileName, message, score) with scoring.critical[] (id,
// selector, reason, points): risky settings that are findings (high) and
// scoring.advise[]: hardening that is not applied (info, low
// confidence). Objects that could not be scanned (valid false) are not
// findings; the message says why.

func init() {
	registerImportFormat(ImportFormat{ID: "kubesec", Label: "kubesec JSON", Tool: "kubesec", Category: "iac", Media: "json", Order: 701,
		match: func(p *importProbe) bool {
			return p.kind == "array" && hasKeys(p.keys, "object", "valid", "scoring", "score")
		},
		parse: parseKubesec})
}

func parseKubesec(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("kubesec: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var o struct {
			Object   string `json:"object"`
			FileName string `json:"fileName"`
			Message  string `json:"message"`
			Scoring  map[string][]struct {
				ID       string `json:"id"`
				Selector string `json:"selector"`
				Reason   string `json:"reason"`
				Points   int    `json:"points"`
			} `json:"scoring"`
		}
		if err := json.Unmarshal(it, &o); err != nil {
			return out, fmt.Errorf("kubesec: object %d: %w", i+1, err)
		}
		for _, kind := range []string{"critical", "advise"} {
			for _, s := range o.Scoring[kind] {
				if s.ID == "" {
					return out, fmt.Errorf("kubesec: %s: %s rule without id", o.Object, kind)
				}
				f := Finding{Category: "iac", RuleID: s.ID, Title: s.Reason, Severity: "high", FilePath: NormalizePath(o.FileName),
					Description: joinText(s.Reason, fmt.Sprintf("Object %s, selector %s (%d points).", o.Object, s.Selector, s.Points), o.Message)}
				if kind == "advise" {
					f.Severity, f.Confidence = "info", "low"
					f.Description = joinText(f.Description, "kubesec advice: hardening that is not applied.")
				}
				out = append(out, importRecord{F: f, SnippetKey: hashOf(o.Object), Raw: rawJSON(map[string]any{"object": o.Object, "fileName": o.FileName, kind: s})})
			}
		}
	}
	return out, nil
}
