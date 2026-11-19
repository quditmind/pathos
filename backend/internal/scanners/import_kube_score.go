package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// kube-score JSON (`kube-score score --output-format json`): an array of
// scored objects (object_name, file_name, file_row, type_meta,
// object_meta) with checks[] (check: id, name, comment, optional; grade
// 1 CRITICAL, 5 WARNING, 7 ALMOST_OK, 10 ALL_OK; skipped; comments[]:
// path, summary, description, documentation_url). Checks graded below 10
// and not skipped are findings: CRITICAL is high, WARNING medium,
// ALMOST_OK low.

func init() {
	registerImportFormat(ImportFormat{ID: "kube-score", Label: "kube-score JSON", Tool: "kube-score", Category: "iac", Media: "json", Order: 700,
		match: func(p *importProbe) bool {
			return p.kind == "array" && hasKeys(p.keys, "checks", "object_name", "type_meta")
		},
		parse: parseKubeScore})
}

func parseKubeScore(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("kube-score: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var o struct {
			ObjectName string            `json:"object_name"`
			FileName   string            `json:"file_name"`
			FileRow    int               `json:"file_row"`
			Checks     []json.RawMessage `json:"checks"`
		}
		if err := json.Unmarshal(it, &o); err != nil {
			return out, fmt.Errorf("kube-score: object %d: %w", i+1, err)
		}
		for _, cr := range o.Checks {
			var c struct {
				Check struct {
					ID      string `json:"id"`
					Name    string `json:"name"`
					Comment string `json:"comment"`
				} `json:"check"`
				Grade    int  `json:"grade"`
				Skipped  bool `json:"skipped"`
				Comments []struct {
					Path        string `json:"path"`
					Summary     string `json:"summary"`
					Description string `json:"description"`
					DocURL      string `json:"documentation_url"`
				} `json:"comments"`
			}
			if err := json.Unmarshal(cr, &c); err != nil || c.Check.ID == "" {
				return out, fmt.Errorf("kube-score: %s: expected check.id", o.ObjectName)
			}
			if c.Skipped || c.Grade >= 10 {
				continue
			}
			sev := "low"
			switch {
			case c.Grade <= 1:
				sev = "high"
			case c.Grade <= 5:
				sev = "medium"
			}
			var notes []string
			for _, cm := range c.Comments {
				notes = append(notes, strings.TrimSpace(fmt.Sprintf("%s: %s. %s %s", cm.Path, cm.Summary, cm.Description, cm.DocURL)))
			}
			f := Finding{Category: "iac", RuleID: c.Check.ID, Title: c.Check.Name, Severity: sev, FilePath: NormalizePath(o.FileName), StartLine: intPtr(o.FileRow),
				Description: joinText(c.Check.Comment, "Object: "+o.ObjectName, strings.Join(notes, "\n"))}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(o.ObjectName), Raw: cr})
		}
	}
	return out, nil
}
