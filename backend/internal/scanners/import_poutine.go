package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// poutine JSON (`poutine analyze_local|analyze_repo|analyze_org --format
// json`): findings[] (rule_id, purl of the analysed repository, meta with
// path, line, job, step and details), rules (by id: title, description,
// level error/warning/note, refs) and packages. CI/CD pipeline findings use
// the cicd category.

type poutineFinding struct {
	RuleID string `json:"rule_id"`
	Purl   string `json:"purl"`
	Meta   struct {
		Path     string `json:"path"`
		Line     int    `json:"line"`
		Job      string `json:"job"`
		Step     string `json:"step"`
		Details  string `json:"details"`
		Workflow string `json:"workflow"`
	} `json:"meta"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "poutine", Label: "poutine JSON", Tool: "poutine", Category: "cicd", Media: "json", Order: 280,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("findings", "rules") && (hasKeys(p.firstOf("findings"), "rule_id", "meta") || p.has("packages"))
		},
		parse: parsePoutine})
}

func parsePoutine(raw []byte) ([]importRecord, error) {
	var doc struct {
		Findings []json.RawMessage `json:"findings"`
		Rules    map[string]struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Level       string `json:"level"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("poutine: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range doc.Findings {
		var p poutineFinding
		if err := json.Unmarshal(it, &p); err != nil || p.RuleID == "" {
			return out, fmt.Errorf("poutine: finding %d: expected an object with rule_id", i+1)
		}
		rule := doc.Rules[p.RuleID]
		f := Finding{Category: "cicd", RuleID: p.RuleID, Title: firstNonEmpty(rule.Title, p.RuleID), Severity: firstNonEmpty(normSeverity(rule.Level), "medium"),
			FilePath: NormalizePath(p.Meta.Path), StartLine: intPtr(p.Meta.Line)}
		var where []string
		if p.Meta.Job != "" {
			where = append(where, "job "+p.Meta.Job)
		}
		if p.Meta.Step != "" {
			where = append(where, "step "+p.Meta.Step)
		}
		f.Description = joinText(p.Meta.Details, strings.Join(where, ", "), rule.Description, "Repository: "+p.Purl)
		out = append(out, importRecord{F: f, SnippetKey: hashOf(p.Purl + "|" + p.Meta.Job + "|" + p.Meta.Step + "|" + p.Meta.Details), Raw: it})
	}
	return out, nil
}
