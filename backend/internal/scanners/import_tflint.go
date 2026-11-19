package scanners

import (
	"encoding/json"
	"fmt"
)

// TFLint JSON (`tflint --format json`): issues[] with rule {name,
// severity (error, warning, notice), link}, message and range {filename,
// start, end}; errors[] are TFLint's own failures (not findings).

type tflintIssue struct {
	Rule struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
		Link     string `json:"link"`
	} `json:"rule"`
	Message string `json:"message"`
	Range   struct {
		Filename string `json:"filename"`
		Start    struct {
			Line int `json:"line"`
		} `json:"start"`
		End struct {
			Line int `json:"line"`
		} `json:"end"`
	} `json:"range"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "tflint", Label: "TFLint JSON", Tool: "TFLint", Category: "iac", Media: "json", Order: 268,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("issues", "errors") && len(p.keys) == 2 &&
				(hasKeys(p.firstOf("issues"), "rule", "range") || p.firstOf("issues") == nil)
		},
		parse: parseTFLint})
}

func parseTFLint(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "issues")
	if err != nil {
		return nil, fmt.Errorf("tflint: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r tflintIssue
		if err := json.Unmarshal(it, &r); err != nil || r.Rule.Name == "" {
			return out, fmt.Errorf("tflint: issue %d: expected an object with rule.name", i+1)
		}
		sev := normSeverity(r.Rule.Severity)
		if r.Rule.Severity == "notice" {
			sev = "low"
		}
		f := Finding{Category: "iac", RuleID: r.Rule.Name, Title: r.Message, Severity: sev, FilePath: NormalizePath(r.Range.Filename),
			StartLine: intPtr(r.Range.Start.Line), EndLine: intPtr(r.Range.End.Line), Description: joinText(r.Message, r.Rule.Link)}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(r.Message), Raw: it})
	}
	return out, nil
}
