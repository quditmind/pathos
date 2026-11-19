package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Psalm JSON (`psalm --output-format=json`, also with --taint-analysis):
// an array of issues with type, severity (error or info, Psalm's own
// level), file_name, line_from/line_to, snippet, is_security and cwe_ids.
// Taint-analysis issues (is_security, types Tainted*) are high sast
// findings with their CWE; the taint trace stays in the original record.
// Other issues are type and code-quality problems: code-quality findings, low
// (error) or info.

type psalmIssue struct {
	Type         string `json:"type"`
	Severity     string `json:"severity"`
	Message      string `json:"message"`
	Link         string `json:"link"`
	FileName     string `json:"file_name"`
	FilePath     string `json:"file_path"`
	LineFrom     int    `json:"line_from"`
	LineTo       int    `json:"line_to"`
	Snippet      string `json:"snippet"`
	SelectedText string `json:"selected_text"`
	IsSecurity   bool   `json:"is_security"`
	CWEIDs       []int  `json:"cwe_ids"`
	TaintTrace   []struct {
		Label    string `json:"label"`
		FileName string `json:"file_name"`
		LineFrom int    `json:"line_from"`
	} `json:"taint_trace"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "psalm", Label: "Psalm JSON", Tool: "Psalm", Media: "json", Order: 151,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("type", "severity", "line_from", "file_name") && p.hasAny("shortcode", "link", "snippet")
		},
		parse: parsePsalm})
}

func parsePsalm(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("psalm: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r psalmIssue
		if err := json.Unmarshal(it, &r); err != nil || r.Type == "" {
			return out, fmt.Errorf("psalm: issue %d: expected an object with type", i+1)
		}
		f := Finding{Category: "code-quality", RuleID: r.Type, Title: firstNonEmpty(r.Message, r.Type), FilePath: NormalizePath(firstNonEmpty(r.FileName, r.FilePath)),
			StartLine: intPtr(r.LineFrom), EndLine: intPtr(r.LineTo), Description: joinText(r.Message, r.Link)}
		if r.IsSecurity || strings.HasPrefix(r.Type, "Tainted") {
			f.Category, f.Severity = "sast", "high"
			for _, c := range r.CWEIDs {
				f.CWE = append(f.CWE, fmt.Sprintf("CWE-%d", c))
			}
			var trace []string
			for _, t := range r.TaintTrace {
				trace = append(trace, fmt.Sprintf("%s (%s:%d)", t.Label, t.FileName, t.LineFrom))
			}
			if len(trace) > 0 {
				f.Description = joinText(f.Description, "Taint trace: "+strings.Join(trace, " -> "))
			}
		} else if strings.EqualFold(r.Severity, "error") {
			f.Severity = "low"
		} else {
			f.Severity = "info"
		}
		code := firstNonEmpty(codeIdentity(r.Snippet), r.SelectedText, r.Message)
		out = append(out, importRecord{F: f, SnippetKey: hashOf(code + "|" + r.SelectedText), Raw: it})
	}
	return out, nil
}
