package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Probely findings JSON (API /targets/{id}/findings/): {"count" or
// "page_total", "results": [...]} with id, definition (id, name, desc,
// cwe_id), severity (30 high, 20 medium, 10 low, other values info),
// state (notfixed, retesting, fixed, accepted, invalid), url, path,
// method, parameter, cvss_score, cvss_vector, fix, evidence and
// requests. Fixed findings are not findings; accepted and invalid (false
// positive) ones are kept with low confidence. HTTP requests and
// responses are redacted.

func init() {
	registerImportFormat(ImportFormat{ID: "probely", Label: "Probely findings JSON (API)", Tool: "Probely", Category: "dast", Media: "json", Order: 621,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("results"), "definition", "state", "severity", "url")
		},
		parse: parseProbely, sanitize: sanitizeHTTPJSON})
}

func parseProbely(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("probely: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var v struct {
			ID         json.Number `json:"id"`
			Severity   int         `json:"severity"`
			State      string      `json:"state"`
			URL        string      `json:"url"`
			Method     string      `json:"method"`
			Parameter  string      `json:"parameter"`
			CVSS       float64     `json:"cvss_score"`
			Vector     string      `json:"cvss_vector"`
			Fix        string      `json:"fix"`
			Evidence   string      `json:"evidence"`
			Definition struct {
				ID   string `json:"id"`
				Name string `json:"name"`
				Desc string `json:"desc"`
				CWE  string `json:"cwe_id"`
			} `json:"definition"`
		}
		if err := json.Unmarshal(it, &v); err != nil || v.Definition.Name == "" {
			return out, fmt.Errorf("probely: finding %d: expected definition.name", i+1)
		}
		st := strings.ToLower(v.State)
		if st == "fixed" {
			continue
		}
		f := Finding{Category: "dast", RuleID: firstNonEmpty(v.Definition.ID, v.Definition.Name), Title: v.Definition.Name,
			Severity: map[int]string{30: "high", 20: "medium", 10: "low"}[v.Severity], CVSS: floatPtr(v.CVSS), CVSSVector: v.Vector,
			CWE: []string{v.Definition.CWE}, FilePath: redactHTTP(v.URL),
			Description: joinText(v.Definition.Desc, whereText(v.Method, v.URL, v.Parameter), labeled("Fix", v.Fix),
				labeled("Evidence", clipText(redactHTTP(v.Evidence), 2000)), "Probely state: "+v.State)}
		if st == "accepted" || st == "invalid" {
			f.Confidence = "low"
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToLower(v.Method) + "|" + v.Parameter), Raw: sanitizeHTTPJSON(it)})
	}
	return out, nil
}
