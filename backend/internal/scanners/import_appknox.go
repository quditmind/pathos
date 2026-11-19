package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Appknox file analyses JSON (API GET /api/v2/files/{fileId}/analyses):
// {"count", "next", "previous", "results": [...]} with id, vulnerability
// (the vulnerability ID), risk, overridden_risk and computed_risk (-1
// unknown, 0 passed, 1 low, 2 medium, 3 high, 4 critical), cvss_base,
// cvss_vector, cwe[], owasp[], masvs[] and findings[] (title,
// description). Passed analyses (risk 0) are not findings. The analysis
// does not name the vulnerability (GET /api/v2/vulnerabilities/{id}
// does): the title is the first finding's title.

func init() {
	registerImportFormat(ImportFormat{ID: "appknox", Label: "Appknox file analyses JSON (API v2)", Tool: "Appknox", Category: "mobile", Media: "json", Order: 624,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("results"), "computed_risk", "vulnerability", "findings")
		},
		parse: parseAppknox})
}

func parseAppknox(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("appknox: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var a struct {
			ID         json.Number `json:"id"`
			Vuln       json.Number `json:"vulnerability"`
			Risk       *int        `json:"risk"`
			Overridden *int        `json:"overridden_risk"`
			Computed   *int        `json:"computed_risk"`
			CVSSBase   float64     `json:"cvss_base"`
			CVSSVector string      `json:"cvss_vector"`
			CWE        []string    `json:"cwe"`
			OWASP      []string    `json:"owasp"`
			MASVS      []string    `json:"masvs"`
			File       json.Number `json:"file"`
			Findings   []struct {
				Title       string `json:"title"`
				Description string `json:"description"`
			} `json:"findings"`
		}
		if err := json.Unmarshal(it, &a); err != nil || a.Vuln == "" {
			return out, fmt.Errorf("appknox: analysis %d: expected vulnerability", i+1)
		}
		risk := -1
		for _, r := range []*int{a.Overridden, a.Computed, a.Risk} {
			if r != nil {
				risk = *r
				break
			}
		}
		if risk == 0 {
			continue
		}
		var texts []string
		title := ""
		for _, x := range a.Findings {
			title = firstNonEmpty(title, x.Title)
			texts = append(texts, joinText(x.Title, x.Description))
		}
		loc := "appknox vulnerability " + a.Vuln.String()
		if a.File != "" {
			loc = "appknox file " + a.File.String()
		}
		f := Finding{Category: "mobile", RuleID: "appknox-" + a.Vuln.String(), Title: firstNonEmpty(title, "Appknox vulnerability "+a.Vuln.String()),
			Severity: map[int]string{4: "critical", 3: "high", 2: "medium", 1: "low"}[risk], CVSS: floatPtr(a.CVSSBase), CVSSVector: a.CVSSVector, CWE: a.CWE,
			FilePath: loc, Description: joinText(strings.Join(texts, "\n\n"), labeled("OWASP", strings.Join(a.OWASP, ", ")), labeled("MASVS", strings.Join(a.MASVS, ", ")))}
		if risk < 0 {
			f.Confidence = "low"
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(a.ID.String()), Raw: it})
	}
	return out, nil
}
