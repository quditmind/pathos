package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Detectify vulnerabilities JSON (API): {"vulnerabilities": [...],
// "has_more", "total_vulnerabilities"} or the bare array. Each has uuid,
// title, host, location (path), status (active, patched, false_positive,
// accepted_risk), severity (critical, high, medium, low, information),
// cvss_scores (cvss_3_1, cvss_3_0, cvss_2_0: score, vector), cwe,
// definition (title, description, risk), references and request (method,
// url). Patched vulnerabilities are not findings; false positives and
// accepted risks are kept with low confidence.

type detectifyVuln struct {
	UUID       string      `json:"uuid"`
	Title      string      `json:"title"`
	Host       string      `json:"host"`
	Location   string      `json:"location"`
	Status     string      `json:"status"`
	Severity   string      `json:"severity"`
	CWE        json.Number `json:"cwe"`
	CVSSScores map[string]struct {
		Score  float64 `json:"score"`
		Vector string  `json:"vector"`
	} `json:"cvss_scores"`
	Definition struct {
		Title       string `json:"title"`
		Description string `json:"description"`
		Risk        string `json:"risk"`
	} `json:"definition"`
	References []struct {
		Name string `json:"name"`
		Link string `json:"link"`
	} `json:"references"`
	Request struct {
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"request"`
}

func isDetectifyVuln(m map[string]json.RawMessage) bool {
	return hasKeys(m, "uuid", "definition", "severity") && (hasKeys(m, "host") || hasKeys(m, "location"))
}

func init() {
	registerImportFormat(ImportFormat{ID: "detectify", Label: "Detectify vulnerabilities JSON (API)", Tool: "Detectify", Category: "dast", Media: "json", Order: 619,
		match: func(p *importProbe) bool {
			return (p.kind == "array" && isDetectifyVuln(p.keys)) || (p.kind == "object" && isDetectifyVuln(p.firstOf("vulnerabilities")))
		},
		parse: parseDetectify, sanitize: sanitizeHTTPJSON})
}

func parseDetectify(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "vulnerabilities")
	if err != nil {
		return nil, fmt.Errorf("detectify: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var v detectifyVuln
		if err := json.Unmarshal(it, &v); err != nil || v.UUID == "" {
			return out, fmt.Errorf("detectify: vulnerability %d: expected uuid", i+1)
		}
		st := strings.ToLower(v.Status)
		if st == "patched" || st == "fixed" {
			continue
		}
		url := v.Request.URL
		if url == "" && v.Host != "" {
			url = "https://" + v.Host + v.Location
		}
		f := Finding{Category: "dast", RuleID: firstNonEmpty(v.Definition.Title, v.Title), Title: firstNonEmpty(v.Title, v.Definition.Title), Severity: v.Severity,
			CWE: []string{v.CWE.String()}, FilePath: firstNonEmpty(redactHTTP(url), v.Host)}
		for _, k := range []string{"cvss_3_1", "cvss_3_0", "cvss_4_0", "cvss_2_0"} {
			if s, ok := v.CVSSScores[k]; ok && s.Score > 0 {
				f.CVSS, f.CVSSVector = floatPtr(s.Score), s.Vector
				break
			}
		}
		var refs []string
		for _, r := range v.References {
			refs = append(refs, strings.TrimSpace(r.Name+" "+r.Link))
		}
		f.Description = joinText(v.Definition.Description, labeled("Risk", v.Definition.Risk), whereText(v.Request.Method, url, ""),
			labeled("References", strings.Join(refs, "\n")), "Detectify status: "+v.Status)
		if st == "false_positive" || st == "accepted_risk" {
			f.Confidence = "low"
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(v.Request.Method), Raw: sanitizeHTTPJSON(it)})
	}
	return out, nil
}
