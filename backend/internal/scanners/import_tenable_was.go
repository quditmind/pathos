package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Tenable Web App Scanning findings export (POST /was/v1/export/vulns,
// then GET .../chunks/{id}): an array of findings with finding_id, url,
// state (OPEN, REOPENED, FIXED), severity (INFO..CRITICAL), input_name,
// http_method, proof, output, asset (fqdn, ipv4) and plugin (id, name,
// synopsis, description, solution, risk_factor, cvss3_base_score,
// cvss3_vector, cve[], cwe[], see_also). FIXED findings are not findings;
// a severity modification (recast or accepted) is kept in the description
// (accepted risks have low confidence).

type tenableWASFinding struct {
	FindingID  string `json:"finding_id"`
	URL        string `json:"url"`
	State      string `json:"state"`
	Severity   string `json:"severity"`
	InputName  string `json:"input_name"`
	HTTPMethod string `json:"http_method"`
	Proof      string `json:"proof"`
	SevMod     string `json:"severity_modification_type"`
	Asset      struct {
		FQDN string `json:"fqdn"`
		IPv4 string `json:"ipv4"`
	} `json:"asset"`
	Plugin struct {
		ID          json.Number `json:"id"`
		Name        string      `json:"name"`
		Synopsis    string      `json:"synopsis"`
		Description string      `json:"description"`
		Solution    string      `json:"solution"`
		RiskFactor  string      `json:"risk_factor"`
		CVSS3       float64     `json:"cvss3_base_score"`
		CVSS3Vector string      `json:"cvss3_vector"`
		CVE         []string    `json:"cve"`
		CWE         []string    `json:"cwe"`
		SeeAlso     []string    `json:"see_also"`
	} `json:"plugin"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "tenable-was", Label: "Tenable Web App Scanning findings export JSON", Tool: "Tenable WAS", Category: "dast", Media: "json", Order: 609,
		match: func(p *importProbe) bool {
			return p.kind == "array" && hasKeys(p.keys, "finding_id", "plugin", "url")
		},
		parse: parseTenableWAS, sanitize: sanitizeHTTPJSON})
}

func parseTenableWAS(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("tenable was: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var w tenableWASFinding
		if err := json.Unmarshal(it, &w); err != nil || w.FindingID == "" {
			return out, fmt.Errorf("tenable was: finding %d: expected finding_id", i+1)
		}
		if strings.EqualFold(w.State, "FIXED") {
			continue
		}
		f := Finding{Category: "dast", RuleID: firstNonEmpty(w.Plugin.ID.String(), w.Plugin.Name), Title: firstNonEmpty(w.Plugin.Name, w.Plugin.Synopsis),
			Severity: firstNonEmpty(w.Severity, w.Plugin.RiskFactor), CVSS: floatPtr(w.Plugin.CVSS3), CVSSVector: w.Plugin.CVSS3Vector, CWE: w.Plugin.CWE,
			FilePath: firstNonEmpty(w.URL, w.Asset.FQDN, w.Asset.IPv4),
			Description: joinText(w.Plugin.Synopsis, w.Plugin.Description, labeled("Solution", w.Plugin.Solution),
				whereText(w.HTTPMethod, w.URL, w.InputName), labeled("Proof", clipText(redactHTTP(w.Proof), 2000)),
				labeled("CVEs", strings.Join(w.Plugin.CVE, ", ")), labeled("See also", strings.Join(w.Plugin.SeeAlso, "\n")))}
		if len(w.Plugin.CVE) > 0 {
			f.CVE = w.Plugin.CVE[0]
		}
		if w.SevMod != "" && !strings.EqualFold(w.SevMod, "NONE") {
			f.Description = joinText(f.Description, "Tenable severity modification: "+w.SevMod+".")
			if strings.EqualFold(w.SevMod, "ACCEPTED") {
				f.Confidence = "low"
			}
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(w.HTTPMethod + "|" + w.InputName), Raw: sanitizeHTTPJSON(it)})
	}
	return out, nil
}
