package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Edgescan vulnerabilities export (API GET
// /api/v1/vulnerabilities/export.json): an array of vulnerabilities with
// id, asset_id, asset_name, name, location (host or URL), status (open,
// closed), severity (5 critical, 4 high, 3 medium, 2 low, 1 info), layer
// (application, network), cves, cwes, cvss_score, cvss_vector,
// description and remediation. Closed vulnerabilities are not findings.

func init() {
	registerImportFormat(ImportFormat{ID: "edgescan", Label: "Edgescan vulnerabilities export JSON (API)", Tool: "Edgescan", Category: "dast", Media: "json", Order: 622,
		match: func(p *importProbe) bool {
			return p.kind == "array" && hasKeys(p.keys, "asset_id", "location", "layer", "severity", "date_opened")
		},
		parse: parseEdgescan})
}

func parseEdgescan(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("edgescan: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var v struct {
			ID          json.Number `json:"id"`
			AssetName   string      `json:"asset_name"`
			Name        string      `json:"name"`
			Location    string      `json:"location"`
			Status      string      `json:"status"`
			Severity    int         `json:"severity"`
			Layer       string      `json:"layer"`
			CVEs        []string    `json:"cves"`
			CWEs        []string    `json:"cwes"`
			CVSS        float64     `json:"cvss_score"`
			Vector      string      `json:"cvss_vector"`
			Description string      `json:"description"`
			Remediation string      `json:"remediation"`
			Opened      string      `json:"date_opened"`
		}
		if err := json.Unmarshal(it, &v); err != nil || v.Name == "" {
			return out, fmt.Errorf("edgescan: vulnerability %d: expected name", i+1)
		}
		if strings.EqualFold(v.Status, "closed") {
			continue
		}
		cat := "dast"
		if strings.EqualFold(v.Layer, "network") {
			cat = "misconfiguration"
		}
		f := Finding{Category: cat, RuleID: v.Name, Title: v.Name, Severity: map[int]string{5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}[v.Severity],
			CWE: v.CWEs, CVSS: floatPtr(v.CVSS), CVSSVector: v.Vector, FilePath: firstNonEmpty(v.Location, v.AssetName),
			Description: joinText(v.Description, labeled("Remediation", v.Remediation), fmt.Sprintf("Asset %s, %s layer, opened %s.", v.AssetName, v.Layer, v.Opened))}
		if len(v.CVEs) > 0 {
			f.CVE = v.CVEs[0]
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(v.ID.String()), Raw: it})
	}
	return out, nil
}
