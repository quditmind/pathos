package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Fortify on Demand release vulnerabilities (API v3 GET
// /api/v3/releases/{releaseId}/vulnerabilities): {"items": [...],
// "totalCount"} with id, vulnId, releaseId, severityString (Critical,
// High, Medium, Low), category, kingdom, scantype (Static, Dynamic, Open
// Source, Mobile), primaryLocationFull, lineNumber, cwe, checkId, status,
// closedStatus, isSuppressed, auditorStatus and developerStatus. Closed
// vulnerabilities are not findings; suppressed ones and those audited as
// "Not an Issue" are kept with low confidence. The list endpoint has no
// description (it is in the vulnerability details endpoint).

func init() {
	registerImportFormat(ImportFormat{ID: "fod", Label: "Fortify on Demand release vulnerabilities JSON (API v3)", Tool: "Fortify on Demand", Media: "json", Order: 617,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("items"), "vulnId", "severityString", "releaseId")
		},
		parse: parseFortifyFoD})
}

func parseFortifyFoD(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "items")
	if err != nil {
		return nil, fmt.Errorf("fortify on demand: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var v struct {
			VulnID          string      `json:"vulnId"`
			Severity        string      `json:"severityString"`
			Category        string      `json:"category"`
			Kingdom         string      `json:"kingdom"`
			ScanType        string      `json:"scantype"`
			Location        string      `json:"primaryLocationFull"`
			ShortLocation   string      `json:"primaryLocation"`
			Line            int         `json:"lineNumber"`
			CWE             looseString `json:"cwe"`
			CheckID         string      `json:"checkId"`
			Status          string      `json:"status"`
			Closed          bool        `json:"closedStatus"`
			Suppressed      bool        `json:"isSuppressed"`
			AuditorStatus   string      `json:"auditorStatus"`
			DeveloperStatus string      `json:"developerStatus"`
			Introduced      string      `json:"introducedDate"`
		}
		if err := json.Unmarshal(it, &v); err != nil || v.VulnID == "" {
			return out, fmt.Errorf("fortify on demand: item %d: expected vulnId", i+1)
		}
		if v.Closed {
			continue
		}
		cat := map[string]string{"static": "sast", "dynamic": "dast", "open source": "sca", "mobile": "mobile"}[strings.ToLower(v.ScanType)]
		f := Finding{Category: firstNonEmpty(cat, "sast"), RuleID: firstNonEmpty(v.CheckID, v.Category), Title: firstNonEmpty(v.Category, v.CheckID), Severity: v.Severity,
			CWE: []string{strings.Replace(string(v.CWE), "CWE ID ", "CWE-", 1)}, FilePath: firstNonEmpty(v.Location, v.ShortLocation), StartLine: intPtr(v.Line),
			Description: joinText(fmt.Sprintf("Fortify on Demand %s vulnerability %s: %s (%s).", v.ScanType, v.VulnID, v.Category, v.Kingdom),
				labeled("Status", v.Status), labeled("Auditor status", v.AuditorStatus), labeled("Developer status", v.DeveloperStatus), labeled("Introduced", v.Introduced),
				"The vulnerabilities list has no description: see the vulnerability details in Fortify on Demand.")}
		if f.Category != "dast" {
			f.FilePath = NormalizePath(f.FilePath)
		}
		if v.Suppressed || strings.EqualFold(v.AuditorStatus, "Not an Issue") {
			f.Confidence = "low"
			f.Description = joinText(f.Description, "Fortify verdict: suppressed or not an issue.")
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(v.VulnID), Raw: it})
	}
	return out, nil
}
