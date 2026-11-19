package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Qualys Container Security image vulnerabilities (API GET
// /csapi/v1.3/images/{imageId}/vuln): {"details": [...], "vulnSummary":
// {...}} with qid, title, severity 1-5, typeDetected (CONFIRMED,
// POTENTIAL), cveids, cvssInfo and cvss3Info (baseScore as text),
// software[] (name, version, fixVersion, packagePath), patchAvailable and
// isExempted. One finding per QID and package; potential (unconfirmed)
// detections and exempted ones have low confidence. The response does not
// name the image: findings are located at the package path, or at
// "image" when there is none.

func init() {
	registerImportFormat(ImportFormat{ID: "qualys-cs", Label: "Qualys Container Security image vulnerabilities JSON (CS API)", Tool: "Qualys Container",
		Category: "container", Media: "json", Order: 608,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("details"), "qid", "software") && p.hasAny("vulnSummary", "details")
		},
		parse: parseQualysCS})
}

func parseQualysCS(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "details")
	if err != nil {
		return nil, fmt.Errorf("qualys cs: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var v struct {
			QID          json.Number `json:"qid"`
			Title        string      `json:"title"`
			Severity     int         `json:"severity"`
			TypeDetected string      `json:"typeDetected"`
			CVEs         []string    `json:"cveids"`
			CVSS3        struct {
				BaseScore looseString `json:"baseScore"`
			} `json:"cvss3Info"`
			CVSS struct {
				BaseScore looseString `json:"baseScore"`
			} `json:"cvssInfo"`
			Software []struct {
				Name        string `json:"name"`
				Version     string `json:"version"`
				FixVersion  string `json:"fixVersion"`
				PackagePath string `json:"packagePath"`
			} `json:"software"`
			PatchAvailable bool `json:"patchAvailable"`
			IsExempted     bool `json:"isExempted"`
		}
		if err := json.Unmarshal(it, &v); err != nil || v.QID == "" {
			return out, fmt.Errorf("qualys cs: detail %d: expected an object with qid", i+1)
		}
		sev := map[int]string{5: "critical", 4: "high", 3: "medium", 2: "low", 1: "info"}[v.Severity]
		score := cvssOf(string(v.CVSS3.BaseScore))
		if score == nil {
			score = cvssOf(string(v.CVSS.BaseScore))
		}
		cve := ""
		if len(v.CVEs) > 0 {
			cve = v.CVEs[0]
		}
		if len(v.Software) == 0 {
			v.Software = append(v.Software, struct {
				Name        string `json:"name"`
				Version     string `json:"version"`
				FixVersion  string `json:"fixVersion"`
				PackagePath string `json:"packagePath"`
			}{})
		}
		for _, s := range v.Software {
			f := Finding{Category: "container", RuleID: "QID-" + v.QID.String(), CVE: cve, Severity: firstNonEmpty(sev, "medium"), CVSS: score,
				PackageName: s.Name, PackageVersion: s.Version, FixedVersion: s.FixVersion, FilePath: firstNonEmpty(s.PackagePath, "image"),
				Title: firstNonEmpty(v.Title, "Qualys QID "+v.QID.String()),
				Description: joinText(fmt.Sprintf("Qualys QID %s (severity %d, %s) in %s %s.", v.QID, v.Severity, v.TypeDetected, s.Name, s.Version),
					labeled("CVEs", strings.Join(v.CVEs, ", ")), labeled("Fixed version", s.FixVersion))}
			if strings.EqualFold(v.TypeDetected, "POTENTIAL") || v.IsExempted {
				f.Confidence = "low"
			}
			if v.IsExempted {
				f.Description = joinText(f.Description, "Qualys verdict: exempted.")
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(s.Name + "@" + s.Version), Raw: it})
		}
	}
	return out, nil
}
