package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// GitHub Dependabot alerts REST API JSON (`GET /repos/{owner}/{repo}/
// dependabot/alerts`, also the organization and enterprise endpoints): an
// array of alerts with number, state, dependency (package, manifest_path),
// security_advisory (ghsa_id, cve_id, summary, severity, cvss, cwes) and
// security_vulnerability (first_patched_version). The installed version is
// not in the alert (only the vulnerable range). Fixed alerts no longer
// exist in the code and are not imported; dismissed alerts are imported
// with low confidence and GitHub's verdict in the description.

type dependabotAlert struct {
	Number     int    `json:"number"`
	State      string `json:"state"`
	HTMLURL    string `json:"html_url"`
	Dependency struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
		Scope        string `json:"scope"`
		Relationship string `json:"relationship"`
	} `json:"dependency"`
	SecurityAdvisory struct {
		GHSAID      string `json:"ghsa_id"`
		CVEID       string `json:"cve_id"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		CVSS        struct {
			VectorString string  `json:"vector_string"`
			Score        float64 `json:"score"`
		} `json:"cvss"`
		CVSSSeverities map[string]struct {
			VectorString string  `json:"vector_string"`
			Score        float64 `json:"score"`
		} `json:"cvss_severities"`
		CWEs []struct {
			CWEID string `json:"cwe_id"`
		} `json:"cwes"`
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	} `json:"security_advisory"`
	SecurityVulnerability struct {
		Severity               string `json:"severity"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    *struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"security_vulnerability"`
	DismissedReason  string `json:"dismissed_reason"`
	DismissedComment string `json:"dismissed_comment"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "dependabot", Label: "GitHub Dependabot alerts API JSON", Tool: "GitHub Dependabot", Category: "sca", Media: "json", Order: 220,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("number", "state", "security_advisory", "dependency")
		},
		parse: parseDependabot})
}

func parseDependabot(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("dependabot: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var a dependabotAlert
		if err := json.Unmarshal(it, &a); err != nil || a.SecurityAdvisory.GHSAID == "" || a.Dependency.Package.Name == "" {
			return out, fmt.Errorf("dependabot: alert %d: expected an alert with security_advisory.ghsa_id and dependency.package", i+1)
		}
		if a.State == "fixed" {
			continue
		}
		sa := a.SecurityAdvisory
		f := Finding{Category: "sca", RuleID: sa.GHSAID, Severity: firstNonEmpty(a.SecurityVulnerability.Severity, sa.Severity),
			PackageName: a.Dependency.Package.Name, FilePath: NormalizePath(a.Dependency.ManifestPath)}
		ids := []string{sa.CVEID}
		for _, id := range sa.Identifiers {
			ids = append(ids, id.Value)
		}
		f.CVE = firstMatch(cveRe, ids...)
		for _, c := range sa.CWEs {
			f.CWE = append(f.CWE, c.CWEID)
		}
		f.CVSS, f.CVSSVector = floatPtr(sa.CVSS.Score), sa.CVSS.VectorString
		for _, k := range []string{"cvss_v4", "cvss_v3"} {
			if c, ok := sa.CVSSSeverities[k]; ok && c.VectorString != "" && f.CVSSVector == "" {
				f.CVSS, f.CVSSVector = floatPtr(c.Score), c.VectorString
			}
		}
		if p := a.SecurityVulnerability.FirstPatchedVersion; p != nil {
			f.FixedVersion = p.Identifier
		}
		f.Title = fmt.Sprintf("%s: %s in %s", firstNonEmpty(f.CVE, sa.GHSAID), sa.Summary, f.PackageName)
		desc := []string{sa.Summary, "Vulnerable versions: " + a.SecurityVulnerability.VulnerableVersionRange,
			fmt.Sprintf("Ecosystem: %s; scope: %s; relationship: %s", a.Dependency.Package.Ecosystem, a.Dependency.Scope, a.Dependency.Relationship),
			fmt.Sprintf("Dependabot alert #%d (%s) %s", a.Number, a.State, a.HTMLURL)}
		if strings.HasSuffix(a.State, "dismissed") {
			f.Confidence = "low"
			desc = append(desc, "Dismissed in GitHub: "+strings.TrimSpace(a.DismissedReason+" "+a.DismissedComment))
		}
		f.Description = joinText(append(desc, sa.Description)...)
		out = append(out, importRecord{F: f, Raw: it})
	}
	return out, nil
}
