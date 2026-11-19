package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JFrog Xray vulnerabilities report JSON ("Xray Unified": Reports API
// export of a vulnerabilities report, POST /xray/api/v1/reports/
// vulnerabilities then export?format=json): total_rows and rows[], each with
// issue_id (XRAY-n), summary, severity, cves[] (cve, cvss_v3_score,
// cvss_v3_vector, cvss_v2_score), cvss3_max_score, vulnerable_component
// ("gav://group:artifact:version", "npm://name:version", ...),
// impacted_artifact, path, fixed_versions ("[2.15.0]") and impact_path.

type xrayRow struct {
	IssueID             string          `json:"issue_id"`
	Summary             string          `json:"summary"`
	Description         string          `json:"description"`
	Severity            string          `json:"severity"`
	IssueType           string          `json:"issue_type"`
	PackageType         string          `json:"package_type"`
	VulnerableComponent string          `json:"vulnerable_component"`
	ImpactedArtifact    string          `json:"impacted_artifact"`
	Path                string          `json:"path"`
	FixedVersions       []string        `json:"-"`
	RawFixed            json.RawMessage `json:"fixed_versions"`
	CVEs                []struct {
		CVE          string      `json:"cve"`
		CVSSv3Score  looseString `json:"cvss_v3_score"`
		CVSSv3Vector string      `json:"cvss_v3_vector"`
		CVSSv2Score  looseString `json:"cvss_v2_score"`
	} `json:"cves"`
	CVSS3Max   looseString `json:"cvss3_max_score"`
	CVSS2Max   looseString `json:"cvss2_max_score"`
	ImpactPath []string    `json:"impact_path"`
	CWE        []string    `json:"cwe"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "jfrog-xray", Label: "JFrog Xray vulnerabilities report JSON", Tool: "JFrog Xray", Category: "sca", Media: "json", Order: 202,
		match: func(p *importProbe) bool {
			if p.kind != "object" || !p.has("rows") {
				return false
			}
			first := p.firstOf("rows")
			return hasKeys(first, "issue_id", "vulnerable_component") || first == nil && p.has("total_rows") && len(p.keys) == 2
		},
		parse: parseJFrogXray})
}

// xrayComponent splits "gav://org.apache:log4j-core:2.14.1" into the
// package name (the artifact) and version.
func xrayComponent(c string) (string, string) {
	if _, rest, ok := strings.Cut(c, "://"); ok {
		c = rest
	}
	i := strings.LastIndex(c, ":")
	if i < 0 {
		return c, ""
	}
	name, version := c[:i], c[i+1:]
	if j := strings.LastIndex(name, ":"); j >= 0 {
		name = name[j+1:]
	}
	return name, version
}

func parseFloatLoose(s looseString) float64 {
	var v float64
	_, _ = fmt.Sscanf(string(s), "%g", &v)
	return v
}

func parseJFrogXray(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "rows")
	if err != nil {
		return nil, fmt.Errorf("jfrog xray: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r xrayRow
		if err := json.Unmarshal(it, &r); err != nil || r.IssueID == "" || r.VulnerableComponent == "" {
			return out, fmt.Errorf("jfrog xray: row %d: expected issue_id and vulnerable_component", i+1)
		}
		// fixed_versions is a list (or, in older exports, a string).
		if json.Unmarshal(r.RawFixed, &r.FixedVersions) != nil {
			var s string
			if json.Unmarshal(r.RawFixed, &s) == nil && s != "" {
				r.FixedVersions = []string{s}
			}
		}
		name, version := xrayComponent(r.VulnerableComponent)
		f := Finding{Category: "sca", RuleID: r.IssueID, Severity: r.Severity, PackageName: name, PackageVersion: version,
			FilePath: NormalizePath(r.Path), CWE: r.CWE, CVSS: floatPtr(parseFloatLoose(r.CVSS3Max))}
		var cves []string
		for _, c := range r.CVEs {
			cves = append(cves, c.CVE)
			if f.CVSSVector == "" && c.CVSSv3Vector != "" {
				f.CVSSVector = c.CVSSv3Vector
				if f.CVSS == nil {
					f.CVSS = floatPtr(parseFloatLoose(c.CVSSv3Score))
				}
			}
		}
		if f.CVSS == nil {
			f.CVSS = floatPtr(parseFloatLoose(r.CVSS2Max))
		}
		f.CVE = firstMatch(cveRe, cves...)
		if len(r.FixedVersions) > 0 {
			fx := strings.Trim(r.FixedVersions[0], "[] ")
			if !strings.ContainsAny(fx, ",()") {
				f.FixedVersion = fx
			}
		}
		id := r.IssueID
		if f.CVE != "" {
			id = f.CVE + " (" + r.IssueID + ")"
		}
		f.Title = fmt.Sprintf("%s in %s %s", id, name, version)
		desc := []string{r.Summary, r.Description, "Component: " + r.VulnerableComponent, "Impacted artifact: " + r.ImpactedArtifact}
		if len(r.FixedVersions) > 0 {
			desc = append(desc, "Fixed versions: "+strings.Join(r.FixedVersions, ", "))
		}
		if len(r.ImpactPath) > 0 {
			desc = append(desc, "Impact path: "+strings.Join(r.ImpactPath, " > "))
		}
		f.Description = joinText(desc...)
		out = append(out, importRecord{F: f, Raw: it})
	}
	return out, nil
}
