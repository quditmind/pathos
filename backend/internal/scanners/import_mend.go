package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Mend (formerly WhiteSource) JSON, two published shapes:
//   - the legacy API / Unified Agent vulnerability report
//     (getProjectVulnerabilityReport / getOrganizationVulnerabilityReport
//     with format json): vulnerabilities[] with name (CVE or WS id),
//     severity, score / cvss3_score, scoreMetadataVector, description,
//     topFix (fixResolution) and library (groupId, artifactId, name,
//     version, filename, type);
//   - the Mend platform API 3.0 dependency findings
//     (/api/v3.0/projects/{uuid}/dependencies/findings/security):
//     response[] with vulnerability (name, severity, score, description),
//     component (name, groupId, artifactId, version, path, dependencyFile),
//     findingInfo (status), topFix and exploitable.
// Findings the platform marks IGNORED are imported with low confidence.

type mendLibrary struct {
	Name       string `json:"name"`
	GroupID    string `json:"groupId"`
	ArtifactID string `json:"artifactId"`
	Version    string `json:"version"`
	Filename   string `json:"filename"`
	Type       string `json:"type"`
	Path       string `json:"path"`
	DepFile    string `json:"dependencyFile"`
}

type mendTopFix struct {
	FixResolution string `json:"fixResolution"`
	URL           string `json:"url"`
}

type mendLegacyVuln struct {
	Name                string      `json:"name"`
	Type                string      `json:"type"`
	Severity            string      `json:"severity"`
	Score               looseString `json:"score"`
	CVSS3Severity       string      `json:"cvss3_severity"`
	CVSS3Score          looseString `json:"cvss3_score"`
	ScoreMetadataVector string      `json:"scoreMetadataVector"`
	Description         string      `json:"description"`
	URL                 string      `json:"url"`
	TopFix              mendTopFix  `json:"topFix"`
	Library             mendLibrary `json:"library"`
	Project             string      `json:"project"`
}

type mendPlatformFinding struct {
	Vulnerability struct {
		Name        string      `json:"name"`
		Type        string      `json:"type"`
		Description string      `json:"description"`
		Score       looseString `json:"score"`
		Severity    string      `json:"severity"`
	} `json:"vulnerability"`
	Component   mendLibrary `json:"component"`
	FindingInfo struct {
		Status string `json:"status"`
	} `json:"findingInfo"`
	TopFix              mendTopFix `json:"topFix"`
	Exploitable         bool       `json:"exploitable"`
	ScoreMetadataVector string     `json:"scoreMetadataVector"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "mend", Label: "Mend (WhiteSource) vulnerability JSON", Tool: "Mend", Category: "sca", Media: "json", Order: 200,
		match: func(p *importProbe) bool {
			if p.kind != "object" {
				return false
			}
			return p.has("vulnerabilities") && hasKeys(p.firstOf("vulnerabilities"), "name", "library") ||
				p.has("response") && hasKeys(p.firstOf("response"), "vulnerability", "component")
		},
		parse: parseMend})
}

// mendFixed extracts the version of "Upgrade to version 1.2.3" fix texts.
func mendFixed(s string) string {
	for _, p := range []string{"Upgrade to version ", "upgrade to version "} {
		if _, v, ok := strings.Cut(s, p); ok {
			v = strings.Fields(v + " ")[0]
			v = strings.TrimRight(v, ".,;")
			if !strings.ContainsAny(v, ",;") {
				return v
			}
		}
	}
	return ""
}

func mendFinding(name, sev string, score looseString, vector, desc string, lib mendLibrary, fix mendTopFix) Finding {
	pkg := firstNonEmpty(lib.ArtifactID, lib.Name)
	f := Finding{Category: "sca", RuleID: name, Severity: sev, CVE: firstMatch(cveRe, name), PackageName: pkg, PackageVersion: lib.Version,
		CVSSVector: vector, FixedVersion: mendFixed(fix.FixResolution), FilePath: NormalizePath(firstNonEmpty(lib.DepFile, lib.Path))}
	var s float64
	if _, err := fmt.Sscanf(string(score), "%g", &s); err == nil {
		f.CVSS = floatPtr(s)
	}
	f.Title = fmt.Sprintf("%s in %s %s", name, pkg, lib.Version)
	coord := lib.Filename
	if lib.GroupID != "" {
		coord = lib.GroupID + ":" + lib.ArtifactID + ":" + lib.Version
	}
	f.Description = joinText(desc, "Library: "+coord, "Fix: "+fix.FixResolution, fix.URL)
	return f
}

func parseMend(raw []byte) ([]importRecord, error) {
	var doc struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		Response        []json.RawMessage `json:"response"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("mend: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range doc.Vulnerabilities {
		var v mendLegacyVuln
		if err := json.Unmarshal(it, &v); err != nil || v.Name == "" || firstNonEmpty(v.Library.ArtifactID, v.Library.Name) == "" {
			return out, fmt.Errorf("mend: vulnerability %d: expected name and library", i+1)
		}
		score := firstNonEmpty(string(v.CVSS3Score), string(v.Score))
		f := mendFinding(v.Name, firstNonEmpty(v.CVSS3Severity, v.Severity), looseString(score), v.ScoreMetadataVector, v.Description, v.Library, v.TopFix)
		if v.Project != "" {
			f.Description += "\n\nMend project: " + v.Project
		}
		out = append(out, importRecord{F: f, Raw: it})
	}
	for i, it := range doc.Response {
		var v mendPlatformFinding
		if err := json.Unmarshal(it, &v); err != nil || v.Vulnerability.Name == "" || firstNonEmpty(v.Component.ArtifactID, v.Component.Name) == "" {
			return out, fmt.Errorf("mend: finding %d: expected vulnerability.name and component", i+1)
		}
		f := mendFinding(v.Vulnerability.Name, v.Vulnerability.Severity, v.Vulnerability.Score, v.ScoreMetadataVector, v.Vulnerability.Description, v.Component, v.TopFix)
		if v.Exploitable {
			f.Description += "\n\nMend: known exploit."
		}
		if strings.EqualFold(v.FindingInfo.Status, "IGNORED") {
			f.Confidence = "low"
			f.Description += "\n\nIgnored in Mend."
		}
		out = append(out, importRecord{F: f, Raw: it})
	}
	return out, nil
}
