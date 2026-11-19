package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Dependency-Track Finding Packaging Format (FPF, `GET /api/v1/finding/
// project/{uuid}/export`): version, meta (application "Dependency-Track"),
// project and findings[], each with component (name, group, version,
// purl), vulnerability (vulnId, source, severity, cwes, cvssV3BaseScore,
// cvssV3Vector, aliases) and analysis (state, isSuppressed). Findings
// analysed as false positive or not affected, and suppressed ones, are
// imported with low confidence and the verdict in the description.

type dtrackFinding struct {
	Component struct {
		Name    string `json:"name"`
		Group   string `json:"group"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"component"`
	Vulnerability struct {
		VulnID          string  `json:"vulnId"`
		Source          string  `json:"source"`
		Title           string  `json:"title"`
		Description     string  `json:"description"`
		Recommendation  string  `json:"recommendation"`
		Severity        string  `json:"severity"`
		CVSSv3BaseScore float64 `json:"cvssV3BaseScore"`
		CVSSv3Vector    string  `json:"cvssV3Vector"`
		CVSSv2BaseScore float64 `json:"cvssV2BaseScore"`
		CWEID           int     `json:"cweId"`
		CWEs            []struct {
			CWEID int `json:"cweId"`
		} `json:"cwes"`
		Aliases []map[string]string `json:"aliases"`
	} `json:"vulnerability"`
	Analysis struct {
		State        string `json:"state"`
		IsSuppressed bool   `json:"isSuppressed"`
	} `json:"analysis"`
}

// isDependencyTrackFPF tells an FPF document from PATHOS findings JSON
// (both have a top-level "findings").
func isDependencyTrackFPF(p *importProbe) bool {
	if p.kind != "object" || !p.has("findings", "meta", "project") {
		return false
	}
	var meta struct {
		Application string `json:"application"`
	}
	return json.Unmarshal(p.keys["meta"], &meta) == nil && strings.EqualFold(meta.Application, "Dependency-Track")
}

func init() {
	registerImportFormat(ImportFormat{ID: "dependency-track", Label: "Dependency-Track findings (FPF JSON)", Tool: "Dependency-Track", Category: "sca", Media: "json", Order: 221,
		match: isDependencyTrackFPF,
		parse: parseDependencyTrack})
}

func parseDependencyTrack(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "findings")
	if err != nil {
		return nil, fmt.Errorf("dependency-track: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var d dtrackFinding
		if err := json.Unmarshal(it, &d); err != nil || d.Vulnerability.VulnID == "" || d.Component.Name == "" {
			return out, fmt.Errorf("dependency-track: finding %d: expected component.name and vulnerability.vulnId", i+1)
		}
		v, c := d.Vulnerability, d.Component
		name, version := c.Name, c.Version
		if pn, pv := purlNameVersion(c.Purl); pn != "" {
			name, version = pn, firstNonEmpty(version, pv)
		}
		f := Finding{Category: "sca", RuleID: v.VulnID, Severity: v.Severity, PackageName: name, PackageVersion: version,
			CVSS: floatPtr(v.CVSSv3BaseScore), CVSSVector: v.CVSSv3Vector}
		if f.CVSS == nil {
			f.CVSS = floatPtr(v.CVSSv2BaseScore)
		}
		if strings.EqualFold(f.Severity, "unassigned") {
			f.Severity = ""
		}
		if v.CWEID > 0 {
			f.CWE = append(f.CWE, fmt.Sprintf("CWE-%d", v.CWEID))
		}
		for _, w := range v.CWEs {
			f.CWE = append(f.CWE, fmt.Sprintf("CWE-%d", w.CWEID))
		}
		ids := []string{v.VulnID}
		for _, a := range v.Aliases {
			ids = append(ids, a["cveId"])
		}
		f.CVE = firstMatch(cveRe, ids...)
		id := v.VulnID
		if f.CVE != "" && f.CVE != v.VulnID {
			id = f.CVE + " (" + v.VulnID + ")"
		}
		pkg := name
		if c.Group != "" && !strings.Contains(c.Purl, "/"+name+"@") {
			pkg = c.Group + ":" + name
		}
		f.Title = fmt.Sprintf("%s in %s %s", id, pkg, version)
		desc := []string{v.Title, v.Description, v.Recommendation, "Source: " + v.Source}
		if c.Purl != "" {
			desc = append(desc, "Component: "+c.Purl)
		}
		switch st := d.Analysis.State; {
		case st == "FALSE_POSITIVE" || st == "NOT_AFFECTED" || d.Analysis.IsSuppressed:
			f.Confidence = "low"
			desc = append(desc, fmt.Sprintf("Dependency-Track analysis: %s (suppressed: %t)", st, d.Analysis.IsSuppressed))
		case st != "" && st != "NOT_SET":
			desc = append(desc, "Dependency-Track analysis: "+st)
		}
		f.Description = joinText(desc...)
		out = append(out, importRecord{F: f, Raw: it})
	}
	return out, nil
}
