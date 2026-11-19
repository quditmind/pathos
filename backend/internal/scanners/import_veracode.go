package scanners

import (
	"fmt"
	"strconv"
	"strings"
)

// Veracode detailed report XML (detailedreport.xsd, "Detailed Report" XML
// from the platform or the getdetailedreport API): severity / category /
// cwe / staticflaws|dynamicflaws / flaw, and
// software_composition_analysis / vulnerable_components / component /
// vulnerabilities / vulnerability. Every flaw carries its own severity
// (0-5: 5 Very High critical, 4 High high, 3 Medium medium, 2 Low low,
// 1 Very Low low, 0 Informational info), cweid, issueid (the identity),
// remediation and mitigation status. Static flaws are sast at
// sourcefilepath+sourcefile and line; dynamic flaws dast at their URL;
// component vulnerabilities sca. Flaws with remediation_status "Fixed" no
// longer exist in the application and are not imported; flaws with an
// accepted mitigation are imported with low confidence and the
// mitigation noted.

type veracodeMitigation struct {
	Action      string `xml:"action,attr" json:"action"`
	Description string `xml:"description,attr" json:"description"`
	User        string `xml:"user,attr" json:"user,omitempty"`
	Date        string `xml:"date,attr" json:"date,omitempty"`
}

type veracodeFlaw struct {
	IssueID           string               `xml:"issueid,attr" json:"issueid"`
	Severity          string               `xml:"severity,attr" json:"severity"`
	CategoryName      string               `xml:"categoryname,attr" json:"categoryname"`
	CWEID             string               `xml:"cweid,attr" json:"cweid,omitempty"`
	Type              string               `xml:"type,attr" json:"type,omitempty"`
	Description       string               `xml:"description,attr" json:"description,omitempty"`
	Module            string               `xml:"module,attr" json:"module,omitempty"`
	RemediationStatus string               `xml:"remediation_status,attr" json:"remediation_status,omitempty"`
	MitigationStatus  string               `xml:"mitigation_status,attr" json:"mitigation_status,omitempty"`
	MitigationDesc    string               `xml:"mitigation_status_desc,attr" json:"mitigation_status_desc,omitempty"`
	AffectsPolicy     string               `xml:"affects_policy_compliance,attr" json:"affects_policy_compliance,omitempty"`
	FirstOccurrence   string               `xml:"date_first_occurrence,attr" json:"date_first_occurrence,omitempty"`
	SourceFile        string               `xml:"sourcefile,attr" json:"sourcefile,omitempty"`
	SourceFilePath    string               `xml:"sourcefilepath,attr" json:"sourcefilepath,omitempty"`
	Line              int                  `xml:"line,attr" json:"line,omitempty"`
	Scope             string               `xml:"scope,attr" json:"scope,omitempty"`
	Function          string               `xml:"functionprototype,attr" json:"functionprototype,omitempty"`
	URL               string               `xml:"url,attr" json:"url,omitempty"`
	Parameter         string               `xml:"vuln_parameter,attr" json:"vuln_parameter,omitempty"`
	Mitigations       []veracodeMitigation `xml:"mitigations>mitigation" json:"mitigations,omitempty"`
}

type veracodeComponent struct {
	ComponentID string `xml:"component_id,attr" json:"component_id"`
	FileName    string `xml:"file_name,attr" json:"file_name"`
	Library     string `xml:"library,attr" json:"library"`
	Version     string `xml:"version,attr" json:"version"`
	Vendor      string `xml:"vendor,attr" json:"vendor,omitempty"`
	FilePaths   []struct {
		Value string `xml:"value,attr" json:"value"`
	} `xml:"file_paths>file_path" json:"file_paths,omitempty"`
	Vulns []veracodeSCAVuln `xml:"vulnerabilities>vulnerability" json:"-"`
}

type veracodeSCAVuln struct {
	CVEID      string `xml:"cve_id,attr" json:"cve_id"`
	CVSSScore  string `xml:"cvss_score,attr" json:"cvss_score"`
	Severity   string `xml:"severity,attr" json:"severity"`
	CWEID      string `xml:"cwe_id,attr" json:"cwe_id,omitempty"`
	Summary    string `xml:"cve_summary,attr" json:"cve_summary,omitempty"`
	Mitigation string `xml:"mitigation,attr" json:"mitigation,omitempty"`
	MitType    string `xml:"mitigation_type,attr" json:"mitigation_type,omitempty"`
}

var veracodeSeverity = map[string]string{"5": "critical", "4": "high", "3": "medium", "2": "low", "1": "low", "0": "info"}

func init() {
	registerImportFormat(ImportFormat{ID: "veracode", Label: "Veracode detailed report XML", Tool: "Veracode", Media: "xml", Order: 101,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "detailedreport" },
		parse: parseVeracodeXML})
}

func parseVeracodeXML(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := eachXMLElement(raw, "", "flaw", func(fl *veracodeFlaw) error {
		if fl.IssueID == "" || fl.CategoryName == "" {
			return fmt.Errorf("veracode: flaw %d: expected issueid and categoryname", len(out)+1)
		}
		if strings.EqualFold(fl.RemediationStatus, "fixed") {
			return nil
		}
		sev, ok := veracodeSeverity[fl.Severity]
		if !ok {
			sev = "medium"
		}
		f := Finding{Category: "sast", RuleID: fl.CategoryName, Title: fl.CategoryName, Severity: sev, CWE: []string{fl.CWEID},
			Description: joinText(fl.Description, labelled("Module", fl.Module), labelled("Function", fl.Function),
				labelled("Veracode status", strings.TrimSpace(fl.RemediationStatus+", "+fl.MitigationDesc)))}
		if fl.URL != "" {
			f.Category, f.FilePath = "dast", fl.URL
			if fl.Parameter != "" {
				f.Title += " (" + fl.Parameter + ")"
			}
		} else {
			f.FilePath, f.StartLine = NormalizePath(fl.SourceFilePath+fl.SourceFile), intPtr(fl.Line)
		}
		if strings.EqualFold(fl.MitigationStatus, "accepted") {
			f.Confidence = "low"
			notes := []string{"Veracode mitigation accepted; the flaw is kept for review."}
			for _, m := range fl.Mitigations {
				notes = append(notes, m.Action+": "+m.Description)
			}
			f.Description = joinText(strings.Join(notes, "\n"), f.Description)
		}
		fl.Description = clipText(fl.Description, maxEvidenceText)
		out = append(out, importRecord{F: f, SnippetKey: hashOf("veracode|" + fl.IssueID), Raw: rawJSON(fl)})
		return nil
	})
	if err != nil {
		return out, err
	}
	err = eachXMLElement(raw, "vulnerable_components", "component", func(c *veracodeComponent) error {
		if c.Library == "" && c.FileName == "" {
			return fmt.Errorf("veracode: component %s without library or file_name", c.ComponentID)
		}
		file := ""
		if len(c.FilePaths) > 0 {
			file = c.FilePaths[0].Value
		}
		for _, v := range c.Vulns {
			sev, ok := veracodeSeverity[v.Severity]
			if !ok {
				sev = ""
			}
			f := Finding{Category: "sca", RuleID: v.CVEID, CVE: v.CVEID, Severity: sev, CWE: []string{v.CWEID},
				PackageName: firstNonEmpty(c.Library, c.FileName), PackageVersion: c.Version, FilePath: NormalizePath(file),
				Title:       fmt.Sprintf("%s in %s %s", firstNonEmpty(v.CVEID, "Vulnerability"), firstNonEmpty(c.Library, c.FileName), c.Version),
				Description: v.Summary}
			if s, err := strconv.ParseFloat(v.CVSSScore, 64); err == nil {
				f.CVSS = floatPtr(s)
			}
			if strings.EqualFold(v.Mitigation, "true") {
				f.Confidence = "low"
				f.Description = joinText("Veracode mitigation: "+firstNonEmpty(v.MitType, "yes")+"; kept for review.", f.Description)
			}
			rec := map[string]any{"component": c, "vulnerability": v}
			out = append(out, importRecord{F: f, Raw: rawJSON(rec)})
		}
		return nil
	})
	return out, err
}
