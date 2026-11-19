package scanners

import (
	"fmt"
	"regexp"
	"strings"
)

// ImmuniWeb vulnerabilities XML export: <Vulnerabilities> with
// <Vulnerability> elements (ID, Name, Date, Status, Type, CWE-ID, CVE-ID,
// CVSSv3 "score [vector]", Risk CRITICAL/HIGH/MEDIUM/LOW/WARNING, URL,
// Description, PoC, Remediation). WARNING is info. Vulnerabilities whose
// Status says fixed or closed are not findings. The proof of concept is
// redacted like other HTTP evidence.

type immuniwebVuln struct {
	ID          string `xml:"ID" json:"id"`
	Name        string `xml:"Name" json:"name"`
	Date        string `xml:"Date" json:"date,omitempty"`
	Status      string `xml:"Status" json:"status,omitempty"`
	Type        string `xml:"Type" json:"type,omitempty"`
	CWE         string `xml:"CWE-ID" json:"cwe,omitempty"`
	CVE         string `xml:"CVE-ID" json:"cve,omitempty"`
	CVSS        string `xml:"CVSSv3" json:"cvss,omitempty"`
	Risk        string `xml:"Risk" json:"risk"`
	URL         string `xml:"URL" json:"url,omitempty"`
	Description string `xml:"Description" json:"description,omitempty"`
	PoC         string `xml:"PoC" json:"poc,omitempty"`
	Remediation string `xml:"Remediation" json:"remediation,omitempty"`
}

var cvssVectorInText = regexp.MustCompile(`CVSS:[0-9.]+/[A-Za-z:/]+`)

func init() {
	registerImportFormat(ImportFormat{ID: "immuniweb", Label: "ImmuniWeb vulnerabilities XML export", Tool: "ImmuniWeb", Category: "dast", Media: "xml", Order: 625,
		match: func(p *importProbe) bool {
			return p.kind == "xml" && p.root == "Vulnerabilities" && (p.rootAttrs["#child"] == "Vulnerability" || p.headHas("<Risk>"))
		},
		parse: parseImmuniWeb, sanitize: sanitizeHTTPText})
}

func parseImmuniWeb(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := eachXMLElement(raw, "Vulnerabilities", "Vulnerability", func(v *immuniwebVuln) error {
		if v.Name == "" {
			return fmt.Errorf("immuniweb: vulnerability %q without Name", v.ID)
		}
		st := strings.ToLower(v.Status)
		if strings.Contains(st, "fixed") || strings.Contains(st, "closed") {
			return nil
		}
		sev := strings.ToLower(v.Risk)
		if sev == "warning" {
			sev = "info"
		}
		v.PoC = clipText(redactHTTP(xmlText(v.PoC)), 4000)
		f := Finding{Category: "dast", RuleID: firstNonEmpty(v.Type, v.Name), Title: v.Name, Severity: sev, CWE: []string{v.CWE}, CVE: v.CVE,
			CVSS: cvssOf(v.CVSS), CVSSVector: cvssVectorInText.FindString(v.CVSS), FilePath: redactHTTP(xmlText(v.URL)),
			Description: joinText(markupToText(v.Description), labeled("Remediation", markupToText(v.Remediation)), labeled("Proof of concept", v.PoC),
				labeled("Status", v.Status), labeled("Found", v.Date))}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(v.ID), Raw: rawJSON(v)})
		return nil
	})
	return out, err
}
