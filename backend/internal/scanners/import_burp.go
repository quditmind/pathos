package scanners

import (
	"fmt"
	"strings"
)

// Burp Suite XML export ("Report selected issues" / "Save selected issues",
// format XML): <issues burpVersion> of <issue>. Request and response bodies
// may carry cookies and credentials; the record keeps only how many there
// were.

type burpIssue struct {
	SerialNumber string `xml:"serialNumber"`
	Type         string `xml:"type"`
	Name         string `xml:"name"`
	Host         struct {
		IP  string `xml:"ip,attr"`
		URL string `xml:",chardata"`
	} `xml:"host"`
	Path                         string `xml:"path"`
	Location                     string `xml:"location"`
	Severity                     string `xml:"severity"`
	Confidence                   string `xml:"confidence"`
	IssueBackground              string `xml:"issueBackground"`
	RemediationBackground        string `xml:"remediationBackground"`
	IssueDetail                  string `xml:"issueDetail"`
	RemediationDetail            string `xml:"remediationDetail"`
	References                   string `xml:"references"`
	VulnerabilityClassifications string `xml:"vulnerabilityClassifications"`
	RequestResponse              []struct {
		Request  struct{} `xml:"request"`
		Response struct{} `xml:"response"`
	} `xml:"requestresponse"`
}

// burpRecord is the record kept as a finding's original output.
type burpRecord struct {
	SerialNumber                 string `json:"serialNumber,omitempty"`
	Type                         string `json:"type"`
	Name                         string `json:"name"`
	Host                         string `json:"host"`
	HostIP                       string `json:"host_ip,omitempty"`
	Path                         string `json:"path"`
	Location                     string `json:"location,omitempty"`
	Severity                     string `json:"severity"`
	Confidence                   string `json:"confidence"`
	IssueDetail                  string `json:"issueDetail,omitempty"`
	IssueBackground              string `json:"issueBackground,omitempty"`
	RemediationDetail            string `json:"remediationDetail,omitempty"`
	RemediationBackground        string `json:"remediationBackground,omitempty"`
	VulnerabilityClassifications string `json:"vulnerabilityClassifications,omitempty"`
	// RequestResponses counts the request/response pairs of the export
	// (their content is not kept).
	RequestResponses int `json:"request_responses"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "burp", Label: "Burp Suite XML export", Category: "dast", Media: "xml", Order: 51,
		match: func(p *importProbe) bool {
			if p.kind != "xml" || p.root != "issues" {
				return false
			}
			_, v := p.rootAttrs["burpVersion"]
			return v || p.rootAttrs["#child"] == "issue"
		},
		parse: parseBurpXML})
}

func parseBurpXML(raw []byte) ([]importRecord, error) {
	var doc struct {
		Issues []burpIssue `xml:"issue"`
	}
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("burp: %w", err)
	}
	var out []importRecord
	for i, is := range doc.Issues {
		name := strings.TrimSpace(is.Name)
		if name == "" && strings.TrimSpace(is.Type) == "" {
			return out, fmt.Errorf("burp: issue %d: missing name and type", i+1)
		}
		host := strings.TrimRight(strings.TrimSpace(is.Host.URL), "/")
		path := strings.TrimSpace(is.Path)
		url := host + path
		f := Finding{Category: "dast", RuleID: firstNonEmpty(strings.TrimSpace(is.Type), name), Title: firstNonEmpty(name, is.Type),
			Severity: firstNonEmpty(normSeverity(is.Severity), "info"), FilePath: locationOf("", url),
			CWE: normCWEs([]string{markupToText(is.VulnerabilityClassifications)})}
		switch strings.ToLower(strings.TrimSpace(is.Confidence)) {
		case "certain":
			f.Confidence = "high"
		case "firm":
			f.Confidence = "medium"
		case "tentative":
			f.Confidence = "low"
		}
		f.Description = joinText(markupToText(is.IssueDetail), markupToText(is.IssueBackground),
			labelled("Location", is.Location), labelled("Remediation", markupToText(firstNonEmpty(is.RemediationDetail, is.RemediationBackground))))
		rec := burpRecord{SerialNumber: is.SerialNumber, Type: is.Type, Name: name, Host: host, HostIP: is.Host.IP, Path: path, Location: is.Location,
			Severity: is.Severity, Confidence: is.Confidence, IssueDetail: clipText(is.IssueDetail, maxEvidenceText),
			IssueBackground: clipText(is.IssueBackground, maxEvidenceText), RemediationDetail: clipText(is.RemediationDetail, maxEvidenceText),
			RemediationBackground:        clipText(is.RemediationBackground, maxEvidenceText),
			VulnerabilityClassifications: clipText(is.VulnerabilityClassifications, maxEvidenceText), RequestResponses: len(is.RequestResponse)}
		// The location names the insertion point ("/search [q parameter]").
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.TrimSpace(is.Location)), Raw: rawJSON(rec)})
	}
	return out, nil
}
