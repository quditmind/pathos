package scanners

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"pathos/internal/platform/logging"
)

// Acunetix reports: the XML export of Acunetix (on-premises; <ScanGroup> of
// <Scan> with <ReportItems>) and the JSON vulnerabilities report of
// Acunetix 360, which has the Invicti JSON layout (import_invicti.go) and is
// told apart by the scanner name Acunetix 360 writes into it. One finding
// per report item: the location is the scan's start URL joined with the
// affected path, identity the module, parameter and path. Items marked as
// false positives are kept with low confidence. Built from the published
// format; not yet verified against a real export.

type acunetixItem struct {
	Name            string   `xml:"Name"`
	ModuleName      string   `xml:"ModuleName"`
	Details         string   `xml:"Details"`
	Affects         string   `xml:"Affects"`
	Parameter       string   `xml:"Parameter"`
	AOPSourceFile   string   `xml:"AOP_SourceFile"`
	AOPSourceLine   string   `xml:"AOP_SourceLine"`
	IsFalsePositive string   `xml:"IsFalsePositive"`
	Severity        string   `xml:"Severity"`
	Type            string   `xml:"Type"`
	Impact          string   `xml:"Impact"`
	Description     string   `xml:"Description"`
	Recommendation  string   `xml:"Recommendation"`
	Requests        []string `xml:"TechnicalDetails>Request"`
	CWEs            []string `xml:"CWEList>CWE"`
	CVEs            []string `xml:"CVEList>CVE"`
	CVSS3           struct {
		Descriptor string `xml:"Descriptor"`
		Score      string `xml:"Score"`
	} `xml:"CVSS3"`
	CVSS struct {
		Descriptor string `xml:"Descriptor"`
		Score      string `xml:"Score"`
	} `xml:"CVSS"`
}

// acunetixRecord is the record kept as a finding's original output.
type acunetixRecord struct {
	StartURL       string   `json:"start_url"`
	Name           string   `json:"name"`
	ModuleName     string   `json:"module_name,omitempty"`
	Type           string   `json:"type,omitempty"`
	Affects        string   `json:"affects"`
	Parameter      string   `json:"parameter,omitempty"`
	Severity       string   `json:"severity"`
	FalsePositive  string   `json:"is_false_positive,omitempty"`
	CWE            []string `json:"cwe,omitempty"`
	CVE            []string `json:"cve,omitempty"`
	CVSS3          string   `json:"cvss3,omitempty"`
	Details        string   `json:"details,omitempty"`
	Description    string   `json:"description,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Requests       []string `json:"requests,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "acunetix", Label: "Acunetix XML export and Acunetix 360 JSON", Tool: "Acunetix", Category: "dast", Media: "xml", Order: 400,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "xml":
				return p.root == "ScanGroup" && p.rootAttrs["#child"] == "Scan"
			case "object":
				return invictiJSONShape(p) && acunetix360Marked(p)
			}
			return false
		},
		parse: parseAcunetix,
		sanitize: func(raw []byte) []byte {
			b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
			if len(b) > 0 && b[0] == '<' {
				return acunetixCookiesRe.ReplaceAll(sanitizeHTTPText(raw), []byte("${1}"+logging.Redacted+"${2}"))
			}
			return sanitizeInvicti(raw)
		}})
}

// acunetix360Marked reports whether an Invicti-layout JSON report was
// written by Acunetix 360 (its scanner header and descriptions name it).
func acunetix360Marked(p *importProbe) bool {
	return p.headHas("Acunetix360") || p.headHas("Acunetix 360")
}

// acunetixCookiesRe matches the crawler's cookie list of the XML export.
var acunetixCookiesRe = regexp.MustCompile(`(?s)(<Cookies>).*?(</Cookies>)`)

func parseAcunetix(raw []byte) ([]importRecord, error) {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if len(b) == 0 || b[0] != '<' {
		return parseInvictiReport("Acunetix 360", raw)
	}
	var doc struct {
		Scans []struct {
			StartURL string         `xml:"StartURL"`
			Items    []acunetixItem `xml:"ReportItems>ReportItem"`
		} `xml:"Scan"`
	}
	if err := decodeXML(b, &doc); err != nil {
		return nil, fmt.Errorf("acunetix: %w", err)
	}
	var out []importRecord
	for _, sc := range doc.Scans {
		start := strings.TrimSpace(sc.StartURL)
		if start != "" && !strings.Contains(start, "://") {
			start = "http://" + start
		}
		for i, it := range sc.Items {
			name := strings.TrimSpace(it.Name)
			if name == "" {
				return out, fmt.Errorf("acunetix: report item %d: missing name", i+1)
			}
			affects := strings.TrimSpace(it.Affects)
			// Affects is a path below the start URL, a full URL, or a
			// component name ("Web Server") for site-wide items.
			url := start
			switch {
			case strings.Contains(affects, "://") || (start == "" && affects != ""):
				url = affects
			case strings.HasPrefix(affects, "/"):
				url = strings.TrimRight(start, "/") + affects
			}
			f := Finding{Category: "dast", RuleID: firstNonEmpty(it.ModuleName, it.Type, name), Title: name,
				Severity: firstNonEmpty(normSeverity(it.Severity), "info"), FilePath: locationOf("", redactHTTP(url)), CWE: it.CWEs}
			for _, c := range it.CVEs {
				if m := firstMatch(cveRe, c); m != "" {
					f.CVE = m
					break
				}
			}
			if d := strings.TrimSpace(it.CVSS3.Descriptor); strings.HasPrefix(d, "CVSS:3") {
				f.CVSSVector, f.CVSS = d, cvssOf(it.CVSS3.Score)
			} else if d := strings.TrimSpace(it.CVSS.Descriptor); strings.HasPrefix(d, "AV:") {
				f.CVSSVector, f.CVSS = d, cvssOf(it.CVSS.Score)
			}
			note := ""
			if strings.EqualFold(strings.TrimSpace(it.IsFalsePositive), "true") {
				f.Confidence, note = "low", "Acunetix marked this item as a false positive; it is kept for review."
			}
			source := ""
			if it.AOPSourceFile != "" {
				source = it.AOPSourceFile + ":" + strings.TrimSpace(it.AOPSourceLine)
			}
			var reqs []string
			for _, r := range it.Requests {
				if r = strings.TrimSpace(r); r != "" {
					reqs = append(reqs, redactHTTP(r))
				}
			}
			f.Description = joinText(note, markupToText(it.Description), whereText("", url, it.Parameter),
				labelled("Details", clipText(redactHTTP(markupToText(it.Details)), 2000)), labelled("Affects", affects), labelled("Impact", it.Impact),
				labelled("Source (AcuSensor)", source), labelled("Recommendation", markupToText(it.Recommendation)))
			rec := acunetixRecord{StartURL: start, Name: name, ModuleName: it.ModuleName, Type: it.Type, Affects: affects, Parameter: it.Parameter,
				Severity: it.Severity, FalsePositive: it.IsFalsePositive, CWE: it.CWEs, CVE: it.CVEs, CVSS3: it.CVSS3.Descriptor,
				Details: clipText(redactHTTP(it.Details), maxEvidenceText), Description: clipText(markupToText(it.Description), maxEvidenceText),
				Recommendation: clipText(it.Recommendation, maxEvidenceText), Requests: reqs}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(it.Parameter + "|" + it.Type), Raw: rawJSON(rec)})
		}
	}
	return out, nil
}
