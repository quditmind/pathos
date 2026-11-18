package scanners

import (
	"fmt"
	"strconv"
	"strings"
)

// Greenbone / OpenVAS XML report (GMP get_reports, report format "XML"):
// <report> (often nested: report > report > results > result) or a
// <get_reports_response>. One finding per result; the location is
// "host:port" ("host general/tcp" for non-port results); identity is the
// NVT OID, host and port. False positives (threat "False Positive",
// severity -1) are kept with low confidence.

type openvasResult struct {
	ID   string `xml:"id,attr"`
	Name string `xml:"name"`
	Host struct {
		IP       string `xml:",chardata"`
		Hostname string `xml:"hostname"`
	} `xml:"host"`
	Port string `xml:"port"`
	NVT  struct {
		OID        string `xml:"oid,attr"`
		Name       string `xml:"name"`
		Family     string `xml:"family"`
		CVSSBase   string `xml:"cvss_base"`
		Severities struct {
			Score    string `xml:"score,attr"`
			Severity []struct {
				Type  string `xml:"type,attr"`
				Value string `xml:"value"`
			} `xml:"severity"`
		} `xml:"severities"`
		Tags string `xml:"tags"`
		Refs []struct {
			Type string `xml:"type,attr"`
			ID   string `xml:"id,attr"`
		} `xml:"refs>ref"`
		Solution struct {
			Type string `xml:"type,attr"`
			Text string `xml:",chardata"`
		} `xml:"solution"`
	} `xml:"nvt"`
	Threat      string `xml:"threat"`
	Severity    string `xml:"severity"`
	QoD         string `xml:"qod>value"`
	Description string `xml:"description"`
}

// openvasRecord is the record kept as a finding's original output.
type openvasRecord struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Host        string            `json:"host"`
	Hostname    string            `json:"hostname,omitempty"`
	Port        string            `json:"port"`
	OID         string            `json:"nvt_oid"`
	Family      string            `json:"nvt_family,omitempty"`
	Threat      string            `json:"threat"`
	Severity    string            `json:"severity"`
	QoD         string            `json:"qod,omitempty"`
	Tags        map[string]string `json:"tags,omitempty"`
	Refs        []string          `json:"refs,omitempty"`
	Description string            `json:"description,omitempty"`
}

// openvasRootChildren are elements that open a Greenbone report.
var openvasRootChildren = map[string]bool{"owner": true, "name": true, "gmp": true, "omp": true, "report_format": true, "report": true,
	"scan_run_status": true, "results": true, "task": true, "creation_time": true, "modification_time": true}

func init() {
	registerImportFormat(ImportFormat{ID: "openvas", Label: "OpenVAS / Greenbone XML report", Category: "other", Media: "xml", Order: 71,
		match: func(p *importProbe) bool {
			if p.kind != "xml" {
				return false
			}
			switch p.root {
			case "get_reports_response":
				return p.rootAttrs["#child"] == "report"
			case "report":
				_, fid := p.rootAttrs["format_id"]
				_, ext := p.rootAttrs["extension"]
				return fid || ext || openvasRootChildren[p.rootAttrs["#child"]]
			}
			return false
		},
		parse: parseOpenVAS})
}

func parseOpenVAS(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := eachXMLElement(raw, "results", "result", func(r *openvasResult) error {
		if len(out) >= MaxFindingsPerReport {
			return nil
		}
		out = append(out, openvasFinding(r))
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("openvas: %w", err)
	}
	return out, nil
}

// openvasTags splits "key=value|key=value" NVT tags.
func openvasTags(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, "|") {
		if k, v, ok := strings.Cut(part, "="); ok && strings.TrimSpace(k) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func openvasFinding(r *openvasResult) importRecord {
	host := strings.TrimSpace(r.Host.IP)
	port := strings.TrimSpace(r.Port)
	loc := host
	switch {
	case port != "" && port[0] >= '0' && port[0] <= '9':
		loc = host + ":" + port
	case port != "":
		loc = host + " " + port
	}
	tags := openvasTags(r.NVT.Tags)
	f := Finding{RuleID: firstNonEmpty(r.NVT.OID, r.NVT.Name, r.Name), Title: firstNonEmpty(r.Name, r.NVT.Name), FilePath: loc}
	score, scoreErr := strconv.ParseFloat(strings.TrimSpace(r.Severity), 64)
	threat := strings.TrimSpace(r.Threat)
	fp := strings.EqualFold(threat, "False Positive") || (scoreErr == nil && score < 0)
	f.Severity = normSeverity(threat)
	if f.Severity == "" && scoreErr == nil && score >= 0 {
		f.Severity = FromScore(score)
	}
	if f.Severity == "" {
		f.Severity = "info"
	}
	if scoreErr == nil {
		f.CVSS = floatPtr(score)
	}
	for _, s := range r.NVT.Severities.Severity {
		if vectorVersion(strings.TrimSpace(s.Value)) != "" {
			f.CVSSVector = strings.TrimSpace(s.Value)
			break
		}
	}
	if f.CVSSVector == "" {
		f.CVSSVector = tags["cvss_base_vector"]
	}
	var refs []string
	for _, ref := range r.NVT.Refs {
		refs = append(refs, ref.Type+":"+ref.ID)
		switch strings.ToLower(ref.Type) {
		case "cve":
			if f.CVE == "" {
				f.CVE = firstMatch(cveRe, ref.ID)
			}
		case "cwe":
			f.CWE = append(f.CWE, ref.ID)
		}
	}
	if qod, err := strconv.Atoi(strings.TrimSpace(r.QoD)); err == nil {
		switch {
		case qod >= 80:
			f.Confidence = "high"
		case qod >= 70:
			f.Confidence = "medium"
		default:
			f.Confidence = "low"
		}
	}
	note := ""
	if fp {
		f.Confidence = "low"
		note = "Greenbone marked this result as a false positive; it is kept for review."
	}
	f.Description = joinText(note, tags["summary"], labelled("Detection result", clipText(r.Description, 2000)),
		labelled("Insight", tags["insight"]), labelled("Impact", tags["impact"]),
		labelled("Solution", firstNonEmpty(strings.TrimSpace(r.NVT.Solution.Text), tags["solution"])))
	rec := openvasRecord{ID: r.ID, Name: f.Title, Host: host, Hostname: strings.TrimSpace(r.Host.Hostname), Port: port, OID: r.NVT.OID,
		Family: r.NVT.Family, Threat: threat, Severity: r.Severity, QoD: r.QoD, Tags: tags, Refs: refs,
		Description: clipText(r.Description, maxEvidenceText)}
	return importRecord{F: f, Raw: rawJSON(rec)}
}
