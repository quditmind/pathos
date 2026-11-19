package scanners

import (
	"fmt"
	"strconv"
	"strings"
)

// Tenable Nessus v2 export (.nessus): ReportHost / ReportItem. One finding
// per item; informational items (severity 0) are kept as info. The location
// is "host:port/protocol"; identity is plugin, host and port.

type nessusItem struct {
	Port         string   `xml:"port,attr"`
	SvcName      string   `xml:"svc_name,attr"`
	Protocol     string   `xml:"protocol,attr"`
	Severity     string   `xml:"severity,attr"`
	PluginID     string   `xml:"pluginID,attr"`
	PluginName   string   `xml:"pluginName,attr"`
	PluginFamily string   `xml:"pluginFamily,attr"`
	Synopsis     string   `xml:"synopsis"`
	Description  string   `xml:"description"`
	Solution     string   `xml:"solution"`
	RiskFactor   string   `xml:"risk_factor"`
	CVSS3Score   string   `xml:"cvss3_base_score"`
	CVSS3Vector  string   `xml:"cvss3_vector"`
	CVSSScore    string   `xml:"cvss_base_score"`
	CVSSVector   string   `xml:"cvss_vector"`
	CVE          []string `xml:"cve"`
	CWE          []string `xml:"cwe"`
	Xref         []string `xml:"xref"`
	SeeAlso      string   `xml:"see_also"`
	PluginOutput string   `xml:"plugin_output"`
}

type nessusHost struct {
	Name  string `xml:"name,attr"`
	Props []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:",chardata"`
	} `xml:"HostProperties>tag"`
	Items []nessusItem `xml:"ReportItem"`
}

// nessusRecord is the record kept as a finding's original output.
type nessusRecord struct {
	Host string `json:"host"`
	nessusItem
}

func init() {
	registerImportFormat(ImportFormat{ID: "nessus", Label: "Nessus (.nessus v2)", Category: "other", Media: "xml", Order: 70,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "NessusClientData_v2" },
		parse: parseNessus})
}

func parseNessus(raw []byte) ([]importRecord, error) {
	var doc struct {
		Reports []struct {
			Hosts []nessusHost `xml:"ReportHost"`
		} `xml:"Report"`
	}
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("nessus: %w", err)
	}
	var out []importRecord
	for _, r := range doc.Reports {
		for _, h := range r.Hosts {
			host := h.Name
			for _, p := range h.Props {
				if p.Name == "host-fqdn" && strings.TrimSpace(p.Value) != "" && host == "" {
					host = strings.TrimSpace(p.Value)
				}
			}
			for _, it := range h.Items {
				if len(out) >= MaxFindingsPerReport {
					return out, nil
				}
				out = append(out, nessusFinding(host, it))
			}
		}
	}
	return out, nil
}

func nessusFinding(host string, it nessusItem) importRecord {
	loc := host
	if it.Port != "" {
		loc = fmt.Sprintf("%s:%s/%s", host, it.Port, firstNonEmpty(it.Protocol, "tcp"))
	}
	f := Finding{RuleID: firstNonEmpty(it.PluginID, it.PluginName), Title: firstNonEmpty(it.PluginName, "Nessus plugin "+it.PluginID),
		Severity: normSeverity(it.Severity), FilePath: loc, CWE: it.CWE}
	if f.Severity == "" {
		f.Severity = firstNonEmpty(normSeverity(it.RiskFactor), "info")
	}
	for _, x := range it.Xref {
		if k, v, ok := strings.Cut(x, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "CWE") {
			f.CWE = append(f.CWE, strings.TrimSpace(v))
		}
	}
	for _, c := range it.CVE {
		if m := firstMatch(cveRe, c); m != "" {
			f.CVE = m
			break
		}
	}
	if s, err := strconv.ParseFloat(strings.TrimSpace(it.CVSS3Score), 64); err == nil {
		f.CVSS = floatPtr(s)
	} else if s, err := strconv.ParseFloat(strings.TrimSpace(it.CVSSScore), 64); err == nil {
		f.CVSS = floatPtr(s)
	}
	switch v := strings.TrimSpace(it.CVSS3Vector); {
	case strings.HasPrefix(v, "CVSS:3"):
		f.CVSSVector = v
	case strings.HasPrefix(v, "AV:"):
		f.CVSSVector = "CVSS:3.0/" + v // Nessus stores v3 vectors with the prefix; older exports did not
	default:
		if v2 := strings.TrimPrefix(strings.TrimSpace(it.CVSSVector), "CVSS2#"); strings.HasPrefix(v2, "AV:") {
			f.CVSSVector = v2
		}
	}
	f.Description = joinText(it.Synopsis, it.Description, labelled("Solution", it.Solution),
		labelled("Plugin output", clipText(it.PluginOutput, 2000)), labelled("See also", it.SeeAlso))
	rec := nessusRecord{Host: host, nessusItem: it}
	rec.PluginOutput = clipText(it.PluginOutput, maxEvidenceText)
	rec.Description = clipText(it.Description, maxEvidenceText)
	return importRecord{F: f, SnippetKey: hashOf(it.SvcName), Raw: rawJSON(rec)}
}
