package scanners

import (
	"fmt"
	"strconv"
	"strings"
)

// Rapid7 Nexpose / InsightVM XML Export 2.0 (<NexposeReport version="2.0">).
// One finding per vulnerable test result (status vulnerable-exploited,
// vulnerable-version or vulnerable-potential) of a node or of a service on
// one of its endpoints; the VulnerabilityDefinitions supply title,
// severity, CVSS, CVEs, description and solution. Tests that found nothing
// (not-vulnerable, error, skipped) are not findings. Potential
// vulnerabilities are imported with low confidence, version checks with
// medium. The location is "address:port/protocol". Rapid7 severity 1 to 10
// maps to low (1-3), medium (4-6), high (7-8) and critical (9-10). Built
// from the published format; not yet verified against a real export.

type nexposeTest struct {
	ID     string `xml:"id,attr"`
	Key    string `xml:"key,attr"`
	Status string `xml:"status,attr"`
	Body   string `xml:",innerxml"`
}

type nexposeVulnDef struct {
	ID          string `xml:"id,attr"`
	Title       string `xml:"title,attr"`
	Severity    string `xml:"severity,attr"`
	CVSSScore   string `xml:"cvssScore,attr"`
	CVSSVector  string `xml:"cvssVector,attr"`
	Description struct {
		Body string `xml:",innerxml"`
	} `xml:"description"`
	Solution struct {
		Body string `xml:",innerxml"`
	} `xml:"solution"`
	References []struct {
		Source string `xml:"source,attr"`
		Value  string `xml:",chardata"`
	} `xml:"references>reference"`
}

// nexposeRecord is the record kept as a finding's original output.
type nexposeRecord struct {
	Address    string   `json:"address"`
	Name       string   `json:"name,omitempty"`
	Port       string   `json:"port,omitempty"`
	Protocol   string   `json:"protocol,omitempty"`
	Service    string   `json:"service,omitempty"`
	TestID     string   `json:"test_id"`
	Key        string   `json:"key,omitempty"`
	Status     string   `json:"status"`
	Title      string   `json:"title,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	CVSSScore  string   `json:"cvss_score,omitempty"`
	CVSSVector string   `json:"cvss_vector,omitempty"`
	CVEs       []string `json:"cves,omitempty"`
	Proof      string   `json:"proof,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "nexpose", Label: "Rapid7 Nexpose / InsightVM XML Export 2.0", Tool: "Nexpose", Category: "other", Media: "xml", Order: 412,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "NexposeReport" },
		parse: parseNexpose, sanitize: sanitizeHTTPText})
}

func parseNexpose(raw []byte) ([]importRecord, error) {
	var doc struct {
		Nodes []struct {
			Address   string        `xml:"address,attr"`
			Names     []string      `xml:"names>name"`
			Tests     []nexposeTest `xml:"tests>test"`
			Endpoints []struct {
				Protocol string `xml:"protocol,attr"`
				Port     string `xml:"port,attr"`
				Services []struct {
					Name  string        `xml:"name,attr"`
					Tests []nexposeTest `xml:"tests>test"`
				} `xml:"services>service"`
			} `xml:"endpoints>endpoint"`
		} `xml:"nodes>node"`
		Defs []nexposeVulnDef `xml:"VulnerabilityDefinitions>vulnerability"`
	}
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("nexpose: %w", err)
	}
	defs := map[string]nexposeVulnDef{}
	for _, d := range doc.Defs {
		defs[strings.ToLower(d.ID)] = d
	}
	var out []importRecord
	add := func(addr, name, port, proto, svc string, t nexposeTest) {
		st := strings.ToLower(t.Status)
		if !strings.HasPrefix(st, "vulnerable") {
			return
		}
		d := defs[strings.ToLower(t.ID)]
		f := Finding{RuleID: t.ID, Title: firstNonEmpty(d.Title, t.ID), Severity: nexposeSeverity(d.Severity),
			FilePath: hostLocation(firstNonEmpty(addr, name), port, proto), CWE: []string{}, CVSS: cvssOf(d.CVSSScore)}
		if v := strings.Trim(strings.TrimSpace(d.CVSSVector), "()"); strings.HasPrefix(v, "AV:") {
			f.CVSSVector = v
		}
		var cves, refs []string
		for _, r := range d.References {
			v := strings.TrimSpace(r.Value)
			switch strings.ToUpper(r.Source) {
			case "CVE":
				cves = append(cves, v)
			case "CWE":
				f.CWE = append(f.CWE, v)
			case "URL":
				refs = append(refs, v)
			}
		}
		f.CVE = firstMatch(cveRe, append(cves, t.ID)...)
		switch st {
		case "vulnerable-exploited":
			f.Confidence = "high"
		case "vulnerable-version":
			f.Confidence = "medium"
		case "vulnerable-potential":
			f.Confidence = "low"
		}
		proof := clipText(redactHTTP(markupToText(t.Body)), 2000)
		cveText := ""
		if len(cves) > 1 {
			cveText = strings.Join(cves, ", ")
		}
		f.Description = joinText(markupToText(d.Description.Body), labelled("Proof", proof), labelled("Status", t.Status),
			labelled("Service", svc), labelled("CVEs", cveText), labelled("Solution", markupToText(d.Solution.Body)),
			labelled("References", strings.Join(refs, "\n")))
		rec := nexposeRecord{Address: addr, Name: name, Port: port, Protocol: proto, Service: svc, TestID: t.ID, Key: t.Key, Status: t.Status,
			Title: d.Title, Severity: d.Severity, CVSSScore: d.CVSSScore, CVSSVector: d.CVSSVector, CVEs: cves,
			Proof: clipText(redactHTTP(markupToText(t.Body)), maxEvidenceText)}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToLower(svc) + "|" + t.Key), Raw: rawJSON(rec)})
	}
	for _, n := range doc.Nodes {
		name := ""
		if len(n.Names) > 0 {
			name = strings.TrimSpace(n.Names[0])
		}
		if n.Address == "" && name == "" {
			return out, fmt.Errorf("nexpose: node without address")
		}
		for _, t := range n.Tests {
			add(n.Address, name, "", "", "", t)
		}
		for _, e := range n.Endpoints {
			for _, s := range e.Services {
				for _, t := range s.Tests {
					add(n.Address, name, e.Port, e.Protocol, s.Name, t)
				}
			}
		}
	}
	return out, nil
}

// nexposeSeverity maps Rapid7 severity 1-10.
func nexposeSeverity(s string) string {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	switch {
	case err != nil || n <= 0:
		return "info"
	case n >= 9:
		return "critical"
	case n >= 7:
		return "high"
	case n >= 4:
		return "medium"
	}
	return "low"
}
