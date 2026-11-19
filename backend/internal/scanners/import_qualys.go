package scanners

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"pathos/internal/platform/logging"
)

// Qualys reports:
//
//   - qualys-was: Qualys Web Application Scanning XML (<WAS_SCAN_REPORT> or
//     <WAS_WEBAPP_REPORT>). One finding per vulnerability, sensitive content
//     and information-gathered item; the QID glossary supplies title,
//     severity, CWE, CVSS, description and solution. Request headers and
//     base64-encoded responses are redacted before the report is stored.
//   - qualys-vm: Qualys VMDR host scan XML (<ASSET_DATA_REPORT>). One
//     finding per host and detection (VULN_INFO); the VULN_DETAILS glossary
//     supplies title, severity, CVE and CVSS. The location is
//     "host:port/protocol".
//
// Qualys severity levels 5 (urgent) to 1 (minimal) map to critical, high,
// medium, low and info. Built from the published format; not yet verified
// against a real export.

type qualysWASItem struct {
	UniqueID      string `xml:"UNIQUE_ID"`
	ID            string `xml:"ID"`
	QID           string `xml:"QID"`
	URL           string `xml:"URL"`
	Param         string `xml:"PARAM"`
	Function      string `xml:"FUNCTION"`
	Content       string `xml:"CONTENT"`
	Ignored       string `xml:"IGNORED"`
	IgnoredReason string `xml:"IGNORE_REASON"`
	Status        string `xml:"STATUS"`
	Payloads      []struct {
		Payload string `xml:"PAYLOAD"`
		Request struct {
			Method  string `xml:"METHOD"`
			URL     string `xml:"URL"`
			Headers []struct {
				Key   string `xml:"key"`
				Value string `xml:"value"`
			} `xml:"HEADERS>HEADER"`
		} `xml:"REQUEST"`
	} `xml:"PAYLOADS>PAYLOAD"`
	Data string `xml:"DATA"`
}

type qualysWASQID struct {
	QID          string `xml:"QID"`
	Category     string `xml:"CATEGORY"`
	Severity     string `xml:"SEVERITY"`
	Title        string `xml:"TITLE"`
	Group        string `xml:"GROUP"`
	CWE          string `xml:"CWE"`
	CVSSBase     string `xml:"CVSS_BASE"`
	CVSSV3Base   string `xml:"CVSS_V3>BASE"`
	CVSSV3Vector string `xml:"CVSS_V3>ATTACK_VECTOR"`
	Description  string `xml:"DESCRIPTION"`
	Impact       string `xml:"IMPACT"`
	Solution     string `xml:"SOLUTION"`
}

// qualysWASRecord is the record kept as a finding's original output.
type qualysWASRecord struct {
	Kind     string   `json:"kind"`
	UniqueID string   `json:"unique_id,omitempty"`
	QID      string   `json:"qid"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"`
	URL      string   `json:"url"`
	Param    string   `json:"param,omitempty"`
	Ignored  string   `json:"ignored,omitempty"`
	Status   string   `json:"status,omitempty"`
	CWE      string   `json:"cwe,omitempty"`
	Payloads []string `json:"payloads,omitempty"`
	Requests []string `json:"requests,omitempty"`
	Data     string   `json:"data,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "qualys-was", Label: "Qualys WAS XML report", Tool: "Qualys WAS", Category: "dast", Media: "xml", Order: 403,
		match: func(p *importProbe) bool {
			return p.kind == "xml" && (p.root == "WAS_SCAN_REPORT" || p.root == "WAS_WEBAPP_REPORT")
		},
		parse:    parseQualysWAS,
		sanitize: sanitizeQualysWAS})
	registerImportFormat(ImportFormat{ID: "qualys-vm", Label: "Qualys VMDR scan report XML (ASSET_DATA_REPORT)", Tool: "Qualys VM", Category: "other", Media: "xml", Order: 410,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "ASSET_DATA_REPORT" },
		parse: parseQualysVM, sanitize: sanitizeHTTPText})
}

var (
	// qualysHeaderRe matches a <HEADER><key>Cookie</key><value>...</value> pair.
	qualysHeaderRe = regexp.MustCompile(`(?is)(<key>\s*([A-Za-z0-9-]+)\s*</key>\s*<value>)(.*?)(</value>)`)
	// qualysB64Re matches base64-encoded content elements.
	qualysB64Re = regexp.MustCompile(`(?s)(<(CONTENTS|DATA|CONTENT)\s+base64="true"\s*>)([^<]*)(</(?:CONTENTS|DATA|CONTENT)>)`)
)

func sanitizeQualysWAS(raw []byte) []byte {
	b := qualysHeaderRe.ReplaceAllFunc(raw, func(m []byte) []byte {
		sub := qualysHeaderRe.FindSubmatch(m)
		if !isSensitiveHeader(string(sub[2])) {
			return m
		}
		return []byte(string(sub[1]) + logging.Redacted + string(sub[4]))
	})
	b = qualysB64Re.ReplaceAllFunc(b, func(m []byte) []byte {
		sub := qualysB64Re.FindSubmatch(m)
		dec, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(sub[3])), ""))
		if err != nil {
			return []byte(string(sub[1]) + string(sub[4]))
		}
		return []byte(string(sub[1]) + base64.StdEncoding.EncodeToString(sanitizeHTTPText(dec)) + string(sub[4]))
	})
	return sanitizeHTTPText(b)
}

// qualysSeverity maps Qualys levels 1-5.
func qualysSeverity(s string) string {
	switch strings.TrimSpace(s) {
	case "5":
		return "critical"
	case "4":
		return "high"
	case "3":
		return "medium"
	case "2":
		return "low"
	}
	return "info"
}

// qualysB64 decodes a Qualys base64 field (raw text when it is not base64).
func qualysB64(s string) string {
	if d, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), "")); err == nil {
		return string(d)
	}
	return s
}

func parseQualysWAS(raw []byte) ([]importRecord, error) {
	type lists struct {
		Vulns     []qualysWASItem `xml:"VULNERABILITY_LIST>VULNERABILITY"`
		Sensitive []qualysWASItem `xml:"SENSITIVE_CONTENT_LIST>SENSITIVE_CONTENT"`
		IG        []qualysWASItem `xml:"INFORMATION_GATHERED_LIST>INFORMATION_GATHERED"`
	}
	var doc struct {
		Results struct {
			lists
			WebApps []lists `xml:"WEB_APPLICATION"`
		} `xml:"RESULTS"`
		Glossary []qualysWASQID `xml:"GLOSSARY>QID_LIST>QID"`
		WebApp   struct {
			Name string `xml:"NAME"`
			URL  string `xml:"URL"`
		} `xml:"APPENDIX>WEBAPP"`
	}
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("qualys-was: %w", err)
	}
	gloss := map[string]qualysWASQID{}
	for _, q := range doc.Glossary {
		gloss[strings.TrimSpace(q.QID)] = q
	}
	all := append([]lists{doc.Results.lists}, doc.Results.WebApps...)
	var out []importRecord
	for _, l := range all {
		for _, group := range []struct {
			kind  string
			items []qualysWASItem
		}{{"vulnerability", l.Vulns}, {"sensitive_content", l.Sensitive}, {"information_gathered", l.IG}} {
			for i, it := range group.items {
				qid := strings.TrimSpace(it.QID)
				if qid == "" {
					return out, fmt.Errorf("qualys-was: %s %d: missing QID", group.kind, i+1)
				}
				out = append(out, qualysWASFinding(group.kind, it, gloss[qid], doc.WebApp.URL))
			}
		}
	}
	return out, nil
}

func qualysWASFinding(kind string, it qualysWASItem, q qualysWASQID, appURL string) importRecord {
	qid := strings.TrimSpace(it.QID)
	url := firstNonEmpty(it.URL, appURL, "qualys-was")
	f := Finding{Category: "dast", RuleID: "QID-" + qid, Title: firstNonEmpty(q.Title, "Qualys QID "+qid), Severity: qualysSeverity(q.Severity),
		FilePath: locationOf("", redactHTTP(url)), CWE: strings.Split(q.CWE, ",")}
	if kind == "information_gathered" {
		f.Severity = "info"
	}
	if s := cvssOf(q.CVSSV3Base); s != nil {
		f.CVSS = s
	} else {
		f.CVSS = cvssOf(q.CVSSBase)
	}
	note := ""
	if strings.EqualFold(strings.TrimSpace(it.Ignored), "true") {
		f.Confidence, note = "low", "Qualys marked this finding as ignored"+labelledSuffix(it.IgnoredReason)+"; it is kept for review."
	}
	var payloads, reqs []string
	for _, p := range it.Payloads {
		if p.Payload != "" && p.Payload != "N/A" {
			payloads = append(payloads, redactHTTP(p.Payload))
		}
		var hs []string
		for _, h := range p.Request.Headers {
			v := strings.TrimSpace(h.Value)
			if isSensitiveHeader(h.Key) {
				v = logging.Redacted
			}
			hs = append(hs, strings.TrimSpace(h.Key)+": "+v)
		}
		reqs = append(reqs, redactHTTP(strings.TrimSpace(p.Request.Method+" "+p.Request.URL)+"\n"+strings.Join(hs, "\n")))
	}
	data := ""
	if it.Data != "" {
		data = clipText(redactHTTP(qualysB64(it.Data)), 2000)
	}
	f.Description = joinText(note, markupToText(q.Description), whereText("", url, it.Param), labelled("Impact", markupToText(q.Impact)),
		labelled("Payload", strings.Join(payloads, "\n")), labelled("Result", data), labelled("Solution", markupToText(q.Solution)))
	rec := qualysWASRecord{Kind: kind, UniqueID: it.UniqueID, QID: qid, Title: f.Title, Severity: q.Severity, URL: redactHTTP(url), Param: it.Param,
		Ignored: it.Ignored, Status: it.Status, CWE: q.CWE, Payloads: payloads, Requests: reqs, Data: clipText(redactHTTP(qualysB64(it.Data)), maxEvidenceText)}
	return importRecord{F: f, SnippetKey: hashOf(kind + "|" + it.Param + "|" + firstNonEmpty(it.UniqueID, it.ID)), Raw: rawJSON(rec)}
}

func labelledSuffix(reason string) string {
	if reason = strings.TrimSpace(reason); reason == "" {
		return ""
	}
	return " (" + reason + ")"
}

type qualysVMInfo struct {
	QID      string `xml:"QID"`
	Type     string `xml:"TYPE"`
	Port     string `xml:"PORT"`
	Service  string `xml:"SERVICE"`
	Protocol string `xml:"PROTOCOL"`
	SSL      string `xml:"SSL"`
	Result   string `xml:"RESULT"`
	Status   string `xml:"VULN_STATUS"`
	First    string `xml:"FIRST_FOUND"`
	Last     string `xml:"LAST_FOUND"`
	Times    string `xml:"TIMES_FOUND"`
}

type qualysVMDetail struct {
	QID      string `xml:"QID"`
	Title    string `xml:"TITLE"`
	Severity string `xml:"SEVERITY"`
	Category string `xml:"CATEGORY"`
	Threat   string `xml:"THREAT"`
	Impact   string `xml:"IMPACT"`
	Solution string `xml:"SOLUTION"`
	CVSSBase string `xml:"CVSS_SCORE>CVSS_BASE"`
	CVSS3    string `xml:"CVSS3_SCORE>CVSS3_BASE"`
	CVEs     []struct {
		ID string `xml:"ID"`
	} `xml:"CVE_ID_LIST>CVE_ID"`
}

// qualysVMRecord is the record kept as a finding's original output.
type qualysVMRecord struct {
	Host     string   `json:"host"`
	DNS      string   `json:"dns,omitempty"`
	QID      string   `json:"qid"`
	Title    string   `json:"title"`
	Type     string   `json:"type,omitempty"`
	Severity string   `json:"severity"`
	Port     string   `json:"port,omitempty"`
	Protocol string   `json:"protocol,omitempty"`
	Service  string   `json:"service,omitempty"`
	Status   string   `json:"vuln_status,omitempty"`
	CVEs     []string `json:"cves,omitempty"`
	CVSS3    string   `json:"cvss3_base,omitempty"`
	CVSS     string   `json:"cvss_base,omitempty"`
	Result   string   `json:"result,omitempty"`
	First    string   `json:"first_found,omitempty"`
	Last     string   `json:"last_found,omitempty"`
}

func parseQualysVM(raw []byte) ([]importRecord, error) {
	var doc struct {
		Hosts []struct {
			IP    string         `xml:"IP"`
			DNS   string         `xml:"DNS"`
			Infos []qualysVMInfo `xml:"VULN_INFO_LIST>VULN_INFO"`
		} `xml:"HOST_LIST>HOST"`
		Details []qualysVMDetail `xml:"GLOSSARY>VULN_DETAILS_LIST>VULN_DETAILS"`
	}
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("qualys-vm: %w", err)
	}
	gloss := map[string]qualysVMDetail{}
	for _, d := range doc.Details {
		gloss[strings.TrimSpace(d.QID)] = d
	}
	var out []importRecord
	for _, h := range doc.Hosts {
		host := firstNonEmpty(h.IP, h.DNS)
		for i, in := range h.Infos {
			qid := strings.TrimSpace(in.QID)
			if qid == "" || host == "" {
				return out, fmt.Errorf("qualys-vm: host %s detection %d: missing QID or host", host, i+1)
			}
			d := gloss[qid]
			f := Finding{RuleID: "QID-" + qid, Title: firstNonEmpty(d.Title, "Qualys QID "+qid), Severity: qualysSeverity(d.Severity),
				FilePath: hostLocation(host, in.Port, in.Protocol), CWE: []string{}}
			var cves []string
			for _, c := range d.CVEs {
				cves = append(cves, strings.TrimSpace(c.ID))
			}
			f.CVE = firstMatch(cveRe, cves...)
			score, vec := qualysVMScore(d.CVSS3)
			if score != nil && vec != "" {
				f.CVSS, f.CVSSVector = score, "CVSS:3.0/"+vec // Qualys does not name the minor version
			} else if s2, v2 := qualysVMScore(d.CVSSBase); s2 != nil {
				f.CVSS, f.CVSSVector = s2, v2
			}
			switch strings.ToLower(strings.TrimSpace(in.Type)) {
			case "ig":
				f.Severity = "info" // information gathered
			case "practice":
				f.Confidence = "medium"
			case "vuln":
				f.Confidence = "high"
			}
			cveText := ""
			if len(cves) > 1 {
				cveText = strings.Join(cves, ", ")
			}
			f.Description = joinText(markupToText(d.Threat), labelled("Impact", markupToText(d.Impact)),
				labelled("Result", clipText(redactHTTP(in.Result), 2000)), labelled("CVEs", cveText),
				labelled("Status", in.Status), labelled("Solution", markupToText(d.Solution)))
			rec := qualysVMRecord{Host: h.IP, DNS: h.DNS, QID: qid, Title: f.Title, Type: in.Type, Severity: d.Severity, Port: in.Port,
				Protocol: in.Protocol, Service: in.Service, Status: in.Status, CVEs: cves, CVSS3: d.CVSS3, CVSS: d.CVSSBase,
				Result: clipText(redactHTTP(in.Result), maxEvidenceText), First: in.First, Last: in.Last}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(in.Service + "|" + in.SSL), Raw: rawJSON(rec)})
		}
	}
	return out, nil
}

// qualysVMScore splits "9.0 (AV:N/AC:H/...)" into score and vector.
func qualysVMScore(s string) (*float64, string) {
	s = strings.TrimSpace(s)
	score, rest, _ := strings.Cut(s, " ")
	vec := strings.Trim(strings.TrimSpace(rest), "()")
	if !strings.HasPrefix(vec, "AV:") {
		vec = ""
	}
	return cvssOf(score), vec
}
