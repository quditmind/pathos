package scanners

import (
	"fmt"
	"regexp"
	"strings"

	"pathos/internal/platform/logging"
)

// HCL AppScan (Standard, Enterprise, on Cloud) XML report (<xml-report>):
// an issue-group whose items reference the issue-type, url, entity and
// remediation groups by id. One finding per issue item: the location is its
// URL, identity the issue type, entity (parameter, cookie, page) and URL.
// Each variant's test HTTP traffic is kept redacted (cookies, authorization
// headers, credential parameters), and the report's cookie list is redacted
// before it is stored. Built from the published format; not yet verified
// against a real export.

type appscanRefItem struct {
	ID         string `xml:"id,attr"`
	Name       string `xml:"name"`
	URLName    string `xml:"url-name"`
	EntityType string `xml:"entity-type"`
	CVE        string `xml:"cve"`
	CWE        string `xml:"cwe"`
}

type appscanIssue struct {
	ID         string `xml:"id,attr"`
	Severity   string `xml:"severity"`
	CVSSScore  string `xml:"cvss-score"`
	CVSSVector string `xml:"cvss-vector>vector"`
	CWE        string `xml:"cwe"`
	IssueType  string `xml:"issue-type>ref"`
	Remedy     string `xml:"remediation>ref"`
	Threat     string `xml:"threat-class>ref"`
	Entity     string `xml:"entity>ref"`
	URL        struct {
		Ref    string `xml:"ref"`
		Method string `xml:"original_request_method,attr"`
	} `xml:"url"`
	Causes   []string `xml:"cause-id>ref"`
	Variants []struct {
		ID        string `xml:"id,attr"`
		Reasoning string `xml:"reasoning"`
		Traffic   string `xml:"test-http-traffic"`
		Diffs     []struct {
			Name     string `xml:"name,attr"`
			Altered  string `xml:"altered,attr"`
			Original string `xml:"original,attr"`
		} `xml:"differences>item"`
	} `xml:"variant-group>item"`
}

// appscanDASTRecord is the record kept as a finding's original output.
type appscanDASTRecord struct {
	ID         string   `json:"id"`
	IssueType  string   `json:"issue_type"`
	Name       string   `json:"name"`
	Severity   string   `json:"severity"`
	URL        string   `json:"url"`
	Method     string   `json:"method,omitempty"`
	Entity     string   `json:"entity,omitempty"`
	EntityType string   `json:"entity_type,omitempty"`
	CWE        string   `json:"cwe,omitempty"`
	CVSSScore  string   `json:"cvss_score,omitempty"`
	CVSSVector string   `json:"cvss_vector,omitempty"`
	Remedy     string   `json:"remediation,omitempty"`
	Reasoning  []string `json:"reasoning,omitempty"`
	Traffic    []string `json:"test_http_traffic,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "appscan-dast", Label: "HCL AppScan XML report", Tool: "HCL AppScan", Category: "dast", Media: "xml", Order: 405,
		match: func(p *importProbe) bool {
			if p.kind != "xml" || p.root != "xml-report" {
				return false
			}
			_, v1 := p.rootAttrs["xmlExportVersion"]
			_, v2 := p.rootAttrs["AsocXmlExportVersion"]
			return v1 || v2 || strings.Contains(p.rootAttrs["name"], "AppScan")
		},
		parse: parseAppScan,
		sanitize: func(raw []byte) []byte {
			b := appscanCookieGroupRe.ReplaceAllFunc(raw, func(m []byte) []byte {
				return appscanValueRe.ReplaceAll(m, []byte("${1}"+logging.Redacted+"${2}"))
			})
			return sanitizeHTTPText(b)
		}})
}

var (
	appscanCookieGroupRe = regexp.MustCompile(`(?s)<cookie-group>.*?</cookie-group>`)
	appscanValueRe       = regexp.MustCompile(`(?s)(<value>).*?(</value>)`)
	appscanHighlightRe   = regexp.MustCompile(`--(?:begin|end)_highlight_tag--`)
)

func parseAppScan(raw []byte) ([]importRecord, error) {
	var doc struct {
		Issues     []appscanIssue   `xml:"issue-group>item"`
		IssueTypes []appscanRefItem `xml:"issue-type-group>item"`
		URLs       []appscanRefItem `xml:"url-group>item"`
		Entities   []appscanRefItem `xml:"entity-group>item"`
		Remedies   []appscanRefItem `xml:"remediation-group>item"`
		Threats    []appscanRefItem `xml:"threat-class-group>item"`
	}
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("appscan-dast: %w", err)
	}
	index := func(items []appscanRefItem) map[string]appscanRefItem {
		m := make(map[string]appscanRefItem, len(items))
		for _, it := range items {
			m[it.ID] = it
		}
		return m
	}
	types, urls, ents, remedies, threats := index(doc.IssueTypes), index(doc.URLs), index(doc.Entities), index(doc.Remedies), index(doc.Threats)
	var out []importRecord
	for i, is := range doc.Issues {
		it := types[is.IssueType]
		name := firstNonEmpty(it.Name, is.IssueType)
		if name == "" {
			return out, fmt.Errorf("appscan-dast: issue %d: missing issue type", i+1)
		}
		ent := ents[is.Entity]
		url := firstNonEmpty(urls[is.URL.Ref].Name, ent.URLName, is.URL.Ref)
		f := Finding{Category: "dast", RuleID: firstNonEmpty(is.IssueType, name), Title: name, Severity: appscanDASTSeverity(is.Severity),
			FilePath: locationOf("", redactHTTP(url)), CWE: []string{is.CWE, it.CWE}, CVE: it.CVE, CVSS: cvssOf(is.CVSSScore)}
		if v := strings.TrimSpace(is.CVSSVector); strings.HasPrefix(v, "AV:") {
			f.CVSSVector = "CVSS:3.0/" + appscanBaseVector(v) // AppScan omits the prefix; base metrics only
		}
		param := ""
		if strings.EqualFold(ent.EntityType, "Parameter") || strings.EqualFold(ent.EntityType, "Cookie") || strings.EqualFold(ent.EntityType, "Header") {
			param = ent.Name
		}
		var reasons, traffic []string
		for _, v := range is.Variants {
			if r := strings.TrimSpace(v.Reasoning); r != "" {
				reasons = append(reasons, r)
			}
			if t := strings.TrimSpace(v.Traffic); t != "" {
				traffic = append(traffic, clipText(redactHTTP(appscanHighlightRe.ReplaceAllString(t, "")), 4000))
			}
		}
		f.Description = joinText(strings.Join(appscanDedupe(reasons), "\n"), whereText(is.URL.Method, url, param),
			labelled("Entity", strings.TrimSpace(ent.Name+" ("+ent.EntityType+")")), labelled("Threat class", threats[is.Threat].Name),
			labelled("Remediation", remedies[is.Remedy].Name))
		rec := appscanDASTRecord{ID: is.ID, IssueType: is.IssueType, Name: name, Severity: is.Severity, URL: redactHTTP(url), Method: is.URL.Method,
			Entity: ent.Name, EntityType: ent.EntityType, CWE: is.CWE, CVSSScore: is.CVSSScore, CVSSVector: is.CVSSVector,
			Remedy: remedies[is.Remedy].Name, Reasoning: reasons, Traffic: traffic}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(is.URL.Method) + "|" + ent.Name + "|" + ent.EntityType), Raw: rawJSON(rec)})
	}
	return out, nil
}

// appscanDASTSeverity maps AppScan severities (Critical, High, Medium, Low,
// Informational).
func appscanDASTSeverity(s string) string { return firstNonEmpty(normSeverity(s), "info") }

// appscanBaseVector keeps the CVSS v3 base metrics of an AppScan vector
// (it appends temporal and environmental metrics set to X).
func appscanBaseVector(v string) string {
	var keep []string
	for _, m := range strings.Split(v, "/") {
		k, _, _ := strings.Cut(m, ":")
		switch k {
		case "AV", "AC", "PR", "UI", "S", "C", "I", "A":
			keep = append(keep, m)
		}
	}
	return strings.Join(keep, "/")
}

// appscanDedupe returns v without repeated strings, in order.
func appscanDedupe(v []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range v {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
