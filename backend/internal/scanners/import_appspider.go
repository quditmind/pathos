package scanners

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
)

// Rapid7 AppSpider VulnerabilitiesSummary.xml (<VulnSummary> of <Vuln>).
// One finding per vulnerability: the location is its URL, identity the
// vulnerability type, method and parameter. AppSpider stores the crawl
// request and response base64-encoded; they are decoded, redacted and
// re-encoded before the report is stored, and the record keeps the redacted
// request only. Built from the published format; not yet verified against a
// real export.

type appspiderVuln struct {
	DbID              string `xml:"DbId"`
	WebSite           string `xml:"WebSite"`
	VulnType          string `xml:"VulnType"`
	VulnURL           string `xml:"VulnUrl"`
	VulnParam         string `xml:"VulnParam"`
	ParameterName     string `xml:"ParameterName"`
	MatchedString     string `xml:"MatchedString"`
	ModuleID          string `xml:"ModuleId"`
	AttackType        string `xml:"AttackType"`
	AttackScore       string `xml:"AttackScore"`
	AttackValue       string `xml:"AttackValue"`
	Method            string `xml:"Method"`
	RootCauseID       string `xml:"RootCauseId"`
	Description       string `xml:"Description"`
	Recommendation    string `xml:"Recommendation"`
	CrawlTraffic      string `xml:"CrawlTraffic"`
	CweID             string `xml:"CweId"`
	Confidence        string `xml:"Confidence"`
	AttackRequestList []struct {
		Request string `xml:"Request"`
	} `xml:"AttackList>AttackRequest"`
}

// appspiderRecord is the record kept as a finding's original output.
type appspiderRecord struct {
	DbID          string `json:"db_id,omitempty"`
	WebSite       string `json:"website,omitempty"`
	VulnType      string `json:"vuln_type"`
	VulnURL       string `json:"vuln_url"`
	Parameter     string `json:"parameter,omitempty"`
	Method        string `json:"method,omitempty"`
	AttackType    string `json:"attack_type,omitempty"`
	AttackScore   string `json:"attack_score"`
	AttackValue   string `json:"attack_value,omitempty"`
	MatchedString string `json:"matched_string,omitempty"`
	CweID         string `json:"cwe_id,omitempty"`
	Confidence    string `json:"confidence,omitempty"`
	Description   string `json:"description,omitempty"`
	Request       string `json:"crawl_request,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "appspider", Label: "Rapid7 AppSpider VulnerabilitiesSummary.xml", Tool: "AppSpider", Category: "dast", Media: "xml", Order: 402,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "VulnSummary" },
		parse: parseAppSpider,
		sanitize: func(raw []byte) []byte {
			return appspiderB64Re.ReplaceAllFunc(sanitizeHTTPText(raw), func(m []byte) []byte {
				sub := appspiderB64Re.FindSubmatch(m)
				return []byte(string(sub[1]) + appspiderRedactB64(string(sub[2])) + string(sub[3]))
			})
		}})
}

// appspiderB64Re matches the base64-encoded traffic elements.
var appspiderB64Re = regexp.MustCompile(`(?s)(<(?:CrawlTraffic|CrawlTrafficTemplate|CrawlTrafficResponse|AttackTraffic|AttackTrafficResponse)>)([^<]*)(</(?:CrawlTraffic|CrawlTrafficTemplate|CrawlTrafficResponse|AttackTraffic|AttackTrafficResponse)>)`)

// appspiderDecode decodes base64 HTTP traffic ("" when it is not base64).
func appspiderDecode(s string) string {
	b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(s), ""))
	if err != nil {
		return ""
	}
	return string(b)
}

// appspiderRedactB64 redacts base64-encoded HTTP traffic in place.
func appspiderRedactB64(s string) string {
	if strings.TrimSpace(s) == "" {
		return s
	}
	d := appspiderDecode(s)
	if d == "" {
		return "" // not decodable: not kept
	}
	return base64.StdEncoding.EncodeToString(sanitizeHTTPText([]byte(d)))
}

func parseAppSpider(raw []byte) ([]importRecord, error) {
	var doc struct {
		Vulns []appspiderVuln `xml:"VulnList>Vuln"`
	}
	if err := decodeXML(raw, &doc); err != nil {
		return nil, fmt.Errorf("appspider: %w", err)
	}
	var out []importRecord
	for i, v := range doc.Vulns {
		name := strings.TrimSpace(v.VulnType)
		if name == "" {
			return out, fmt.Errorf("appspider: vulnerability %d: missing VulnType", i+1)
		}
		url := firstNonEmpty(v.VulnURL, v.WebSite)
		param := firstNonEmpty(v.VulnParam, strings.TrimPrefix(v.ParameterName, "N/A"))
		method := strings.TrimPrefix(strings.TrimSpace(v.Method), "N/A")
		f := Finding{Category: "dast", RuleID: name, Title: name, Severity: appspiderSeverity(v.AttackScore),
			FilePath: locationOf("", redactHTTP(url)), CWE: []string{v.CweID}}
		switch strings.ToLower(strings.TrimSpace(v.Confidence)) {
		case "high":
			f.Confidence = "high"
		case "medium":
			f.Confidence = "medium"
		case "low":
			f.Confidence = "low"
		}
		req := redactHTTP(appspiderDecode(v.CrawlTraffic))
		if req == "" && len(v.AttackRequestList) > 0 {
			req = redactHTTP(v.AttackRequestList[0].Request)
		}
		attack := strings.TrimPrefix(v.AttackValue, "N/A")
		f.Description = joinText(markupToText(v.Description), whereText(method, url, param), labelled("Attack", redactHTTP(attack)),
			labelled("Matched", redactHTTP(v.MatchedString)), labelled("Recommendation", markupToText(v.Recommendation)))
		rec := appspiderRecord{DbID: v.DbID, WebSite: v.WebSite, VulnType: name, VulnURL: redactHTTP(url), Parameter: param, Method: method,
			AttackType: v.AttackType, AttackScore: v.AttackScore, AttackValue: redactHTTP(attack), MatchedString: redactHTTP(v.MatchedString),
			CweID: v.CweID, Confidence: v.Confidence, Description: clipText(markupToText(v.Description), maxEvidenceText), Request: req}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(method) + "|" + param), Raw: rawJSON(rec)})
	}
	return out, nil
}

// appspiderSeverity maps AttackScore ("4-High", "3-Medium", "2-Low",
// "1-Informational", "0-Safe").
func appspiderSeverity(s string) string {
	s = strings.TrimSpace(s)
	if _, label, ok := strings.Cut(s, "-"); ok {
		s = label
	}
	switch strings.ToLower(s) {
	case "safe":
		return "info"
	}
	return firstNonEmpty(normSeverity(s), "info")
}
