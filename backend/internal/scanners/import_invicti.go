package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"pathos/internal/platform/logging"
)

// Invicti (formerly Netsparker) Enterprise and Standard reports: the JSON
// vulnerabilities report ({"Generated", "Target", "Vulnerabilities"}) and
// the XML report (<invicti-enterprise> or <netsparker-enterprise>, the same
// fields in kebab case). Acunetix 360 exports the same JSON (import_acunetix.go).
// One finding per vulnerability: the location is its URL, identity the
// vulnerability type, method and vulnerable parameter. Request and response
// evidence is kept redacted (cookies, authorization headers, credential
// parameters); vulnerabilities marked as false positives are kept with low
// confidence. Built from the published format; not yet verified against a
// real export.

type invictiParam struct {
	Name       string `json:"Name" xml:"name"`
	Type       string `json:"Type" xml:"type"`
	Value      string `json:"Value" xml:"value"`
	Vulnerable bool   `json:"Vulnerable" xml:"vulnerable"`
}

type invictiScore struct {
	Value looseString `json:"Value" xml:"value"`
}

type invictiCVSS struct {
	BaseScore invictiScore `json:"BaseScore" xml:"base-score"`
	Vector    string       `json:"Vector" xml:"vector"`
}

type invictiVuln struct {
	Certainty      looseString `json:"Certainty" xml:"certainty"`
	Confirmed      bool        `json:"Confirmed" xml:"confirmed"`
	Classification struct {
		Cwe    looseString  `json:"Cwe" xml:"cwe"`
		Capec  looseString  `json:"Capec" xml:"capec"`
		Owasp  string       `json:"Owasp" xml:"owasp"`
		Wasc   looseString  `json:"Wasc" xml:"wasc"`
		Cvss   *invictiCVSS `json:"Cvss" xml:"cvss"`
		Cvss31 *invictiCVSS `json:"Cvss31" xml:"cvss31"`
		Cvss40 *invictiCVSS `json:"Cvss40" xml:"cvss40"`
		// The XML report carries the CVSS v3 score and vector directly.
		XMLScore  invictiScore `json:"-" xml:"score"`
		XMLVector string       `json:"-" xml:"vector"`
	} `json:"Classification" xml:"classification"`
	Description      string `json:"Description" xml:"description"`
	ExtraInformation []struct {
		Name  string `json:"Name" xml:"name"`
		Value string `json:"Value" xml:"value"`
	} `json:"ExtraInformation" xml:"extra-information>info"`
	HttpRequest struct {
		Content    string         `json:"Content" xml:"content"`
		Method     string         `json:"Method" xml:"method"`
		Parameters []invictiParam `json:"Parameters" xml:"parameters>parameter"`
	} `json:"HttpRequest" xml:"http-request"`
	HttpResponse struct {
		Content    string      `json:"Content" xml:"content"`
		StatusCode looseString `json:"StatusCode" xml:"status-code"`
	} `json:"HttpResponse" xml:"http-response"`
	LookupID             string `json:"LookupId" xml:"look-up-id"`
	Impact               string `json:"Impact" xml:"impact"`
	Name                 string `json:"Name" xml:"name"`
	ProofOfConcept       string `json:"ProofOfConcept" xml:"proof-of-concept"`
	RemedialActions      string `json:"RemedialActions" xml:"remedial-actions"`
	RemedialProcedure    string `json:"RemedialProcedure" xml:"remedial-procedure"`
	Severity             string `json:"Severity" xml:"severity"`
	State                string `json:"State" xml:"state"`
	Type                 string `json:"Type" xml:"type"`
	URL                  string `json:"Url" xml:"url"`
	KnownVulnerabilities []struct {
		Title    string `json:"Title" xml:"title"`
		Severity string `json:"Severity" xml:"severity"`
	} `json:"KnownVulnerabilities" xml:"known-vulnerabilities>known-vulnerability"`
}

type invictiReport struct {
	Generated string `json:"Generated" xml:"generated,attr"`
	Target    struct {
		ScanID string `json:"ScanId" xml:"scan-id"`
		URL    string `json:"Url" xml:"url"`
	} `json:"Target" xml:"target"`
	Vulnerabilities []invictiVuln `json:"Vulnerabilities" xml:"vulnerabilities>vulnerability"`
}

// invictiRecord is the record kept as a finding's original output.
type invictiRecord struct {
	Target         string         `json:"target,omitempty"`
	Name           string         `json:"name"`
	Type           string         `json:"type,omitempty"`
	URL            string         `json:"url"`
	Severity       string         `json:"severity"`
	Certainty      string         `json:"certainty,omitempty"`
	Confirmed      bool           `json:"confirmed"`
	State          string         `json:"state,omitempty"`
	LookupID       string         `json:"lookup_id,omitempty"`
	CWE            string         `json:"cwe,omitempty"`
	CVSSVector     string         `json:"cvss_vector,omitempty"`
	Method         string         `json:"method,omitempty"`
	Parameters     []invictiParam `json:"parameters,omitempty"`
	Request        string         `json:"request,omitempty"`
	Response       string         `json:"response,omitempty"`
	ResponseStatus string         `json:"response_status,omitempty"`
	Description    string         `json:"description,omitempty"`
	Remedy         string         `json:"remedy,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "invicti", Label: "Invicti / Netsparker report (JSON or XML)", Tool: "Invicti", Category: "dast", Media: "json", Order: 401,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				return invictiJSONShape(p) && !acunetix360Marked(p)
			case "xml":
				return p.root == "invicti-enterprise" || p.root == "netsparker-enterprise" || p.root == "invicti" || p.root == "netsparker"
			}
			return false
		},
		parse:    func(raw []byte) ([]importRecord, error) { return parseInvictiReport("invicti", raw) },
		sanitize: sanitizeInvicti})
}

// invictiJSONShape reports whether a JSON object is an Invicti / Acunetix
// 360 vulnerabilities report.
func invictiJSONShape(p *importProbe) bool {
	if !p.has("Target", "Vulnerabilities") || !p.hasAny("Generated", "Target") {
		return false
	}
	var t map[string]json.RawMessage
	if json.Unmarshal(p.keys["Target"], &t) != nil || !hasKeys(t, "Url") || !(hasKeys(t, "ScanId") || hasKeys(t, "Initiated")) {
		return false
	}
	return p.firstOf("Vulnerabilities") == nil || hasKeys(p.firstOf("Vulnerabilities"), "Url", "Severity")
}

func parseInvictiReport(tool string, raw []byte) ([]importRecord, error) {
	var rep invictiReport
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if len(b) > 0 && b[0] == '<' {
		if err := decodeXML(b, &rep); err != nil {
			return nil, fmt.Errorf("%s: %w", tool, err)
		}
	} else if err := json.Unmarshal(b, &rep); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", tool, err)
	}
	var out []importRecord
	for i, v := range rep.Vulnerabilities {
		name := firstNonEmpty(v.Name, v.Type)
		if name == "" {
			return out, fmt.Errorf("%s: vulnerability %d: missing name and type", tool, i+1)
		}
		url := firstNonEmpty(v.URL, rep.Target.URL)
		f := Finding{Category: "dast", RuleID: firstNonEmpty(v.Type, name), Title: name, FilePath: locationOf("", redactHTTP(url)),
			CWE: []string{string(v.Classification.Cwe)}}
		f.Severity = invictiSeverity(v.Severity)
		for _, c := range []*invictiCVSS{v.Classification.Cvss31, v.Classification.Cvss, v.Classification.Cvss40} {
			if c != nil && f.CVSSVector == "" && strings.HasPrefix(strings.TrimSpace(c.Vector), "CVSS:3") {
				f.CVSSVector = strings.TrimSpace(c.Vector)
				f.CVSS = cvssOf(string(c.BaseScore.Value))
			}
		}
		if vec := strings.TrimSpace(v.Classification.XMLVector); f.CVSSVector == "" && strings.HasPrefix(vec, "CVSS:3") {
			f.CVSSVector, f.CVSS = vec, cvssOf(string(v.Classification.XMLScore.Value))
		}
		cert, _ := strconv.Atoi(strings.TrimSpace(string(v.Certainty)))
		switch {
		case v.Confirmed || cert >= 95:
			f.Confidence = "high"
		case cert >= 70:
			f.Confidence = "medium"
		case cert > 0:
			f.Confidence = "low"
		}
		note := ""
		if st := strings.ToLower(v.State); strings.Contains(st, "falsepositive") || strings.Contains(st, "false positive") {
			f.Confidence, note = "low", tool+" marked this vulnerability as a false positive; it is kept for review."
		} else if strings.Contains(st, "acceptedrisk") {
			note = tool + " marked this vulnerability as an accepted risk."
		}
		var vulnParams []string
		for _, p := range v.HttpRequest.Parameters {
			if p.Vulnerable {
				vulnParams = append(vulnParams, p.Name)
			}
		}
		param := strings.Join(vulnParams, ",")
		var extra []string
		for _, e := range v.ExtraInformation {
			extra = append(extra, e.Name+": "+redactHTTP(e.Value))
		}
		var known []string
		for _, k := range v.KnownVulnerabilities {
			known = append(known, k.Title+" ("+k.Severity+")")
		}
		f.Description = joinText(note, markupToText(v.Description), whereText(v.HttpRequest.Method, url, param),
			labelled("Impact", markupToText(v.Impact)), labelled("Details", strings.Join(extra, "\n")),
			labelled("Known vulnerabilities", strings.Join(known, "\n")),
			labelled("Proof of concept", clipText(redactHTTP(markupToText(v.ProofOfConcept)), 1000)),
			labelled("Remedy", markupToText(firstNonEmpty(v.RemedialProcedure, v.RemedialActions))))
		params := make([]invictiParam, len(v.HttpRequest.Parameters))
		for i, p := range v.HttpRequest.Parameters {
			params[i] = p
			params[i].Value = invictiParamValue(p.Name, p.Value)
		}
		rec := invictiRecord{Target: rep.Target.URL, Name: name, Type: v.Type, URL: redactHTTP(url), Severity: v.Severity, Certainty: string(v.Certainty),
			Confirmed: v.Confirmed, State: v.State, LookupID: v.LookupID, CWE: string(v.Classification.Cwe), CVSSVector: f.CVSSVector,
			Method: v.HttpRequest.Method, Parameters: params, Request: redactHTTP(v.HttpRequest.Content), Response: redactHTTP(v.HttpResponse.Content),
			ResponseStatus: string(v.HttpResponse.StatusCode), Description: clipText(markupToText(v.Description), maxEvidenceText),
			Remedy: clipText(markupToText(firstNonEmpty(v.RemedialProcedure, v.RemedialActions)), maxEvidenceText)}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(v.HttpRequest.Method) + "|" + param), Raw: rawJSON(rec)})
	}
	return out, nil
}

// invictiSeverity maps Invicti / Acunetix 360 severities (BestPractice and
// Information are informational).
func invictiSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "bestpractice", "best practice", "information":
		return "info"
	}
	return firstNonEmpty(normSeverity(s), "info")
}

// invictiSecretName matches parameter names whose values are credentials.
var invictiSecretName = regexp.MustCompile(`(?i)(pass|pwd|token|secret|api[_-]?key|session|auth|credential|cookie)`)

// invictiParamValue redacts the value of a credential-like parameter.
func invictiParamValue(name, value string) string {
	if value != "" && invictiSecretName.MatchString(name) {
		return logging.Redacted
	}
	return redactHTTP(value)
}

// sanitizeInvicti redacts the stored report: HTTP evidence and the values
// of credential-like request parameters.
func sanitizeInvicti(raw []byte) []byte {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if len(b) > 0 && b[0] == '<' {
		return invictiRedactXMLParams(sanitizeHTTPText(raw))
	}
	var x any
	if json.Unmarshal(b, &x) != nil {
		return sanitizeHTTPText(raw)
	}
	out, err := json.Marshal(redactHTTPIn(invictiRedactParams(x)))
	if err != nil {
		return raw
	}
	return out
}

// invictiRedactParams redacts {"Name": "password", "Value": ...} objects.
func invictiRedactParams(x any) any {
	switch t := x.(type) {
	case []any:
		for i := range t {
			t[i] = invictiRedactParams(t[i])
		}
	case map[string]any:
		for _, nk := range []string{"Name", "name"} {
			if n, ok := t[nk].(string); ok && invictiSecretName.MatchString(n) {
				for _, vk := range []string{"Value", "value"} {
					if v, ok := t[vk].(string); ok && v != "" {
						t[vk] = logging.Redacted
					}
				}
			}
		}
		for k, v := range t {
			t[k] = invictiRedactParams(v)
		}
	}
	return x
}

var (
	invictiXMLParamRe = regexp.MustCompile(`(?is)<parameter>.*?</parameter>`)
	invictiXMLNameRe  = regexp.MustCompile(`(?is)<name>(.*?)</name>`)
	invictiXMLValueRe = regexp.MustCompile(`(?is)(<value>)(.*?)(</value>)`)
)

// invictiRedactXMLParams redacts the values of credential-like
// <parameter><name>password</name><value>...</value></parameter> elements.
func invictiRedactXMLParams(b []byte) []byte {
	return invictiXMLParamRe.ReplaceAllFunc(b, func(m []byte) []byte {
		name := invictiXMLNameRe.FindSubmatch(m)
		if name == nil || !invictiSecretName.Match(name[1]) {
			return m
		}
		return invictiXMLValueRe.ReplaceAll(m, []byte("${1}"+logging.Redacted+"${3}"))
	})
}
