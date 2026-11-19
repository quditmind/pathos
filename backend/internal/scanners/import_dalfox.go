package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Dalfox JSON (`dalfox url ... --format json`): version 3 writes
// {"findings": [...], "meta": {...}}, version 2 an array of PoC objects
// (empty objects separate them). Types: V verified XSS, R reflected
// parameter, A DOM XSS from static analysis, I informational. One finding
// per PoC; identity is the method, parameter, injection type and the
// finding type (payloads vary between runs). The request and response,
// which carry the scan's cookies and authorization, are redacted before the
// report is stored.

type dalfoxPoC struct {
	Type             string      `json:"type"`
	TypeDescription  string      `json:"type_description"`
	InjectType       string      `json:"inject_type"`
	PoCType          string      `json:"poc_type"`
	Method           string      `json:"method"`
	Data             string      `json:"data"`
	Param            string      `json:"param"`
	Payload          string      `json:"payload"`
	Evidence         string      `json:"evidence"`
	CWE              string      `json:"cwe"`
	Severity         string      `json:"severity"`
	Confidence       string      `json:"confidence"`
	ConfidenceReason string      `json:"confidence_reason"`
	DetectionMethod  string      `json:"detection_method"`
	Location         string      `json:"location"`
	MessageID        looseString `json:"message_id"`
	MessageStr       string      `json:"message_str"`
	Request          string      `json:"request"`
	Response         string      `json:"response"`
	RawRequest       string      `json:"raw_request"`
	RawResponse      string      `json:"raw_response"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "dalfox", Label: "Dalfox JSON", Tool: "Dalfox", Category: "dast", Media: "json", Order: 304,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				var meta map[string]json.RawMessage
				return p.has("findings", "meta") && json.Unmarshal(p.keys["meta"], &meta) == nil && hasKeys(meta, "dalfox_version")
			case "array":
				// The first element may be an empty separator object.
				return p.has("type", "inject_type", "param") && p.hasAny("poc_type", "message_id") ||
					len(p.keys) == 0 && p.headHas(`"inject_type"`, `"poc_type"`, `"param"`)
			}
			return false
		},
		parse:    parseDalfox,
		sanitize: func(raw []byte) []byte { return g1Sanitize(raw) },
	})
}

func parseDalfox(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "findings")
	if err != nil {
		return nil, fmt.Errorf("dalfox: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var p dalfoxPoC
		if err := json.Unmarshal(it, &p); err != nil {
			return out, fmt.Errorf("dalfox: finding %d: %w", i+1, err)
		}
		if p.Type == "" && p.Data == "" && p.Param == "" {
			continue // version 2 separates PoCs with empty objects
		}
		if p.Data == "" {
			return out, fmt.Errorf("dalfox: finding %d: missing data (the URL)", i+1)
		}
		rule, title := "dalfox-"+strings.ToLower(p.Type), "Cross-site scripting"
		switch strings.ToUpper(p.Type) {
		case "V":
			rule, title = "xss-verified", "Cross-site scripting (verified)"
		case "R":
			rule, title = "xss-reflected", "Reflected parameter (possible cross-site scripting)"
		case "A":
			rule, title = "xss-dom-static", "DOM cross-site scripting (static analysis)"
		case "I":
			rule, title = "info", firstNonEmpty(p.MessageStr, "Dalfox information")
		}
		if p.Param != "" && strings.ToUpper(p.Type) != "I" {
			title += fmt.Sprintf(" in parameter %q", p.Param)
		}
		u, cwe := redactHTTP(p.Data), p.CWE
		if cwe == "" && strings.ToUpper(p.Type) != "I" {
			cwe = "CWE-79"
		}
		f := Finding{Category: "dast", RuleID: rule, Title: title, FilePath: locationOf("", g1StripQuery(u)),
			CWE: []string{cwe}, Severity: normSeverity(p.Severity)}
		if f.Severity == "" {
			f.Severity = map[string]string{"V": "high", "A": "medium", "R": "low"}[strings.ToUpper(p.Type)]
		}
		switch strings.ToLower(p.Confidence) {
		case "high", "medium", "low":
			f.Confidence = strings.ToLower(p.Confidence)
		default:
			if strings.ToUpper(p.Type) == "R" {
				f.Confidence = "low"
			}
		}
		f.Description = joinText(firstNonEmpty(p.TypeDescription, p.MessageStr), whereText(p.Method, u, p.Param),
			labelled("Injection context", p.InjectType), labelled("Payload", clipText(p.Payload, 500)),
			labelled("Evidence", clipText(redactHTTP(p.Evidence), 500)), labelled("Confidence", p.ConfidenceReason))
		p.Data, p.Evidence = u, redactHTTP(p.Evidence)
		p.Request, p.Response = redactHTTP(g1RedactCmd(p.Request)), redactHTTP(p.Response)
		p.RawRequest, p.RawResponse = redactHTTP(g1RedactCmd(p.RawRequest)), redactHTTP(p.RawResponse)
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(p.Method) + "|" + p.Param + "|" + p.InjectType + "|" + p.Location + "|" + p.Type),
			Raw: rawJSON(p)})
	}
	return out, nil
}
