package scanners

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"strings"
)

// Burp Suite DAST (formerly Burp Suite Enterprise Edition) and Burp REST
// API scan results JSON:
//
//   - the REST API scan resource (GET /v0.1/scan/{task_id}): {"scan_metrics",
//     "issue_events": [{"type": "issue_found", "issue": {...}}]}, request
//     and response segments base64-encoded;
//   - a GraphQL API response with the issues of a scan
//     ({"data": {"scan": {"issues": [...]}}}), segments as HTML text.
//
// One finding per issue: the location is origin + path, identity the issue
// type and serial number. Request and response segments are decoded and
// redacted; the stored report has them redacted in place. Issues with
// confidence false_positive are kept with low confidence. Built from the
// published format; not yet verified against a real export.

type burpEntSegment struct {
	Type          string `json:"type"`
	Typename      string `json:"__typename"`
	Data          string `json:"data"`
	DataHTML      string `json:"data_html"`
	HighlightHTML string `json:"highlight_html"`
}

type burpEntEvidence struct {
	Type            string `json:"type"`
	Typename        string `json:"__typename"`
	RequestResponse *struct {
		URL      string           `json:"url"`
		Request  []burpEntSegment `json:"request"`
		Response []burpEntSegment `json:"response"`
	} `json:"request_response"`
	RequestSegments  []burpEntSegment `json:"request_segments"`
	ResponseSegments []burpEntSegment `json:"response_segments"`
	Title            string           `json:"title"`
	DescriptionHTML  string           `json:"description_html"`
}

type burpEntIssue struct {
	// REST API fields.
	Name                  string      `json:"name"`
	TypeIndex             looseString `json:"type_index"`
	Description           string      `json:"description"`
	IssueBackground       string      `json:"issue_background"`
	RemediationBackground string      `json:"remediation_background"`
	Caption               string      `json:"caption"`
	// GraphQL fields.
	IssueType *struct {
		Name                         string      `json:"name"`
		TypeIndex                    looseString `json:"type_index"`
		DescriptionHTML              string      `json:"description_html"`
		RemediationHTML              string      `json:"remediation_html"`
		VulnerabilityClassifications string      `json:"vulnerability_classifications_html"`
	} `json:"issue_type"`
	DescriptionHTML string `json:"description_html"`
	RemediationHTML string `json:"remediation_html"`
	Novelty         string `json:"novelty"`
	AcceptedRisk    bool   `json:"accepted_risk"`
	// Common.
	SerialNumber looseString       `json:"serial_number"`
	Origin       string            `json:"origin"`
	Path         string            `json:"path"`
	Severity     string            `json:"severity"`
	Confidence   string            `json:"confidence"`
	Evidence     []burpEntEvidence `json:"evidence"`
}

// burpEntRecord is the record kept as a finding's original output.
type burpEntRecord struct {
	Name         string   `json:"name"`
	TypeIndex    string   `json:"type_index,omitempty"`
	SerialNumber string   `json:"serial_number,omitempty"`
	Origin       string   `json:"origin"`
	Path         string   `json:"path"`
	Severity     string   `json:"severity"`
	Confidence   string   `json:"confidence"`
	Novelty      string   `json:"novelty,omitempty"`
	AcceptedRisk bool     `json:"accepted_risk,omitempty"`
	Description  string   `json:"description,omitempty"`
	Requests     []string `json:"requests,omitempty"`
	Responses    []string `json:"responses,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "burp-enterprise", Label: "Burp Suite DAST / Enterprise and REST API scan JSON", Tool: "Burp Suite DAST", Category: "dast", Media: "json", Order: 406,
		match: func(p *importProbe) bool {
			if p.kind != "object" {
				return false
			}
			if p.has("issue_events") && p.hasAny("scan_metrics", "scan_status", "task_id") {
				return true
			}
			var data map[string]json.RawMessage
			return p.has("data") && json.Unmarshal(p.keys["data"], &data) == nil && hasKeys(data, "scan") &&
				p.headHas(`"issues"`, `"serial_number"`, `"issue_type"`)
		},
		parse:    parseBurpEnterprise,
		sanitize: sanitizeBurpEnterprise})
}

func parseBurpEnterprise(raw []byte) ([]importRecord, error) {
	var doc struct {
		IssueEvents []struct {
			Type  string        `json:"type"`
			Issue *burpEntIssue `json:"issue"`
		} `json:"issue_events"`
		Data struct {
			Scan struct {
				Issues []burpEntIssue `json:"issues"`
			} `json:"scan"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bytes.TrimPrefix(raw, utf8BOM), &doc); err != nil {
		return nil, fmt.Errorf("burp-enterprise: invalid JSON: %w", err)
	}
	issues := doc.Data.Scan.Issues
	for _, e := range doc.IssueEvents {
		if e.Issue != nil && (e.Type == "" || e.Type == "issue_found") {
			issues = append(issues, *e.Issue)
		}
	}
	var out []importRecord
	for i, is := range issues {
		name, typeIndex, desc, remed, classes := is.Name, string(is.TypeIndex), firstNonEmpty(is.DescriptionHTML, is.Description, is.IssueBackground), firstNonEmpty(is.RemediationHTML, is.RemediationBackground), ""
		if it := is.IssueType; it != nil {
			name, typeIndex = firstNonEmpty(it.Name, name), firstNonEmpty(string(it.TypeIndex), typeIndex)
			desc, remed, classes = firstNonEmpty(desc, it.DescriptionHTML), firstNonEmpty(remed, it.RemediationHTML), it.VulnerabilityClassifications
		}
		if name == "" && typeIndex == "" {
			return out, fmt.Errorf("burp-enterprise: issue %d: missing name and type", i+1)
		}
		url := strings.TrimRight(is.Origin, "/") + is.Path
		f := Finding{Category: "dast", RuleID: firstNonEmpty(typeIndex, name), Title: firstNonEmpty(name, typeIndex),
			Severity: firstNonEmpty(normSeverity(is.Severity), "info"), FilePath: locationOf("", redactHTTP(url)),
			CWE: normCWEs([]string{markupToText(classes)})}
		note := ""
		switch strings.ToLower(is.Confidence) {
		case "certain":
			f.Confidence = "high"
		case "firm":
			f.Confidence = "medium"
		case "tentative":
			f.Confidence = "low"
		case "false_positive":
			f.Confidence, note = "low", "Burp marked this issue as a false positive; it is kept for review."
		}
		if is.AcceptedRisk {
			note = joinText(note, "Burp marked this issue as an accepted risk.")
		}
		var reqs, resps []string
		for _, ev := range is.Evidence {
			if rr := ev.RequestResponse; rr != nil {
				if s := burpEntSegments(rr.Request); s != "" {
					reqs = append(reqs, s)
				}
				if s := burpEntSegments(rr.Response); s != "" {
					resps = append(resps, clipText(s, 4000))
				}
			}
			if s := burpEntSegments(ev.RequestSegments); s != "" {
				reqs = append(reqs, s)
			}
			if s := burpEntSegments(ev.ResponseSegments); s != "" {
				resps = append(resps, clipText(s, 4000))
			}
		}
		f.Description = joinText(note, markupToText(desc), whereText("", url, ""), labelled("Detail", markupToText(is.Caption)),
			labelled("Remediation", markupToText(remed)))
		rec := burpEntRecord{Name: name, TypeIndex: typeIndex, SerialNumber: string(is.SerialNumber), Origin: is.Origin, Path: redactHTTP(is.Path),
			Severity: is.Severity, Confidence: is.Confidence, Novelty: is.Novelty, AcceptedRisk: is.AcceptedRisk,
			Description: clipText(markupToText(desc), maxEvidenceText), Requests: reqs, Responses: resps}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(string(is.SerialNumber)), Raw: rawJSON(rec)})
	}
	return out, nil
}

// burpEntSegments joins the text of request or response segments (REST:
// base64 "data"; GraphQL: HTML "data_html" / "highlight_html"), redacted.
func burpEntSegments(segs []burpEntSegment) string {
	var b strings.Builder
	for _, s := range segs {
		switch {
		case s.Data != "":
			if d, err := base64.StdEncoding.DecodeString(s.Data); err == nil {
				b.Write(d)
			}
		case s.DataHTML != "":
			b.WriteString(html.UnescapeString(s.DataHTML))
		case s.HighlightHTML != "":
			b.WriteString(html.UnescapeString(s.HighlightHTML))
		}
	}
	return redactHTTP(b.String())
}

// sanitizeBurpEnterprise redacts the stored report: base64 segments are
// decoded, redacted and re-encoded; text segments are redacted in place.
func sanitizeBurpEnterprise(raw []byte) []byte {
	var x any
	if json.Unmarshal(bytes.TrimPrefix(raw, utf8BOM), &x) != nil {
		return sanitizeHTTPText(raw)
	}
	out, err := json.Marshal(redactHTTPIn(burpEntRedactB64(x)))
	if err != nil {
		return raw
	}
	return out
}

func burpEntRedactB64(x any) any {
	switch t := x.(type) {
	case []any:
		for i := range t {
			t[i] = burpEntRedactB64(t[i])
		}
	case map[string]any:
		if s, ok := t["data"].(string); ok && s != "" {
			if d, err := base64.StdEncoding.DecodeString(s); err == nil {
				t["data"] = base64.StdEncoding.EncodeToString(sanitizeHTTPText(d))
			}
		}
		for k, v := range t {
			if k != "data" {
				t[k] = burpEntRedactB64(v)
			} else if _, isStr := v.(string); !isStr {
				t[k] = burpEntRedactB64(v)
			}
		}
	}
	return x
}
