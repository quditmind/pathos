package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Schemathesis reports (`st run --report json,junit`): the JSON run report
// (failures[] with the check code ST1xx..ST9xx, title, severity and the
// API operations) and the JUnit XML report (a testcase per operation, a
// failure per test case naming the check codes). One finding per check and
// operation; identity is the check code, the operation's method and path.
// The JUnit report has no severities: they are taken from Schemathesis'
// own check definitions (schemathesisSeverity). Schemathesis filters
// configured headers itself ("[Filtered]"); responses are redacted too.

// schemathesisSeverity maps check codes to the severities Schemathesis
// 4.x assigns (core/failures.py, openapi/checks.py, graphql/checks.py);
// other codes are medium.
var schemathesisSeverity = map[string]string{
	"ST101": "critical", "ST301": "critical", "ST401": "critical", "ST402": "critical", "ST113": "critical",
	"ST108": "high", "ST114": "high", "ST116": "high",
	"ST112": "low",
}

var (
	schemathesisCodeRe    = regexp.MustCompile(`\bST\d{3}\b`)
	schemathesisCheckLine = regexp.MustCompile(`(?m)^- (ST\d{3}) (.+)$`)
)

type schemathesisRecord struct {
	Code       string   `json:"code"`
	Title      string   `json:"title"`
	Type       string   `json:"type,omitempty"`
	Severity   string   `json:"severity,omitempty"`
	Count      int      `json:"count,omitempty"`
	Operation  string   `json:"operation"`
	Operations []string `json:"operations,omitempty"`
	Message    string   `json:"message,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "schemathesis", Label: "Schemathesis report (JSON or JUnit XML)", Tool: "Schemathesis", Category: "other",
		Media: "json", Order: 308,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				return p.has("schemathesis_version", "failures")
			case "xml":
				return (p.root == "testsuites" || p.root == "testsuite") && p.headHas(`<testsuite name="schemathesis"`)
			}
			return false
		},
		parse: parseSchemathesis, sanitize: sanitizeSchemathesis})
}

func sanitizeSchemathesis(raw []byte) []byte {
	if g1IsJSON(raw) {
		return g1Sanitize(raw)
	}
	return sanitizeHTTPText([]byte(g1RedactCmd(string(raw))))
}

func parseSchemathesis(raw []byte) ([]importRecord, error) {
	if !g1IsJSON(raw) {
		return parseSchemathesisJUnit(raw)
	}
	items, err := jsonArray(raw, "failures")
	if err != nil {
		return nil, fmt.Errorf("schemathesis: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var fl struct {
			Type       string   `json:"type"`
			Code       string   `json:"code"`
			Title      string   `json:"title"`
			Severity   string   `json:"severity"`
			Count      int      `json:"count"`
			Operations []string `json:"operations"`
		}
		if err := json.Unmarshal(it, &fl); err != nil || (fl.Code == "" && fl.Title == "") {
			return out, fmt.Errorf("schemathesis: failure %d: expected an object with code and title", i+1)
		}
		ops := fl.Operations
		if len(ops) == 0 {
			ops = []string{""}
		}
		for _, op := range ops {
			rec := schemathesisRecord{Code: fl.Code, Title: fl.Title, Type: fl.Type, Severity: fl.Severity, Count: fl.Count, Operation: op, Operations: fl.Operations}
			out = append(out, schemathesisFinding(rec, fmt.Sprintf("Schemathesis found %d unique failure(s) of this check in the run.", fl.Count)))
		}
	}
	return out, nil
}

func parseSchemathesisJUnit(raw []byte) ([]importRecord, error) {
	type testcase struct {
		Name     string `xml:"name,attr"`
		Failures []struct {
			Message string `xml:"message,attr"`
			Text    string `xml:",chardata"`
		} `xml:"failure"`
		Errors []struct {
			Message string `xml:"message,attr"`
			Text    string `xml:",chardata"`
		} `xml:"error"`
	}
	var out []importRecord
	err := eachXMLElement(raw, "testsuite", "testcase", func(tc *testcase) error {
		seen := map[string]bool{}
		for _, fl := range tc.Failures {
			codes := schemathesisCodeRe.FindAllString(fl.Message, -1)
			titles := map[string]string{}
			for _, m := range schemathesisCheckLine.FindAllStringSubmatch(fl.Text, -1) {
				titles[m[1]] = strings.TrimSpace(m[2])
				if !strings.Contains(fl.Message, m[1]) {
					codes = append(codes, m[1])
				}
			}
			for _, code := range codes {
				if seen[code] {
					continue // one finding per check and operation
				}
				seen[code] = true
				rec := schemathesisRecord{Code: code, Title: firstNonEmpty(titles[code], code), Severity: schemathesisSeverity[code],
					Operation: strings.TrimSpace(tc.Name), Message: clipText(redactHTTP(g1RedactCmd(fl.Text)), maxEvidenceText)}
				out = append(out, schemathesisFinding(rec, clipText(rec.Message, 2000)))
			}
		}
		for _, e := range tc.Errors {
			// Errors are problems running the test (the API could not be
			// reached, invalid schema), kept as info findings.
			rec := schemathesisRecord{Code: "error", Title: firstNonEmpty(e.Message, "Schemathesis error"), Severity: "info",
				Operation: strings.TrimSpace(tc.Name), Message: clipText(redactHTTP(g1RedactCmd(e.Text)), maxEvidenceText)}
			out = append(out, schemathesisFinding(rec, "Schemathesis could not complete the test: "+clipText(rec.Message, 2000)))
		}
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("schemathesis: %w", err)
	}
	return out, nil
}

func schemathesisFinding(rec schemathesisRecord, detail string) importRecord {
	method, path, ok := strings.Cut(rec.Operation, " ")
	if !ok {
		method, path = "", rec.Operation
	}
	sev := normSeverity(rec.Severity)
	if sev == "" {
		sev = firstNonEmpty(schemathesisSeverity[rec.Code], "medium")
	}
	title := firstNonEmpty(rec.Title, rec.Code)
	if rec.Operation != "" {
		title += " (" + rec.Operation + ")"
	}
	f := Finding{RuleID: firstNonEmpty(rec.Code, rec.Title), Title: title, Severity: sev, FilePath: firstNonEmpty(path, "api"),
		Description: joinText(labelled("Operation", rec.Operation), detail)}
	return importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(method)), Raw: rawJSON(rec)}
}
