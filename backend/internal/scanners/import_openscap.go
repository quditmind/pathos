package scanners

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// XCCDF results: OpenSCAP (`oscap xccdf eval --results results.xml` or
// `--results-arf arf.xml`) and other SCAP scanners write XCCDF 1.1/1.2
// TestResult elements (target, target-address, rule-result with idref,
// severity, result and ident), either in the evaluated Benchmark document
// or in an ARF asset report collection that also carries the benchmark.
// The Rule definitions (title, description, rationale, fixtext, ident,
// reference) give each failed rule its text. Results fail is a finding
// with the rule's severity; error and unknown (the check could not be
// evaluated) are findings with low confidence. pass, fixed,
// notapplicable, notchecked, notselected and informational are not
// findings. A finding is located on the scanned target (host name or
// first address). CIS-CAT Pro writes the same XCCDF results (cis-cat).

type xccdfRule struct {
	ID          string       `xml:"id,attr"`
	Severity    string       `xml:"severity,attr"`
	Title       xccdfText    `xml:"title"`
	Description xccdfText    `xml:"description"`
	Rationale   xccdfText    `xml:"rationale"`
	Fixtext     xccdfText    `xml:"fixtext"`
	Idents      []xccdfIdent `xml:"ident"`
	References  []xccdfIdent `xml:"reference"`
}

type xccdfText struct {
	Inner string `xml:",innerxml"`
}

func (t xccdfText) text() string { return markupToText(t.Inner) }

type xccdfIdent struct {
	System string `xml:"system,attr"`
	Href   string `xml:"href,attr"`
	Value  string `xml:",chardata"`
}

type xccdfRuleResult struct {
	IDRef    string       `xml:"idref,attr" json:"idref"`
	Severity string       `xml:"severity,attr" json:"severity,omitempty"`
	Time     string       `xml:"time,attr" json:"time,omitempty"`
	Result   string       `xml:"result" json:"result"`
	Idents   []xccdfIdent `xml:"ident" json:"ident,omitempty"`
	Messages []string     `xml:"message" json:"message,omitempty"`
	// Target is the scanned system (from the TestResult), kept in the
	// finding's original record.
	Target string `xml:"-" json:"target,omitempty"`
}

func isXCCDFResults(p *importProbe) bool {
	if p.kind != "xml" {
		return false
	}
	switch p.root {
	case "asset-report-collection":
		return true
	case "Benchmark", "TestResult":
		return p.headHas("checklists.nist.gov/xccdf")
	}
	return false
}

func isCISCAT(p *importProbe) bool {
	return p.headHas("org.cisecurity") || p.headHas("cis-cat") || p.headHas("CIS-CAT")
}

func init() {
	registerImportFormat(ImportFormat{ID: "openscap", Label: "OpenSCAP / SCAP XCCDF results (XCCDF or ARF XML)", Tool: "OpenSCAP", Category: "compliance",
		Media: "xml", Order: 560,
		match: func(p *importProbe) bool { return isXCCDFResults(p) && !isCISCAT(p) },
		parse: parseXCCDF})
	registerImportFormat(ImportFormat{ID: "cis-cat", Label: "CIS-CAT Pro Assessor results (XCCDF or ARF XML)", Tool: "CIS-CAT", Category: "compliance",
		Media: "xml", Parser: "openscap", Order: 561,
		match: func(p *importProbe) bool { return isXCCDFResults(p) && isCISCAT(p) }})
}

func parseXCCDF(raw []byte) ([]importRecord, error) {
	d := newXMLDecoder(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM)))
	rules := map[string]xccdfRule{}
	type testResult struct {
		target  string
		results []xccdfRuleResult
	}
	var tests []*testResult
	var cur *testResult
	depth, testDepth := 0, -1
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("xccdf: invalid XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			switch t.Name.Local {
			case "Rule":
				var r xccdfRule
				if err := d.DecodeElement(&r, &t); err != nil {
					return nil, fmt.Errorf("xccdf: invalid Rule: %w", err)
				}
				rules[r.ID] = r
				continue
			case "TestResult":
				cur, testDepth = &testResult{}, depth
				tests = append(tests, cur)
			case "target", "target-address":
				if cur != nil {
					var s string
					if err := d.DecodeElement(&s, &t); err != nil {
						return nil, fmt.Errorf("xccdf: invalid %s: %w", t.Name.Local, err)
					}
					if cur.target == "" {
						cur.target = strings.TrimSpace(s)
					}
					continue
				}
			case "rule-result":
				if cur != nil {
					var rr xccdfRuleResult
					if err := d.DecodeElement(&rr, &t); err != nil {
						return nil, fmt.Errorf("xccdf: invalid rule-result: %w", err)
					}
					cur.results = append(cur.results, rr)
					continue
				}
			}
			depth++
		case xml.EndElement:
			depth--
			if t.Name.Local == "TestResult" && depth == testDepth {
				cur, testDepth = nil, -1
			}
		}
	}
	if len(tests) == 0 {
		return nil, errors.New("xccdf: no TestResult: import the results of an evaluation (oscap xccdf eval --results or --results-arf)")
	}
	var out []importRecord
	for _, tr := range tests {
		for _, rr := range tr.results {
			res := strings.ToLower(strings.TrimSpace(rr.Result))
			if res != "fail" && res != "error" && res != "unknown" {
				continue
			}
			if rr.IDRef == "" {
				return out, errors.New("xccdf: rule-result without idref")
			}
			rule := rules[rr.IDRef]
			rr.Target = tr.target
			f := Finding{Category: "compliance", RuleID: rr.IDRef, Title: firstNonEmpty(rule.Title.text(), rr.IDRef),
				Severity: firstNonEmpty(normSeverity(rr.Severity), normSeverity(rule.Severity), "medium"), FilePath: tr.target}
			var ids, refs []string
			for _, id := range append(rr.Idents, rule.Idents...) {
				if v := strings.TrimSpace(id.Value); v != "" && !strings.Contains(strings.Join(ids, " "), v) {
					ids = append(ids, v)
				}
			}
			for i, r := range rule.References {
				if i == 10 {
					break
				}
				if v := strings.TrimSpace(r.Value); v != "" {
					refs = append(refs, v)
				}
			}
			f.Description = joinText(rule.Description.text(), labeled("Rationale", rule.Rationale.text()), labeled("Identifiers", strings.Join(ids, ", ")),
				labeled("References", strings.Join(refs, ", ")), labeled("Fix", rule.Fixtext.text()), labeled("Messages", strings.Join(rr.Messages, "\n")))
			if res != "fail" {
				f.Severity, f.Confidence = "low", "low"
				f.Description = joinText(f.Description, "The check could not be evaluated (result "+res+"); it needs a manual review.")
			}
			out = append(out, importRecord{F: f, Raw: rawJSON(rr)})
		}
	}
	return out, nil
}
