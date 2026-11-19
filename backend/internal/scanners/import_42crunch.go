package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
)

// 42Crunch API Security Audit JSON report: {"report": {"index": [JSON
// pointers], "security": {"issues": {...}}, "data": ..., "semanticErrors",
// "validationErrors", "warnings"}} (also the bare report object, and an
// array of reports). One finding per issue occurrence: the location is the
// JSON pointer into the OpenAPI definition ("openapi#/paths/..."), identity
// the issue id and pointer. Criticality 5 to 1 maps to critical, high,
// medium, low and info. Built from the published format; not yet verified
// against a real export.

type crunch42Issue struct {
	Description string `json:"description"`
	Criticality *int   `json:"criticality"`
	Issues      []struct {
		Score               json.Number `json:"score"`
		Pointer             json.Number `json:"pointer"`
		Criticality         *int        `json:"criticality"`
		SpecificDescription string      `json:"specificDescription"`
		Fingerprint         string      `json:"fingerprint"`
	} `json:"issues"`
}

type crunch42Section struct {
	Issues map[string]crunch42Issue `json:"issues"`
}

type crunch42Report struct {
	Index             []string         `json:"index"`
	AssessmentVersion string           `json:"assessmentVersion"`
	Score             json.Number      `json:"score"`
	Security          *crunch42Section `json:"security"`
	Data              *crunch42Section `json:"data"`
	SemanticErrors    *crunch42Section `json:"semanticErrors"`
	ValidationErrors  *crunch42Section `json:"validationErrors"`
	Warnings          *crunch42Section `json:"warnings"`
}

// crunch42Record is the record kept as a finding's original output.
type crunch42Record struct {
	APIID       string `json:"apiId,omitempty"`
	Section     string `json:"section"`
	IssueID     string `json:"issue_id"`
	Description string `json:"description"`
	Specific    string `json:"specificDescription,omitempty"`
	Pointer     string `json:"pointer"`
	Criticality int    `json:"criticality"`
	Score       string `json:"score,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "42crunch", Label: "42Crunch API Security Audit JSON", Tool: "42Crunch", Category: "other", Media: "json", Order: 408,
		match: func(p *importProbe) bool {
			crunch := func(m map[string]json.RawMessage) bool {
				return hasKeys(m, "index", "security") && (hasKeys(m, "assessmentVersion") || hasKeys(m, "score"))
			}
			if p.kind != "object" && p.kind != "array" {
				return false
			}
			var rep map[string]json.RawMessage
			return crunch(p.keys) || (p.has("report") && json.Unmarshal(p.keys["report"], &rep) == nil && crunch(rep))
		},
		parse: parse42Crunch})
}

func parse42Crunch(raw []byte) ([]importRecord, error) {
	type wrapped struct {
		APIID  string          `json:"apiId"`
		Report *crunch42Report `json:"report"`
	}
	var docs []json.RawMessage
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if len(b) > 0 && b[0] == '[' {
		if err := json.Unmarshal(b, &docs); err != nil {
			return nil, fmt.Errorf("42crunch: invalid JSON: %w", err)
		}
	} else {
		docs = []json.RawMessage{b}
	}
	var out []importRecord
	for _, d := range docs {
		var w wrapped
		if err := json.Unmarshal(d, &w); err != nil {
			return out, fmt.Errorf("42crunch: invalid JSON: %w", err)
		}
		if w.Report == nil {
			w.Report = &crunch42Report{}
			if err := json.Unmarshal(d, w.Report); err != nil {
				return out, fmt.Errorf("42crunch: invalid JSON: %w", err)
			}
		}
		rep := w.Report
		for _, sec := range []struct {
			name string
			s    *crunch42Section
		}{{"security", rep.Security}, {"data", rep.Data}, {"semanticErrors", rep.SemanticErrors}, {"validationErrors", rep.ValidationErrors}, {"warnings", rep.Warnings}} {
			if sec.s == nil {
				continue
			}
			ids := make([]string, 0, len(sec.s.Issues))
			for id := range sec.s.Issues {
				ids = append(ids, id)
			}
			slices.Sort(ids) // map order is random; keep the output stable
			for _, id := range ids {
				is := sec.s.Issues[id]
				for _, occ := range is.Issues {
					ptr := occ.Pointer.String()
					if n, err := occ.Pointer.Int64(); err == nil && n >= 0 && int(n) < len(rep.Index) {
						ptr = rep.Index[n]
					}
					crit := 0
					for _, c := range []*int{occ.Criticality, is.Criticality} {
						if c != nil {
							crit = *c
							break
						}
					}
					f := Finding{RuleID: id, Title: firstNonEmpty(is.Description, id), Severity: crunch42Severity(crit),
						FilePath: "openapi#" + ptr, CWE: []string{}}
					if sec.name == "semanticErrors" || sec.name == "validationErrors" {
						f.Confidence = "high"
					}
					f.Description = joinText(occ.SpecificDescription, labelled("Section", sec.name), labelled("JSON pointer", ptr),
						labelled("Score impact", occ.Score.String()))
					rec := crunch42Record{APIID: w.APIID, Section: sec.name, IssueID: id, Description: is.Description, Specific: occ.SpecificDescription,
						Pointer: ptr, Criticality: crit, Score: occ.Score.String(), Fingerprint: occ.Fingerprint}
					out = append(out, importRecord{F: f, SnippetKey: hashOf(sec.name), Raw: rawJSON(rec)})
				}
			}
		}
	}
	return out, nil
}

func crunch42Severity(c int) string {
	switch c {
	case 5:
		return "critical"
	case 4:
		return "high"
	case 3:
		return "medium"
	case 2:
		return "low"
	}
	return "info"
}
