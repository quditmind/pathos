package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Sobelow JSON (`mix sobelow --format json`): findings.high_confidence,
// medium_confidence and low_confidence, each a list of {type, file, line,
// variable or pipeline}. type is "<Module>: <title>", e.g.
// "XSS.HTML: XSS in `html`". Sobelow reports a confidence, no severity:
// the severity comes from the vulnerability class (injection, XSS,
// traversal, deserialisation and secrets high; configuration and DoS
// medium), the confidence from the section.

type sobelowFinding struct {
	Type     string      `json:"type"`
	File     string      `json:"file"`
	Line     int         `json:"line"`
	Variable looseString `json:"variable"`
	Pipeline looseString `json:"pipeline"`
}

// sobelowClasses maps a Sobelow module prefix to severity and CWE.
var sobelowClasses = []struct {
	prefix, severity, cwe string
}{
	{"XSS", "high", "CWE-79"},
	{"SQL", "high", "CWE-89"},
	{"CI", "high", "CWE-78"},
	{"RCE", "high", "CWE-94"},
	{"Traversal", "high", "CWE-22"},
	{"Misc.BinToTerm", "high", "CWE-502"},
	{"Misc", "medium", ""},
	{"Config.Secrets", "high", "CWE-798"},
	{"Config.CSRF", "medium", "CWE-352"},
	{"Config.CSWH", "medium", "CWE-1385"},
	{"Config.Headers", "medium", "CWE-693"},
	{"Config.CSP", "medium", "CWE-693"},
	{"Config.HTTPS", "medium", "CWE-319"},
	{"Config.HSTS", "medium", "CWE-319"},
	{"Config", "medium", ""},
	{"DOS", "medium", "CWE-400"},
	{"Vuln", "high", "CWE-1395"},
}

func init() {
	registerImportFormat(ImportFormat{ID: "sobelow", Label: "Sobelow JSON", Tool: "Sobelow", Category: "sast", Media: "json", Order: 154,
		match: func(p *importProbe) bool { return p.kind == "object" && p.has("sobelow_version", "findings") },
		parse: parseSobelow})
}

func parseSobelow(raw []byte) ([]importRecord, error) {
	var doc struct {
		Findings map[string][]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("sobelow: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, conf := range []string{"high", "medium", "low"} {
		for i, it := range doc.Findings[conf+"_confidence"] {
			var r sobelowFinding
			if err := json.Unmarshal(it, &r); err != nil || r.Type == "" {
				return out, fmt.Errorf("sobelow: %s_confidence finding %d: expected an object with type", conf, i+1)
			}
			rule, title, ok := strings.Cut(r.Type, ":")
			if !ok {
				title = r.Type
			}
			rule, title = strings.TrimSpace(rule), strings.TrimSpace(title)
			f := Finding{Category: "sast", RuleID: rule, Title: firstNonEmpty(title, rule), Severity: "medium", Confidence: conf,
				FilePath: NormalizePath(r.File), StartLine: intPtr(r.Line), Description: "Sobelow " + r.Type}
			for _, c := range sobelowClasses {
				if rule == c.prefix || strings.HasPrefix(rule, c.prefix+".") {
					f.Severity = c.severity
					if c.cwe != "" {
						f.CWE = []string{c.cwe}
					}
					break
				}
			}
			if v := firstNonEmpty(string(r.Variable), string(r.Pipeline)); v != "" {
				f.Description += " (" + v + ")"
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%s|%s|%d", r.Variable, r.Pipeline, r.Line)), Raw: it})
		}
	}
	return out, nil
}
