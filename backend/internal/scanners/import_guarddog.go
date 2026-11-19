package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// GuardDog JSON (`guarddog <ecosystem> scan <package or dir>
// --output-format json`): package, path, issues, errors and results: one
// entry per heuristic rule, which is empty when the rule did not match, a
// message (metadata rules) or a list of code matches (location
// "file:line", code, message). Every match is a finding with the malware
// category; GuardDog's rules are heuristics without a severity: findings
// are medium with medium confidence.

func init() {
	registerImportFormat(ImportFormat{ID: "guarddog", Label: "GuardDog JSON", Tool: "GuardDog", Category: "malware", Media: "json", Order: 712,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("package", "issues", "results")
		},
		parse: parseGuardDog})
}

func parseGuardDog(raw []byte) ([]importRecord, error) {
	var doc struct {
		Package string                     `json:"package"`
		Results map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("guarddog: invalid JSON: %w", err)
	}
	rules := make([]string, 0, len(doc.Results))
	for r := range doc.Results {
		rules = append(rules, r)
	}
	slices.Sort(rules)
	var out []importRecord
	add := func(rule, loc, code, msg string) {
		file, line, _ := strings.Cut(loc, ":")
		n, _ := strconv.Atoi(line)
		f := Finding{Category: "malware", RuleID: rule, Title: "GuardDog " + rule + ": " + firstLine(msg), Severity: "medium", Confidence: "medium",
			FilePath: NormalizePath(firstNonEmpty(file, doc.Package)), StartLine: intPtr(n),
			Description: joinText(msg, labeled("Code", clipText(strings.TrimSpace(code), 2000)), "Package: "+doc.Package)}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(codeIdentity(code) + "|" + msg),
			Raw: rawJSON(map[string]any{"rule": rule, "location": loc, "code": code, "message": msg})})
	}
	for _, rule := range rules {
		v := doc.Results[rule]
		var msg string
		if json.Unmarshal(v, &msg) == nil {
			if msg != "" {
				add(rule, "", "", msg)
			}
			continue
		}
		var hits []struct {
			Location string `json:"location"`
			Code     string `json:"code"`
			Message  string `json:"message"`
		}
		if json.Unmarshal(v, &hits) == nil {
			for _, h := range hits {
				add(rule, h.Location, h.Code, h.Message)
			}
		}
	}
	return out, nil
}
