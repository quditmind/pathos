package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Conftest JSON (`conftest test -o json`): an array of {filename,
// namespace, successes, warnings[], failures[], exceptions[]}; each result
// has msg and metadata (query, and whatever the policy adds, e.g. an id or
// severity). Failures (deny, violation) are high, warnings medium,
// exceptions (excepted by the policy) low confidence info. The policies
// are the organisation's own, so the rule is the query (or metadata.id)
// and the message.

type conftestResult struct {
	Msg      string         `json:"msg"`
	Metadata map[string]any `json:"metadata"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "conftest", Label: "Conftest JSON", Tool: "Conftest", Category: "iac", Media: "json", Order: 269,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("filename", "namespace", "successes")
		},
		parse: parseConftest})
}

func parseConftest(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("conftest: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, it := range items {
		var file struct {
			Filename   string            `json:"filename"`
			Namespace  string            `json:"namespace"`
			Failures   []json.RawMessage `json:"failures"`
			Warnings   []json.RawMessage `json:"warnings"`
			Exceptions []json.RawMessage `json:"exceptions"`
		}
		if err := json.Unmarshal(it, &file); err != nil {
			return out, fmt.Errorf("conftest: invalid file result: %w", err)
		}
		for _, set := range []struct {
			kind, sev string
			items     []json.RawMessage
		}{{"failure", "high", file.Failures}, {"warning", "medium", file.Warnings}, {"exception", "info", file.Exceptions}} {
			for i, rr := range set.items {
				var r conftestResult
				if err := json.Unmarshal(rr, &r); err != nil || r.Msg == "" {
					return out, fmt.Errorf("conftest: %s: %s %d: expected an object with msg", file.Filename, set.kind, i+1)
				}
				query, _ := r.Metadata["query"].(string)
				id := conftestMeta(r.Metadata, "id", "rule", "policyID")
				rule := firstNonEmpty(id, query, file.Namespace)
				f := Finding{Category: "iac", RuleID: rule, Title: r.Msg, FilePath: NormalizePath(file.Filename),
					Severity:    firstNonEmpty(normSeverity(conftestMeta(r.Metadata, "severity")), set.sev),
					Description: joinText(r.Msg, fmt.Sprintf("Conftest %s of policy namespace %s (%s)", set.kind, file.Namespace, query))}
				if set.kind == "exception" {
					f.Confidence = "low"
					f.Description = joinText(f.Description, "Excepted by the policy; imported for triage.")
				}
				out = append(out, importRecord{F: f, SnippetKey: hashOf(set.kind + "|" + strings.TrimSpace(r.Msg)), Raw: rr})
			}
		}
	}
	return out, nil
}

// conftestMeta returns the first string value of keys in a result's
// metadata (top level or under details).
func conftestMeta(m map[string]any, keys ...string) string {
	for _, src := range []map[string]any{m, func() map[string]any { d, _ := m["details"].(map[string]any); return d }()} {
		for _, k := range keys {
			if s, ok := src[k].(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}
