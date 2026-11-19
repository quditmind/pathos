package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Arjun JSON (`arjun -u <url> -oJ <file>`): an object keyed by the tested
// URL, each with method, headers (the request headers used) and params
// (the hidden HTTP parameters Arjun found). Each parameter is an info
// finding: an input the application accepts that the tester may not have
// known about. Request headers (which can carry credentials) are
// redacted.

func isArjun(p *importProbe) bool {
	if p.kind != "object" || len(p.keys) == 0 {
		return false
	}
	for k, v := range p.keys {
		var m map[string]json.RawMessage
		if !strings.HasPrefix(k, "http://") && !strings.HasPrefix(k, "https://") || json.Unmarshal(v, &m) != nil || !hasKeys(m, "params", "method") {
			return false
		}
	}
	return true
}

func init() {
	registerImportFormat(ImportFormat{ID: "arjun", Label: "Arjun JSON (-oJ)", Tool: "Arjun", Category: "dast", Media: "json", Order: 708,
		match: isArjun, parse: parseArjun, sanitize: sanitizeHTTPJSON})
}

func parseArjun(raw []byte) ([]importRecord, error) {
	var doc map[string]struct {
		Method string   `json:"method"`
		Params []string `json:"params"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("arjun: invalid JSON: %w", err)
	}
	urls := make([]string, 0, len(doc))
	for u := range doc {
		urls = append(urls, u)
	}
	slices.Sort(urls)
	var out []importRecord
	for _, u := range urls {
		r := doc[u]
		for _, p := range r.Params {
			f := Finding{Category: "dast", RuleID: "arjun-hidden-parameter", Title: fmt.Sprintf("Hidden %s parameter %q", strings.ToUpper(r.Method), p), Severity: "info",
				FilePath: redactHTTP(u),
				Description: fmt.Sprintf("Arjun found that %s accepts the %s parameter %q (the response changes when it is sent). Review what the parameter does.",
					redactHTTP(u), strings.ToUpper(r.Method), p)}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(r.Method) + "|" + p),
				Raw: rawJSON(map[string]any{"url": redactHTTP(u), "method": r.Method, "param": p})})
		}
	}
	return out, nil
}
