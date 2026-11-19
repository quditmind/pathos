package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RESTler bug buckets (RestlerResults/experiment*/bug_buckets/): the
// per-bug JSON files (<bucket>_<n>.json: checker, reproducibility, verb,
// endpoint, status and the request sequence that triggers the bug) and the
// Bugs.json index ({"bugs": [{filepath, reproducible, checker_name,
// error_code}]}). One finding per bug. Server errors found by the main
// driver and data-leak or invalid-object checker violations are medium;
// checkers for authorization and resource lifecycle flaws
// (UseAfterFree, NamespaceRule, ResourceHierarchy) high. Bugs RESTler could
// not reproduce are kept with low confidence. The replayed requests carry
// the fuzzing credentials and are redacted before the report is stored.

var restlerHighCheckers = []string{"useafterfreechecker", "namespacerulechecker", "resourcehierarchychecker"}

type restlerBug struct {
	// Bug detail file.
	StatusCode      looseString `json:"status_code"`
	StatusText      string      `json:"status_text"`
	CheckerName     string      `json:"checker_name"`
	Reproducible    *bool       `json:"reproducible"`
	Verb            string      `json:"verb"`
	Endpoint        string      `json:"endpoint"`
	RequestSequence []struct {
		ProducerTimingDelay looseString `json:"producer_timing_delay"`
		MaxAsyncWaitTime    looseString `json:"max_async_wait_time"`
		ReplayRequest       string      `json:"replay_request"`
		Response            string      `json:"response"`
	} `json:"request_sequence"`
	// Bugs.json entry.
	FilePath  string      `json:"filepath"`
	ErrorCode looseString `json:"error_code"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "restler", Label: "RESTler bug buckets (JSON)", Tool: "RESTler", Category: "other", Media: "json", Order: 309,
		match: func(p *importProbe) bool {
			if p.kind != "object" {
				return false
			}
			if p.has("checker_name", "request_sequence", "verb", "endpoint") {
				return true
			}
			return len(p.keys) == 1 && p.has("bugs") && hasKeys(p.firstOf("bugs"), "filepath", "checker_name")
		},
		parse:    parseRestler,
		sanitize: func(raw []byte) []byte { return g1Sanitize(raw) },
	})
}

func parseRestler(raw []byte) ([]importRecord, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("restler: invalid JSON: %w", err)
	}
	var bugs []restlerBug
	if _, index := probe["bugs"]; index {
		items, err := jsonArray(raw, "bugs")
		if err != nil {
			return nil, fmt.Errorf("restler: invalid JSON: %w", err)
		}
		for i, it := range items {
			var b restlerBug
			if err := json.Unmarshal(it, &b); err != nil || b.CheckerName == "" {
				return nil, fmt.Errorf("restler: bug %d: expected an object with checker_name", i+1)
			}
			bugs = append(bugs, b)
		}
	} else {
		var b restlerBug
		if err := json.Unmarshal(raw, &b); err != nil || b.CheckerName == "" {
			return nil, fmt.Errorf("restler: expected a bug with checker_name")
		}
		bugs = []restlerBug{b}
	}
	var out []importRecord
	for _, b := range bugs {
		code := firstNonEmpty(string(b.ErrorCode), string(b.StatusCode))
		sev := "medium"
		for _, c := range restlerHighCheckers {
			if strings.EqualFold(b.CheckerName, c) {
				sev = "high"
			}
		}
		title := b.CheckerName + " bug"
		if code != "" {
			title += " (HTTP " + code + ")"
		}
		loc := firstNonEmpty(b.Endpoint, b.FilePath)
		if b.Verb != "" {
			title += " in " + strings.ToUpper(b.Verb) + " " + b.Endpoint
		}
		f := Finding{RuleID: b.CheckerName + "/" + firstNonEmpty(code, "bug"), Title: title, Severity: sev, FilePath: loc}
		note := ""
		if b.Reproducible != nil && !*b.Reproducible {
			f.Confidence = "low"
			note = "RESTler could not reproduce this bug; it is kept for review."
		}
		var seq []string
		for i := range b.RequestSequence {
			r := &b.RequestSequence[i]
			r.ReplayRequest, r.Response = redactHTTP(g1RedactCmd(r.ReplayRequest)), redactHTTP(r.Response)
			if line := g1Lines(r.ReplayRequest, 1); line != "" {
				seq = append(seq, line)
			}
		}
		f.Description = joinText(note, fmt.Sprintf("RESTler checker %s reported a bug.", b.CheckerName), labelled("Response status", strings.TrimSpace(code+" "+b.StatusText)),
			labelled("Request sequence", strings.Join(seq, "\n")), labelled("Bug file", b.FilePath))
		key := strings.ToUpper(b.Verb)
		if b.Endpoint == "" {
			key = b.FilePath
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(key), Raw: rawJSON(b)})
	}
	return out, nil
}
