package scanners

import (
	"fmt"
	"regexp"
	"strings"
)

// Contrast Assess (IAST) vulnerability CSV export (Vulnerabilities >
// Export > CSV): one row per vulnerability with the rule, severity,
// status, CWE link and the request that exercised it. Fixed and
// remediated vulnerabilities are not imported; vulnerabilities marked
// "Not a Problem" are kept with low confidence. Request query strings and
// bodies may contain credentials and session data: they are redacted
// before the report is stored.

func init() {
	registerImportFormat(ImportFormat{ID: "contrast", Label: "Contrast Assess vulnerabilities CSV", Tool: "Contrast Assess", Category: "other", Media: "csv", Order: 470,
		match: func(p *importProbe) bool {
			return p.kind == "csv" && headerHas(p.header, "vulnerability_name", "vulnerability_id", "rule_name", "severity", "status", "application_name", "request_uri")
		},
		parse:    parseContrastCSV,
		sanitize: sanitizeCSVHTTP})
}

func parseContrastCSV(raw []byte) ([]importRecord, error) {
	_, rows, err := csvTable(raw)
	if err != nil && len(rows) == 0 {
		return nil, fmt.Errorf("contrast: %w", err)
	}
	var out []importRecord
	for _, r := range rows {
		id, rule := r.get("vulnerability_id"), r.get("rule_name")
		if id == "" && rule == "" {
			return out, fmt.Errorf("contrast: row %d: no vulnerability ID or rule", r.N)
		}
		status := r.get("status")
		switch strings.ToLower(strings.ReplaceAll(status, " ", "")) {
		case "fixed", "remediated", "auto-remediated", "remediated-auto-verified":
			continue
		}
		app := r.get("application_name")
		uri := r.get("request_uri")
		loc := app + uri
		if uri == "" {
			loc = firstNonEmpty(app, "application")
		}
		f := Finding{Category: "other", RuleID: firstNonEmpty(rule, id), Title: firstNonEmpty(r.get("vulnerability_name"), rule),
			Severity: normSeverity(r.get("severity")), FilePath: loc, CWE: []string{contrastCWE(r.get("cwe_id"))}}
		if strings.EqualFold(r.get("severity"), "note") {
			f.Severity = "info" // Contrast "Note" is its lowest level, below Low
		}
		note := ""
		if strings.EqualFold(strings.ReplaceAll(status, " ", ""), "notaproblem") {
			f.Confidence, note = "low", "Contrast reports this vulnerability as Not a Problem; it is kept for review."
		}
		req := strings.TrimSpace(r.get("request_method") + " " + uri)
		if qs := r.get("request_qs"); qs != "" {
			req += "?" + qs
		}
		f.Description = joinText(note, labelled("Request", redactHTTP(req)), labelled("Request body", clipText(redactHTTP(r.get("request_body")), 2000)),
			labelled("Category", r.get("category")), labelled("Status", status), labelled("Application", app), labelled("Contrast ID", id),
			labelled("Events", r.get("number_of_events")), labelled("Last seen", r.get("last_seen_datetime")))
		rec := map[string]string{}
		for k, v := range r.Orig {
			rec[k] = redactHTTP(v)
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(firstNonEmpty(id, rule+"|"+r.get("request_method")+"|"+uri)), Raw: rawJSON(rec)})
	}
	return out, err
}

var contrastCWERe = regexp.MustCompile(`definitions/(\d+)`)

// contrastCWE turns Contrast's CWE link into "CWE-n".
func contrastCWE(s string) string {
	if m := contrastCWERe.FindStringSubmatch(s); m != nil {
		return "CWE-" + m[1]
	}
	return s
}
