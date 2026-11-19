package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// klocworkLineRe matches the line numbers Klocwork puts in messages; they
// are left out of the identity so it survives code moving.
var klocworkLineRe = regexp.MustCompile(`(?i)\bline \d+`)

// Klocwork JSON: the array of `kwcheck list -F json` (and kwciagent), or
// the JSON Lines of the Klocwork Web API `action=search`. Each issue has
// id, code (the checker), title, message, file, line (kwcheck only),
// method, severity / severityCode (1 Critical critical, 2 Error high,
// 3 Warning medium, 4 Review low, 5-10 info), state (New, Existing,
// Fixed) and status (Analyze, Ignore, Not a Problem, Fix, Defer, ...).
// Issues whose state is Fixed are gone from the code and not imported;
// issues with status Ignore, Not a Problem or Defer are imported with low
// confidence and the status noted. Coding-standard checkers (MISRA,
// AUTOSAR) are code quality (other); every other checker is sast. CWE ids
// come from the reference field when present. Identity is the checker,
// method and message (without line numbers).

type klocworkIssue struct {
	ID           looseString `json:"id"`
	Code         string      `json:"code"`
	Title        string      `json:"title"`
	Message      string      `json:"message"`
	File         string      `json:"file"`
	Line         int         `json:"line"`
	Method       string      `json:"method"`
	Severity     string      `json:"severity"`
	SeverityCode int         `json:"severityCode"`
	State        string      `json:"state"`
	Status       string      `json:"status"`
	Taxonomy     string      `json:"taxonomy"`
	TaxonomyName string      `json:"taxonomyName"`
	Reference    string      `json:"reference"`
	URL          string      `json:"url"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "klocwork", Label: "Klocwork JSON (kwcheck, Web API)", Tool: "Klocwork", Media: "json", Order: 104,
		match: func(p *importProbe) bool {
			return (p.kind == "array" || p.kind == "jsonl") && p.has("code", "severityCode", "file") && p.hasAny("taxonomy", "taxonomyName", "status")
		},
		parse: parseKlocwork})
}

func parseKlocwork(raw []byte) ([]importRecord, error) {
	var lines []json.RawMessage
	if b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM)); len(b) > 0 && b[0] == '[' {
		arr, err := jsonArray(b, "")
		if err != nil {
			return nil, fmt.Errorf("klocwork: invalid JSON: %w", err)
		}
		lines = arr
	} else if err := jsonLines(raw, func(n int, line []byte) error {
		lines = append(lines, append(json.RawMessage{}, line...))
		return nil
	}); err != nil {
		return nil, fmt.Errorf("klocwork: %w", err)
	}
	var out []importRecord
	for i, it := range lines {
		var k klocworkIssue
		if err := json.Unmarshal(it, &k); err != nil || k.Code == "" {
			return out, fmt.Errorf("klocwork: issue %d: expected an object with code", i+1)
		}
		if strings.EqualFold(k.State, "fixed") {
			continue
		}
		sev := "info"
		switch {
		case k.SeverityCode == 1:
			sev = "critical"
		case k.SeverityCode == 2:
			sev = "high"
		case k.SeverityCode == 3:
			sev = "medium"
		case k.SeverityCode == 4:
			sev = "low"
		case k.SeverityCode <= 0:
			sev = firstNonEmpty(normSeverity(k.Severity), "medium")
		}
		cat := "sast"
		if up := strings.ToUpper(k.Code); strings.HasPrefix(up, "MISRA.") || strings.HasPrefix(up, "AUTOSAR.") {
			cat = "other"
		}
		f := Finding{Category: cat, RuleID: k.Code, Title: firstNonEmpty(k.Title, k.Code) + " (" + k.Code + ")", Severity: sev,
			FilePath: NormalizePath(k.File), StartLine: intPtr(k.Line), CWE: []string{k.Reference},
			Description: joinText(k.Message, labelled("Method", k.Method), labelled("Taxonomy", firstNonEmpty(k.Taxonomy, k.TaxonomyName)),
				labelled("Klocwork status", k.Status), labelled("Issue", k.URL))}
		switch st := strings.ToLower(k.Status); st {
		case "ignore", "not a problem", "defer":
			f.Confidence = "low"
			f.Description = "Klocwork status " + k.Status + "; kept for review.\n\n" + f.Description
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("klocwork|" + k.Method + "|" + klocworkLineRe.ReplaceAllString(k.Message, "line")), Raw: it})
	}
	return out, nil
}
