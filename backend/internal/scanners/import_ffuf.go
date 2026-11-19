package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// ffuf JSON output (`ffuf -of json -o out.json`): results[] of matched
// responses, with the command line and configuration. ffuf finds content
// (paths, parameters, virtual hosts), not vulnerabilities: every result is
// an info finding for review. Identity is the URL and the fuzzed inputs.
// The command line and configured headers carry the scan's credentials and
// are redacted before the report is stored.

type ffufResult struct {
	Input            map[string]string `json:"input"`
	Position         int               `json:"position"`
	Status           int               `json:"status"`
	Length           int               `json:"length"`
	Words            int               `json:"words"`
	Lines            int               `json:"lines"`
	ContentType      string            `json:"content-type"`
	RedirectLocation string            `json:"redirectlocation"`
	URL              string            `json:"url"`
	Host             string            `json:"host"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "ffuf", Label: "ffuf JSON", Tool: "ffuf", Category: "dast", Media: "json", Order: 305,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("commandline", "results", "config")
		},
		parse:    parseFfuf,
		sanitize: func(raw []byte) []byte { return g1Sanitize(raw, "headers") },
	})
}

func parseFfuf(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("ffuf: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r ffufResult
		if err := json.Unmarshal(it, &r); err != nil || r.URL == "" {
			return out, fmt.Errorf("ffuf: result %d: expected an object with url", i+1)
		}
		delete(r.Input, "FFUFHASH") // differs between runs
		keys := make([]string, 0, len(r.Input))
		for k := range r.Input {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		var inputs []string
		for _, k := range keys {
			inputs = append(inputs, k+"="+redactHTTP(r.Input[k]))
		}
		u := redactHTTP(r.URL)
		f := Finding{Category: "dast", RuleID: "ffuf-match", Title: fmt.Sprintf("Content discovered: %s (HTTP %d)", g1StripQuery(u), r.Status),
			Severity: "info", Confidence: "medium", FilePath: locationOf("", u)}
		f.Description = joinText("ffuf matched this response while fuzzing; content discovery results are not vulnerabilities and need review.",
			labelled("Inputs", strings.Join(inputs, ", ")),
			fmt.Sprintf("Status %d, %d bytes, %d words, %d lines", r.Status, r.Length, r.Words, r.Lines),
			labelled("Content type", r.ContentType), labelled("Redirect", redactHTTP(r.RedirectLocation)))
		r.URL, r.RedirectLocation = u, redactHTTP(r.RedirectLocation)
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.Join(inputs, "&")), Raw: rawJSON(r)})
	}
	return out, nil
}
