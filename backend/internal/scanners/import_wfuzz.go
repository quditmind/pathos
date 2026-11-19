package scanners

import (
	"encoding/json"
	"fmt"
	"strings"

	"pathos/internal/platform/logging"
)

// Wfuzz JSON output (`wfuzz -f out.json,json`): an array of the responses
// that passed the filters, with the payload, status and size. Wfuzz finds
// content, not vulnerabilities: every result is an info finding for review.
// Identity is the URL, method and payload. Credential-like POST parameters
// are redacted before the report is stored.

type wfuzzResult struct {
	Chars    int    `json:"chars"`
	Code     int    `json:"code"`
	Payload  string `json:"payload"`
	Lines    int    `json:"lines"`
	Words    int    `json:"words"`
	Location string `json:"location"`
	Method   string `json:"method"`
	PostData []struct {
		Parameter string `json:"parameter"`
		Value     string `json:"value"`
	} `json:"post_data"`
	Server string `json:"server"`
	URL    string `json:"url"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "wfuzz", Label: "Wfuzz JSON", Tool: "Wfuzz", Category: "dast", Media: "json", Order: 306,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("chars", "code", "payload", "words", "url")
		},
		parse:    parseWfuzz,
		sanitize: sanitizeWfuzz,
	})
}

// sanitizeWfuzz redacts HTTP evidence and the values of credential-like
// POST parameters ({"parameter": "password", "value": ...}).
func sanitizeWfuzz(raw []byte) []byte {
	b := g1Sanitize(raw)
	var items []map[string]any
	if json.Unmarshal(b, &items) != nil {
		return b
	}
	for _, it := range items {
		pd, _ := it["post_data"].([]any)
		for _, x := range pd {
			if m, ok := x.(map[string]any); ok {
				if n, _ := m["parameter"].(string); wfuzzSecretParam(n) {
					m["value"] = logging.Redacted
				}
			}
		}
	}
	out, err := json.Marshal(items)
	if err != nil {
		return b
	}
	return out
}

func wfuzzSecretParam(name string) bool {
	return secretParamRe.MatchString(strings.ToLower(name) + "=x")
}

func parseWfuzz(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("wfuzz: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r wfuzzResult
		if err := json.Unmarshal(it, &r); err != nil || r.URL == "" {
			return out, fmt.Errorf("wfuzz: result %d: expected an object with url", i+1)
		}
		u := redactHTTP(r.URL)
		var post []string
		for j := range r.PostData {
			if wfuzzSecretParam(r.PostData[j].Parameter) {
				r.PostData[j].Value = logging.Redacted
			}
			post = append(post, r.PostData[j].Parameter+"="+redactHTTP(r.PostData[j].Value))
		}
		f := Finding{Category: "dast", RuleID: "wfuzz-match", Title: fmt.Sprintf("Content discovered: %s (HTTP %d)", g1StripQuery(u), r.Code),
			Severity: "info", Confidence: "medium", FilePath: locationOf("", u)}
		f.Description = joinText("Wfuzz matched this response while fuzzing; content discovery results are not vulnerabilities and need review.",
			labelled("Payload", redactHTTP(r.Payload)), whereText(r.Method, u, ""), labelled("POST data", strings.Join(post, "&")),
			fmt.Sprintf("Status %d, %d characters, %d words, %d lines", r.Code, r.Chars, r.Words, r.Lines),
			labelled("Server", r.Server), labelled("Redirect", redactHTTP(r.Location)))
		r.URL, r.Location, r.Payload = u, redactHTTP(r.Location), redactHTTP(r.Payload)
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(r.Method) + "|" + r.Payload), Raw: rawJSON(r)})
	}
	return out, nil
}
