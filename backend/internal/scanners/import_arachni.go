package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"pathos/internal/platform/logging"
)

// Arachni JSON report (`arachni_reporter scan.afr --reporter=json`):
// issues[] with the check, severity, CWE, the vector (URL, method, input)
// and the request and response. One finding per issue; identity is
// Arachni's issue digest. Issues Arachni marks as untrusted are kept with
// low confidence. Request and response headers carry the scan's
// credentials: they are redacted before the report is stored.

type arachniIssue struct {
	Name           string      `json:"name"`
	Description    string      `json:"description"`
	RemedyGuidance string      `json:"remedy_guidance"`
	Severity       string      `json:"severity"`
	CWE            looseString `json:"cwe"`
	Digest         looseString `json:"digest"`
	Trusted        *bool       `json:"trusted"`
	Proof          string      `json:"proof"`
	Signature      string      `json:"signature"`
	Check          struct {
		Name      string `json:"name"`
		Shortname string `json:"shortname"`
	} `json:"check"`
	Vector struct {
		Type               string `json:"type"`
		URL                string `json:"url"`
		Action             string `json:"action"`
		Method             string `json:"method"`
		AffectedInputName  string `json:"affected_input_name"`
		AffectedInputValue string `json:"affected_input_value"`
	} `json:"vector"`
	Request struct {
		URL           string `json:"url"`
		Method        string `json:"method"`
		HeadersString string `json:"headers_string"`
	} `json:"request"`
	Response struct {
		Code          int    `json:"code"`
		HeadersString string `json:"headers_string"`
	} `json:"response"`
}

// arachniRecord is the record kept as a finding's original output (the
// page bodies are not kept).
type arachniRecord struct {
	Name           string `json:"name"`
	Check          string `json:"check"`
	Severity       string `json:"severity"`
	CWE            string `json:"cwe,omitempty"`
	Digest         string `json:"digest,omitempty"`
	Trusted        *bool  `json:"trusted,omitempty"`
	VectorType     string `json:"vector_type,omitempty"`
	URL            string `json:"url"`
	Method         string `json:"method,omitempty"`
	Input          string `json:"affected_input_name,omitempty"`
	InputValue     string `json:"affected_input_value,omitempty"`
	Proof          string `json:"proof,omitempty"`
	Request        string `json:"request,omitempty"`
	ResponseStatus int    `json:"response_code,omitempty"`
	Response       string `json:"response_headers,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "arachni", Label: "Arachni JSON report", Tool: "Arachni", Category: "dast", Media: "json", Order: 302,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("issues", "sitemap", "options") && p.hasAny("seed", "delta_time", "plugins")
		},
		parse:    parseArachni,
		sanitize: func(raw []byte) []byte { return g1Sanitize(raw, "cookie_string", "cookies", "request_headers") },
	})
}

func parseArachni(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "issues")
	if err != nil {
		return nil, fmt.Errorf("arachni: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var is arachniIssue
		if err := json.Unmarshal(it, &is); err != nil || (is.Name == "" && is.Check.Shortname == "") {
			return out, fmt.Errorf("arachni: issue %d: expected an object with name and check", i+1)
		}
		loc := firstNonEmpty(is.Vector.Action, is.Vector.URL, is.Request.URL)
		method := firstNonEmpty(is.Vector.Method, is.Request.Method)
		f := Finding{Category: "dast", RuleID: firstNonEmpty(is.Check.Shortname, is.Name), Title: firstNonEmpty(is.Name, is.Check.Name),
			Severity: firstNonEmpty(normSeverity(is.Severity), "info"), FilePath: locationOf("", g1StripQuery(loc)), CWE: []string{string(is.CWE)}}
		note := ""
		if is.Trusted != nil && !*is.Trusted {
			f.Confidence = "low"
			note = "Arachni marked this issue as untrusted (it needs manual verification); it is kept for review."
		}
		f.Description = joinText(note, strings.TrimSpace(is.Description), whereText(method, loc, is.Vector.AffectedInputName),
			labelled("Proof", clipText(redactHTTP(is.Proof), 500)), labelled("Remedy", strings.TrimSpace(is.RemedyGuidance)))
		rec := arachniRecord{Name: is.Name, Check: is.Check.Shortname, Severity: is.Severity, CWE: string(is.CWE), Digest: string(is.Digest),
			Trusted: is.Trusted, VectorType: is.Vector.Type, URL: redactHTTP(loc), Method: method, Input: is.Vector.AffectedInputName,
			InputValue: redactHTTP(is.Vector.AffectedInputValue), Proof: redactHTTP(is.Proof), Request: redactHTTP(is.Request.HeadersString),
			ResponseStatus: is.Response.Code, Response: redactHTTP(is.Response.HeadersString)}
		key := string(is.Digest)
		if key == "" {
			key = strings.ToUpper(method) + "|" + is.Vector.AffectedInputName + "|" + is.Vector.Type + "|" + loc
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(key), Raw: rawJSON(rec)})
	}
	return out, nil
}

// --- helpers shared by the group of DAST and API tool formats (Nikto,
// Wapiti, Arachni, sqlmap, Dalfox, ffuf, Wfuzz, w3af, Schemathesis,
// RESTler) ---------------------------------------------------------------

// g1CmdHeaderRe and g1CmdCookieRe find credentials in command lines tools
// copy into their reports (`-H "Cookie: ..."`, `-b ...`, `--cookie=...`).
var (
	g1CmdHeaderRe = regexp.MustCompile(`(?i)((?:-H|--header|--headers|--http-request-header)(?:\s+|=)["']?(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token)\s*[:=]\s*)(?:[^"'\n]*?)(\s+-{1,2}[A-Za-z]|["'\n]|$)`)
	g1CmdCookieRe = regexp.MustCompile(`(?i)((?:^|\s)(?:-b|-C|--cookie|--cookies|--cookie-string|--http-cookie-string)(?:\s+|=)["']?)[^"'\s]+`)
)

// g1RedactCmd removes header values and cookies from a command line or
// any free text that quotes HTTP headers inline.
func g1RedactCmd(s string) string {
	s = g1CmdHeaderRe.ReplaceAllString(s, "${1}"+logging.Redacted+"${2}")
	return g1CmdCookieRe.ReplaceAllString(s, "${1}"+logging.Redacted)
}

// g1Sanitize redacts a JSON report: HTTP evidence (sanitizeHTTPJSON),
// credentials quoted in command lines, and the values of the named keys
// (when not empty).
func g1Sanitize(raw []byte, keys ...string) []byte {
	b := sanitizeHTTPJSON(raw)
	var x any
	if json.Unmarshal(b, &x) != nil {
		return b
	}
	out, err := json.Marshal(g1RedactIn(x, keys))
	if err != nil {
		return b
	}
	return out
}

func g1RedactIn(x any, keys []string) any {
	switch t := x.(type) {
	case string:
		return g1RedactCmd(t)
	case []any:
		for i := range t {
			t[i] = g1RedactIn(t[i], keys)
		}
	case map[string]any:
		for k, v := range t {
			named := false
			for _, n := range keys {
				named = named || strings.EqualFold(n, k)
			}
			if named && !g1Empty(v) {
				t[k] = logging.Redacted
				continue
			}
			t[k] = g1RedactIn(v, keys)
		}
	}
	return x
}

func g1Empty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// g1StripQuery returns a URL without its query and fragment (payloads
// tools inject vary between scans; they are kept in the description).
func g1StripQuery(u string) string {
	u = strings.TrimSpace(u)
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		return u[:i]
	}
	return u
}

// g1Resolve joins a path reported relative to the scan target.
func g1Resolve(base, p string) string {
	p = strings.TrimSpace(p)
	if p == "" || strings.Contains(p, "://") {
		return p
	}
	b, err := url.Parse(strings.TrimSpace(base))
	if err != nil || b.Host == "" {
		return p
	}
	r, err := b.Parse(p)
	if err != nil {
		return p
	}
	return r.String()
}

// g1Lines returns the trimmed first n lines of s (n <= 0: all).
func g1Lines(s string, n int) string {
	lines := strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
	if n > 0 && len(lines) > n {
		lines = lines[:n]
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// g1Atoi parses an integer field ("" gives 0).
func g1Atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// g1IsJSON reports whether raw starts like a JSON document.
func g1IsJSON(raw []byte) bool {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}
