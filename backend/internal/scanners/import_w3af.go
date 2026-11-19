package scanners

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"pathos/internal/platform/logging"
)

// w3af XML report (output plugin xml_file): <w3af-run> with <scan-info
// target>, <vulnerability> elements (id list, method, name, plugin,
// severity, url, var) with description, long description, fix guidance,
// references and HTTP transactions (headers as attributes, bodies in
// base64). One finding per vulnerability; identity is the plugin, name,
// method and parameter. Header values of credentials, plugin options that
// hold passwords and request bodies are redacted before the report is
// stored.

type w3afVuln struct {
	ID              string `xml:"id,attr"`
	Method          string `xml:"method,attr"`
	Name            string `xml:"name,attr"`
	Plugin          string `xml:"plugin,attr"`
	Severity        string `xml:"severity,attr"`
	URL             string `xml:"url,attr"`
	Var             string `xml:"var,attr"`
	Description     string `xml:"description"`
	LongDescription string `xml:"long-description"`
	FixGuidance     string `xml:"fix-guidance"`
	FixEffort       string `xml:"fix-effort"`
	References      []struct {
		Title string `xml:"title,attr"`
		URL   string `xml:"url,attr"`
	} `xml:"references>reference"`
	Transactions []struct {
		ID      string `xml:"id,attr"`
		Request struct {
			Status string `xml:"status"`
		} `xml:"http-request"`
		Response struct {
			Status string `xml:"status"`
		} `xml:"http-response"`
	} `xml:"http-transactions>http-transaction"`
}

// w3afRecord is the record kept as a finding's original output (no
// headers or bodies).
type w3afRecord struct {
	ID              string   `json:"id"`
	Method          string   `json:"method"`
	Name            string   `json:"name"`
	Plugin          string   `json:"plugin"`
	Severity        string   `json:"severity"`
	URL             string   `json:"url"`
	Var             string   `json:"var,omitempty"`
	Description     string   `json:"description,omitempty"`
	LongDescription string   `json:"long_description,omitempty"`
	FixGuidance     string   `json:"fix_guidance,omitempty"`
	FixEffort       string   `json:"fix_effort,omitempty"`
	References      []string `json:"references,omitempty"`
	Requests        []string `json:"requests,omitempty"`
}

var (
	w3afHeaderAttrRe = regexp.MustCompile(`(?i)(<header\s+field="(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)"\s+content=")[^"]*`)
	w3afConfigRe     = regexp.MustCompile(`(?i)(<config\s+parameter="[^"]*(?:pass|secret|token|cookie|key|auth)[^"]*"\s+value=")[^"]*`)
	w3afBodyRe       = regexp.MustCompile(`(<http-request>(?s:.*?)<body content-encoding="base64">)([^<]*)(</body>)`)
)

func init() {
	registerImportFormat(ImportFormat{ID: "w3af", Label: "w3af XML report", Tool: "w3af", Category: "dast", Media: "xml", Order: 307,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "w3af-run" },
		parse: parseW3af, sanitize: sanitizeW3af})
}

// sanitizeW3af redacts credential headers, password-like plugin options
// and request bodies (base64, decoded and redacted) in a w3af report.
func sanitizeW3af(raw []byte) []byte {
	s := w3afHeaderAttrRe.ReplaceAllString(string(raw), "${1}"+logging.Redacted)
	s = w3afConfigRe.ReplaceAllString(s, "${1}"+logging.Redacted)
	s = w3afBodyRe.ReplaceAllStringFunc(s, func(m string) string {
		g := w3afBodyRe.FindStringSubmatch(m)
		body, err := base64.StdEncoding.DecodeString(strings.TrimSpace(g[2]))
		if err != nil {
			return g[1] + g[3]
		}
		return g[1] + base64.StdEncoding.EncodeToString(sanitizeHTTPText(body)) + g[3]
	})
	return sanitizeHTTPText([]byte(s))
}

func parseW3af(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := eachXMLElement(raw, "w3af-run", "vulnerability", func(v *w3afVuln) error {
		name := strings.TrimSpace(v.Name)
		if name == "" && v.Plugin == "" {
			return fmt.Errorf("vulnerability %d: missing name and plugin", len(out)+1)
		}
		u := redactHTTP(strings.TrimSpace(v.URL))
		rec := w3afRecord{ID: v.ID, Method: v.Method, Name: name, Plugin: v.Plugin, Severity: v.Severity, URL: u, Var: v.Var,
			Description: clipText(redactHTTP(v.Description), maxEvidenceText), LongDescription: clipText(v.LongDescription, maxEvidenceText),
			FixGuidance: clipText(v.FixGuidance, maxEvidenceText), FixEffort: v.FixEffort}
		var refs []string
		for _, r := range v.References {
			rec.References = append(rec.References, strings.TrimSpace(r.Title+" "+r.URL))
			refs = append(refs, r.Title, r.URL)
		}
		for _, t := range v.Transactions {
			if s := strings.TrimSpace(t.Request.Status); s != "" {
				rec.Requests = append(rec.Requests, redactHTTP(s))
			}
		}
		f := Finding{Category: "dast", RuleID: firstNonEmpty(v.Plugin, name) + "/" + name, Title: firstNonEmpty(name, v.Plugin),
			Severity: firstNonEmpty(normSeverity(v.Severity), "info"), FilePath: locationOf("", g1StripQuery(u)), CWE: normCWEs(refs)}
		if v.Plugin == "" {
			f.RuleID = name
		}
		f.Description = joinText(redactHTTP(v.Description), whereText(v.Method, u, v.Var), strings.TrimSpace(v.LongDescription),
			labelled("Fix", strings.TrimSpace(v.FixGuidance)), labelled("Requests", strings.Join(rec.Requests, "\n")))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(v.Method) + "|" + v.Var), Raw: rawJSON(rec)})
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("w3af: %w", err)
	}
	return out, nil
}
