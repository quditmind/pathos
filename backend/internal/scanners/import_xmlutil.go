package scanners

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Helpers shared by the XML (and HTML-carrying) import formats: ZAP, Burp,
// Nessus, OpenVAS and Checkmarx.

// maxEvidenceText bounds long free-text fields (plugin output, evidence)
// kept in a finding's original record.
const maxEvidenceText = 8 << 10

var (
	markupBreakRe = regexp.MustCompile(`(?i)<\s*(br|/p|/li|/div|/h[1-6]|/tr)\s*/?>`)
	markupTagRe   = regexp.MustCompile(`<[^>]+>`)
	blankRunRe    = regexp.MustCompile(`[ \t\r\f\v]+`)
	blankLinesRe  = regexp.MustCompile(`\n\s*\n+`)
)

// markupToText turns the HTML fragments tools embed in descriptions
// (ZAP, Burp) into plain text.
func markupToText(s string) string {
	s = markupBreakRe.ReplaceAllString(s, "\n")
	s = markupTagRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = blankRunRe.ReplaceAllString(s, " ")
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	s = blankLinesRe.ReplaceAllString(strings.Join(lines, "\n"), "\n\n")
	return strings.TrimSpace(s)
}

// clipText truncates evidence text at a valid UTF-8 boundary.
func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s + " [truncated]"
}

// joinText joins the non-empty parts with blank lines.
func joinText(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "\n\n")
}

// looseString decodes a JSON string or number (tools are inconsistent).
type looseString string

func (l *looseString) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || string(b) == "null" {
		*l = ""
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*l = looseString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return errors.New("expected a string or a number")
	}
	*l = looseString(n.String())
	return nil
}

// eachXMLElement streams an XML report and decodes every element named
// name whose parent is named parent ("" for any parent), calling fn with
// it. It uses the safe decoder (newXMLDecoder).
func eachXMLElement[T any](raw []byte, parent, name string, fn func(*T) error) error {
	d := newXMLDecoder(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM)))
	var stack []string
	for {
		tok, err := d.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return errors.New("invalid XML: " + err.Error())
		}
		switch t := tok.(type) {
		case xml.StartElement:
			up := ""
			if len(stack) > 0 {
				up = stack[len(stack)-1]
			}
			if t.Name.Local == name && (parent == "" || up == parent) {
				v := new(T)
				if err := d.DecodeElement(v, &t); err != nil {
					return errors.New("invalid XML: " + err.Error())
				}
				if err := fn(v); err != nil {
					return err
				}
				continue
			}
			stack = append(stack, t.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
}
