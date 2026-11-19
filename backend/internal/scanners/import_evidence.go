package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"pathos/internal/platform/logging"
)

// Helpers shared by the DAST, API, infrastructure, cloud, runtime and
// pentest import formats: redaction of HTTP evidence (requests and
// responses carry session cookies and credentials), CSV exports read by
// column name, and host:port locations.

// sensitiveHeaders are HTTP headers whose values are never kept.
var sensitiveHeaders = []string{"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key",
	"x-auth-token", "x-access-token", "x-csrf-token", "x-xsrf-token"}

var (
	// headerLineRe matches a sensitive header line of a raw HTTP message.
	headerLineRe = regexp.MustCompile(`(?im)((?:^|>)[ \t]*(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token|x-xsrf-token)[ \t]*:[ \t]*)[^\r\n<"]*`)
	// secretParamRe matches credential-like query or form parameters.
	secretParamRe = regexp.MustCompile(`(?i)\b((?:password|passwd|pwd|pass|token|access_token|refresh_token|id_token|api[_-]?key|apikey|secret|client_secret|session|sessionid|phpsessid|jsessionid|sid|auth)=)([^&\s"'<>;]+)`)
)

// redactHTTP removes sensitive header values, credential-like parameters
// and token-shaped values from HTTP evidence (a request, a response or a
// URL) and bounds its size.
func redactHTTP(s string) string {
	if s == "" {
		return s
	}
	s = headerLineRe.ReplaceAllString(s, "${1}"+logging.Redacted)
	s = secretParamRe.ReplaceAllString(s, "${1}"+logging.Redacted)
	return clipText(logging.RedactString(s), maxEvidenceText)
}

// isSensitiveHeader reports whether name is a header whose value is never kept.
func isSensitiveHeader(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, h := range sensitiveHeaders {
		if name == h {
			return true
		}
	}
	return false
}

// sanitizeHTTPJSON redacts HTTP evidence in a JSON (or JSON Lines) report:
// values of keys named like sensitive headers, header objects of the form
// {"name": "Cookie", "value": ...}, and header lines, credential
// parameters and tokens inside every string. Non-JSON input is redacted
// as text.
func sanitizeHTTPJSON(raw []byte) []byte {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	var x any
	if len(b) > 0 && json.Unmarshal(b, &x) == nil {
		out, err := json.Marshal(redactHTTPIn(x))
		if err != nil {
			return raw
		}
		return out
	}
	if len(b) > 0 && b[0] == '{' { // JSON Lines
		var out bytes.Buffer
		err := jsonLines(raw, func(_ int, line []byte) error {
			var v any
			if json.Unmarshal(line, &v) != nil {
				return errors.New("not JSON Lines")
			}
			enc, err := json.Marshal(redactHTTPIn(v))
			if err != nil {
				return err
			}
			out.Write(enc)
			out.WriteByte('\n')
			return nil
		})
		if err == nil {
			return out.Bytes()
		}
	}
	return sanitizeHTTPText(raw)
}

// sanitizeHTTPText redacts HTTP evidence in a text report (XML, CSV, logs).
// Values are replaced in place, so the document structure is kept.
func sanitizeHTTPText(raw []byte) []byte {
	s := headerLineRe.ReplaceAllString(string(raw), "${1}"+logging.Redacted)
	s = secretParamRe.ReplaceAllString(s, "${1}"+logging.Redacted)
	return []byte(logging.RedactString(s))
}

func redactHTTPIn(x any) any {
	switch t := x.(type) {
	case string:
		s := headerLineRe.ReplaceAllString(t, "${1}"+logging.Redacted)
		s = secretParamRe.ReplaceAllString(s, "${1}"+logging.Redacted)
		return logging.RedactString(s)
	case []any:
		for i := range t {
			t[i] = redactHTTPIn(t[i])
		}
	case map[string]any:
		// {"name": "Cookie", "value": "..."} header objects.
		for _, nk := range []string{"name", "Name", "key", "Key", "header", "Header"} {
			if n, ok := t[nk].(string); ok && isSensitiveHeader(n) {
				for _, vk := range []string{"value", "Value", "values", "Values"} {
					if v, ok := t[vk]; ok && v != nil && v != "" {
						t[vk] = logging.Redacted
					}
				}
			}
		}
		for k, v := range t {
			if isSensitiveHeader(k) || strings.EqualFold(k, "password") || strings.EqualFold(k, "secret") {
				if v != nil && v != "" {
					t[k] = logging.Redacted
				}
				continue
			}
			t[k] = redactHTTPIn(v)
		}
	}
	return x
}

// csvTable reads a CSV export with a header row. Rows are maps from the
// normalised column name (lower case, spaces as underscores) to the
// trimmed cell; orig keeps the original column names for the record.
type csvRow struct {
	N    int               // row number in the file (header is 1)
	V    map[string]string // normalised column name -> cell
	Orig map[string]string // original column name -> cell
}

func csvTable(raw []byte) ([]string, []csvRow, error) {
	raw = bytes.TrimPrefix(raw, utf8BOM)
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	cr := csvReader(bytes.NewReader(raw))
	cr.Comma = csvComma(line)
	header, err := cr.Read()
	if err != nil {
		return nil, nil, err
	}
	cols := lowerAll(header)
	var rows []csvRow
	for n := 2; ; n++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return cols, rows, fmt.Errorf("row %d: %w", n, err)
		}
		if len(rows) >= MaxFindingsPerReport {
			return cols, rows, errors.New("report truncated: too many findings")
		}
		r := csvRow{N: n, V: map[string]string{}, Orig: map[string]string{}}
		blank := true
		for i, cell := range rec {
			if i >= len(cols) {
				break
			}
			cell = strings.TrimSpace(cell)
			blank = blank && cell == ""
			r.Orig[strings.TrimSpace(header[i])] = cell
			if _, dup := r.V[cols[i]]; !dup || r.V[cols[i]] == "" {
				r.V[cols[i]] = cell
			}
		}
		if !blank {
			rows = append(rows, r)
		}
	}
	return cols, rows, nil
}

// get returns the first non-empty cell of the named (normalised) columns.
func (r csvRow) get(cols ...string) string {
	for _, c := range cols {
		if v := strings.TrimSpace(r.V[c]); v != "" {
			return v
		}
	}
	return ""
}

// headerHas reports whether a CSV header (normalised) has every column.
func headerHas(h []string, cols ...string) bool {
	for _, c := range cols {
		found := false
		for _, x := range h {
			found = found || x == c
		}
		if !found {
			return false
		}
	}
	return true
}

// cvssOf parses a CVSS-like score ("7.5", "7.5 (High)"); nil when absent
// or out of range.
func cvssOf(s string) *float64 {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " (/"); i > 0 {
		s = s[:i]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return floatPtr(v)
}

// atoiLoose parses a positive integer ("" and garbage give 0).
func atoiLoose(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// hostLocation is the location of a network finding: "host:port/proto",
// "host:port" or "host".
func hostLocation(host, port, proto string) string {
	host, port, proto = strings.TrimSpace(host), strings.TrimSpace(port), strings.ToLower(strings.TrimSpace(proto))
	switch {
	case port == "" || port == "0":
		return host
	case proto == "":
		return host + ":" + port
	}
	return host + ":" + port + "/" + proto
}

// whereText describes an HTTP finding's location for the description.
func whereText(method, url, param string) string {
	w := strings.TrimSpace(strings.ToUpper(method) + " " + redactHTTP(url))
	if param = strings.TrimSpace(param); param != "" {
		w += fmt.Sprintf(" (parameter %q)", param)
	}
	return w
}
