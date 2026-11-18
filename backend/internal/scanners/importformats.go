package scanners

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"slices"
	"strings"
	"unicode/utf8"

	"pathos/internal/platform/logging"
)

// Native import formats: reports of third-party tools in their own JSON,
// XML, JSON Lines or CSV output (docs/api-reference/result-imports.md).
// Every format parses into importRecords (a finding without key and
// fingerprint, plus the tool's own record), which keyRecords turns into
// findings of the import's scanner key. The format is detected from the
// content; callers may name it explicitly, and the stored artifact's content
// type carries it so evidence can be located later (LocateImport).

// ImportFormat describes one importable result format.
type ImportFormat struct {
	// ID is the value of the import's "format" field.
	ID string `json:"id"`
	// Label is the display name.
	Label string `json:"label"`
	// Tool is the tool name imports default to ("" for generic formats,
	// whose imports must name the tool).
	Tool string `json:"tool"`
	// Category is the default import category ("" means each finding keeps
	// its own: package vulnerabilities sca, misconfigurations iac, ...).
	Category string `json:"category"`
	// Media is json, jsonl, xml, csv or sarif.
	Media string `json:"media"`
	// Parser is the format that parses it (an alias like snyk-code names
	// sarif); empty for itself.
	Parser string `json:"-"`
	// Order sorts the format list.
	Order int `json:"-"`

	match    func(*importProbe) bool
	parse    func(raw []byte) ([]importRecord, error)
	sanitize func(raw []byte) []byte
}

// importRecord is one finding of a foreign report before it is keyed.
type importRecord struct {
	// F carries everything but ScannerKey and Fingerprint. F.Category is the
	// natural category of the record, used when the import category is
	// "other"; empty means the import category.
	F Finding
	// SnippetKey distinguishes findings with the same rule and location
	// (ignored for sca, whose identity is package@version|vulnerability).
	SnippetKey string
	// Raw is the tool's own record, kept as the finding's original output.
	Raw json.RawMessage
}

var importFormats = map[string]*ImportFormat{}

// importTools names the tool of tool-specific formats.
var importTools = map[string]string{
	"grype": "Grype", "snyk-code": "Snyk Code", "snyk": "Snyk Open Source", "semgrep": "Semgrep", "sonarqube": "SonarQube",
	"zap": "OWASP ZAP", "burp": "Burp Suite", "trivy": "Trivy", "gitleaks": "Gitleaks", "trufflehog": "TruffleHog",
	"checkov": "Checkov", "bandit": "Bandit", "gosec": "Gosec", "eslint": "ESLint", "npm-audit": "npm audit",
	"pip-audit": "pip-audit", "osv-scanner": "OSV-Scanner", "nessus": "Nessus", "openvas": "OpenVAS", "nuclei": "Nuclei",
	"dependency-check": "Dependency-Check", "checkmarx": "Checkmarx",
}

// registerImportFormat adds a format (called from init functions).
func registerImportFormat(f ImportFormat) {
	if _, dup := importFormats[f.ID]; dup {
		panic("duplicate import format " + f.ID)
	}
	if f.Tool == "" {
		f.Tool = importTools[f.ID]
	}
	importFormats[f.ID] = &f
}

func init() {
	registerImportFormat(ImportFormat{ID: "sarif", Label: "SARIF 2.1", Media: "sarif", Order: 1})
	registerImportFormat(ImportFormat{ID: "grype", Label: "Grype JSON", Category: "sca", Media: "json", Order: 2})
	registerImportFormat(ImportFormat{ID: "pathos", Label: "PATHOS findings JSON", Media: "json", Order: 3})
	registerImportFormat(ImportFormat{ID: "snyk-code", Label: "Snyk Code (SARIF)", Category: "sast", Media: "sarif", Parser: "sarif", Order: 40})
}

// ImportFormats lists the importable result formats.
func ImportFormats() []ImportFormat {
	out := make([]ImportFormat, 0, len(importFormats))
	for _, f := range importFormats {
		out = append(out, *f)
	}
	slices.SortFunc(out, func(a, b ImportFormat) int {
		if a.Order != b.Order {
			return a.Order - b.Order
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out
}

// LookupImportFormat returns a registered format.
func LookupImportFormat(id string) (ImportFormat, bool) {
	f, ok := importFormats[strings.ToLower(strings.TrimSpace(id))]
	if !ok {
		return ImportFormat{}, false
	}
	return *f, true
}

// parserOf returns the format that parses id.
func parserOf(id string) string {
	if f, ok := importFormats[id]; ok && f.Parser != "" {
		return f.Parser
	}
	return id
}

// SameImportParser reports whether formats a and b parse the same way
// (snyk-code and sarif do).
func SameImportParser(a, b string) bool { return parserOf(a) == parserOf(b) }

// SanitizeImport removes secret values from a report before it is stored
// (Gitleaks and TruffleHog report the secrets they find in plain text).
// Finding identity never depends on the removed values.
func SanitizeImport(format string, raw []byte) []byte {
	if f, ok := importFormats[parserOf(format)]; ok && f.sanitize != nil {
		return f.sanitize(raw)
	}
	return raw
}

// ImportContentType is the content type a raw imported report is stored
// with; it records the format for LocateImport.
func ImportContentType(format string) string {
	ct := "application/json"
	if f, ok := importFormats[format]; ok {
		switch f.Media {
		case "sarif":
			ct = "application/sarif+json"
		case "xml":
			ct = "application/xml"
		case "jsonl":
			ct = "application/x-ndjson"
		case "csv":
			ct = "text/csv"
		}
	}
	return mime.FormatMediaType(ct, map[string]string{"pathos-format": format})
}

// FormatFromContentType returns the import format recorded in a stored
// artifact's content type ("" when none).
func FormatFromContentType(ct string) string {
	_, params, err := mime.ParseMediaType(ct)
	if err != nil {
		return ""
	}
	return params["pathos-format"]
}

// --- detection ---------------------------------------------------------------

// importProbe is what detection looks at: the top-level JSON keys (of the
// object, the first array element or the first JSON line), the XML root
// element, or the CSV header.
type importProbe struct {
	kind       string // object, array, jsonl, xml, csv
	keys       map[string]json.RawMessage
	emptyArray bool
	root       string
	rootAttrs  map[string]string
	header     []string
}

func (p *importProbe) has(keys ...string) bool {
	for _, k := range keys {
		if _, ok := p.keys[k]; !ok {
			return false
		}
	}
	return true
}

func (p *importProbe) hasAny(keys ...string) bool {
	for _, k := range keys {
		if _, ok := p.keys[k]; ok {
			return true
		}
	}
	return false
}

// firstOf returns the keys of the first element of array field name.
func (p *importProbe) firstOf(name string) map[string]json.RawMessage {
	var arr []json.RawMessage
	if json.Unmarshal(p.keys[name], &arr) != nil || len(arr) == 0 {
		return nil
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(arr[0], &m) != nil {
		return nil
	}
	return m
}

func hasKeys(m map[string]json.RawMessage, keys ...string) bool {
	if m == nil {
		return false
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func newImportProbe(raw []byte) *importProbe {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	p := &importProbe{}
	if len(b) == 0 {
		return p
	}
	switch b[0] {
	case '{':
		if json.Unmarshal(b, &p.keys) == nil {
			p.kind = "object"
			return p
		}
		line, _, _ := bytes.Cut(b, []byte("\n"))
		if json.Unmarshal(bytes.TrimSpace(line), &p.keys) == nil {
			p.kind = "jsonl"
		}
		return p
	case '[':
		var arr []json.RawMessage
		if json.Unmarshal(b, &arr) != nil {
			return p
		}
		p.kind = "array"
		if len(arr) == 0 {
			p.emptyArray = true
			return p
		}
		_ = json.Unmarshal(arr[0], &p.keys)
		return p
	case '<':
		d := newXMLDecoder(bytes.NewReader(b))
		for {
			tok, err := d.Token()
			if err != nil {
				return p
			}
			if se, ok := tok.(xml.StartElement); ok {
				p.kind, p.root, p.rootAttrs = "xml", se.Name.Local, map[string]string{}
				for _, a := range se.Attr {
					p.rootAttrs[a.Name.Local] = a.Value
				}
				// The first child element helps tell generic roots apart.
				for {
					tok, err := d.Token()
					if err != nil {
						return p
					}
					if c, ok := tok.(xml.StartElement); ok {
						p.rootAttrs["#child"] = c.Name.Local
						return p
					}
				}
			}
		}
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	if utf8.Valid(line) && bytes.ContainsAny(line, ",;\t") {
		if h, err := csvHeader(line); err == nil {
			p.kind, p.header = "csv", h
		}
	}
	return p
}

// DetectImportFormat returns the format of an imported report ("" when it
// is not recognised).
func DetectImportFormat(raw []byte) string { return importFormat(raw) }

// importFormat detects the format of an imported report.
func importFormat(raw []byte) string {
	p := newImportProbe(raw)
	if p.kind == "object" {
		// The original three formats.
		switch {
		case p.has("runs"):
			return "sarif"
		case p.has("matches"):
			return "grype"
		case p.has("findings"):
			return "pathos"
		}
	}
	for _, f := range ImportFormats() {
		if f.match != nil && f.match(p) {
			return f.ID
		}
	}
	return ""
}

// --- parsing ------------------------------------------------------------------

func parseImported(key string, raw []byte) ([]Finding, error) { return ParseImport(key, "", raw) }

// ParseImport parses an imported report of format (detected when empty)
// as findings of the import scanner key.
func ParseImport(key, format string, raw []byte) ([]Finding, error) {
	if format == "" {
		format = importFormat(raw)
	}
	switch parserOf(format) {
	case "sarif":
		return ParseSARIF(key, raw)
	case "grype":
		fs, err := ParseGrypeJSON(raw)
		for i := range fs {
			fs[i].ScannerKey = key
		}
		return fs, err
	case "pathos":
		return parseGeneric(key, raw)
	}
	recs, err := parseRecords(format, raw)
	return keyRecords(key, recs), err
}

func parseRecords(format string, raw []byte) ([]importRecord, error) {
	f, ok := importFormats[parserOf(format)]
	if !ok || f.parse == nil {
		if format == "" {
			return nil, errors.New("unrecognised report: name its format (see the supported formats) or use SARIF 2.1 or PATHOS findings JSON")
		}
		return nil, fmt.Errorf("unknown import format %q", format)
	}
	recs, err := f.parse(raw)
	if len(recs) > MaxFindingsPerReport {
		recs, err = recs[:MaxFindingsPerReport], errors.New("report truncated: too many findings")
	}
	return recs, err
}

// keyRecords turns records into findings of scanner key.
func keyRecords(key string, recs []importRecord) []Finding {
	sc, _ := Resolve(key)
	cat := sc.FindingCategory()
	out := make([]Finding, 0, len(recs))
	for _, r := range recs {
		f := r.F
		f.ScannerKey = key
		if cat != "other" || f.Category == "" {
			f.Category = cat
		}
		f.Severity = normSeverity(f.Severity)
		if f.Severity == "" {
			f.Severity = "info"
			if f.CVSS != nil {
				f.Severity = FromScore(*f.CVSS)
			}
		}
		if f.CVSS != nil && (*f.CVSS < 0 || *f.CVSS > 10) {
			f.CVSS = nil
		}
		f.RuleID = truncate(firstNonEmpty(f.RuleID, f.Title), 300)
		f.Title = truncate(logging.RedactString(firstNonEmpty(f.Title, f.RuleID)), 300)
		f.Description = truncate(logging.RedactString(strings.TrimSpace(f.Description)), 4000)
		f.CWE = normCWEs(f.CWE)
		f.CVE = firstNonEmpty(firstMatch(cveRe, f.CVE), firstMatch(cveRe, f.RuleID, f.Title))
		if f.CVSSVector != "" && (vectorVersion(f.CVSSVector) == "" || len(f.CVSSVector) > 300) {
			f.CVSSVector = ""
		}
		if f.CVSSVector != "" {
			f.CVSSVersion = vectorVersion(f.CVSSVector)
		} else {
			f.CVSSVersion = ""
		}
		f.PackageName, f.PackageVersion, f.FixedVersion = truncate(f.PackageName, 300), truncate(f.PackageVersion, 200), truncate(f.FixedVersion, 200)
		if f.StartLine != nil && *f.StartLine <= 0 {
			f.StartLine, f.EndLine = nil, nil
		}
		if f.StartLine != nil && (f.EndLine == nil || *f.EndLine < *f.StartLine) {
			el := *f.StartLine
			f.EndLine = &el
		}
		switch f.Confidence {
		case "high", "medium", "low":
		default:
			f.Confidence = confidenceOf(f.Category, nil)
		}
		snippetKey := r.SnippetKey
		if f.Category == "sca" {
			snippetKey = ""
		}
		f.Fingerprint = Fingerprint(f, snippetKey)
		out = append(out, f)
	}
	return out
}

// LocateImport finds a finding in an imported report of format (detected
// when empty).
func LocateImport(key, format string, raw []byte, fingerprint string) (*Located, error) {
	if format == "" {
		format = importFormat(raw)
	}
	switch parserOf(format) {
	case "sarif":
		return LocateSARIF(key, raw, fingerprint)
	case "pathos":
		return locateGeneric(key, raw, fingerprint)
	case "grype":
		return locateGrype(key, raw, fingerprint)
	}
	recs, err := parseRecords(format, raw)
	if err != nil && len(recs) == 0 {
		return nil, err
	}
	for i, f := range keyRecords(key, recs) {
		if f.Fingerprint == fingerprint {
			return &Located{Raw: redactJSON(recs[i].Raw)}, nil
		}
	}
	return nil, ErrNotLocated
}

// LocateArtifact finds a finding in a stored raw report, using the import
// format recorded in its content type.
func LocateArtifact(key, contentType string, raw []byte, fingerprint string) (*Located, error) {
	if IsImportKey(key) {
		return LocateImport(key, FormatFromContentType(contentType), raw, fingerprint)
	}
	return Locate(key, raw, fingerprint)
}

// --- helpers for parsers -------------------------------------------------------

// normSeverity maps the severity vocabularies of common tools to PATHOS
// severities ("" when unknown).
func normSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "blocker", "urgent", "4":
		return "critical"
	case "high", "error", "severe", "serious", "3":
		return "high"
	case "medium", "moderate", "warning", "warn", "major", "2":
		return "medium"
	case "low", "minor", "note", "1":
		return "low"
	case "info", "informational", "information", "negligible", "none", "log", "debug", "trivial", "unknown", "0":
		return "info"
	}
	return ""
}

// normCWEs returns the distinct "CWE-n" identifiers in v (at most 10).
func normCWEs(v []string) []string {
	out := []string{}
	for _, s := range v {
		s = strings.TrimSpace(s)
		ids := cweRe.FindAllStringSubmatch(s, -1)
		if len(ids) == 0 && s != "" && strings.Trim(s, "0123456789") == "" && s != "0" {
			ids = [][]string{{s, s}}
		}
		for _, m := range ids {
			id := "CWE-" + strings.TrimLeft(m[1], "0")
			if id != "CWE-" && !slices.Contains(out, id) {
				out = append(out, id)
			}
		}
	}
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

func intPtr(n int) *int {
	if n <= 0 {
		return nil
	}
	return &n
}

func floatPtr(v float64) *float64 {
	if v <= 0 || v > 10 {
		return nil
	}
	return &v
}

// rawJSON marshals v as the record kept for evidence.
func rawJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`null`)
	}
	return b
}

// jsonArray decodes a JSON array, or an object holding the array in field
// (when field is not empty).
func jsonArray(raw []byte, field string) ([]json.RawMessage, error) {
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	var arr []json.RawMessage
	if len(raw) > 0 && raw[0] == '[' {
		err := json.Unmarshal(raw, &arr)
		return arr, err
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	if field == "" || obj[field] == nil || string(obj[field]) == "null" {
		return nil, nil
	}
	err := json.Unmarshal(obj[field], &arr)
	return arr, err
}

// jsonLines calls fn for every non-empty line of a JSON Lines report.
func jsonLines(raw []byte, fn func(n int, line []byte) error) error {
	sc := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM)))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	n := 0
	for sc.Scan() {
		n++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		if err := fn(n, b); err != nil {
			return err
		}
	}
	return sc.Err()
}

// maxXMLBytes bounds an XML report (the upload limit applies first).
const maxXMLBytes = 256 << 20

// newXMLDecoder returns a decoder that is safe for untrusted input:
// encoding/xml never resolves external entities or DTDs, only the five
// predefined entities are known (Strict mode rejects others), nesting depth
// is bounded by the standard library, and only UTF-8, US-ASCII and
// ISO-8859-1/Windows-1252 encodings are accepted.
func newXMLDecoder(r io.Reader) *xml.Decoder {
	d := xml.NewDecoder(io.LimitReader(r, maxXMLBytes))
	d.Strict = true
	d.Entity = nil
	d.CharsetReader = func(charset string, input io.Reader) (io.Reader, error) {
		switch strings.ToLower(charset) {
		case "utf-8", "utf8", "us-ascii", "ascii":
			return input, nil
		case "iso-8859-1", "latin1", "latin-1", "windows-1252", "cp1252":
			return latin1Reader{r: bufio.NewReader(input)}, nil
		}
		return nil, fmt.Errorf("unsupported XML encoding %q", charset)
	}
	return d
}

// decodeXML decodes an XML report into v.
func decodeXML(raw []byte, v any) error {
	if err := newXMLDecoder(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM))).Decode(v); err != nil {
		return fmt.Errorf("invalid XML: %w", err)
	}
	return nil
}

// latin1Reader converts ISO-8859-1 to UTF-8.
type latin1Reader struct{ r *bufio.Reader }

func (l latin1Reader) Read(p []byte) (int, error) {
	n := 0
	for n+2 <= len(p) {
		c, err := l.r.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		n += utf8.EncodeRune(p[n:], rune(c))
	}
	if n == 0 && len(p) > 0 {
		return 0, io.ErrShortBuffer
	}
	return n, nil
}

// xmlText collapses the whitespace of an XML text node; HTML tags some
// tools embed (ZAP, Burp, Nessus) are kept as text.
func xmlText(s string) string { return strings.TrimSpace(s) }

// redactKeys replaces the values of the named keys in every object of a
// JSON document (secret material) and re-encodes it; the input is
// returned unchanged when it is not JSON.
func redactKeys(raw []byte, keys ...string) []byte {
	var x any
	if json.Unmarshal(raw, &x) != nil {
		return raw
	}
	b, err := json.Marshal(redactKeysIn(x, keys))
	if err != nil {
		return raw
	}
	return b
}

func redactKeysIn(x any, keys []string) any {
	switch t := x.(type) {
	case []any:
		for i := range t {
			t[i] = redactKeysIn(t[i], keys)
		}
	case map[string]any:
		for k, v := range t {
			if slices.ContainsFunc(keys, func(s string) bool { return strings.EqualFold(s, k) }) {
				if v != nil && v != "" {
					t[k] = "[REDACTED]"
				}
				continue
			}
			t[k] = redactKeysIn(v, keys)
		}
	}
	return x
}

// redactLines applies redactKeys to every line of a JSON Lines document.
func redactLines(raw []byte, keys ...string) []byte {
	var out bytes.Buffer
	_ = jsonLines(raw, func(_ int, line []byte) error {
		out.Write(redactKeys(line, keys...))
		out.WriteByte('\n')
		return nil
	})
	return out.Bytes()
}
