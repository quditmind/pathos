package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Tool manifests (worker.PluginDef) name the parser of their tool's output:
//
//	sarif            SARIF 2.1 (the default)
//	import:<format>  one of the result import formats (ImportFormats), e.g.
//	                 import:bandit for `bandit -f json`
//	jsonmap          a declarative mapping of a JSON or JSON Lines report
//	                 (JSONMap)
//
// The worker uploads the tool's own output unchanged together with the
// parser; the server parses it and stores both, so the original report is
// kept as evidence and findings can be located in it later.

// ToolParser is the parser of a tool's output.
type ToolParser struct {
	// Kind is sarif, import or jsonmap.
	Kind string `json:"kind"`
	// Format is the import format (Kind import).
	Format string `json:"format,omitempty"`
	// Map is the mapping (Kind jsonmap).
	Map *JSONMap `json:"jsonmap,omitempty"`
}

// JSONMap maps the records of a JSON report to findings. Field values are
// paths into a record: dot-separated object keys and array indexes
// ("location.path", "identifiers.0.value"), several alternatives separated
// by "|" (the first non-empty value wins), or a template with paths in
// braces ("SC{code}"). A value that is an array of scalars (cwe, cve) is
// read as a list.
type JSONMap struct {
	// Records is the path of the array of findings in the report ("" when
	// the report itself is the array). With Lines, it is the path of the
	// array in each line ("" when each line is one finding).
	Records string `json:"records,omitempty" yaml:"records"`
	// Lines reads the report as JSON Lines (one JSON document per line).
	Lines       bool              `json:"lines,omitempty" yaml:"lines"`
	RuleID      string            `json:"rule_id" yaml:"rule_id"`
	Title       string            `json:"title,omitempty" yaml:"title"`
	Message     string            `json:"message,omitempty" yaml:"message"`
	Severity    string            `json:"severity,omitempty" yaml:"severity"`
	SeverityMap map[string]string `json:"severity_map,omitempty" yaml:"severity_map"`
	// DefaultSeverity applies when the record has no (mapped) severity.
	DefaultSeverity string `json:"default_severity,omitempty" yaml:"default_severity"`
	Confidence      string `json:"confidence,omitempty" yaml:"confidence"`
	File            string `json:"file,omitempty" yaml:"file"`
	Line            string `json:"line,omitempty" yaml:"line"`
	EndLine         string `json:"end_line,omitempty" yaml:"end_line"`
	URL             string `json:"url,omitempty" yaml:"url"`
	Package         string `json:"package,omitempty" yaml:"package"`
	Version         string `json:"version,omitempty" yaml:"version"`
	FixedVersion    string `json:"fixed_version,omitempty" yaml:"fixed_version"`
	CVE             string `json:"cve,omitempty" yaml:"cve"`
	CWE             string `json:"cwe,omitempty" yaml:"cwe"`
	CVSS            string `json:"cvss,omitempty" yaml:"cvss"`
	// Category of each finding (a finding category; "" = the tool's).
	Category string `json:"category,omitempty" yaml:"category"`
	// Identity distinguishes findings with the same rule and location
	// (default: the message).
	Identity string `json:"identity,omitempty" yaml:"identity"`
}

var (
	mapPathRe     = regexp.MustCompile(`^[A-Za-z0-9_$@-]+(\.[A-Za-z0-9_$@-]+)*$`)
	mapTemplateRe = regexp.MustCompile(`\{([^{}]*)\}`)
	parserFmtRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)
)

// ParseToolParserSpec parses a manifest's parser value (sarif,
// import:<format> or jsonmap) with its mapping.
func ParseToolParserSpec(spec string, m *JSONMap) (ToolParser, error) {
	switch {
	case spec == "" || spec == "sarif":
		if m != nil {
			return ToolParser{}, errors.New("jsonmap is only used with parser: jsonmap")
		}
		return ToolParser{Kind: "sarif"}, nil
	case strings.HasPrefix(spec, "import:"):
		if m != nil {
			return ToolParser{}, errors.New("jsonmap is only used with parser: jsonmap")
		}
		p := ToolParser{Kind: "import", Format: strings.TrimPrefix(spec, "import:")}
		return p, p.Validate()
	case spec == "jsonmap":
		p := ToolParser{Kind: "jsonmap", Map: m}
		return p, p.Validate()
	}
	return ToolParser{}, errors.New("parser must be sarif, import:<format> or jsonmap")
}

// String is the manifest form of the parser.
func (p ToolParser) String() string {
	switch p.Kind {
	case "import":
		return "import:" + p.Format
	case "":
		return "sarif"
	}
	return p.Kind
}

// Validate checks a parser (also when it comes from a worker upload).
func (p ToolParser) Validate() error {
	switch p.Kind {
	case "", "sarif":
		if p.Format != "" || p.Map != nil {
			return errors.New("a sarif parser takes no format or mapping")
		}
		return nil
	case "import":
		if p.Map != nil || !parserFmtRe.MatchString(p.Format) {
			return errors.New("import parser: invalid format")
		}
		if _, ok := LookupImportFormat(p.Format); !ok {
			return fmt.Errorf("import parser: unknown import format %q", p.Format)
		}
		return nil
	case "jsonmap":
		if p.Format != "" {
			return errors.New("a jsonmap parser takes no format")
		}
		if p.Map == nil {
			return errors.New("parser jsonmap needs a jsonmap mapping")
		}
		return p.Map.validate()
	}
	return errors.New("parser kind must be sarif, import or jsonmap")
}

func (m *JSONMap) validate() error {
	if m.RuleID == "" {
		return errors.New("jsonmap: rule_id is required")
	}
	if m.Records != "" && !mapPathRe.MatchString(m.Records) || len(m.Records) > 200 {
		return errors.New("jsonmap: records must be a dot-separated path")
	}
	for name, v := range map[string]string{"rule_id": m.RuleID, "title": m.Title, "message": m.Message, "severity": m.Severity,
		"confidence": m.Confidence, "file": m.File, "line": m.Line, "end_line": m.EndLine, "url": m.URL, "package": m.Package,
		"version": m.Version, "fixed_version": m.FixedVersion, "cve": m.CVE, "cwe": m.CWE, "cvss": m.CVSS, "identity": m.Identity} {
		if err := validMapExpr(v); err != nil {
			return fmt.Errorf("jsonmap: %s: %w", name, err)
		}
	}
	if len(m.SeverityMap) > 50 {
		return errors.New("jsonmap: severity_map has at most 50 entries")
	}
	for k, v := range m.SeverityMap {
		if len(k) > 100 || !isSeverity(v) {
			return fmt.Errorf("jsonmap: severity_map %q must map to critical, high, medium, low or info", k)
		}
	}
	if m.DefaultSeverity != "" && !isSeverity(m.DefaultSeverity) {
		return errors.New("jsonmap: default_severity must be critical, high, medium, low or info")
	}
	if m.Category != "" && (m.Category == "eol" || !IsFindingCategory(m.Category)) {
		return errors.New("jsonmap: category must be a finding category")
	}
	return nil
}

func isSeverity(s string) bool {
	for _, v := range Severities {
		if v == s {
			return true
		}
	}
	return false
}

// validMapExpr checks a field expression: paths, alternatives or a template.
func validMapExpr(e string) error {
	if e == "" {
		return nil
	}
	if len(e) > 300 {
		return errors.New("at most 300 characters")
	}
	if strings.ContainsAny(e, "{}") {
		ms := mapTemplateRe.FindAllStringSubmatch(e, -1)
		if len(ms) == 0 || strings.Count(e, "{") != len(ms) || strings.Count(e, "}") != len(ms) {
			return errors.New("unbalanced template braces")
		}
		for _, m := range ms {
			if !mapPathRe.MatchString(m[1]) {
				return fmt.Errorf("invalid path %q", m[1])
			}
		}
		return nil
	}
	for _, alt := range strings.Split(e, "|") {
		if !mapPathRe.MatchString(alt) {
			return fmt.Errorf("invalid path %q", alt)
		}
	}
	return nil
}

// --- evaluation ---------------------------------------------------------------

// lookupPath returns the value at a dot path.
func lookupPath(v any, path string) any {
	for _, seg := range strings.Split(path, ".") {
		switch t := v.(type) {
		case map[string]any:
			v = t[seg]
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(t) {
				return nil
			}
			v = t[i]
		default:
			return nil
		}
	}
	return v
}

// scalar renders a JSON scalar as text ("" for objects, arrays and null).
func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case json.Number:
		return t.String()
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
}

// evalText evaluates an expression to text.
func evalText(rec any, e string) string {
	if e == "" {
		return ""
	}
	if strings.Contains(e, "{") {
		empty := true
		out := mapTemplateRe.ReplaceAllStringFunc(e, func(m string) string {
			s := scalar(lookupPath(rec, m[1:len(m)-1]))
			if s != "" {
				empty = false
			}
			return s
		})
		if empty {
			return ""
		}
		return out
	}
	for _, alt := range strings.Split(e, "|") {
		if s := scalar(lookupPath(rec, alt)); s != "" {
			return s
		}
	}
	return ""
}

// evalList evaluates an expression to a list (arrays of scalars are
// expanded).
func evalList(rec any, e string) []string {
	if e == "" {
		return nil
	}
	if !strings.Contains(e, "{") {
		for _, alt := range strings.Split(e, "|") {
			if arr, ok := lookupPath(rec, alt).([]any); ok {
				var out []string
				for _, x := range arr {
					if s := scalar(x); s != "" {
						out = append(out, s)
					}
				}
				if len(out) > 0 {
					return out
				}
			}
		}
	}
	if s := evalText(rec, e); s != "" {
		return []string{s}
	}
	return nil
}

func decodeNumbers(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(v)
}

// mapRecords returns the records of a report as raw JSON.
func (m *JSONMap) mapRecords(raw []byte) ([]json.RawMessage, error) {
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if len(raw) == 0 {
		return nil, nil
	}
	if m.Lines {
		var out []json.RawMessage
		err := jsonLines(raw, func(n int, line []byte) error {
			if !json.Valid(line) {
				return fmt.Errorf("line %d is not JSON", n)
			}
			if m.Records == "" {
				out = append(out, json.RawMessage(bytes.Clone(line)))
				return nil
			}
			recs, err := m.recordsIn(line)
			out = append(out, recs...)
			if err != nil {
				return fmt.Errorf("line %d: %w", n, err)
			}
			return nil
		})
		return out, err
	}
	if m.Records == "" {
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err != nil {
			return nil, fmt.Errorf("expected a JSON array: %w", err)
		}
		return arr, nil
	}
	return m.recordsIn(raw)
}

// recordsIn returns the elements of the Records array of one document.
func (m *JSONMap) recordsIn(raw []byte) ([]json.RawMessage, error) {
	var doc any
	if err := decodeNumbers(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	v := lookupPath(doc, m.Records)
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%s is not an array", m.Records)
	}
	out := make([]json.RawMessage, 0, len(arr))
	for _, x := range arr {
		b, err := json.Marshal(x)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// parseJSONMap turns a report into import records.
func (m *JSONMap) parse(raw []byte) ([]importRecord, error) {
	items, err := m.mapRecords(raw)
	if err != nil {
		return nil, fmt.Errorf("jsonmap: %w", err)
	}
	out := make([]importRecord, 0, len(items))
	// Findings with the same rule, file and identity (e.g. one ShellCheck
	// warning on several lines of a file) are told apart by their order in
	// the file, so none is merged into another; line numbers stay out of
	// the identity.
	seen := map[string]int{}
	for i, it := range items {
		var rec any
		if err := decodeNumbers(it, &rec); err != nil {
			return out, fmt.Errorf("jsonmap: record %d: %w", i+1, err)
		}
		if _, ok := rec.(map[string]any); !ok {
			return out, fmt.Errorf("jsonmap: record %d is not an object", i+1)
		}
		f := Finding{Category: m.Category, RuleID: evalText(rec, m.RuleID), Title: evalText(rec, m.Title),
			Description: evalText(rec, m.Message), Confidence: strings.ToLower(evalText(rec, m.Confidence)),
			PackageName: evalText(rec, m.Package), PackageVersion: evalText(rec, m.Version), FixedVersion: evalText(rec, m.FixedVersion),
			CWE: evalList(rec, m.CWE)}
		if f.RuleID == "" {
			return out, fmt.Errorf("jsonmap: record %d has no rule id", i+1)
		}
		if f.Title == "" {
			f.Title = firstLine(f.Description)
		}
		sev := evalText(rec, m.Severity)
		if mapped, ok := m.SeverityMap[sev]; ok {
			f.Severity = mapped
		} else if mapped, ok := m.SeverityMap[strings.ToLower(sev)]; ok {
			f.Severity = mapped
		} else {
			f.Severity = normSeverity(sev)
		}
		if f.Severity == "" {
			f.Severity = m.DefaultSeverity
		}
		if cves := evalList(rec, m.CVE); len(cves) > 0 {
			f.CVE = firstMatch(cveRe, cves...)
		}
		if s := evalText(rec, m.CVSS); s != "" {
			if v, err := strconv.ParseFloat(s, 64); err == nil {
				f.CVSS = floatPtr(v)
			}
		}
		if n, err := strconv.Atoi(evalText(rec, m.Line)); err == nil {
			f.StartLine = intPtr(n)
		}
		if n, err := strconv.Atoi(evalText(rec, m.EndLine)); err == nil && f.StartLine != nil {
			f.EndLine = intPtr(n)
		}
		f.FilePath = locationOf(evalText(rec, m.File), evalText(rec, m.URL))
		identity := evalText(rec, m.Identity)
		if m.Identity == "" {
			identity = f.Description
		}
		dup := f.RuleID + "\x00" + f.FilePath + "\x00" + f.PackageName + "\x00" + f.PackageVersion + "\x00" + identity
		seen[dup]++
		if n := seen[dup]; n > 1 {
			identity += "#" + strconv.Itoa(n)
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(identity), Raw: it})
	}
	return out, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}

// --- parsing and locating tool output ---------------------------------------

// ParseToolOutput parses a tool's output with its manifest parser as
// findings of scanner key.
func ParseToolOutput(key string, p ToolParser, raw []byte) ([]Finding, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	switch p.Kind {
	case "import":
		return ParseImport(key, p.Format, raw)
	case "jsonmap":
		recs, err := p.Map.parse(raw)
		if len(recs) > MaxFindingsPerReport {
			recs, err = recs[:MaxFindingsPerReport], errors.New("report truncated: too many findings")
		}
		return keyRecords(key, recs), err
	}
	return ParseSARIF(key, raw)
}

// LocateToolOutput finds a finding in a tool's output parsed with p.
func LocateToolOutput(key string, p ToolParser, raw []byte, fingerprint string) (*Located, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	switch p.Kind {
	case "import":
		return LocateImport(key, p.Format, raw, fingerprint)
	case "jsonmap":
		recs, err := p.Map.parse(raw)
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
	return LocateSARIF(key, raw, fingerprint)
}

// LocateStored finds a finding in a stored raw report: with the parser
// recorded with the artifact (tool manifests), else by content type and key.
func LocateStored(key, contentType string, parser []byte, raw []byte, fingerprint string) (*Located, error) {
	if len(parser) > 0 && string(parser) != "null" {
		var p ToolParser
		if err := json.Unmarshal(parser, &p); err != nil {
			return nil, fmt.Errorf("stored parser: %w", err)
		}
		return LocateToolOutput(key, p, raw, fingerprint)
	}
	return LocateArtifact(key, contentType, raw, fingerprint)
}

// ToolContentType is the content type a tool's raw output is stored with.
func ToolContentType(p ToolParser) string {
	switch p.Kind {
	case "import":
		return ImportContentType(p.Format)
	case "jsonmap":
		if p.Map != nil && p.Map.Lines {
			return "application/x-ndjson"
		}
		return "application/json"
	}
	return "application/sarif+json"
}
