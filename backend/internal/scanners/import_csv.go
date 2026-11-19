package scanners

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// Generic CSV: one finding per row, columns named by the header row
// (case-insensitive; aliases below). Documented in
// docs/api-reference/result-imports.md#generic-csv.

// csvColumns maps accepted header names to the field they fill.
var csvColumns = map[string]string{
	"title": "title", "name": "title", "summary": "title",
	"severity": "severity", "risk": "severity",
	"description": "description", "details": "description",
	"rule_id": "rule_id", "rule": "rule_id", "check_id": "rule_id", "id": "rule_id",
	"cwe": "cwe",
	"cve": "cve", "vulnerability_id": "cve",
	"cvss": "cvss", "cvss_score": "cvss",
	"cvss_vector": "cvss_vector",
	"file_path":   "file_path", "file": "file_path", "path": "file_path", "location": "file_path",
	"start_line": "start_line", "line": "start_line",
	"end_line": "end_line",
	"url":      "url", "endpoint": "url",
	"package_name": "package_name", "package": "package_name", "component": "package_name",
	"package_version": "package_version", "version": "package_version", "installed_version": "package_version",
	"fixed_version": "fixed_version", "fix_version": "fixed_version",
	"confidence":  "confidence",
	"fingerprint": "fingerprint", "unique_id": "fingerprint",
	"category": "category",
}

func csvReader(r io.Reader) *csv.Reader {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	cr.TrimLeadingSpace = true
	cr.ReuseRecord = false
	return cr
}

// csvComma guesses the delimiter of a header line (comma, semicolon, tab).
func csvComma(line []byte) rune {
	best, n := ',', bytes.Count(line, []byte(","))
	for _, c := range []rune{';', '\t'} {
		if k := bytes.Count(line, []byte(string(c))); k > n {
			best, n = c, k
		}
	}
	return best
}

func csvHeader(line []byte) ([]string, error) {
	cr := csvReader(bytes.NewReader(line))
	cr.Comma = csvComma(line)
	rec, err := cr.Read()
	if err != nil {
		return nil, err
	}
	for i := range rec {
		rec[i] = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(rec[i], " ", "_")))
	}
	return rec, nil
}

func csvField(h []string, field string) bool {
	for _, c := range h {
		if csvColumns[c] == field {
			return true
		}
	}
	return false
}

func init() {
	registerImportFormat(ImportFormat{ID: "csv", Label: "Generic CSV", Media: "csv", Order: 99,
		match: func(p *importProbe) bool {
			return p.kind == "csv" && csvField(p.header, "title") && csvField(p.header, "severity")
		},
		parse: parseCSVImport})
}

func parseCSVImport(raw []byte) ([]importRecord, error) {
	raw = bytes.TrimPrefix(raw, utf8BOM)
	line, _, _ := bytes.Cut(raw, []byte("\n"))
	cr := csvReader(bytes.NewReader(raw))
	cr.Comma = csvComma(line)
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("csv: %w", err)
	}
	cols := make([]string, len(header))
	for i, h := range header {
		cols[i] = csvColumns[strings.ToLower(strings.TrimSpace(strings.ReplaceAll(h, " ", "_")))]
	}
	if !csvField(lowerAll(header), "title") || !csvField(lowerAll(header), "severity") {
		return nil, errors.New("csv: the header row needs a title and a severity column")
	}
	var out []importRecord
	for row := 2; ; row++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("csv: row %d: %w", row, err)
		}
		if len(out) >= MaxFindingsPerReport {
			return out, errors.New("report truncated: too many findings")
		}
		v := map[string]string{}
		orig := map[string]string{}
		blank := true
		for i, cell := range rec {
			if i >= len(cols) {
				break
			}
			cell = strings.TrimSpace(cell)
			blank = blank && cell == ""
			orig[header[i]] = cell
			if cols[i] != "" && v[cols[i]] == "" {
				v[cols[i]] = cell
			}
		}
		if blank {
			continue
		}
		f := Finding{RuleID: v["rule_id"], Title: v["title"], Description: v["description"], CVE: v["cve"],
			CVSSVector: v["cvss_vector"], PackageName: v["package_name"], PackageVersion: v["package_version"],
			FixedVersion: v["fixed_version"], FilePath: locationOf(v["file_path"], v["url"]), Confidence: strings.ToLower(v["confidence"])}
		if f.Title == "" && f.RuleID == "" {
			return out, fmt.Errorf("csv: row %d: title is empty", row)
		}
		if s, err := strconv.ParseFloat(v["cvss"], 64); err == nil {
			f.CVSS = floatPtr(s)
		}
		f.Severity = normSeverity(v["severity"])
		if f.Severity == "" && f.CVSS == nil {
			return out, fmt.Errorf("csv: row %d: severity %q is not critical, high, medium, low or info", row, v["severity"])
		}
		if f.Severity == "" {
			f.Severity = FromScore(*f.CVSS)
		}
		if v["cwe"] != "" {
			f.CWE = strings.FieldsFunc(v["cwe"], func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '|' })
		}
		if n, err := strconv.Atoi(v["start_line"]); err == nil {
			f.StartLine = intPtr(n)
		}
		if n, err := strconv.Atoi(v["end_line"]); err == nil {
			f.EndLine = intPtr(n)
		}
		// Any import category but "other" (an empty column means the
		// import category).
		if c := strings.ToLower(strings.TrimSpace(v["category"])); c != "other" && slices.Contains(ImportCategories, c) {
			f.Category = c
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(firstNonEmpty(v["fingerprint"], v["description"]+"|"+v["url"])), Raw: rawJSON(orig)})
	}
	return out, nil
}

func lowerAll(v []string) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, " ", "_")))
	}
	return out
}
