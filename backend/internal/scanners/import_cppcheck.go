package scanners

import (
	"fmt"
	"strings"
)

// Cppcheck XML version 2 (`cppcheck --xml --xml-version=2`, written to
// stderr): results / errors / error with id, severity (error, warning,
// style, performance, portability, information), msg, verbose, cwe and
// location elements (the first is the primary location). error and
// warning are bugs with a security impact in C and C++ (sast: error high,
// warning medium); style, performance and portability are code quality
// (other, low); information is info. Cppcheck's own diagnostics (missing
// includes, the checkers report, configuration limits) are not findings.

type cppcheckError struct {
	ID        string `xml:"id,attr" json:"id"`
	Severity  string `xml:"severity,attr" json:"severity"`
	Msg       string `xml:"msg,attr" json:"msg"`
	Verbose   string `xml:"verbose,attr" json:"verbose,omitempty"`
	CWE       string `xml:"cwe,attr" json:"cwe,omitempty"`
	Inconclus string `xml:"inconclusive,attr" json:"inconclusive,omitempty"`
	Hash      string `xml:"hash,attr" json:"hash,omitempty"`
	Locations []struct {
		File   string `xml:"file,attr" json:"file"`
		Line   int    `xml:"line,attr" json:"line"`
		Column int    `xml:"column,attr" json:"column,omitempty"`
		Info   string `xml:"info,attr" json:"info,omitempty"`
	} `xml:"location" json:"locations,omitempty"`
	Symbols []string `xml:"symbol" json:"symbols,omitempty"`
}

// cppcheckDiagnostics are messages about the analysis itself.
var cppcheckDiagnostics = map[string]bool{"missingInclude": true, "missingIncludeSystem": true, "checkersReport": true,
	"toomanyconfigs": true, "unmatchedSuppression": true, "noValidConfiguration": true, "normalCheckLevelMaxBranches": true}

var cppcheckSeverity = map[string]string{"error": "high", "warning": "medium", "style": "low", "performance": "low",
	"portability": "low", "information": "info"}

func init() {
	registerImportFormat(ImportFormat{ID: "cppcheck", Label: "Cppcheck XML (version 2)", Tool: "Cppcheck", Media: "xml", Order: 110,
		match: func(p *importProbe) bool {
			return p.kind == "xml" && p.root == "results" && p.rootAttrs["version"] == "2" && p.rootAttrs["#child"] == "cppcheck"
		},
		parse: parseCppcheckXML})
}

func parseCppcheckXML(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := eachXMLElement(raw, "errors", "error", func(e *cppcheckError) error {
		if e.ID == "" {
			return fmt.Errorf("cppcheck: error element %d without id", len(out)+1)
		}
		if cppcheckDiagnostics[e.ID] {
			return nil
		}
		sev, ok := cppcheckSeverity[e.Severity]
		if !ok {
			sev = "info"
		}
		f := Finding{Category: "other", RuleID: e.ID, Severity: sev, Title: firstNonEmpty(e.Msg, e.ID),
			Description: joinText(e.Verbose, "Cppcheck check "+e.ID+" ("+e.Severity+")."), CWE: []string{e.CWE}}
		if e.Severity == "error" || e.Severity == "warning" {
			f.Category = "sast"
		}
		if strings.EqualFold(e.Inconclus, "true") {
			f.Confidence = "low"
			f.Description += " Cppcheck marks this result inconclusive."
		}
		if len(e.Locations) > 0 {
			f.FilePath, f.StartLine = NormalizePath(e.Locations[0].File), intPtr(e.Locations[0].Line)
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("cppcheck|" + e.Msg + "|" + strings.Join(e.Symbols, ",")), Raw: rawJSON(e)})
		return nil
	})
	return out, err
}
