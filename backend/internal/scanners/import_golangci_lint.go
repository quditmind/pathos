package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// golangci-lint JSON (v2 `--output.json.path`, v1 `--out-format json`):
// {"Issues": [...], "Report": {...}}; each issue has FromLinter, Text,
// Severity (often empty), SourceLines and Pos {Filename, Line, Column}.
// Issues of the gosec linter are sast findings (rule G<nnn> from the text,
// gosec's CWE, gosec's severity, medium when empty); all other linters
// are code-quality findings, rule "<linter>" or
// "<linter>:<code>" (staticcheck SA4006), with the severity configured in
// golangci-lint or low. Identity is the linter, the code line (or the
// line number), the text and the file.

type golangciIssue struct {
	FromLinter  string   `json:"FromLinter"`
	Text        string   `json:"Text"`
	Severity    string   `json:"Severity"`
	SourceLines []string `json:"SourceLines"`
	Pos         struct {
		Filename string `json:"Filename"`
		Line     int    `json:"Line"`
		Column   int    `json:"Column"`
	} `json:"Pos"`
}

// golangciRuleCode is the check code some linters put in front of the text
// (gosec G202, staticcheck SA4006).
var golangciRuleCode = regexp.MustCompile(`^([A-Z]{1,4}\d{3,4}):\s*`)

// golangciGosecCWE is gosec's rule to CWE mapping (gosec issue/issue.go).
var golangciGosecCWE = map[string]string{
	"G101": "798", "G102": "200", "G103": "242", "G104": "703", "G106": "322", "G107": "88", "G108": "200",
	"G109": "190", "G110": "409", "G111": "22", "G112": "400", "G114": "676", "G115": "190",
	"G201": "89", "G202": "89", "G203": "79", "G204": "78",
	"G301": "276", "G302": "276", "G303": "377", "G304": "22", "G305": "22", "G306": "276", "G307": "703",
	"G401": "328", "G402": "295", "G403": "310", "G404": "338", "G405": "327", "G406": "328",
	"G501": "327", "G502": "327", "G503": "327", "G504": "327", "G505": "327", "G506": "328", "G507": "328",
	"G601": "118", "G602": "118",
}

func init() {
	registerImportFormat(ImportFormat{ID: "golangci-lint", Label: "golangci-lint JSON", Tool: "golangci-lint", Media: "json", Order: 163,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("Issues", "Report") && !p.hasAny("Stats", "Golang errors", "GosecVersion")
		},
		parse: parseGolangciLint})
}

func parseGolangciLint(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "Issues")
	if err != nil {
		return nil, fmt.Errorf("golangci-lint: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r golangciIssue
		if err := json.Unmarshal(it, &r); err != nil || r.FromLinter == "" || r.Text == "" {
			return out, fmt.Errorf("golangci-lint: issue %d: expected an object with FromLinter and Text", i+1)
		}
		f := Finding{Category: "code-quality", RuleID: r.FromLinter, Title: r.Text, Description: r.Text, Severity: firstNonEmpty(normSeverity(r.Severity), "low"),
			FilePath: NormalizePath(r.Pos.Filename), StartLine: intPtr(r.Pos.Line)}
		m := golangciRuleCode.FindStringSubmatch(r.Text)
		if m != nil {
			f.RuleID, f.Title = r.FromLinter+":"+m[1], strings.TrimSpace(r.Text[len(m[0]):])
		}
		if r.FromLinter == "gosec" || r.FromLinter == "gas" {
			f.Category, f.Severity = "sast", firstNonEmpty(normSeverity(r.Severity), "medium")
			if m != nil {
				f.RuleID = m[1]
				if c := golangciGosecCWE[m[1]]; c != "" {
					f.CWE = []string{"CWE-" + c}
				}
			}
		}
		if n := len(r.SourceLines); n > 1 {
			f.EndLine = intPtr(r.Pos.Line + n - 1)
		}
		code := codeIdentity(strings.Join(r.SourceLines, "\n"))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(firstNonEmpty(code, fmt.Sprint(r.Pos.Line)) + "|" + r.Text), Raw: it})
	}
	return out, nil
}
