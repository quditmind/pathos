package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Codacy Analysis CLI JSON (`codacy-analysis-cli analyze --format json`):
// an array of results, each wrapped by kind: {"Issue": {patternId.value,
// filename, message.text, level (Error/Warning/Info, newer High...),
// category, location.LineLocation.line}} or {"FileError": {...}} (a file
// the tool could not analyse; not a finding). Issues of category Security,
// or of the security tools Codacy runs (Bandit, Brakeman, gosec, ...;
// their category is often null), are sast findings, others code-quality (code
// quality); Bandit patterns get Bandit's CWE. Codacy CLI v2 writes SARIF:
// import that as sarif.

type codacyIssue struct {
	PatternID struct {
		Value string `json:"value"`
	} `json:"patternId"`
	Filename string `json:"filename"`
	Message  struct {
		Text string `json:"text"`
	} `json:"message"`
	Level    string  `json:"level"`
	Category *string `json:"category"`
	Location struct {
		LineLocation *struct {
			Line int `json:"line"`
		} `json:"LineLocation"`
		FullLocation *struct {
			Line   int `json:"line"`
			Column int `json:"column"`
		} `json:"FullLocation"`
	} `json:"location"`
}

// codacySecurityTools prefix the pattern ids of the security-only
// analysers Codacy runs.
var codacySecurityTools = []string{"bandit", "brakeman", "gosec", "findsecbugs"}

func init() {
	registerImportFormat(ImportFormat{ID: "codacy", Label: "Codacy Analysis CLI JSON", Tool: "Codacy", Media: "json", Order: 164,
		match: func(p *importProbe) bool {
			return p.kind == "array" && len(p.keys) == 1 && p.hasAny("Issue", "FileError")
		},
		parse: parseCodacy})
}

func parseCodacy(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("codacy: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var w map[string]json.RawMessage
		if err := json.Unmarshal(it, &w); err != nil {
			return out, fmt.Errorf("codacy: result %d: expected an object", i+1)
		}
		if w["Issue"] == nil {
			if w["FileError"] != nil {
				continue
			}
			return out, fmt.Errorf("codacy: result %d: expected Issue or FileError", i+1)
		}
		var r codacyIssue
		if err := json.Unmarshal(w["Issue"], &r); err != nil || r.PatternID.Value == "" {
			return out, fmt.Errorf("codacy: issue %d: expected an object with patternId", i+1)
		}
		line := 0
		if l := r.Location.LineLocation; l != nil {
			line = l.Line
		} else if l := r.Location.FullLocation; l != nil {
			line = l.Line
		}
		f := Finding{Category: "code-quality", RuleID: r.PatternID.Value, Title: firstNonEmpty(r.Message.Text, r.PatternID.Value),
			Description: r.Message.Text, Severity: firstNonEmpty(normSeverity(r.Level), "low"), FilePath: NormalizePath(r.Filename), StartLine: intPtr(line)}
		pid := strings.ToLower(r.PatternID.Value)
		if r.Category != nil && strings.EqualFold(*r.Category, "security") {
			f.Category = "sast"
		}
		for _, t := range codacySecurityTools {
			if strings.HasPrefix(pid, t) {
				f.Category = "sast"
			}
		}
		if r.Category != nil {
			f.Description = joinText(f.Description, "Codacy category: "+*r.Category)
		}
		// Bandit_B602 is Ruff's S602: Bandit's CWE.
		if b, ok := strings.CutPrefix(pid, "bandit_b"); ok {
			if m, ok := ruffBandit["S"+b]; ok {
				f.CWE = []string{m[0]}
			}
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%s|%d", r.Message.Text, line)), Raw: it})
	}
	return out, nil
}
