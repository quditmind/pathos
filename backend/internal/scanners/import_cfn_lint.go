package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// cfn-lint JSON (`cfn-lint -f json`): an array of matches with Filename,
// Level (Error, Warning, Informational), Location {Start, End, Path},
// Message and Rule {Id, ShortDescription, Description, Source}. Rule ids
// starting with E are errors (high), W warnings (medium), I informational.
// Most cfn-lint rules check template validity; its security-relevant rules
// are kept in the iac category like the others.

type cfnLintMatch struct {
	Filename string `json:"Filename"`
	Level    string `json:"Level"`
	Location struct {
		Start struct {
			LineNumber int `json:"LineNumber"`
		} `json:"Start"`
		End struct {
			LineNumber int `json:"LineNumber"`
		} `json:"End"`
		Path []any `json:"Path"`
	} `json:"Location"`
	Message string `json:"Message"`
	Rule    struct {
		ID               string `json:"Id"`
		ShortDescription string `json:"ShortDescription"`
		Description      string `json:"Description"`
		Source           string `json:"Source"`
	} `json:"Rule"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "cfn-lint", Label: "cfn-lint JSON", Tool: "cfn-lint", Category: "iac", Media: "json", Order: 265,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("Filename", "Level", "Location", "Rule")
		},
		parse: parseCfnLint})
}

func parseCfnLint(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("cfn-lint: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var m cfnLintMatch
		if err := json.Unmarshal(it, &m); err != nil || m.Rule.ID == "" {
			return out, fmt.Errorf("cfn-lint: match %d: expected an object with Rule.Id", i+1)
		}
		sev := normSeverity(m.Level)
		if strings.EqualFold(m.Level, "informational") {
			sev = "info"
		}
		path := make([]string, len(m.Location.Path))
		for j, p := range m.Location.Path {
			path[j] = fmt.Sprint(p)
		}
		f := Finding{Category: "iac", RuleID: m.Rule.ID, Title: firstNonEmpty(m.Rule.ShortDescription, m.Message), Severity: sev,
			FilePath: NormalizePath(m.Filename), StartLine: intPtr(m.Location.Start.LineNumber), EndLine: intPtr(m.Location.End.LineNumber),
			Description: joinText(m.Message, m.Rule.Description, "Path: "+strings.Join(path, "/"), m.Rule.Source)}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.Join(path, "/") + "|" + m.Message), Raw: it})
	}
	return out, nil
}
