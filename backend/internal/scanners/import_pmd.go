package scanners

import (
	"fmt"
	"strings"
)

// PMD XML (`pmd check -f xml`, report schema 2.0.0): pmd / file (name) /
// violation with beginline, endline, rule, ruleset, package, class,
// method, variable, externalInfoUrl, priority (1 high, 2 medium, 3-4 low,
// 5 info) and the message as text. Violations of the Security ruleset are
// sast; the others (Best Practices, Error Prone, Design, ...) are code
// quality (other). Processing errors (error elements) are not findings.
// Identity is the rule, class, method, variable and message.

type pmdViolation struct {
	BeginLine int    `xml:"beginline,attr" json:"beginline"`
	EndLine   int    `xml:"endline,attr" json:"endline"`
	Rule      string `xml:"rule,attr" json:"rule"`
	RuleSet   string `xml:"ruleset,attr" json:"ruleset"`
	Package   string `xml:"package,attr" json:"package,omitempty"`
	Class     string `xml:"class,attr" json:"class,omitempty"`
	Method    string `xml:"method,attr" json:"method,omitempty"`
	Variable  string `xml:"variable,attr" json:"variable,omitempty"`
	URL       string `xml:"externalInfoUrl,attr" json:"external_info_url,omitempty"`
	Priority  string `xml:"priority,attr" json:"priority"`
	Message   string `xml:",chardata" json:"message"`
	File      string `xml:"-" json:"file"`
}

var pmdPriority = map[string]string{"1": "high", "2": "medium", "3": "low", "4": "low", "5": "info"}

func init() {
	registerImportFormat(ImportFormat{ID: "pmd", Label: "PMD XML", Tool: "PMD", Media: "xml", Order: 109,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "pmd" },
		parse: parsePMDXML})
}

func parsePMDXML(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := eachXMLElement(raw, "pmd", "file", func(file *struct {
		Name       string         `xml:"name,attr"`
		Violations []pmdViolation `xml:"violation"`
	}) error {
		for _, v := range file.Violations {
			if v.Rule == "" {
				return fmt.Errorf("pmd: %s: violation without rule", file.Name)
			}
			v.File, v.Message = file.Name, strings.TrimSpace(v.Message)
			sev, ok := pmdPriority[v.Priority]
			if !ok {
				sev = "medium"
			}
			cat := "other"
			if strings.EqualFold(v.RuleSet, "Security") {
				cat = "sast"
			}
			f := Finding{Category: cat, RuleID: v.Rule, Title: firstNonEmpty(v.Message, v.Rule), Severity: sev,
				FilePath: NormalizePath(file.Name), StartLine: intPtr(v.BeginLine), EndLine: intPtr(v.EndLine),
				Description: joinText(v.Message, fmt.Sprintf("PMD rule %s (%s).", v.Rule, v.RuleSet), labelled("More information", v.URL))}
			key := strings.Join([]string{v.Rule, v.Class, v.Method, v.Variable, v.Message}, "|")
			out = append(out, importRecord{F: f, SnippetKey: hashOf("pmd|" + key), Raw: rawJSON(v)})
		}
		return nil
	})
	return out, err
}
