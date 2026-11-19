package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Ruff JSON (`ruff check --output-format json`): an array of diagnostics
// with code, message, filename (absolute), location and end_location
// ({row, column}) and url. Ruff's "severity" is the same for every rule, so
// it is not used. The flake8-bandit rules (S, Bandit's checks) are sast
// findings with Bandit's CWE and severity; every other rule is an "other"
// (code quality) finding of low severity. The report has no code, so
// identity is the code, file, message and line.

type ruffDiagnostic struct {
	Code     string `json:"code"`
	Name     string `json:"name"`
	Message  string `json:"message"`
	Filename string `json:"filename"`
	URL      string `json:"url"`
	Location struct {
		Row    int `json:"row"`
		Column int `json:"column"`
	} `json:"location"`
	EndLocation struct {
		Row int `json:"row"`
	} `json:"end_location"`
}

// ruffBandit is the CWE and severity Bandit gives its checks, by Ruff code
// (Ruff's S<nnn> is Bandit's B<nnn>). Unlisted S rules are medium.
var ruffBandit = map[string][2]string{
	"S101": {"CWE-703", "low"}, "S102": {"CWE-78", "medium"}, "S103": {"CWE-732", "high"}, "S104": {"CWE-605", "medium"},
	"S105": {"CWE-259", "low"}, "S106": {"CWE-259", "low"}, "S107": {"CWE-259", "low"}, "S108": {"CWE-377", "medium"},
	"S110": {"CWE-703", "low"}, "S112": {"CWE-703", "low"}, "S113": {"CWE-400", "medium"},
	"S201": {"CWE-94", "high"}, "S202": {"CWE-22", "high"},
	"S301": {"CWE-502", "medium"}, "S302": {"CWE-502", "medium"}, "S303": {"CWE-327", "medium"}, "S304": {"CWE-327", "high"},
	"S305": {"CWE-327", "medium"}, "S306": {"CWE-377", "medium"}, "S307": {"CWE-78", "medium"}, "S308": {"CWE-79", "medium"},
	"S310": {"CWE-22", "medium"}, "S311": {"CWE-330", "low"}, "S312": {"CWE-319", "high"}, "S313": {"CWE-20", "medium"},
	"S321": {"CWE-319", "high"}, "S323": {"CWE-295", "medium"}, "S324": {"CWE-327", "high"},
	"S501": {"CWE-295", "high"}, "S502": {"CWE-327", "high"}, "S503": {"CWE-327", "medium"}, "S504": {"CWE-327", "low"},
	"S505": {"CWE-326", "high"}, "S506": {"CWE-20", "medium"}, "S507": {"CWE-295", "high"}, "S508": {"CWE-319", "medium"},
	"S509": {"CWE-319", "medium"},
	"S601": {"CWE-78", "medium"}, "S602": {"CWE-78", "high"}, "S603": {"CWE-78", "low"}, "S604": {"CWE-78", "medium"},
	"S605": {"CWE-78", "high"}, "S606": {"CWE-78", "low"}, "S607": {"CWE-78", "low"}, "S608": {"CWE-89", "medium"},
	"S609": {"CWE-78", "high"}, "S610": {"CWE-89", "medium"}, "S611": {"CWE-89", "medium"},
	"S701": {"CWE-94", "high"}, "S702": {"CWE-80", "medium"}, "S704": {"CWE-80", "medium"},
}

func init() {
	registerImportFormat(ImportFormat{ID: "ruff", Label: "Ruff JSON", Tool: "Ruff", Media: "json", Order: 161,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("code", "filename", "location", "message")
		},
		parse: parseRuff})
}

// ruffSecurity reports whether a Ruff code is a flake8-bandit rule (S
// followed by digits only; SIM, SLF, SLOT are other plugins).
func ruffSecurity(code string) bool {
	return len(code) > 1 && code[0] == 'S' && strings.Trim(code[1:], "0123456789") == ""
}

func parseRuff(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("ruff: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var d ruffDiagnostic
		if err := json.Unmarshal(it, &d); err != nil || d.Message == "" {
			return out, fmt.Errorf("ruff: diagnostic %d: expected an object with message", i+1)
		}
		// Syntax errors have no code.
		rule := firstNonEmpty(d.Code, d.Name, "syntax-error")
		f := Finding{Category: "other", RuleID: rule, Title: d.Message, Severity: "low", FilePath: NormalizePath(d.Filename),
			StartLine: intPtr(d.Location.Row), EndLine: intPtr(d.EndLocation.Row), Description: joinText(d.Message, d.URL)}
		if ruffSecurity(d.Code) {
			f.Category, f.Severity = "sast", "medium"
			if m, ok := ruffBandit[d.Code]; ok {
				f.CWE, f.Severity = []string{m[0]}, m[1]
			}
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%s|%d", d.Message, d.Location.Row)), Raw: it})
	}
	return out, nil
}
