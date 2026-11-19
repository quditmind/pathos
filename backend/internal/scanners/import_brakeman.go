package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Brakeman JSON (`brakeman -f json`): warnings[] (and ignored_warnings[],
// warnings the team marked as ignored) with warning_type, check_name,
// message, file, line, code, confidence (High, Medium, Weak), cwe_id[],
// link and Brakeman's fingerprint (stable across line moves; the
// identity). Brakeman has no severity: its confidence is used for both
// (High high, Medium medium, Weak low). Ignored warnings are imported with
// low confidence and noted, never dropped.

type brakemanWarning struct {
	WarningType string `json:"warning_type"`
	CheckName   string `json:"check_name"`
	Message     string `json:"message"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Link        string `json:"link"`
	Code        string `json:"code"`
	Confidence  string `json:"confidence"`
	CWEID       []int  `json:"cwe_id"`
	Fingerprint string `json:"fingerprint"`
	UserInput   string `json:"user_input"`
	Note        string `json:"note"`
}

var brakemanLevels = map[string]string{"high": "high", "medium": "medium", "weak": "low", "low": "low"}

func init() {
	registerImportFormat(ImportFormat{ID: "brakeman", Label: "Brakeman JSON", Tool: "Brakeman", Category: "sast", Media: "json", Order: 107,
		match: func(p *importProbe) bool { return p.kind == "object" && p.has("scan_info", "warnings") },
		parse: parseBrakemanJSON})
}

func parseBrakemanJSON(raw []byte) ([]importRecord, error) {
	var doc struct {
		Warnings []json.RawMessage `json:"warnings"`
		Ignored  []json.RawMessage `json:"ignored_warnings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("brakeman: invalid JSON: %w", err)
	}
	var out []importRecord
	add := func(items []json.RawMessage, ignored bool) error {
		for i, it := range items {
			var w brakemanWarning
			if err := json.Unmarshal(it, &w); err != nil || w.WarningType == "" {
				return fmt.Errorf("brakeman: warning %d: expected an object with warning_type", i+1)
			}
			lvl := brakemanLevels[strings.ToLower(w.Confidence)]
			if lvl == "" {
				lvl = "medium"
			}
			f := Finding{Category: "sast", RuleID: firstNonEmpty(w.CheckName, w.WarningType), Title: w.WarningType + ": " + w.Message,
				Severity: lvl, Confidence: lvl, FilePath: NormalizePath(w.File), StartLine: intPtr(w.Line),
				Description: joinText(w.Message, labelled("Code", w.Code), labelled("User input", w.UserInput), labelled("More information", w.Link))}
			for _, c := range w.CWEID {
				f.CWE = append(f.CWE, fmt.Sprintf("CWE-%d", c))
			}
			if ignored {
				f.Confidence = "low"
				f.Description = joinText("Brakeman lists this warning as ignored; it is kept for review.", labelled("Note", w.Note), f.Description)
			}
			key := w.Fingerprint
			if key == "" {
				key = codeIdentity(w.Code) + "|" + w.Message
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf("brakeman|" + key), Raw: it})
		}
		return nil
	}
	if err := add(doc.Warnings, false); err != nil {
		return out, err
	}
	return out, add(doc.Ignored, true)
}
