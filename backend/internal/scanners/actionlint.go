package scanners

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"pathos/internal/platform/logging"
)

// Actionlint is the GitHub Actions workflow linter.
const Actionlint = "actionlint"

type actionlintError struct {
	Message  string `json:"message"`
	Filepath string `json:"filepath"`
	Line     int    `json:"line"`
	Column   int    `json:"column"`
	Kind     string `json:"kind"`
	Snippet  string `json:"snippet"`
}

// ParseActionlint normalises actionlint's JSON output. Script injection
// through untrusted expressions is high severity; credential and
// permission problems medium; syntax and type errors low.
func ParseActionlint(raw []byte) ([]Finding, error) {
	var errs []actionlintError
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	if err := json.Unmarshal(raw, &errs); err != nil {
		return nil, fmt.Errorf("actionlint: invalid JSON: %w", err)
	}
	var out []Finding
	for _, e := range errs {
		if len(out) >= MaxFindingsPerReport {
			return out, errors.New("report truncated: too many findings")
		}
		kind := e.Kind
		if kind == "" {
			kind = "syntax-check"
		}
		f := Finding{ScannerKey: Actionlint, Category: "iac", RuleID: "actionlint/" + kind, FilePath: NormalizePath(e.Filepath)}
		msg := strings.TrimSpace(e.Message)
		title := msg
		if i := strings.Index(title, ". "); i > 0 {
			title = title[:i]
		}
		f.Title = truncate(logging.RedactString(title), 300)
		f.Description = truncate(logging.RedactString(msg), 4000)
		if e.Line > 0 {
			l := e.Line
			f.StartLine, f.EndLine = &l, &l
		}
		lm := strings.ToLower(msg)
		switch {
		case kind == "expression" && strings.Contains(lm, "untrusted"):
			f.Severity, f.Confidence = "high", "high"
			f.CWE = []string{"CWE-94"}
		case strings.Contains(lm, "credential") || strings.Contains(lm, "secret") || kind == "permissions":
			f.Severity, f.Confidence = "medium", "medium"
		case kind == "deprecated-commands":
			f.Severity, f.Confidence = "medium", "high"
		default:
			f.Severity, f.Confidence = "low", "high"
		}
		f.Fingerprint = Fingerprint(f, hashOf(msg))
		out = append(out, f)
	}
	return out, nil
}
