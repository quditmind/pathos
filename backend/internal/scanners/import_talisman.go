package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Talisman JSON report (`talisman --scan`, written to
// talisman_report/talisman_reports/data/report.json): summary and
// results[] per file with failure_list, warning_list and ignore_list, each
// entry {type (filecontent, filename, filesize), message, commits,
// severity}. filecontent messages quote the secret ("Potential secret
// pattern : KEY=value"): the text after the message's first colon is
// removed before the report is stored. Talisman reports no line; identity
// is the file, type, the message without the secret and the position
// among such messages of the file. Warnings are imported with low
// confidence, ignored entries are not findings.

type talismanEntry struct {
	Type     string   `json:"type"`
	Message  string   `json:"message"`
	Commits  []string `json:"commits"`
	Severity string   `json:"severity"`
}

type talismanFile struct {
	Filename    string            `json:"filename"`
	FailureList []json.RawMessage `json:"failure_list"`
	WarningList []json.RawMessage `json:"warning_list"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "talisman", Label: "Talisman JSON report", Tool: "Talisman", Category: "secrets", Media: "json", Order: 185,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("summary", "results") && (hasKeys(p.firstOf("results"), "filename", "failure_list") ||
				(p.firstOf("results") == nil && strings.Contains(string(p.keys["summary"]), `"filecontent"`)))
		},
		parse:    parseTalisman,
		sanitize: sanitizeTalisman,
	})
}

// talismanScrub removes the quoted secret of a filecontent message.
func talismanScrub(typ, msg string) string {
	if typ != "filecontent" {
		return msg
	}
	if head, _, ok := strings.Cut(msg, ":"); ok {
		return strings.TrimSpace(head) + ": [REDACTED]"
	}
	return "[REDACTED]"
}

func sanitizeTalisman(raw []byte) []byte {
	var x any
	if json.Unmarshal(raw, &x) != nil {
		return raw
	}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			if typ, ok := t["type"].(string); ok {
				if msg, ok := t["message"].(string); ok {
					t["message"] = talismanScrub(typ, msg)
				}
			}
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(x)
	b, err := json.Marshal(x)
	if err != nil {
		return raw
	}
	return b
}

func parseTalisman(raw []byte) ([]importRecord, error) {
	var doc struct {
		Results []talismanFile `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("talisman: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, file := range doc.Results {
		seen := map[string]int{}
		for _, list := range []struct {
			entries []json.RawMessage
			warning bool
		}{{file.FailureList, false}, {file.WarningList, true}} {
			for i, it := range list.entries {
				var e talismanEntry
				if err := json.Unmarshal(it, &e); err != nil || e.Type == "" {
					return out, fmt.Errorf("talisman: %s: entry %d: expected an object with type", file.Filename, i+1)
				}
				msg := talismanScrub(e.Type, e.Message)
				path := NormalizePath(file.Filename)
				f := Finding{Category: "secrets", RuleID: "talisman-" + e.Type, Severity: firstNonEmpty(normSeverity(e.Severity), "medium"),
					CWE: []string{"CWE-798"}, FilePath: path}
				switch e.Type {
				case "filename":
					f.Title, f.CWE = "File name suggests secrets", []string{"CWE-538"}
				case "filesize":
					f.Title, f.CWE = "Large file", nil
				default:
					head, _, _ := strings.Cut(msg, ":")
					f.Title = strings.TrimSpace(head)
				}
				f.Description = fmt.Sprintf("Talisman %s check on %s: %s", e.Type, path, msg)
				if len(e.Commits) > 0 {
					f.Description += " (commits " + strings.Join(e.Commits, ", ") + ")"
				}
				if list.warning {
					f.Confidence = "low"
					f.Description += "; reported as a warning"
				}
				id := e.Type + "|" + msg
				seen[id]++
				var rec map[string]any
				_ = json.Unmarshal(it, &rec)
				rec["message"] = msg
				rec["filename"] = file.Filename
				out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%s|%d", id, seen[id])), Raw: rawJSON(rec)})
			}
		}
	}
	return out, nil
}
