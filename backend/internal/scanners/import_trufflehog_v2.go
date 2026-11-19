package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// TruffleHog 2 (legacy Python version, `trufflehog --json <repo>`): one
// JSON object per line with branch, commit (the message), commitHash,
// date, path, reason (High Entropy or the regex name), stringsFound,
// diff and printDiff. The secrets (stringsFound, diff, printDiff) are
// removed before the report is stored; identity does not depend on them.
// Secrets are high.

var trufflehogV2SecretKeys = []string{"stringsFound", "diff", "printDiff"}

func init() {
	registerImportFormat(ImportFormat{ID: "trufflehog-v2", Label: "TruffleHog 2 JSON lines (legacy)", Tool: "TruffleHog", Category: "secrets", Media: "jsonl", Order: 706,
		match: func(p *importProbe) bool {
			return (p.kind == "jsonl" || p.kind == "object") && p.has("stringsFound", "commitHash", "reason")
		},
		parse:    parseTrufflehogV2,
		sanitize: func(raw []byte) []byte { return redactLines(raw, trufflehogV2SecretKeys...) }})
}

func parseTrufflehogV2(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := jsonLines(raw, func(n int, line []byte) error {
		var r struct {
			Branch     string          `json:"branch"`
			Commit     string          `json:"commit"`
			CommitHash string          `json:"commitHash"`
			Date       string          `json:"date"`
			Path       string          `json:"path"`
			Reason     string          `json:"reason"`
			Strings    json.RawMessage `json:"stringsFound"`
		}
		if err := json.Unmarshal(line, &r); err != nil || r.Reason == "" {
			return fmt.Errorf("trufflehog v2: line %d: expected an object with reason", n)
		}
		var found []string
		count := ""
		if json.Unmarshal(r.Strings, &found) == nil && len(found) > 0 {
			count = fmt.Sprintf(" (%d strings)", len(found))
		}
		f := Finding{Category: "secrets", RuleID: r.Reason, Title: "Secret in commit history: " + r.Reason, Severity: "high", FilePath: NormalizePath(r.Path),
			Description: joinText(fmt.Sprintf("TruffleHog found a possible secret%s in %s, commit %s on %s (%s).", count, r.Path, r.CommitHash, r.Branch, r.Date),
				labeled("Commit message", strings.TrimSpace(r.Commit)), "The secret values are not kept.")}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(r.CommitHash + "|" + r.Branch), Raw: redactKeys(append([]byte(nil), line...), trufflehogV2SecretKeys...)})
		return nil
	})
	return out, err
}
