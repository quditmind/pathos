package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Nosey Parker JSON and JSON Lines (`noseyparker report --format json` or
// `--format jsonl`): one object per finding (a secret, possibly matched in
// several places) with finding_id, rule_name, rule_text_id, groups (the
// secret, base64) and matches[] (provenance: a file path, or a git commit
// and blob path; location.source_span; snippet with the secret). One
// finding per match. groups and snippet are removed before the report is
// stored; identity is the rule, file, commit and line. Matches the
// reviewer marked as reject (statuses) are imported with low confidence.

var noseyparkerSecretKeys = []string{"groups", "snippet"}

type noseyparkerFinding struct {
	FindingID  string            `json:"finding_id"`
	RuleName   string            `json:"rule_name"`
	RuleTextID string            `json:"rule_text_id"`
	Statuses   []string          `json:"statuses"`
	Matches    []json.RawMessage `json:"matches"`
}

type noseyparkerMatch struct {
	Provenance []struct {
		Kind             string `json:"kind"`
		Path             string `json:"path"`
		RepoPath         string `json:"repo_path"`
		CommitProvenance *struct {
			CommitMetadata struct {
				CommitID string `json:"commit_id"`
			} `json:"commit_metadata"`
			BlobPath string `json:"blob_path"`
		} `json:"first_commit"`
	} `json:"provenance"`
	Location struct {
		SourceSpan struct {
			Start struct {
				Line int `json:"line"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
			} `json:"end"`
		} `json:"source_span"`
	} `json:"location"`
	Status *string `json:"status"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "noseyparker", Label: "Nosey Parker JSON / JSON Lines", Tool: "Nosey Parker", Category: "secrets", Media: "json", Order: 182,
		match: func(p *importProbe) bool {
			return (p.kind == "array" || p.kind == "jsonl" || p.kind == "object") && p.has("finding_id", "rule_name", "matches")
		},
		parse: parseNoseyParker,
		sanitize: func(raw []byte) []byte {
			if b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM)); len(b) > 0 && b[0] == '[' {
				return redactKeys(raw, noseyparkerSecretKeys...)
			}
			return redactLines(raw, noseyparkerSecretKeys...)
		},
	})
}

func parseNoseyParker(raw []byte) ([]importRecord, error) {
	var items []json.RawMessage
	if b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM)); len(b) > 0 && b[0] == '[' {
		var err error
		if items, err = jsonArray(b, ""); err != nil {
			return nil, fmt.Errorf("noseyparker: invalid JSON: %w", err)
		}
	} else if err := jsonLines(raw, func(n int, line []byte) error {
		items = append(items, append(json.RawMessage(nil), line...))
		return nil
	}); err != nil {
		return nil, fmt.Errorf("noseyparker: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r noseyparkerFinding
		if err := json.Unmarshal(it, &r); err != nil || r.RuleName == "" {
			return out, fmt.Errorf("noseyparker: finding %d: expected an object with rule_name", i+1)
		}
		var whole map[string]json.RawMessage
		_ = json.Unmarshal(it, &whole)
		for j, mr := range r.Matches {
			var m noseyparkerMatch
			if err := json.Unmarshal(mr, &m); err != nil {
				return out, fmt.Errorf("noseyparker: finding %d: match %d: invalid", i+1, j+1)
			}
			var path, commit string
			for _, p := range m.Provenance {
				if p.CommitProvenance != nil {
					path, commit = firstNonEmpty(path, p.CommitProvenance.BlobPath), p.CommitProvenance.CommitMetadata.CommitID
				} else if p.Path != "" && path == "" {
					path = p.Path
				}
			}
			rule := firstNonEmpty(r.RuleTextID, r.RuleName)
			f := Finding{Category: "secrets", RuleID: rule, Title: r.RuleName + " (Nosey Parker)", Severity: "high", CWE: []string{"CWE-798"},
				FilePath: NormalizePath(path), StartLine: intPtr(m.Location.SourceSpan.Start.Line), EndLine: intPtr(m.Location.SourceSpan.End.Line),
				Description: fmt.Sprintf("Nosey Parker rule %s (%s) matched a secret", r.RuleName, rule)}
			if path != "" {
				f.Description += " in " + NormalizePath(path)
			}
			if commit != "" {
				f.Description += " (commit " + commit + ")"
			}
			if m.Status != nil && *m.Status != "" {
				f.Description += "; reviewed: " + *m.Status
				if *m.Status == "reject" {
					f.Confidence = "low"
				}
			}
			// The original record is the finding with this one match.
			rec := map[string]json.RawMessage{}
			for k, v := range whole {
				rec[k] = v
			}
			rec["matches"] = rawJSON([]json.RawMessage{mr})
			out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprintf("%s|%d", commit, m.Location.SourceSpan.Start.Line)),
				Raw: redactKeys(rawJSON(rec), noseyparkerSecretKeys...)})
		}
	}
	return out, nil
}
