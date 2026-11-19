package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
)

// TruffleHog JSON Lines (`trufflehog git|filesystem|github ... --json`):
// one object per secret with SourceMetadata.Data.<source>.{file, line,
// commit}, DetectorName and Verified. Raw, RawV2, Redacted and (since
// TruffleHog 3.9x) SecretParts carry the secret and are removed before the
// report is stored; identity is the detector, file, commit and line.
// Verified (live) secrets are critical, others high.

// SecretParts splits the secret into its parts (for a connection string:
// user, host and password).
var trufflehogSecretKeys = []string{"Raw", "RawV2", "Redacted", "SecretParts"}

type trufflehogResult struct {
	SourceMetadata struct {
		Data map[string]struct {
			File       string `json:"file"`
			Line       int    `json:"line"`
			Commit     string `json:"commit"`
			Repository string `json:"repository"`
			Link       string `json:"link"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
	SourceName   string `json:"SourceName"`
	DetectorName string `json:"DetectorName"`
	DecoderName  string `json:"DecoderName"`
	Verified     bool   `json:"Verified"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "trufflehog", Label: "TruffleHog JSON Lines", Category: "secrets", Media: "jsonl", Order: 31,
		match: func(p *importProbe) bool {
			return (p.kind == "jsonl" || p.kind == "object") && p.has("DetectorName", "SourceMetadata")
		},
		parse:    parseTrufflehog,
		sanitize: func(raw []byte) []byte { return redactLines(raw, trufflehogSecretKeys...) },
	})
}

func parseTrufflehog(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := jsonLines(raw, func(n int, line []byte) error {
		var r trufflehogResult
		if err := json.Unmarshal(line, &r); err != nil || r.DetectorName == "" {
			return fmt.Errorf("trufflehog: line %d: expected a JSON object with DetectorName", n)
		}
		f := Finding{Category: "secrets", RuleID: r.DetectorName, Severity: "high", CWE: []string{"CWE-798"}}
		// One source per result (Git, Filesystem, Github, ...); sorted for
		// determinism if a tool ever reports several.
		srcs := make([]string, 0, len(r.SourceMetadata.Data))
		for s := range r.SourceMetadata.Data {
			srcs = append(srcs, s)
		}
		slices.Sort(srcs)
		var commit, where string
		if len(srcs) > 0 {
			d := r.SourceMetadata.Data[srcs[0]]
			f.FilePath, f.StartLine, commit = NormalizePath(d.File), intPtr(d.Line), d.Commit
			where = firstNonEmpty(d.Repository, d.Link)
		}
		state := "unverified"
		if r.Verified {
			f.Severity, f.Confidence, state = "critical", "high", "verified"
		}
		f.Title = fmt.Sprintf("%s secret (%s)", r.DetectorName, state)
		f.Description = fmt.Sprintf("TruffleHog detector %s found a %s secret", r.DetectorName, state)
		if f.FilePath != "" {
			f.Description += " in " + f.FilePath
		}
		if commit != "" {
			f.Description += " (commit " + commit + ")"
		}
		if where != "" {
			f.Description += "; source " + where
		}
		snip := fmt.Sprintf("%s|%d", commit, derefInt(f.StartLine))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(snip), Raw: redactKeys(line, trufflehogSecretKeys...)})
		return nil
	})
	return out, err
}

func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}
