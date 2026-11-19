package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OpenSSF Scorecard JSON (`scorecard --format json --show-details`): repo
// {name, commit}, scorecard {version}, score and checks[] {name, score
// 0-10 or -1, reason, details[], documentation {url, short}}. Every check
// scoring below 10 is a finding; -1 (inconclusive or not applicable) is
// not. Severity is the check's risk level from the Scorecard
// documentation, one level lower when the check scores 5 or more. The
// details (with the files and lines of each warning) are in the
// description; the finding has no file because a check covers the whole
// repository. Supply-chain posture findings use the "other" category.

// scorecardRisk is the risk level of each check (docs/checks.md).
var scorecardRisk = map[string]string{
	"Dangerous-Workflow": "critical", "Binary-Artifacts": "high", "Branch-Protection": "high", "Code-Review": "high",
	"Dependency-Update-Tool": "high", "Maintained": "high", "Signed-Releases": "high", "Token-Permissions": "high",
	"Vulnerabilities": "high", "Webhooks": "high", "Fuzzing": "medium", "Packaging": "medium", "Pinned-Dependencies": "medium",
	"SAST": "medium", "Security-Policy": "medium", "CI-Tests": "low", "CII-Best-Practices": "low", "Contributors": "low",
	"License": "low", "SBOM": "low",
}

func init() {
	registerImportFormat(ImportFormat{ID: "scorecard", Label: "OpenSSF Scorecard JSON", Tool: "OpenSSF Scorecard", Category: "other", Media: "json", Order: 282,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("repo", "scorecard", "checks")
		},
		parse: parseScorecard})
}

func parseScorecard(raw []byte) ([]importRecord, error) {
	var doc struct {
		Repo struct {
			Name   string `json:"name"`
			Commit string `json:"commit"`
		} `json:"repo"`
		Checks []json.RawMessage `json:"checks"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("scorecard: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range doc.Checks {
		var c struct {
			Name          string   `json:"name"`
			Score         *int     `json:"score"`
			Reason        string   `json:"reason"`
			Details       []string `json:"details"`
			Documentation struct {
				URL   string `json:"url"`
				Short string `json:"short"`
			} `json:"documentation"`
		}
		if err := json.Unmarshal(it, &c); err != nil || c.Name == "" || c.Score == nil {
			return out, fmt.Errorf("scorecard: check %d: expected an object with name and score", i+1)
		}
		if *c.Score < 0 || *c.Score >= 10 {
			continue
		}
		sev := firstNonEmpty(scorecardRisk[c.Name], "medium")
		if *c.Score >= 5 {
			sev = map[string]string{"critical": "high", "high": "medium", "medium": "low", "low": "info"}[sev]
		}
		f := Finding{Category: "other", RuleID: c.Name, Title: fmt.Sprintf("Scorecard %s: %s", c.Name, c.Reason), Severity: sev,
			Description: joinText(fmt.Sprintf("%s (score %d of 10)", c.Documentation.Short, *c.Score), c.Reason,
				strings.Join(c.Details, "\n"), c.Documentation.URL)}
		// Identity is the check of the repository, not the score, reason
		// or the first warning's location, which change between runs.
		out = append(out, importRecord{F: f, SnippetKey: hashOf(doc.Repo.Name), Raw: it})
	}
	return out, nil
}
