package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// promptfoo eval and red-team results (`promptfoo eval -o results.json`,
// `promptfoo redteam run` with an output file): {evalId, results: {version,
// results[]}, config}. One finding per failed test case (an assertion or a
// red-team grader failed); passing test cases and test cases that ended in
// an error (no verdict) are not findings. Red-team test cases carry the
// plugin (harmful:*, pii:*, prompt-injection, ...) and strategy in their
// metadata; the plugin is the rule. Prompts and model outputs may contain
// secrets and the config provider credentials: they are redacted before
// the report is stored.

type promptfooResult struct {
	ID            string `json:"id"`
	Success       *bool  `json:"success"`
	FailureReason int    `json:"failureReason"`
	Error         string `json:"error"`
	Score         any    `json:"score"`
	PromptIdx     int    `json:"promptIdx"`
	TestIdx       int    `json:"testIdx"`
	Provider      struct {
		ID    string `json:"id"`
		Label string `json:"label"`
	} `json:"provider"`
	Prompt struct {
		Raw   string `json:"raw"`
		Label string `json:"label"`
	} `json:"prompt"`
	Response struct {
		Output any `json:"output"`
	} `json:"response"`
	GradingResult *struct {
		Pass             bool   `json:"pass"`
		Reason           string `json:"reason"`
		ComponentResults []struct {
			Pass      bool   `json:"pass"`
			Reason    string `json:"reason"`
			Assertion *struct {
				Type string `json:"type"`
			} `json:"assertion"`
		} `json:"componentResults"`
	} `json:"gradingResult"`
	TestCase struct {
		Description string         `json:"description"`
		Metadata    map[string]any `json:"metadata"`
	} `json:"testCase"`
	Metadata map[string]any `json:"metadata"`
}

// promptfooSecretKeys are config and provider fields holding credentials.
var promptfooSecretKeys = []string{"apiKey", "api_key", "apiKeyEnvar", "token", "accessToken", "password", "secret", "clientSecret"}

func init() {
	registerImportFormat(ImportFormat{ID: "promptfoo", Label: "promptfoo eval / red-team results JSON", Tool: "promptfoo", Category: "other", Media: "json", Order: 371,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("evalId", "results") && p.hasAny("config", "shareableUrl")
		},
		parse:    parsePromptfoo,
		sanitize: sanitizePromptfoo})
}

func sanitizePromptfoo(raw []byte) []byte {
	return sanitizeHTTPJSON(redactKeys(raw, promptfooSecretKeys...))
}

func parsePromptfoo(raw []byte) ([]importRecord, error) {
	var rep struct {
		EvalID  string `json:"evalId"`
		Results struct {
			Version int               `json:"version"`
			Results []json.RawMessage `json:"results"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("promptfoo: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range rep.Results.Results {
		var r promptfooResult
		if err := json.Unmarshal(it, &r); err != nil {
			return out, fmt.Errorf("promptfoo: result %d: expected an object", i+1)
		}
		failed := r.Success != nil && !*r.Success
		if r.Success == nil && r.GradingResult != nil {
			failed = !r.GradingResult.Pass
		}
		// failureReason 2 is an error (the provider failed): no verdict.
		if !failed || r.FailureReason == 2 {
			continue
		}
		out = append(out, promptfooFinding(r, it))
	}
	return out, nil
}

func promptfooMeta(r promptfooResult, key string) string {
	for _, m := range []map[string]any{r.Metadata, r.TestCase.Metadata} {
		if s, ok := m[key].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func promptfooFinding(r promptfooResult, raw json.RawMessage) importRecord {
	plugin, strategy := promptfooMeta(r, "pluginId"), promptfooMeta(r, "strategyId")
	var asserts []string
	reasons := []string{}
	if g := r.GradingResult; g != nil {
		for _, c := range g.ComponentResults {
			if c.Pass {
				continue
			}
			if c.Assertion != nil && c.Assertion.Type != "" {
				asserts = append(asserts, c.Assertion.Type)
			}
			reasons = append(reasons, c.Reason)
		}
		if len(reasons) == 0 {
			reasons = append(reasons, g.Reason)
		}
	}
	rule := plugin
	if rule == "" {
		rule = "assertion:" + firstNonEmpty(strings.Join(asserts, "+"), "failed")
	}
	desc := firstNonEmpty(r.TestCase.Description, promptfooMeta(r, "goal"), fmt.Sprintf("test %d", r.TestIdx+1))
	title := desc
	if plugin != "" {
		title = "Red-team plugin " + plugin + " failed: " + desc
	}
	f := Finding{Category: "other", RuleID: "promptfoo:" + rule, Title: title,
		Severity: firstNonEmpty(normSeverity(promptfooMeta(r, "severity")), "medium"),
		FilePath: firstNonEmpty(r.Provider.ID, r.Provider.Label, "provider"), Confidence: "medium"}
	output := ""
	switch o := r.Response.Output.(type) {
	case string:
		output = o
	case nil:
	default:
		b, _ := json.Marshal(o)
		output = string(b)
	}
	f.Description = joinText(
		fmt.Sprintf("The model behind provider %s failed this promptfoo test case.", f.FilePath),
		labelled("Strategy", strategy), labelled("Goal", promptfooMeta(r, "goal")),
		labelled("Grader", clipText(strings.Join(reasons, "\n"), 1000)),
		labelled("Prompt", redactHTTP(clipText(r.Prompt.Raw, 1000))), labelled("Output", redactHTTP(clipText(output, 1000))))
	key := strings.Join([]string{plugin, strategy, r.TestCase.Description, fmt.Sprint(r.TestIdx), fmt.Sprint(r.PromptIdx)}, "|")
	return importRecord{F: f, SnippetKey: hashOf(key), Raw: sanitizeHTTPJSON(redactKeys(raw, promptfooSecretKeys...))}
}
