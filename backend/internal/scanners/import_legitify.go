package scanners

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Legitify JSON (`legitify analyze --output-format json`, the default
// "flattened" scheme): {type: "flattened", content: {<policy>: {policyInfo
// {title, description, policyName, fullyQualifiedPolicyName, severity,
// threat[], remediationSteps[], namespace}, violations[] {
// violationEntityType, canonicalLink, aux, status}}}}. FAILED violations
// are findings; PASSED and SKIPPED are not. The location is the GitHub or
// GitLab entity's link. SCM posture findings use the cicd category.
// Other output schemes (--scheme-type group-by-*) are not supported.

type legitifyPolicy struct {
	PolicyInfo struct {
		Title                    string   `json:"title"`
		Description              string   `json:"description"`
		PolicyName               string   `json:"policyName"`
		FullyQualifiedPolicyName string   `json:"fullyQualifiedPolicyName"`
		Severity                 string   `json:"severity"`
		Threat                   []string `json:"threat"`
		RemediationSteps         []string `json:"remediationSteps"`
		Namespace                string   `json:"namespace"`
	} `json:"policyInfo"`
	Violations []json.RawMessage `json:"violations"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "legitify", Label: "Legitify JSON", Tool: "Legitify", Category: "cicd", Media: "json", Order: 281,
		match: func(p *importProbe) bool {
			var t string
			return p.kind == "object" && p.has("type", "content") && len(p.keys) == 2 && json.Unmarshal(p.keys["type"], &t) == nil &&
				(t == "flattened" || strings.HasPrefix(t, "group-by-"))
		},
		parse: parseLegitify})
}

func parseLegitify(raw []byte) ([]importRecord, error) {
	var doc struct {
		Type    string                     `json:"type"`
		Content map[string]json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("legitify: invalid JSON: %w", err)
	}
	if doc.Type != "flattened" {
		return nil, errors.New("legitify: only the default flattened output scheme can be imported (do not set --scheme-type)")
	}
	names := make([]string, 0, len(doc.Content))
	for n := range doc.Content {
		names = append(names, n)
	}
	slices.Sort(names)
	var out []importRecord
	for _, name := range names {
		var p legitifyPolicy
		if err := json.Unmarshal(doc.Content[name], &p); err != nil {
			return out, fmt.Errorf("legitify: policy %s: %w", name, err)
		}
		info := p.PolicyInfo
		for i, vr := range p.Violations {
			var v struct {
				ViolationEntityType string         `json:"violationEntityType"`
				CanonicalLink       string         `json:"canonicalLink"`
				Aux                 map[string]any `json:"aux"`
				Status              string         `json:"status"`
			}
			if err := json.Unmarshal(vr, &v); err != nil || v.Status == "" {
				return out, fmt.Errorf("legitify: policy %s: violation %d: expected an object with status", name, i+1)
			}
			if !strings.EqualFold(v.Status, "FAILED") {
				continue
			}
			entity, _ := v.Aux["entityName"].(string)
			title := info.Title
			if entity != "" {
				title += " (" + entity + ")"
			}
			f := Finding{Category: "cicd", RuleID: firstNonEmpty(info.FullyQualifiedPolicyName, name), Title: firstNonEmpty(title, name),
				Severity: info.Severity, FilePath: v.CanonicalLink,
				Description: joinText(info.Description, "Entity: "+v.ViolationEntityType+" "+v.CanonicalLink,
					"Threat: "+strings.Join(info.Threat, " "), "Remediation:\n"+strings.Join(info.RemediationSteps, "\n"))}
			rec := map[string]any{"policy": name, "policyInfo": info, "violation": json.RawMessage(vr)}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(v.CanonicalLink), Raw: rawJSON(rec)})
		}
	}
	return out, nil
}
