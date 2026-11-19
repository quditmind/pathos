package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Azure Policy compliance states: `az policy state list` (an array) or
// the Policy Insights REST response (policyStates/latest/queryResults,
// {"value": [...]}). Each PolicyState names the resource (resourceId,
// resourceType), the assignment and definition (policyAssignmentName,
// policyDefinitionId, policyDefinitionName, policyDefinitionReferenceId,
// policySetDefinitionName, policyDefinitionAction: the effect,
// policyDefinitionCategory) and complianceState (or isCompliant).
// NonCompliant states are findings; Exempt states are kept with low
// confidence; Compliant, Conflict and Unknown are not findings. Azure
// Policy has no severity: deny effects are high, others medium. A
// finding is located at its resource ID.

type azurePolicyState struct {
	ResourceID          string `json:"resourceId"`
	ResourceType        string `json:"resourceType"`
	ComplianceState     string `json:"complianceState"`
	IsCompliant         *bool  `json:"isCompliant"`
	AssignmentName      string `json:"policyAssignmentName"`
	AssignmentID        string `json:"policyAssignmentId"`
	DefinitionID        string `json:"policyDefinitionId"`
	DefinitionName      string `json:"policyDefinitionName"`
	DefinitionAction    string `json:"policyDefinitionAction"`
	DefinitionCategory  string `json:"policyDefinitionCategory"`
	DefinitionReference string `json:"policyDefinitionReferenceId"`
	SetDefinitionName   string `json:"policySetDefinitionName"`
	Timestamp           string `json:"timestamp"`
}

func isAzurePolicyState(m map[string]json.RawMessage) bool {
	return hasKeys(m, "resourceId", "policyAssignmentId", "policyDefinitionId") && (hasKeys(m, "complianceState") || hasKeys(m, "isCompliant"))
}

func init() {
	registerImportFormat(ImportFormat{ID: "azure-policy", Label: "Azure Policy compliance states JSON (az policy state list, Policy Insights)",
		Tool: "Azure Policy", Category: "compliance", Media: "json", Order: 565,
		match: func(p *importProbe) bool {
			return (p.kind == "array" && isAzurePolicyState(p.keys)) || (p.kind == "object" && isAzurePolicyState(p.firstOf("value")))
		},
		parse: parseAzurePolicy})
}

func parseAzurePolicy(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "value")
	if err != nil {
		return nil, fmt.Errorf("azure policy: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var s azurePolicyState
		if err := json.Unmarshal(it, &s); err != nil || s.ResourceID == "" || s.DefinitionID == "" {
			return out, fmt.Errorf("azure policy: state %d: expected resourceId and policyDefinitionId", i+1)
		}
		state := s.ComplianceState
		if state == "" && s.IsCompliant != nil {
			state = map[bool]string{true: "Compliant", false: "NonCompliant"}[*s.IsCompliant]
		}
		if !strings.EqualFold(state, "NonCompliant") && !strings.EqualFold(state, "Exempt") {
			continue
		}
		name := firstNonEmpty(s.DefinitionReference, s.DefinitionName)
		f := Finding{Category: "compliance", RuleID: s.DefinitionID, Title: "Azure Policy " + name + " is not met", Severity: "medium",
			FilePath: strings.ToLower(s.ResourceID),
			Description: joinText(fmt.Sprintf("The resource %s (%s) is %s with the policy definition %s.", s.ResourceID, s.ResourceType, state, s.DefinitionID),
				labeled("Assignment", firstNonEmpty(s.AssignmentName, s.AssignmentID)), labeled("Initiative", s.SetDefinitionName),
				labeled("Effect", s.DefinitionAction), labeled("Category", s.DefinitionCategory), labeled("Evaluated", s.Timestamp),
				"Azure Policy reports no severity: deny effects are high, other effects medium.")}
		if strings.EqualFold(s.DefinitionAction, "deny") {
			f.Severity = "high"
		}
		if strings.EqualFold(state, "Exempt") {
			f.Confidence = "low"
			f.Description = joinText(f.Description, "Azure Policy verdict: exempt.")
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToLower(s.AssignmentID + "|" + s.DefinitionReference)), Raw: it})
	}
	return out, nil
}
