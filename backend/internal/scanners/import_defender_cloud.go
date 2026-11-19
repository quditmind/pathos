package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Microsoft Defender for Cloud security assessments (recommendations per
// resource): the REST API list response ({"value": [...]},
// Microsoft.Security/assessments, also with $expand=metadata), `az
// security assessment list` output (an array) and Azure Resource Graph
// rows of securityresources with that type. Unhealthy assessments are
// findings; Healthy and NotApplicable ones are not imported. Without
// metadata the severity is not in the export and findings are medium.

type defenderAssessment struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	Properties struct {
		DisplayName     string `json:"displayName"`
		ResourceDetails struct {
			Source      string `json:"source"`
			ID          string `json:"id"`
			MachineName string `json:"machineName"`
		} `json:"resourceDetails"`
		Status struct {
			Code        string `json:"code"`
			Cause       string `json:"cause"`
			Description string `json:"description"`
		} `json:"status"`
		Metadata struct {
			DisplayName            string   `json:"displayName"`
			Description            string   `json:"description"`
			RemediationDescription string   `json:"remediationDescription"`
			Severity               string   `json:"severity"`
			Categories             []string `json:"categories"`
			Threats                []string `json:"threats"`
		} `json:"metadata"`
		Links struct {
			AzurePortalURI string `json:"azurePortalUri"`
		} `json:"links"`
	} `json:"properties"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "defender-cloud", Label: "Microsoft Defender for Cloud assessments JSON", Tool: "Defender for Cloud", Category: "other", Media: "json", Order: 455,
		match: func(p *importProbe) bool {
			isAssessment := func(m map[string]json.RawMessage) bool {
				var t string
				return hasKeys(m, "id", "type", "properties") && json.Unmarshal(m["type"], &t) == nil &&
					strings.EqualFold(t, "Microsoft.Security/assessments")
			}
			switch p.kind {
			case "object":
				return isAssessment(p.firstOf("value")) || isAssessment(p.firstOf("data"))
			case "array":
				return isAssessment(p.keys)
			}
			return false
		},
		parse:    parseDefenderCloud,
		sanitize: func(raw []byte) []byte { return redactKeys(raw, "secret") }})
}

func parseDefenderCloud(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "value")
	if err == nil && items == nil {
		items, err = jsonArray(raw, "data") // Azure Resource Graph response
	}
	if err != nil {
		return nil, fmt.Errorf("defender-cloud: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var a defenderAssessment
		if err := json.Unmarshal(it, &a); err != nil || a.ID == "" {
			return out, fmt.Errorf("defender-cloud: assessment %d: expected an object with id", i+1)
		}
		if !strings.EqualFold(a.Properties.Status.Code, "Unhealthy") {
			continue
		}
		p := a.Properties
		res := firstNonEmpty(p.ResourceDetails.ID, p.ResourceDetails.MachineName)
		if res == "" {
			res, _, _ = strings.Cut(a.ID, "/providers/Microsoft.Security/assessments/")
		}
		f := Finding{Category: "misconfiguration", RuleID: firstNonEmpty(a.Name, p.DisplayName), Title: firstNonEmpty(p.DisplayName, p.Metadata.DisplayName, a.Name),
			Severity: normSeverity(p.Metadata.Severity), FilePath: cspmLocation(res, "azure", "", "")}
		note := ""
		if f.Severity == "" {
			f.Severity, note = "medium", "The export has no assessment metadata (severity); imported as medium."
		}
		f.Description = joinText(p.Metadata.Description, note, labelled("Status", strings.TrimSpace(p.Status.Cause+" "+p.Status.Description)),
			labelled("Remediation", markupToText(p.Metadata.RemediationDescription)), labelled("Categories", strings.Join(p.Metadata.Categories, ", ")),
			labelled("Threats", strings.Join(p.Metadata.Threats, ", ")), labelled("Portal", p.Links.AzurePortalURI))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToLower(res)), Raw: redactKeys(it, "secret")})
	}
	return out, nil
}
