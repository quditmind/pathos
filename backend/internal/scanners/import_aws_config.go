package scanners

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// AWS Config compliance JSON: `aws configservice
// get-compliance-details-by-config-rule` (and -by-resource):
// EvaluationResults[] with EvaluationResultIdentifier.
// EvaluationResultQualifier (ConfigRuleName, ResourceType, ResourceId),
// ComplianceType and Annotation; or `describe-compliance-by-resource`:
// ComplianceByResources[] (ResourceType, ResourceId,
// Compliance.ComplianceType, without the rule). NON_COMPLIANT results are
// findings; COMPLIANT, NOT_APPLICABLE and INSUFFICIENT_DATA are not. AWS
// Config has no severity: findings are medium. A finding is located at
// its resource (type/id).

func init() {
	registerImportFormat(ImportFormat{ID: "aws-config", Label: "AWS Config compliance JSON (get-compliance-details-by-config-rule, describe-compliance-by-resource)",
		Tool: "AWS Config", Category: "compliance", Media: "json", Order: 564,
		match: func(p *importProbe) bool {
			return p.kind == "object" && (hasKeys(p.firstOf("EvaluationResults"), "EvaluationResultIdentifier", "ComplianceType") ||
				hasKeys(p.firstOf("ComplianceByResources"), "ResourceId", "Compliance"))
		},
		parse: parseAWSConfig})
}

func parseAWSConfig(raw []byte) ([]importRecord, error) {
	var doc struct {
		EvaluationResults     []json.RawMessage `json:"EvaluationResults"`
		ComplianceByResources []json.RawMessage `json:"ComplianceByResources"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("aws config: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, er := range doc.EvaluationResults {
		var r struct {
			ID struct {
				Q struct {
					Rule         string `json:"ConfigRuleName"`
					ResourceType string `json:"ResourceType"`
					ResourceID   string `json:"ResourceId"`
				} `json:"EvaluationResultQualifier"`
			} `json:"EvaluationResultIdentifier"`
			ComplianceType string `json:"ComplianceType"`
			Annotation     string `json:"Annotation"`
		}
		if err := json.Unmarshal(er, &r); err != nil || r.ID.Q.Rule == "" {
			return out, fmt.Errorf("aws config: evaluation result %d: expected a ConfigRuleName", i+1)
		}
		if !strings.EqualFold(r.ComplianceType, "NON_COMPLIANT") {
			continue
		}
		res := strings.Trim(r.ID.Q.ResourceType+"/"+r.ID.Q.ResourceID, "/")
		out = append(out, importRecord{F: Finding{Category: "compliance", RuleID: r.ID.Q.Rule, Title: "AWS Config rule " + r.ID.Q.Rule + " is not met",
			Severity: "medium", FilePath: res,
			Description: joinText(fmt.Sprintf("The resource %s does not comply with the AWS Config rule %s.", res, r.ID.Q.Rule), labeled("Annotation", r.Annotation),
				"AWS Config reports no severity; the finding is medium.")}, Raw: er})
	}
	for i, cr := range doc.ComplianceByResources {
		var r struct {
			ResourceType string `json:"ResourceType"`
			ResourceID   string `json:"ResourceId"`
			Compliance   struct {
				ComplianceType string `json:"ComplianceType"`
				Contributors   struct {
					CappedCount int  `json:"CappedCount"`
					CapExceeded bool `json:"CapExceeded"`
				} `json:"ComplianceContributorCount"`
			} `json:"Compliance"`
		}
		if err := json.Unmarshal(cr, &r); err != nil || r.ResourceID == "" {
			return out, fmt.Errorf("aws config: resource %d: expected a ResourceId", i+1)
		}
		if !strings.EqualFold(r.Compliance.ComplianceType, "NON_COMPLIANT") {
			continue
		}
		res := strings.Trim(r.ResourceType+"/"+r.ResourceID, "/")
		n := fmt.Sprint(r.Compliance.Contributors.CappedCount)
		if r.Compliance.Contributors.CapExceeded {
			n += "+"
		}
		out = append(out, importRecord{F: Finding{Category: "compliance", RuleID: "NON_COMPLIANT " + r.ResourceType, Title: "Non-compliant resource " + res,
			Severity: "medium", FilePath: res,
			Description: joinText(fmt.Sprintf("AWS Config reports %s as NON_COMPLIANT with %s rule(s). This report does not name the rules: get-compliance-details-by-resource lists them.", res, n),
				"AWS Config reports no severity; the finding is medium.")}, Raw: cr})
	}
	if doc.EvaluationResults == nil && doc.ComplianceByResources == nil {
		return nil, errors.New("aws config: expected EvaluationResults or ComplianceByResources")
	}
	return out, nil
}
