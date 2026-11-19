package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// AWS Security Hub findings in the AWS Security Finding Format (ASFF):
// `aws securityhub get-findings` output ({"Findings": [...]}) or an array
// of findings. Security Hub aggregates many products (its own controls,
// Inspector, GuardDuty, Config, partners). Findings whose compliance
// status is PASSED or whose record state is ARCHIVED are no longer active
// and are not imported. Suppressed and resolved workflow states are kept
// with the state in the description. Each finding keeps its own category:
// controls and other posture checks compliance, threat detections (types
// TTPs, Effects, Unusual Behaviors) runtime, package vulnerabilities sca or
// container.

type asffFinding struct {
	ID            string            `json:"Id"`
	ProductArn    string            `json:"ProductArn"`
	ProductName   string            `json:"ProductName"`
	GeneratorID   string            `json:"GeneratorId"`
	AwsAccountID  string            `json:"AwsAccountId"`
	Region        string            `json:"Region"`
	Types         []string          `json:"Types"`
	Title         string            `json:"Title"`
	Description   string            `json:"Description"`
	SourceURL     string            `json:"SourceUrl"`
	RecordState   string            `json:"RecordState"`
	ProductFields map[string]string `json:"ProductFields"`
	Severity      struct {
		Label      string  `json:"Label"`
		Normalized float64 `json:"Normalized"`
		Original   string  `json:"Original"`
	} `json:"Severity"`
	Remediation struct {
		Recommendation struct {
			Text string `json:"Text"`
			URL  string `json:"Url"`
		} `json:"Recommendation"`
	} `json:"Remediation"`
	Resources []struct {
		Type   string `json:"Type"`
		ID     string `json:"Id"`
		Region string `json:"Region"`
	} `json:"Resources"`
	Compliance struct {
		Status          string   `json:"Status"`
		SecurityControl string   `json:"SecurityControlId"`
		RelatedReqs     []string `json:"RelatedRequirements"`
	} `json:"Compliance"`
	Workflow struct {
		Status string `json:"Status"`
	} `json:"Workflow"`
	Vulnerabilities []struct {
		ID                 string `json:"Id"`
		VulnerablePackages []struct {
			Name           string `json:"Name"`
			Version        string `json:"Version"`
			Release        string `json:"Release"`
			FixedInVersion string `json:"FixedInVersion"`
			FilePath       string `json:"FilePath"`
		} `json:"VulnerablePackages"`
		Cvss []struct {
			Version    string  `json:"Version"`
			BaseScore  float64 `json:"BaseScore"`
			BaseVector string  `json:"BaseVector"`
		} `json:"Cvss"`
		FixAvailable string `json:"FixAvailable"`
	} `json:"Vulnerabilities"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "asff", Label: "AWS Security Hub findings (ASFF)", Tool: "AWS Security Hub", Media: "json", Order: 453,
		match: func(p *importProbe) bool {
			asff := func(m map[string]json.RawMessage) bool {
				return hasKeys(m, "SchemaVersion", "ProductArn", "AwsAccountId") && hasKeys(m, "GeneratorId")
			}
			switch p.kind {
			case "object":
				return asff(p.firstOf("Findings")) || (p.has("Findings") && len(p.keys) <= 2)
			case "array":
				return asff(p.keys)
			}
			return false
		},
		parse: parseASFF})
}

func parseASFF(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "Findings")
	if err == nil && items == nil {
		items, err = jsonArray(raw, "findings")
	}
	if err != nil {
		return nil, fmt.Errorf("asff: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var a asffFinding
		if err := json.Unmarshal(it, &a); err != nil || (a.ID == "" && a.GeneratorID == "") {
			return out, fmt.Errorf("asff: finding %d: expected an ASFF finding with Id", i+1)
		}
		if strings.EqualFold(a.Compliance.Status, "PASSED") || strings.EqualFold(a.RecordState, "ARCHIVED") {
			continue
		}
		out = append(out, asffRecord(a, it))
	}
	return out, nil
}

func asffRecord(a asffFinding, raw json.RawMessage) importRecord {
	res, rtype, region := "", "", a.Region
	if len(a.Resources) > 0 {
		res, rtype, region = a.Resources[0].ID, a.Resources[0].Type, firstNonEmpty(a.Resources[0].Region, region)
	}
	rule := firstNonEmpty(a.Compliance.SecurityControl, a.ProductFields["ControlId"], a.ProductFields["RuleId"], a.GeneratorID)
	f := Finding{Category: "compliance", RuleID: rule, Title: firstNonEmpty(a.Title, rule),
		Severity: normSeverity(a.Severity.Label), FilePath: cspmLocation(res, "aws", a.AwsAccountID, region)}
	if f.Severity == "" {
		// Normalized 0-100 (ASFF): 90+ critical, 70+ high, 40+ medium, 1+ low.
		switch n := a.Severity.Normalized; {
		case n >= 90:
			f.Severity = "critical"
		case n >= 70:
			f.Severity = "high"
		case n >= 40:
			f.Severity = "medium"
		case n >= 1:
			f.Severity = "low"
		}
	}
	for _, t := range a.Types {
		// GuardDuty and other threat detection findings.
		if strings.HasPrefix(t, "TTPs/") || strings.HasPrefix(t, "Effects/") || strings.HasPrefix(t, "Unusual Behaviors/") {
			f.Category = "runtime"
		}
	}
	vuln := ""
	if len(a.Vulnerabilities) > 0 {
		v := a.Vulnerabilities[0]
		vuln = v.ID
		f.CVE = firstMatch(cveRe, v.ID)
		f.Category = "sca"
		if strings.Contains(strings.ToLower(rtype), "containerimage") {
			f.Category = "container"
		}
		if len(v.VulnerablePackages) > 0 {
			pk := v.VulnerablePackages[0]
			f.PackageName, f.PackageVersion, f.FixedVersion = pk.Name, strings.Trim(pk.Version+"-"+pk.Release, "-"), pk.FixedInVersion
			if pk.Release == "" {
				f.PackageVersion = pk.Version
			}
		}
		for _, c := range v.Cvss {
			if c.BaseScore > 0 {
				f.CVSS, f.CVSSVector = floatPtr(c.BaseScore), c.BaseVector
				break
			}
		}
		if f.RuleID == a.GeneratorID {
			f.RuleID = firstNonEmpty(v.ID, f.RuleID)
		}
	}
	product := firstNonEmpty(a.ProductName, a.ProductFields["aws/securityhub/ProductName"], a.ProductArn)
	f.Description = joinText(a.Description, labelled("Remediation", a.Remediation.Recommendation.Text), labelled("Reference", firstNonEmpty(a.Remediation.Recommendation.URL, a.SourceURL)),
		labelled("Product", product), labelled("Resource type", rtype), labelled("Account", a.AwsAccountID), labelled("Region", region),
		labelled("Compliance status", a.Compliance.Status), labelled("Workflow status", a.Workflow.Status), labelled("Types", strings.Join(a.Types, ", ")))
	return importRecord{F: f, SnippetKey: hashOf(a.ID + "|" + vuln), Raw: raw}
}
