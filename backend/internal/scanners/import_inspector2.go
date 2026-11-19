package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Amazon Inspector (v2) findings: `aws inspector2 list-findings` output
// ({"findings": [...]}) or the findings array (`--query findings`).
// Package vulnerabilities (container for ECR images, sca otherwise), code
// vulnerabilities of Lambda functions (sast) and network reachability
// findings. CLOSED findings are no longer present and are not imported;
// SUPPRESSED ones are kept with low confidence.

type inspector2Finding struct {
	FindingArn     string  `json:"findingArn"`
	AwsAccountID   string  `json:"awsAccountId"`
	Type           string  `json:"type"`
	Title          string  `json:"title"`
	Description    string  `json:"description"`
	Severity       string  `json:"severity"`
	Status         string  `json:"status"`
	InspectorScore float64 `json:"inspectorScore"`
	FixAvailable   string  `json:"fixAvailable"`
	Remediation    struct {
		Recommendation struct {
			Text string `json:"text"`
			URL  string `json:"Url"`
		} `json:"recommendation"`
	} `json:"remediation"`
	Resources []struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Region string `json:"region"`
	} `json:"resources"`
	PackageVulnerabilityDetails *struct {
		VulnerabilityID    string `json:"vulnerabilityId"`
		SourceURL          string `json:"sourceUrl"`
		VulnerablePackages []struct {
			Name           string `json:"name"`
			Version        string `json:"version"`
			Release        string `json:"release"`
			FixedInVersion string `json:"fixedInVersion"`
			FilePath       string `json:"filePath"`
		} `json:"vulnerablePackages"`
		Cvss []struct {
			BaseScore     float64 `json:"baseScore"`
			ScoringVector string  `json:"scoringVector"`
		} `json:"cvss"`
	} `json:"packageVulnerabilityDetails"`
	CodeVulnerabilityDetails *struct {
		Cwes         []string `json:"cwes"`
		DetectorID   string   `json:"detectorId"`
		DetectorName string   `json:"detectorName"`
		RuleID       string   `json:"ruleId"`
		FilePath     struct {
			FileName  string `json:"fileName"`
			FilePath  string `json:"filePath"`
			StartLine int    `json:"startLine"`
			EndLine   int    `json:"endLine"`
		} `json:"filePath"`
	} `json:"codeVulnerabilityDetails"`
	NetworkReachabilityDetails *struct {
		Protocol      string `json:"protocol"`
		OpenPortRange struct {
			Begin int `json:"begin"`
			End   int `json:"end"`
		} `json:"openPortRange"`
	} `json:"networkReachabilityDetails"`
	InspectorScoreDetails struct {
		AdjustedCvss struct {
			ScoringVector string `json:"scoringVector"`
		} `json:"adjustedCvss"`
	} `json:"inspectorScoreDetails"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "inspector2", Label: "Amazon Inspector findings JSON", Tool: "Amazon Inspector", Category: "other", Media: "json", Order: 454,
		match: func(p *importProbe) bool {
			ins := func(m map[string]json.RawMessage) bool {
				return hasKeys(m, "findingArn", "awsAccountId", "type", "resources") &&
					(hasKeys(m, "packageVulnerabilityDetails") || hasKeys(m, "codeVulnerabilityDetails") || hasKeys(m, "networkReachabilityDetails"))
			}
			switch p.kind {
			case "object":
				return ins(p.firstOf("findings"))
			case "array":
				return ins(p.keys)
			}
			return false
		},
		parse: parseInspector2})
}

func parseInspector2(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "findings")
	if err != nil {
		return nil, fmt.Errorf("inspector2: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var a inspector2Finding
		if err := json.Unmarshal(it, &a); err != nil || a.FindingArn == "" {
			return out, fmt.Errorf("inspector2: finding %d: expected an object with findingArn", i+1)
		}
		if strings.EqualFold(a.Status, "CLOSED") {
			continue
		}
		res, rtype, region := "", "", ""
		if len(a.Resources) > 0 {
			res, rtype, region = a.Resources[0].ID, a.Resources[0].Type, a.Resources[0].Region
		}
		f := Finding{Category: "other", RuleID: a.Type, Title: firstNonEmpty(a.Title, a.Type), Severity: normSeverity(a.Severity),
			FilePath: cspmLocation(res, "aws", a.AwsAccountID, region), CVSS: floatPtr(a.InspectorScore)}
		if f.Severity == "" && strings.EqualFold(a.Severity, "UNTRIAGED") {
			f.Severity = "info"
		}
		key := ""
		if d := a.PackageVulnerabilityDetails; d != nil {
			f.Category, f.RuleID, f.CVE = "sca", firstNonEmpty(d.VulnerabilityID, f.RuleID), firstMatch(cveRe, d.VulnerabilityID)
			if strings.Contains(strings.ToUpper(rtype), "CONTAINER_IMAGE") {
				f.Category = "container"
			}
			if len(d.VulnerablePackages) > 0 {
				pk := d.VulnerablePackages[0]
				f.PackageName, f.PackageVersion, f.FixedVersion = pk.Name, pk.Version, pk.FixedInVersion
				if pk.Release != "" {
					f.PackageVersion += "-" + pk.Release
				}
			}
			for _, c := range d.Cvss {
				if c.BaseScore > 0 && f.CVSS == nil {
					f.CVSS = floatPtr(c.BaseScore)
				}
			}
			key = d.VulnerabilityID
		}
		f.CVSSVector = a.InspectorScoreDetails.AdjustedCvss.ScoringVector
		if d := a.CodeVulnerabilityDetails; d != nil {
			f.Category, f.RuleID, f.CWE = "sast", firstNonEmpty(d.RuleID, d.DetectorID, f.RuleID), d.Cwes
			f.FilePath = NormalizePath(firstNonEmpty(d.FilePath.FilePath, d.FilePath.FileName, f.FilePath))
			f.StartLine, f.EndLine = intPtr(d.FilePath.StartLine), intPtr(d.FilePath.EndLine)
			key = res
		}
		port := ""
		if d := a.NetworkReachabilityDetails; d != nil {
			f.Category = "other"
			port = fmt.Sprintf("%s %d-%d", d.Protocol, d.OpenPortRange.Begin, d.OpenPortRange.End)
			key = port
		}
		note := ""
		if strings.EqualFold(a.Status, "SUPPRESSED") {
			f.Confidence, note = "low", "Amazon Inspector reports this finding as suppressed; it is kept for review."
		}
		f.Description = joinText(note, a.Description, labelled("Remediation", a.Remediation.Recommendation.Text),
			labelled("Resource", res), labelled("Resource type", rtype), labelled("Account", a.AwsAccountID), labelled("Region", region),
			labelled("Open ports", port), labelled("Fix available", a.FixAvailable))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(a.FindingArn + "|" + key), Raw: it})
	}
	return out, nil
}
