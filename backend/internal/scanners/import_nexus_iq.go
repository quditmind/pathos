package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Sonatype Nexus IQ (Lifecycle) report JSON, two published shapes of the
// Report REST API (GET /api/v2/applications/{id}/reports/{reportId}/...):
//   - raw: components[] with componentIdentifier (coordinates), packageUrl,
//     pathnames and securityData.securityIssues[] (source, reference: the
//     CVE or sonatype id, severity: the CVSS score, threatCategory, cwe,
//     url, status);
//   - policy: components[] with violations[] (policyName,
//     policyThreatCategory SECURITY, LICENSE, QUALITY or OTHER,
//     policyThreatLevel 0-10, waived, grandfathered, constraints[] with
//     conditions[].conditionReason).
// Security issues and SECURITY violations are sca findings, LICENSE
// violations license findings, other violations "other" (natural
// categories, used when the import category is "other"). Threat levels
// map to severities as in Nexus IQ: 8-10 critical, 4-7 high (Nexus
// "severe"), 2-3 medium, 1 low, 0 info. Waived and grandfathered
// violations, and issues whose status is not Open, have low confidence.

type nexusComponent struct {
	Hash                string `json:"hash"`
	DisplayName         string `json:"displayName"`
	PackageURL          string `json:"packageUrl"`
	ComponentIdentifier struct {
		Format      string            `json:"format"`
		Coordinates map[string]string `json:"coordinates"`
	} `json:"componentIdentifier"`
	Pathnames    []string `json:"pathnames"`
	SecurityData *struct {
		SecurityIssues []struct {
			Source         string      `json:"source"`
			Reference      string      `json:"reference"`
			Severity       float64     `json:"severity"`
			Status         string      `json:"status"`
			URL            string      `json:"url"`
			ThreatCategory string      `json:"threatCategory"`
			CWE            looseString `json:"cwe"`
		} `json:"securityIssues"`
	} `json:"securityData"`
	Violations []struct {
		PolicyName           string `json:"policyName"`
		PolicyThreatCategory string `json:"policyThreatCategory"`
		PolicyThreatLevel    int    `json:"policyThreatLevel"`
		PolicyViolationID    string `json:"policyViolationId"`
		Waived               bool   `json:"waived"`
		Grandfathered        bool   `json:"grandfathered"`
		Constraints          []struct {
			ConstraintName string `json:"constraintName"`
			Conditions     []struct {
				ConditionSummary string `json:"conditionSummary"`
				ConditionReason  string `json:"conditionReason"`
			} `json:"conditions"`
		} `json:"constraints"`
	} `json:"violations"`
}

func isNexusComponent(m map[string]json.RawMessage) bool {
	return hasKeys(m, "componentIdentifier") && (hasKeys(m, "securityData") || hasKeys(m, "violations"))
}

func init() {
	registerImportFormat(ImportFormat{ID: "nexus-iq", Label: "Sonatype Nexus IQ report JSON (raw or policy)", Tool: "Sonatype Nexus IQ", Category: "sca", Media: "json", Order: 203,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("components") && isNexusComponent(p.firstOf("components"))
		},
		parse: parseNexusIQ})
}

func nexusThreatSeverity(level int) string {
	switch {
	case level >= 8:
		return "critical"
	case level >= 4:
		return "high"
	case level >= 2:
		return "medium"
	case level == 1:
		return "low"
	}
	return "info"
}

func parseNexusIQ(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "components")
	if err != nil {
		return nil, fmt.Errorf("nexus iq: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var c nexusComponent
		if err := json.Unmarshal(it, &c); err != nil {
			return out, fmt.Errorf("nexus iq: component %d: invalid", i+1)
		}
		co := c.ComponentIdentifier.Coordinates
		name := firstNonEmpty(co["artifactId"], co["packageId"], co["name"])
		version := co["version"]
		if pn, pv := purlNameVersion(c.PackageURL); pn != "" {
			name, version = firstNonEmpty(name, pn), firstNonEmpty(version, pv)
		}
		if name == "" {
			return out, fmt.Errorf("nexus iq: component %d: no coordinates or packageUrl", i+1)
		}
		file := ""
		if len(c.Pathnames) > 0 {
			file = NormalizePath(c.Pathnames[0])
		}
		where := joinText("Component: "+firstNonEmpty(c.PackageURL, c.DisplayName, name+" "+version), strings.Join(c.Pathnames, "\n"))
		if c.SecurityData != nil {
			for _, s := range c.SecurityData.SecurityIssues {
				if s.Reference == "" {
					return out, fmt.Errorf("nexus iq: %s: security issue without reference", name)
				}
				f := Finding{Category: "sca", RuleID: s.Reference, CVE: firstMatch(cveRe, s.Reference), PackageName: name, PackageVersion: version,
					FilePath: file, CVSS: floatPtr(s.Severity), Severity: normSeverity(s.ThreatCategory), CWE: []string{string(s.CWE)}}
				if f.CVSS != nil {
					f.Severity = FromScore(*f.CVSS)
				}
				f.Title = fmt.Sprintf("%s in %s %s", s.Reference, name, version)
				desc := []string{"Source: " + s.Source + "; threat category: " + s.ThreatCategory + "; status: " + s.Status, s.URL, where}
				if s.Status != "" && !strings.EqualFold(s.Status, "Open") {
					f.Confidence = "low"
				}
				f.Description = joinText(desc...)
				out = append(out, importRecord{F: f, Raw: rawJSON(map[string]any{"packageUrl": c.PackageURL, "componentIdentifier": c.ComponentIdentifier, "securityIssue": s})})
			}
		}
		for _, v := range c.Violations {
			var reasons []string
			for _, ct := range v.Constraints {
				for _, cd := range ct.Conditions {
					reasons = append(reasons, ct.ConstraintName+": "+firstNonEmpty(cd.ConditionReason, cd.ConditionSummary))
				}
			}
			f := Finding{PackageName: name, PackageVersion: version, FilePath: file, Severity: nexusThreatSeverity(v.PolicyThreatLevel)}
			switch strings.ToUpper(v.PolicyThreatCategory) {
			case "SECURITY":
				f.Category = "sca"
			case "LICENSE":
				f.Category = "license"
			default:
				f.Category = "other"
			}
			f.CVE = firstMatch(cveRe, reasons...)
			f.RuleID = firstNonEmpty(f.CVE, "nexus-policy-"+v.PolicyName)
			if f.Category != "sca" {
				f.RuleID = "nexus-policy-" + v.PolicyName
			}
			f.Title = fmt.Sprintf("Policy %s violated by %s %s", v.PolicyName, name, version)
			if f.CVE != "" {
				f.Title = fmt.Sprintf("%s in %s %s (policy %s)", f.CVE, name, version, v.PolicyName)
			}
			desc := []string{strings.Join(reasons, "\n"), fmt.Sprintf("Policy threat category %s, level %d", v.PolicyThreatCategory, v.PolicyThreatLevel), where}
			if v.Waived || v.Grandfathered {
				f.Confidence = "low"
				desc = append(desc, fmt.Sprintf("Waived: %t; grandfathered: %t", v.Waived, v.Grandfathered))
			}
			f.Description = joinText(desc...)
			out = append(out, importRecord{F: f, SnippetKey: hashOf(v.PolicyName + "|" + strings.Join(reasons, "|")),
				Raw: rawJSON(map[string]any{"packageUrl": c.PackageURL, "componentIdentifier": c.ComponentIdentifier, "violation": v})})
		}
	}
	return out, nil
}
