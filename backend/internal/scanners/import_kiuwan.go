package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Kiuwan Code Security analysis defects (REST API GET
// /apps/analysis/{code}/defects or /applications/defects): an analysis
// object (name, analysisCode, defects_count) with defects[] (defectId,
// ruleCode, rule, priority Very High/High/Normal/Low/Very Low, language,
// characteristic, vulnerabilityType, file, line, code, cweId, muted,
// status). Security defects are sast, other characteristics
// code-quality. Muted defects are kept with low confidence. Kiuwan
// Insights (SCA) exports are the kiuwan-sca format.

func init() {
	registerImportFormat(ImportFormat{ID: "kiuwan", Label: "Kiuwan Code Security defects JSON (REST API)", Tool: "Kiuwan", Media: "json", Order: 612,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("defects"), "defectId", "ruleCode") && p.hasAny("analysisCode", "defects_count", "count")
		},
		parse: parseKiuwan})
	registerImportFormat(ImportFormat{ID: "kiuwan-sca", Label: "Kiuwan Insights (SCA) vulnerabilities JSON", Tool: "Kiuwan", Category: "sca", Media: "json", Order: 613,
		match: func(p *importProbe) bool {
			return p.kind == "array" && hasKeys(p.keys, "cve", "components", "securityRisk")
		},
		parse: parseKiuwanSCA})
}

func kiuwanSeverity(priority string) string {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "very high":
		return "critical"
	case "high":
		return "high"
	case "normal":
		return "medium"
	case "low":
		return "low"
	}
	return "info"
}

func parseKiuwan(raw []byte) ([]importRecord, error) {
	var doc struct {
		Name     string            `json:"name"`
		Analysis string            `json:"analysisCode"`
		Defects  []json.RawMessage `json:"defects"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("kiuwan: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, dr := range doc.Defects {
		var d struct {
			DefectID       json.Number `json:"defectId"`
			RuleCode       string      `json:"ruleCode"`
			Rule           string      `json:"rule"`
			Priority       string      `json:"priority"`
			Language       string      `json:"language"`
			Characteristic string      `json:"characteristic"`
			VulnType       string      `json:"vulnerabilityType"`
			File           string      `json:"file"`
			Line           int         `json:"line"`
			Code           string      `json:"code"`
			CWE            json.Number `json:"cweId"`
			Muted          bool        `json:"muted"`
			Status         string      `json:"status"`
			Explanation    string      `json:"explanation"`
		}
		if err := json.Unmarshal(dr, &d); err != nil || d.RuleCode == "" {
			return out, fmt.Errorf("kiuwan: defect %d: expected ruleCode", i+1)
		}
		cat := "code-quality"
		if strings.EqualFold(d.Characteristic, "Security") {
			cat = "sast"
		}
		f := Finding{Category: cat, RuleID: d.RuleCode, Title: firstNonEmpty(d.Rule, d.RuleCode), Severity: kiuwanSeverity(d.Priority),
			FilePath: NormalizePath(d.File), StartLine: intPtr(d.Line), CWE: []string{d.CWE.String()},
			Description: joinText(d.Explanation, fmt.Sprintf("Kiuwan rule %s (%s, %s, priority %s).", d.RuleCode, d.Language, d.Characteristic, d.Priority),
				labeled("Vulnerability type", d.VulnType), labeled("Status", d.Status))}
		if d.Muted {
			f.Confidence = "low"
			f.Description = joinText(f.Description, "Kiuwan verdict: muted.")
		}
		out = append(out, importRecord{F: f, SnippetKey: codeIdentity(d.Code), Raw: dr})
	}
	return out, nil
}

func parseKiuwanSCA(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("kiuwan sca: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var v struct {
			ID          json.Number `json:"id"`
			CVE         string      `json:"cve"`
			CWE         string      `json:"cwe"`
			Muted       bool        `json:"muted"`
			Risk        string      `json:"securityRisk"`
			CVSS3       looseString `json:"cVSSv3BaseScore"`
			CVSS2       looseString `json:"cVSSv2BaseScore"`
			Description string      `json:"description"`
			Components  []struct {
				Artifact string `json:"artifact"`
				Version  string `json:"version"`
			} `json:"components"`
		}
		if err := json.Unmarshal(it, &v); err != nil || v.CVE == "" {
			return out, fmt.Errorf("kiuwan sca: vulnerability %d: expected cve", i+1)
		}
		score := cvssOf(string(v.CVSS3))
		if score == nil {
			score = cvssOf(string(v.CVSS2))
		}
		if len(v.Components) == 0 {
			v.Components = append(v.Components, struct {
				Artifact string `json:"artifact"`
				Version  string `json:"version"`
			}{})
		}
		for _, c := range v.Components {
			f := Finding{Category: "sca", RuleID: v.CVE, CVE: v.CVE, CWE: []string{v.CWE}, Severity: normSeverity(v.Risk), CVSS: score,
				PackageName: c.Artifact, PackageVersion: c.Version, FilePath: c.Artifact, Title: fmt.Sprintf("%s in %s %s", v.CVE, c.Artifact, c.Version),
				Description: joinText(v.Description, labeled("Kiuwan security risk", v.Risk))}
			if v.Muted {
				f.Confidence = "low"
				f.Description = joinText(f.Description, "Kiuwan verdict: muted.")
			}
			out = append(out, importRecord{F: f, Raw: it})
		}
	}
	return out, nil
}
