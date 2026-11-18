package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SonarQube issues API JSON (`/api/issues/search`) and the security
// hotspots API (`/api/hotspots/search`). Components are "<project>:<path>".
// CLOSED issues no longer exist in the code and are not imported; every
// other status is, and SonarQube resolutions are only shown in the
// description, never applied. The report carries no CWE identifiers (only
// tags such as "cwe"), so CWE is set only when a tag names one.

type sonarIssue struct {
	Key       string `json:"key"`
	Rule      string `json:"rule"`
	RuleKey   string `json:"ruleKey"`
	Severity  string `json:"severity"`
	Component string `json:"component"`
	Line      int    `json:"line"`
	TextRange *struct {
		StartLine int `json:"startLine"`
		EndLine   int `json:"endLine"`
	} `json:"textRange"`
	Message    string   `json:"message"`
	Type       string   `json:"type"`
	Status     string   `json:"status"`
	Resolution string   `json:"resolution"`
	Tags       []string `json:"tags"`
	Impacts    []struct {
		SoftwareQuality string `json:"softwareQuality"`
		Severity        string `json:"severity"`
	} `json:"impacts"`
	// Hotspots.
	SecurityCategory         string `json:"securityCategory"`
	VulnerabilityProbability string `json:"vulnerabilityProbability"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "sonarqube", Label: "SonarQube issues JSON", Category: "sast", Media: "json", Order: 42,
		match: func(p *importProbe) bool {
			if p.kind != "object" {
				return false
			}
			if p.has("issues") && hasKeys(p.firstOf("issues"), "rule", "component") {
				return true
			}
			return p.has("hotspots") && hasKeys(p.firstOf("hotspots"), "component", "vulnerabilityProbability")
		},
		parse: parseSonarJSON})
}

// sonarSeverity maps Sonar's legacy severities (BLOCKER..INFO, where
// CRITICAL is one step below BLOCKER) and impact/probability severities.
func sonarSeverity(s string) string {
	switch strings.ToUpper(s) {
	case "BLOCKER":
		return "critical"
	case "CRITICAL", "HIGH":
		return "high"
	case "MAJOR", "MEDIUM":
		return "medium"
	case "MINOR", "LOW":
		return "low"
	case "INFO":
		return "info"
	}
	return ""
}

func parseSonarJSON(raw []byte) ([]importRecord, error) {
	var doc struct {
		Issues   []json.RawMessage `json:"issues"`
		Hotspots []json.RawMessage `json:"hotspots"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("sonarqube: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, it := range append(doc.Issues, doc.Hotspots...) {
		var is sonarIssue
		if err := json.Unmarshal(it, &is); err != nil {
			return out, fmt.Errorf("sonarqube: invalid issue: %w", err)
		}
		rule := firstNonEmpty(is.Rule, is.RuleKey)
		if rule == "" {
			return out, fmt.Errorf("sonarqube: issue %q has no rule", is.Key)
		}
		if strings.EqualFold(is.Status, "CLOSED") {
			continue
		}
		path := is.Component
		if _, p, ok := strings.Cut(is.Component, ":"); ok {
			path = p
		}
		f := Finding{RuleID: rule, Title: firstNonEmpty(is.Message, rule), FilePath: NormalizePath(path), CWE: is.Tags}
		start, end := is.Line, 0
		if is.TextRange != nil {
			start, end = max(start, is.TextRange.StartLine), is.TextRange.EndLine
		}
		f.StartLine, f.EndLine = intPtr(start), intPtr(end)
		// Impacts (SonarQube 10+) are more precise than the legacy severity.
		for _, im := range is.Impacts {
			if s := sonarSeverity(im.Severity); s != "" && (f.Severity == "" || SeverityRank(s) > SeverityRank(f.Severity)) {
				f.Severity = s
			}
		}
		if f.Severity == "" {
			f.Severity = sonarSeverity(is.Severity)
		}
		kind := is.Type
		if is.VulnerabilityProbability != "" {
			kind = "SECURITY_HOTSPOT"
			f.Severity = sonarSeverity(is.VulnerabilityProbability)
			f.Confidence = "low" // a hotspot needs review by definition
		}
		switch kind {
		case "VULNERABILITY", "SECURITY_HOTSPOT":
			f.Category = "sast"
		default:
			f.Category = "other"
		}
		desc := []string{is.Message, "Type: " + strings.ToLower(strings.ReplaceAll(kind, "_", " "))}
		if is.SecurityCategory != "" {
			desc = append(desc, "Security category: "+is.SecurityCategory)
		}
		if is.Status != "" {
			desc = append(desc, "SonarQube status: "+strings.TrimSpace(is.Status+" "+is.Resolution))
		}
		f.Description = strings.Join(desc, "\n")
		out = append(out, importRecord{F: f, SnippetKey: hashOf(firstNonEmpty(is.Key, is.Message)), Raw: it})
	}
	return out, nil
}
