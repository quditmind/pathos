package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Horusec JSON (`horusec start -o json -O report.json`): an analysis with
// analysisVulnerabilities[].vulnerabilities holding rule_id, severity
// (CRITICAL ... INFO, UNKNOWN), confidence, file, line, code, details
// (the text, with the CWE), language, securityTool and type
// (Vulnerability, Risk Accepted, False Positive, Corrected). Findings of
// the "Leaks" language are secrets: their code line holds the secret and is
// removed before the report is stored, and their identity is the rule,
// file and line. Other findings are identified by their code without
// whitespace. Records the user marked as false positive, accepted risk or
// corrected are imported with low confidence and the verdict noted.

type horusecVuln struct {
	RuleID       string      `json:"rule_id"`
	Line         looseString `json:"line"`
	Confidence   string      `json:"confidence"`
	File         string      `json:"file"`
	Code         string      `json:"code"`
	Details      string      `json:"details"`
	SecurityTool string      `json:"securityTool"`
	Language     string      `json:"language"`
	Severity     string      `json:"severity"`
	Type         string      `json:"type"`
	CommitHash   string      `json:"commitHash"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "horusec", Label: "Horusec JSON", Tool: "Horusec", Media: "json", Order: 105,
		match: func(p *importProbe) bool { return p.kind == "object" && p.has("analysisVulnerabilities") },
		parse: parseHorusecJSON, sanitize: sanitizeHorusec})
}

func horusecIsLeak(v map[string]any) bool {
	l, _ := v["language"].(string)
	return strings.EqualFold(l, "leaks")
}

// sanitizeHorusec removes the code line of secret (Leaks) findings.
func sanitizeHorusec(raw []byte) []byte {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	items, _ := doc["analysisVulnerabilities"].([]any)
	for _, it := range items {
		m, _ := it.(map[string]any)
		v, _ := m["vulnerabilities"].(map[string]any)
		if v != nil && horusecIsLeak(v) && v["code"] != nil && v["code"] != "" {
			v["code"] = "[REDACTED]"
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return b
}

func parseHorusecJSON(raw []byte) ([]importRecord, error) {
	var doc struct {
		Vulns []struct {
			Vulnerabilities json.RawMessage `json:"vulnerabilities"`
		} `json:"analysisVulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("horusec: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, av := range doc.Vulns {
		var v horusecVuln
		if err := json.Unmarshal(av.Vulnerabilities, &v); err != nil || (v.RuleID == "" && v.Details == "") {
			return out, fmt.Errorf("horusec: vulnerability %d: expected an object with rule_id", i+1)
		}
		line := 0
		_, _ = fmt.Sscan(string(v.Line), &line)
		title, _, _ := strings.Cut(strings.TrimSpace(v.Details), "\n")
		title = strings.TrimSpace(strings.TrimPrefix(title[strings.Index(title, ")")+1:], " * Possible vulnerability detected:"))
		f := Finding{Category: "sast", RuleID: firstNonEmpty(v.RuleID, title), Title: title, Severity: v.Severity,
			Confidence: strings.ToLower(v.Confidence), FilePath: NormalizePath(v.File), StartLine: intPtr(line),
			Description: joinText(v.Details, fmt.Sprintf("Horusec %s (%s).", v.SecurityTool, v.Language)), CWE: []string{v.Details}}
		raw := av.Vulnerabilities
		key := "code|" + codeIdentity(v.Code)
		if strings.EqualFold(v.Language, "leaks") {
			f.Category = "secrets"
			key = fmt.Sprintf("leak|%s|%d", v.CommitHash, line)
			raw = redactKeys(raw, "code")
		}
		switch t := strings.ToLower(v.Type); t {
		case "false positive", "risk accepted", "corrected":
			f.Confidence = "low"
			f.Description = "Horusec marks this result as " + t + "; it is kept for review.\n\n" + f.Description
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("horusec|" + key), Raw: raw})
	}
	return out, nil
}
