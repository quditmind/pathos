package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Rapid7 InsightVM Cloud Integrations API v4 assets (POST
// /vm/v4/integration/assets): {"data": [...], "metadata": {...}} with one
// asset per entry (id, host_name, ip, os_description, risk_score) and its
// vulnerability instances in new[] and same[] (vulnerability_id,
// check_id, port, protocol, proof, status, first_found, last_found);
// remediated[] instances are not findings, nor instances whose status is
// NOT_VULNERABLE. The assets endpoint carries no severity or title (they
// are in the separate vulnerabilities endpoint): findings are medium and
// titled with the vulnerability ID, whose CVE, when it names one, is
// kept. Instances with an EXCEPTION status have low confidence.

type insightVMInstance struct {
	VulnID    string          `json:"vulnerability_id"`
	CheckID   string          `json:"check_id"`
	Port      json.RawMessage `json:"port"`
	Protocol  string          `json:"protocol"`
	Proof     string          `json:"proof"`
	Status    string          `json:"status"`
	First     string          `json:"first_found"`
	Last      string          `json:"last_found"`
	Severity  string          `json:"severity"`
	Title     string          `json:"title"`
	Solution  string          `json:"solution_fix"`
	CVSS3     float64         `json:"cvss_v3_score"`
	Reference string          `json:"key"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "insightvm", Label: "Rapid7 InsightVM assets JSON (Cloud Integrations API v4)", Tool: "InsightVM", Media: "json", Order: 610,
		match: func(p *importProbe) bool {
			m := p.firstOf("data")
			return p.kind == "object" && hasKeys(m, "id") && (hasKeys(m, "new") || hasKeys(m, "same")) && (hasKeys(m, "host_name") || hasKeys(m, "ip"))
		},
		parse: parseInsightVM})
}

func parseInsightVM(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "data")
	if err != nil {
		return nil, fmt.Errorf("insightvm: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var a struct {
			ID       string            `json:"id"`
			HostName string            `json:"host_name"`
			IP       string            `json:"ip"`
			OS       string            `json:"os_description"`
			New      []json.RawMessage `json:"new"`
			Same     []json.RawMessage `json:"same"`
		}
		if err := json.Unmarshal(it, &a); err != nil {
			return out, fmt.Errorf("insightvm: asset %d: %w", i+1, err)
		}
		host := firstNonEmpty(a.HostName, a.IP, a.ID)
		for _, vr := range append(a.New, a.Same...) {
			var v insightVMInstance
			if err := json.Unmarshal(vr, &v); err != nil || v.VulnID == "" {
				return out, fmt.Errorf("insightvm: asset %s: expected vulnerability_id", host)
			}
			st := strings.ToUpper(v.Status)
			if st == "NOT_VULNERABLE" {
				continue
			}
			port := strings.Trim(string(v.Port), `"`)
			if port == "null" {
				port = ""
			}
			loc := host
			if port != "" && port != "0" {
				loc = hostLocation(host, port, v.Protocol)
			}
			f := Finding{Category: "sca", RuleID: v.VulnID, Title: firstNonEmpty(v.Title, v.VulnID), Severity: firstNonEmpty(normSeverity(v.Severity), "medium"),
				CVSS: floatPtr(v.CVSS3), FilePath: loc,
				Description: joinText(fmt.Sprintf("InsightVM vulnerability %s on %s (%s, %s): %s.", v.VulnID, host, a.IP, a.OS, v.Status),
					labeled("Proof", clipText(markupToText(v.Proof), 2000)), labeled("Fix", v.Solution), labeled("First found", v.First), labeled("Last found", v.Last))}
			if v.Severity == "" {
				f.Description = joinText(f.Description, "The assets endpoint reports no severity; the finding is medium (the InsightVM vulnerabilities endpoint has it).")
			}
			if strings.HasPrefix(st, "EXCEPTION") {
				f.Confidence = "low"
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(v.CheckID + "|" + v.Reference), Raw: vr})
		}
	}
	return out, nil
}
