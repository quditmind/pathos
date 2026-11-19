package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CrowdStrike Falcon Spotlight vulnerabilities (API
// /spotlight/combined/vulnerabilities/v1 with facet=cve, host_info and
// remediation): {"resources": [...]} where each resource is one CVE on one
// host: id, aid, status (open, reopen, closed, expired), apps[]
// (product_name_version), cve (id, base_score, severity, vector,
// description, cwes, exprt_rating, cisa_info), host_info (hostname,
// local_ip, os_version, platform) and remediation.entities[] (title,
// action, link). Closed and expired vulnerabilities are not findings.

type spotlightVuln struct {
	ID     string `json:"id"`
	AID    string `json:"aid"`
	Status string `json:"status"`
	Apps   []struct {
		ProductNameVersion string `json:"product_name_version"`
		ProductName        string `json:"product_name_normalized"`
	} `json:"apps"`
	CVE struct {
		ID          string   `json:"id"`
		BaseScore   float64  `json:"base_score"`
		Severity    string   `json:"severity"`
		Vector      string   `json:"vector"`
		Description string   `json:"description"`
		CWEs        []string `json:"cwes"`
		ExPRT       string   `json:"exprt_rating"`
		CISA        struct {
			IsKEV bool `json:"is_cisa_kev"`
		} `json:"cisa_info"`
	} `json:"cve"`
	Host struct {
		Hostname  string `json:"hostname"`
		LocalIP   string `json:"local_ip"`
		OSVersion string `json:"os_version"`
	} `json:"host_info"`
	Remediation struct {
		Entities []struct {
			Title  string `json:"title"`
			Action string `json:"action"`
			Link   string `json:"link"`
		} `json:"entities"`
	} `json:"remediation"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "crowdstrike-spotlight", Label: "CrowdStrike Falcon Spotlight vulnerabilities JSON (combined API)", Tool: "CrowdStrike Spotlight",
		Category: "sca", Media: "json", Order: 606,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("resources"), "aid", "cve") && p.headHas(`"host_info"`)
		},
		parse: parseSpotlight})
}

func parseSpotlight(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "resources")
	if err != nil {
		return nil, fmt.Errorf("crowdstrike spotlight: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var v spotlightVuln
		if err := json.Unmarshal(it, &v); err != nil || v.CVE.ID == "" {
			return out, fmt.Errorf("crowdstrike spotlight: resource %d: expected cve.id", i+1)
		}
		if st := strings.ToLower(v.Status); st == "closed" || st == "expired" {
			continue
		}
		f := Finding{Category: "sca", RuleID: v.CVE.ID, CVE: v.CVE.ID, Severity: v.CVE.Severity, CVSS: floatPtr(v.CVE.BaseScore), CVSSVector: v.CVE.Vector,
			CWE: v.CVE.CWEs, FilePath: firstNonEmpty(v.Host.Hostname, v.Host.LocalIP, v.AID)}
		var apps, rem []string
		for _, a := range v.Apps {
			apps = append(apps, a.ProductNameVersion)
		}
		if len(v.Apps) > 0 {
			f.PackageName = firstNonEmpty(v.Apps[0].ProductName, v.Apps[0].ProductNameVersion)
		}
		for _, e := range v.Remediation.Entities {
			rem = append(rem, strings.TrimSpace(firstNonEmpty(e.Action, e.Title)+" "+e.Link))
		}
		f.Title = strings.TrimSpace(fmt.Sprintf("%s in %s", v.CVE.ID, strings.Join(apps, ", ")))
		f.Description = joinText(v.CVE.Description, fmt.Sprintf("Host %s (%s, %s).", f.FilePath, v.Host.LocalIP, v.Host.OSVersion),
			labeled("Remediation", strings.Join(rem, "\n")), labeled("ExPRT rating", v.CVE.ExPRT), "Spotlight status: "+v.Status)
		if v.CVE.CISA.IsKEV {
			f.Description = joinText(f.Description, "Listed in the CISA Known Exploited Vulnerabilities catalog.")
		}
		out = append(out, importRecord{F: f, Raw: it})
	}
	return out, nil
}
