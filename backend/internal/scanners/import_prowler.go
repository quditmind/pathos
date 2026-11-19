package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Prowler (AWS, Azure, GCP, Kubernetes posture checks): the OCSF JSON
// output (`-M json-ocsf`, Prowler 4 and 5), the native JSON of Prowler 3
// (`-M json`) and the CSV output (`-M csv`, semicolon separated). One
// finding per failed check and resource; PASS and MANUAL results are
// checks, not findings, and are not imported. Muted results are imported
// with low confidence. Prowler imports are compliance
// findings (natural category misconfiguration).

type prowlerOCSF struct {
	Message  string `json:"message"`
	Metadata struct {
		EventCode string `json:"event_code"`
		Product   struct {
			Name string `json:"name"`
		} `json:"product"`
	} `json:"metadata"`
	Severity     string `json:"severity"`
	Status       string `json:"status"`
	StatusCode   string `json:"status_code"`
	StatusDetail string `json:"status_detail"`
	FindingInfo  struct {
		UID   string   `json:"uid"`
		Title string   `json:"title"`
		Desc  string   `json:"desc"`
		Types []string `json:"types"`
	} `json:"finding_info"`
	Resources []struct {
		UID    string `json:"uid"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Region string `json:"region"`
	} `json:"resources"`
	Cloud struct {
		Account struct {
			UID string `json:"uid"`
		} `json:"account"`
		Provider string `json:"provider"`
		Region   string `json:"region"`
	} `json:"cloud"`
	Remediation struct {
		Desc       string   `json:"desc"`
		References []string `json:"references"`
	} `json:"remediation"`
	RiskDetails string `json:"risk_details"`
	Unmapped    struct {
		Compliance map[string][]string `json:"compliance"`
		RelatedURL string              `json:"related_url"`
	} `json:"unmapped"`
}

type prowlerV3 struct {
	CheckID        string `json:"CheckID"`
	CheckTitle     string `json:"CheckTitle"`
	Provider       string `json:"Provider"`
	ServiceName    string `json:"ServiceName"`
	Status         string `json:"Status"`
	StatusExtended string `json:"StatusExtended"`
	Muted          bool   `json:"Muted"`
	Severity       string `json:"Severity"`
	ResourceType   string `json:"ResourceType"`
	ResourceID     string `json:"ResourceId"`
	ResourceArn    string `json:"ResourceArn"`
	AccountID      string `json:"AccountId"`
	Region         string `json:"Region"`
	Description    string `json:"Description"`
	Risk           string `json:"Risk"`
	Remediation    struct {
		Recommendation struct {
			Text string `json:"Text"`
			URL  string `json:"Url"`
		} `json:"Recommendation"`
	} `json:"Remediation"`
	Compliance map[string][]string `json:"Compliance"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "prowler", Label: "Prowler JSON (OCSF, or Prowler 3 JSON)", Tool: "Prowler", Category: "compliance", Media: "json", Order: 450,
		match: func(p *importProbe) bool {
			if p.kind != "array" {
				return false
			}
			return p.has("finding_info", "metadata", "status_code", "cloud") || p.has("CheckID", "CheckTitle", "StatusExtended", "ServiceName")
		},
		parse: parseProwlerJSON})
	registerImportFormat(ImportFormat{ID: "prowler-csv", Label: "Prowler CSV", Tool: "Prowler", Category: "compliance", Media: "csv", Order: 451,
		match: func(p *importProbe) bool {
			return p.kind == "csv" && headerHas(p.header, "check_id", "check_title", "status", "severity", "provider") &&
				(headerHas(p.header, "resource_uid") || headerHas(p.header, "resource_id") || headerHas(p.header, "resource_arn"))
		},
		parse: parseProwlerCSV})
}

// cspmLocation is the location of a cloud posture finding: the resource
// (ARN, resource ID), else the account and region.
func cspmLocation(resource, provider, account, region string) string {
	if r := strings.TrimSpace(resource); r != "" {
		return r
	}
	var parts []string
	for _, p := range []string{provider, account, region} {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	return firstNonEmpty(strings.Join(parts, "/"), "cloud")
}

// complianceText lists the compliance requirements a check maps to.
func complianceText(c map[string][]string) string {
	keys := make([]string, 0, len(c))
	for k := range c {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+": "+strings.Join(c[k], ", "))
	}
	return clipText(strings.Join(parts, "; "), 2000)
}

func parseProwlerJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("prowler: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var probe map[string]json.RawMessage
		if json.Unmarshal(it, &probe) != nil {
			return out, fmt.Errorf("prowler: finding %d: expected an object", i+1)
		}
		if _, ocsf := probe["finding_info"]; ocsf {
			var o prowlerOCSF
			if err := json.Unmarshal(it, &o); err != nil || firstNonEmpty(o.Metadata.EventCode, o.FindingInfo.Title) == "" {
				return out, fmt.Errorf("prowler: finding %d: expected an OCSF detection finding with metadata.event_code", i+1)
			}
			if !strings.EqualFold(o.StatusCode, "FAIL") {
				continue
			}
			res, rtype, region := "", "", o.Cloud.Region
			if len(o.Resources) > 0 {
				res, rtype, region = firstNonEmpty(o.Resources[0].UID, o.Resources[0].Name), o.Resources[0].Type, firstNonEmpty(o.Resources[0].Region, region)
			}
			muted := strings.EqualFold(o.Status, "Suppressed")
			out = append(out, prowlerRecord(o.Metadata.EventCode, o.FindingInfo.Title, o.Severity, firstNonEmpty(o.StatusDetail, o.Message),
				o.FindingInfo.Desc, o.RiskDetails, o.Remediation.Desc, o.Unmapped.RelatedURL, complianceText(o.Unmapped.Compliance),
				res, rtype, o.Cloud.Provider, o.Cloud.Account.UID, region, muted, it))
			continue
		}
		var v prowlerV3
		if err := json.Unmarshal(it, &v); err != nil || v.CheckID == "" {
			return out, fmt.Errorf("prowler: finding %d: expected an object with CheckID", i+1)
		}
		if !strings.EqualFold(v.Status, "FAIL") {
			continue
		}
		out = append(out, prowlerRecord(v.CheckID, v.CheckTitle, v.Severity, v.StatusExtended, v.Description, v.Risk,
			v.Remediation.Recommendation.Text, v.Remediation.Recommendation.URL, complianceText(v.Compliance),
			firstNonEmpty(v.ResourceArn, v.ResourceID), v.ResourceType, v.Provider, v.AccountID, v.Region, v.Muted, it))
	}
	return out, nil
}

func parseProwlerCSV(raw []byte) ([]importRecord, error) {
	_, rows, err := csvTable(raw)
	if err != nil && len(rows) == 0 {
		return nil, fmt.Errorf("prowler: %w", err)
	}
	var out []importRecord
	for _, r := range rows {
		check := r.get("check_id")
		if check == "" {
			return out, fmt.Errorf("prowler: row %d: CHECK_ID is empty", r.N)
		}
		if !strings.EqualFold(r.get("status"), "FAIL") {
			continue
		}
		muted := strings.EqualFold(r.get("muted"), "true")
		out = append(out, prowlerRecord(check, r.get("check_title"), r.get("severity"), r.get("status_extended"), r.get("description"),
			r.get("risk"), r.get("remediation_recommendation_text"), firstNonEmpty(r.get("remediation_recommendation_url"), r.get("related_url")),
			clipText(r.get("compliance"), 2000), r.get("resource_uid", "resource_arn", "resource_id", "resource_name"), r.get("resource_type"),
			r.get("provider"), r.get("account_uid", "account_id"), r.get("region"), muted, rawJSON(r.Orig)))
	}
	return out, err
}

func prowlerRecord(check, title, sev, status, desc, risk, remediation, url, compliance, resource, rtype, provider, account, region string, muted bool, raw json.RawMessage) importRecord {
	f := Finding{Category: "misconfiguration", RuleID: check, Title: firstNonEmpty(title, check), Severity: normSeverity(sev),
		FilePath: cspmLocation(resource, provider, account, region)}
	note := ""
	if muted {
		f.Confidence, note = "low", "Prowler reports this result as muted; it is kept for review."
	}
	f.Description = joinText(note, status, desc, labelled("Risk", risk), labelled("Remediation", remediation), labelled("Reference", url),
		labelled("Resource type", rtype), labelled("Account", account), labelled("Region", region), labelled("Compliance", compliance))
	return importRecord{F: f, SnippetKey: hashOf(account + "|" + region + "|" + resource), Raw: raw}
}
