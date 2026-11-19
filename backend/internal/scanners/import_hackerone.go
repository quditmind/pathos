package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// HackerOne reports: the API JSON (GET /v1/reports, {"data": [...]} of
// type "report" with attributes and relationships) and the program's
// report CSV export. Resolved reports are fixed and not imported;
// reports closed as duplicate, informative, not applicable or spam are
// kept with low confidence and the verdict in the description. Report
// texts are written by researchers and may contain requests with session
// cookies or tokens: these are redacted before the report is stored.

type h1Report struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Attributes struct {
		Title                    string `json:"title"`
		State                    string `json:"state"`
		Substate                 string `json:"substate"`
		CreatedAt                string `json:"created_at"`
		VulnerabilityInformation string `json:"vulnerability_information"`
		Impact                   string `json:"impact"`
	} `json:"attributes"`
	Relationships struct {
		Severity struct {
			Data struct {
				Attributes struct {
					Rating string  `json:"rating"`
					Score  float64 `json:"score"`
				} `json:"attributes"`
			} `json:"data"`
		} `json:"severity"`
		Weakness struct {
			Data struct {
				Attributes struct {
					Name       string `json:"name"`
					ExternalID string `json:"external_id"`
				} `json:"attributes"`
			} `json:"data"`
		} `json:"weakness"`
		StructuredScope struct {
			Data struct {
				Attributes struct {
					AssetIdentifier string `json:"asset_identifier"`
					AssetType       string `json:"asset_type"`
				} `json:"attributes"`
			} `json:"data"`
		} `json:"structured_scope"`
		Program struct {
			Data struct {
				Attributes struct {
					Handle string `json:"handle"`
				} `json:"attributes"`
			} `json:"data"`
		} `json:"program"`
	} `json:"relationships"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "hackerone", Label: "HackerOne reports API JSON", Tool: "HackerOne", Category: "other", Media: "json", Order: 480,
		match: func(p *importProbe) bool {
			if p.kind != "object" {
				return false
			}
			r := p.firstOf("data")
			var t string
			return hasKeys(r, "id", "type", "attributes", "relationships") && json.Unmarshal(r["type"], &t) == nil && t == "report"
		},
		parse:    parseHackerOneJSON,
		sanitize: sanitizeHTTPJSON})
	registerImportFormat(ImportFormat{ID: "hackerone-csv", Label: "HackerOne reports CSV", Tool: "HackerOne", Category: "other", Media: "csv", Order: 481,
		match: func(p *importProbe) bool {
			return p.kind == "csv" && headerHas(p.header, "id", "title", "severity_rating", "state", "substate", "weakness", "reported_at", "structured_scope")
		},
		parse:    parseHackerOneCSV,
		sanitize: sanitizeCSVHTTP})
}

// bountyVerdict classifies a bug bounty state: skip (fixed) or a
// low-confidence note (rejected), else "".
func bountyVerdict(tool string, states ...string) (skip bool, note string) {
	for _, s := range states {
		switch k := strings.ToLower(strings.NewReplacer(" ", "", "_", "", "-", "").Replace(s)); k {
		case "resolved", "fixed":
			return true, ""
		case "duplicate", "informative", "informational", "notapplicable", "spam", "outofscope", "notreproducible", "wontfix", "acceptedrisk":
			return false, fmt.Sprintf("%s closed this report as %s; it is kept for review.", tool, s)
		}
	}
	return false, ""
}

var h1CWERe = regexp.MustCompile(`(?i)cwe-(\d+)`)

func parseHackerOneJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "data")
	if err != nil {
		return nil, fmt.Errorf("hackerone: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r h1Report
		if err := json.Unmarshal(it, &r); err != nil || r.ID == "" || r.Attributes.Title == "" {
			return out, fmt.Errorf("hackerone: report %d: expected a report with id and title", i+1)
		}
		a, rel := r.Attributes, r.Relationships
		skip, note := bountyVerdict("HackerOne", a.State, a.Substate)
		if skip {
			continue
		}
		w := rel.Weakness.Data.Attributes
		asset := rel.StructuredScope.Data.Attributes.AssetIdentifier
		f := Finding{Category: "other", RuleID: firstNonEmpty(w.ExternalID, w.Name, "hackerone-report"), Title: a.Title,
			Severity: normSeverity(rel.Severity.Data.Attributes.Rating), CVSS: floatPtr(rel.Severity.Data.Attributes.Score),
			FilePath: locationOf("", firstNonEmpty(asset, "https://hackerone.com/reports/"+r.ID)), CWE: []string{firstMatch(h1CWERe, w.ExternalID)}}
		if f.Severity == "" && f.CVSS != nil {
			f.Severity = FromScore(*f.CVSS)
		}
		if note != "" {
			f.Confidence = "low"
		}
		f.Description = joinText(note, clipText(redactHTTP(a.VulnerabilityInformation), 3000), labelled("Impact", redactHTTP(a.Impact)),
			labelled("Weakness", w.Name), labelled("Asset", strings.TrimSpace(asset+" "+rel.StructuredScope.Data.Attributes.AssetType)),
			labelled("State", a.State), labelled("Program", rel.Program.Data.Attributes.Handle), labelled("Report", "https://hackerone.com/reports/"+r.ID))
		out = append(out, importRecord{F: f, SnippetKey: hashOf("h1|" + r.ID), Raw: sanitizeHTTPJSON(it)})
	}
	return out, nil
}

func parseHackerOneCSV(raw []byte) ([]importRecord, error) {
	_, rows, err := csvTable(raw)
	if err != nil && len(rows) == 0 {
		return nil, fmt.Errorf("hackerone: %w", err)
	}
	var out []importRecord
	for _, r := range rows {
		id, title := r.get("id"), r.get("title")
		if id == "" || title == "" {
			return out, fmt.Errorf("hackerone: row %d: id and title are required", r.N)
		}
		skip, note := bountyVerdict("HackerOne", r.get("state"), r.get("substate"))
		if skip {
			continue
		}
		f := Finding{Category: "other", RuleID: firstNonEmpty(r.get("weakness"), "hackerone-report"), Title: title,
			Severity: normSeverity(r.get("severity_rating")), CVSS: cvssOf(r.get("severity_score")),
			FilePath: locationOf("", firstNonEmpty(r.get("structured_scope_reference"), r.get("structured_scope"), "https://hackerone.com/reports/"+id)),
			CVE:      firstMatch(cveRe, r.get("cve_ids"))}
		if f.Severity == "" && f.CVSS != nil {
			f.Severity = FromScore(*f.CVSS)
		}
		if note != "" {
			f.Confidence = "low"
		}
		f.Description = joinText(note, labelled("Weakness", r.get("weakness")), labelled("State", strings.Trim(r.get("state")+" / "+r.get("substate"), " /")),
			labelled("Reported", r.get("reported_at")), labelled("Report", "https://hackerone.com/reports/"+id))
		rec := map[string]string{}
		for k, v := range r.Orig {
			rec[k] = redactHTTP(v)
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("h1|" + id), Raw: rawJSON(rec)})
	}
	return out, err
}
