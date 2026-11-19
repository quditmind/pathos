package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// ScoutSuite results: scoutsuite-results/scoutsuite_results_<account>.js
// (`scoutsuite_results =` followed by the JSON document) or that JSON
// document alone. services.<service>.findings.<rule> lists the flagged
// items (paths into the results); one finding per flagged item. Rules
// with no flagged items are passed checks and are not imported. Levels:
// danger is high, warning medium.

type scoutFinding struct {
	Description  string   `json:"description"`
	Rationale    string   `json:"rationale"`
	Remediation  string   `json:"remediation"`
	Level        string   `json:"level"`
	Service      string   `json:"service"`
	Dashboard    string   `json:"dashboard_name"`
	FlaggedItems int      `json:"flagged_items"`
	CheckedItems int      `json:"checked_items"`
	Items        []string `json:"items"`
	IDSuffix     string   `json:"id_suffix"`
	References   []string `json:"references"`
	Compliance   []struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Reference string `json:"reference"`
	} `json:"compliance"`
}

type scoutReport struct {
	ProviderCode string `json:"provider_code"`
	ProviderName string `json:"provider_name"`
	AccountID    string `json:"account_id"`
	Services     map[string]struct {
		Findings map[string]json.RawMessage `json:"findings"`
	} `json:"services"`
}

// scoutRecord is the record kept as a finding's original output.
type scoutRecord struct {
	Provider string          `json:"provider"`
	Account  string          `json:"account_id"`
	Service  string          `json:"service"`
	Rule     string          `json:"rule"`
	Item     string          `json:"item"`
	Finding  json.RawMessage `json:"finding"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "scoutsuite", Label: "ScoutSuite results (.js or JSON)", Tool: "ScoutSuite", Category: "other", Media: "json", Order: 452,
		match: func(p *importProbe) bool {
			if p.kind == "object" {
				return p.has("provider_code", "services", "last_run")
			}
			return p.kind == "" && bytes.HasPrefix(p.head, []byte("scoutsuite_results")) && p.headHas(`"provider_code"`)
		},
		parse: parseScoutSuite})
}

// scoutJSON strips the JavaScript assignment of a results .js file.
func scoutJSON(raw []byte) []byte {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if bytes.HasPrefix(b, []byte("scoutsuite_results")) {
		if i := bytes.IndexByte(b, '{'); i >= 0 {
			b = b[i:]
		}
	}
	return bytes.TrimRight(b, "; \r\n\t")
}

func parseScoutSuite(raw []byte) ([]importRecord, error) {
	var rep scoutReport
	if err := json.Unmarshal(scoutJSON(raw), &rep); err != nil {
		return nil, fmt.Errorf("scoutsuite: invalid results: %w", err)
	}
	services := make([]string, 0, len(rep.Services))
	for s := range rep.Services {
		services = append(services, s)
	}
	slices.Sort(services)
	var out []importRecord
	for _, svc := range services {
		rules := make([]string, 0, len(rep.Services[svc].Findings))
		for r := range rep.Services[svc].Findings {
			rules = append(rules, r)
		}
		slices.Sort(rules)
		for _, rule := range rules {
			rawF := rep.Services[svc].Findings[rule]
			var sf scoutFinding
			if err := json.Unmarshal(rawF, &sf); err != nil {
				return out, fmt.Errorf("scoutsuite: %s.%s: %w", svc, rule, err)
			}
			if sf.FlaggedItems == 0 && len(sf.Items) == 0 {
				continue
			}
			items := sf.Items
			if len(items) == 0 {
				items = []string{svc}
			}
			var comp []string
			for _, c := range sf.Compliance {
				comp = append(comp, strings.TrimSpace(c.Name+" "+c.Version+" "+c.Reference))
			}
			for _, item := range items {
				res := strings.TrimSuffix(item, "."+sf.IDSuffix)
				f := Finding{Category: "misconfiguration", RuleID: rule, Title: firstNonEmpty(sf.Description, rule),
					FilePath: cspmLocation(res, rep.ProviderCode, rep.AccountID, "")}
				switch strings.ToLower(sf.Level) {
				case "danger":
					f.Severity = "high"
				case "warning":
					f.Severity = "medium"
				default:
					f.Severity = firstNonEmpty(normSeverity(sf.Level), "medium")
				}
				f.Description = joinText(sf.Rationale, labelled("Remediation", markupToText(sf.Remediation)),
					labelled("Flagged item", item), fmt.Sprintf("%d of %d checked items flagged.", sf.FlaggedItems, sf.CheckedItems),
					labelled("Account", rep.AccountID), labelled("Compliance", strings.Join(comp, "; ")), labelled("References", strings.Join(sf.References, " ")))
				rec := scoutRecord{Provider: rep.ProviderCode, Account: rep.AccountID, Service: svc, Rule: rule, Item: item, Finding: rawF}
				if len(items) > 1 {
					// Keep the record of one item small: the item list is the report's.
					var m map[string]any
					if json.Unmarshal(rawF, &m) == nil {
						delete(m, "items")
						rec.Finding = rawJSON(m)
					}
				}
				out = append(out, importRecord{F: f, SnippetKey: hashOf(item), Raw: rawJSON(rec)})
			}
		}
	}
	return out, nil
}
