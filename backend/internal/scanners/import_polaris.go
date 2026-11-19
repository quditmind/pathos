package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Polaris JSON (`polaris audit --format json`): Results[] per Kubernetes
// controller (Name, Namespace, Kind) with check results at three levels:
// Results (controller), PodResult.Results and
// PodResult.ContainerResults[].Results; each check has ID, Message,
// Success, Severity (danger, warning, ignore) and Category (Security,
// Efficiency, Reliability). Failed checks are findings: danger is high,
// warning medium. Security checks are iac findings; Efficiency and
// Reliability checks are not security findings and keep the category
// "other". The audit does not report file names or lines.

type polarisCheck struct {
	ID       string `json:"ID"`
	Message  string `json:"Message"`
	Success  bool   `json:"Success"`
	Severity string `json:"Severity"`
	Category string `json:"Category"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "polaris", Label: "Polaris audit JSON", Tool: "Polaris", Media: "json", Order: 270,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("PolarisOutputVersion", "Results")
		},
		parse: parsePolaris})
}

func parsePolaris(raw []byte) ([]importRecord, error) {
	var doc struct {
		SourceName string `json:"SourceName"`
		Results    []struct {
			Name      string                     `json:"Name"`
			Namespace string                     `json:"Namespace"`
			Kind      string                     `json:"Kind"`
			Results   map[string]json.RawMessage `json:"Results"`
			PodResult *struct {
				Results          map[string]json.RawMessage `json:"Results"`
				ContainerResults []struct {
					Name    string                     `json:"Name"`
					Results map[string]json.RawMessage `json:"Results"`
				} `json:"ContainerResults"`
			} `json:"PodResult"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("polaris: invalid JSON: %w", err)
	}
	var out []importRecord
	add := func(ref, container string, checks map[string]json.RawMessage) error {
		ids := make([]string, 0, len(checks))
		for id := range checks {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			var c polarisCheck
			if err := json.Unmarshal(checks[id], &c); err != nil {
				return fmt.Errorf("polaris: %s: check %s: %w", ref, id, err)
			}
			if c.Success || strings.EqualFold(c.Severity, "ignore") {
				continue
			}
			where := ref
			if container != "" {
				where += " container " + container
			}
			cat := "iac"
			if !strings.EqualFold(c.Category, "security") {
				cat = "other"
			}
			sev := "medium"
			if strings.EqualFold(c.Severity, "danger") {
				sev = "high"
			}
			f := Finding{Category: cat, RuleID: firstNonEmpty(c.ID, id), Title: fmt.Sprintf("%s (%s)", c.Message, where), Severity: sev,
				Description: joinText(c.Message, "Object: "+where, "Polaris category: "+c.Category)}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(where), Raw: checks[id]})
		}
		return nil
	}
	for _, r := range doc.Results {
		ref := strings.Trim(r.Namespace+"/"+r.Kind+"/"+r.Name, "/")
		if err := add(ref, "", r.Results); err != nil {
			return out, err
		}
		if r.PodResult == nil {
			continue
		}
		if err := add(ref, "", r.PodResult.Results); err != nil {
			return out, err
		}
		for _, c := range r.PodResult.ContainerResults {
			if err := add(ref, c.Name, c.Results); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}
