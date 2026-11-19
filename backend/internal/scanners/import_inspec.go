package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Chef InSpec JSON (`inspec exec <profile> --reporter json:<file>`):
// platform (name, release, target_id), profiles[] with controls[] (id,
// title, desc, impact, tags, source_location, waiver_data) and their
// results[] (status passed/failed/skipped, code_desc, message,
// resource_id). A control with a failed result is one finding; its
// severity follows InSpec's impact scale (0.9 and above critical, 0.7
// high, 0.4 medium, above 0 low, 0 info). Controls that only passed or
// were skipped are not findings. Waived controls that failed are kept with
// low confidence. Findings are located on the scanned platform.

type inspecControl struct {
	ID     string          `json:"id"`
	Title  string          `json:"title"`
	Desc   string          `json:"desc"`
	Impact float64         `json:"impact"`
	Tags   json.RawMessage `json:"tags"`
	Source struct {
		Ref  string `json:"ref"`
		Line int    `json:"line"`
	} `json:"source_location"`
	Waiver *struct {
		Justification string `json:"justification"`
		Run           *bool  `json:"run"`
	} `json:"waiver_data"`
	Results []struct {
		Status     string `json:"status"`
		CodeDesc   string `json:"code_desc"`
		Message    string `json:"message"`
		ResourceID string `json:"resource_id"`
	} `json:"results"`
}

func inspecSeverity(impact float64) string {
	switch {
	case impact >= 0.9:
		return "critical"
	case impact >= 0.7:
		return "high"
	case impact >= 0.4:
		return "medium"
	case impact > 0:
		return "low"
	}
	return "info"
}

func init() {
	registerImportFormat(ImportFormat{ID: "inspec", Label: "Chef InSpec JSON (--reporter json)", Tool: "InSpec", Category: "compliance", Media: "json", Order: 562,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("profiles", "platform") && hasKeys(p.firstOf("profiles"), "controls")
		},
		parse: parseInSpec})
}

func parseInSpec(raw []byte) ([]importRecord, error) {
	var doc struct {
		Platform struct {
			Name     string `json:"name"`
			Release  string `json:"release"`
			TargetID string `json:"target_id"`
		} `json:"platform"`
		Profiles []struct {
			Name     string            `json:"name"`
			Title    string            `json:"title"`
			Controls []json.RawMessage `json:"controls"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("inspec: invalid JSON: %w", err)
	}
	target := firstNonEmpty(doc.Platform.TargetID, strings.TrimSpace(doc.Platform.Name+" "+doc.Platform.Release))
	var out []importRecord
	for _, pr := range doc.Profiles {
		for i, cr := range pr.Controls {
			var c inspecControl
			if err := json.Unmarshal(cr, &c); err != nil || c.ID == "" {
				return out, fmt.Errorf("inspec: profile %s: control %d: expected an object with id", pr.Name, i+1)
			}
			var failed []string
			for _, r := range c.Results {
				if strings.EqualFold(r.Status, "failed") {
					failed = append(failed, joinText(r.CodeDesc, r.Message))
				}
			}
			if len(failed) == 0 {
				continue
			}
			tags := strings.TrimSpace(string(c.Tags))
			if tags == "{}" || tags == "null" {
				tags = ""
			}
			f := Finding{Category: "compliance", RuleID: c.ID, Title: firstNonEmpty(c.Title, c.ID), Severity: inspecSeverity(c.Impact), FilePath: target,
				Description: joinText(c.Desc, fmt.Sprintf("Profile %s, control %s (impact %.1f). Failed tests:", firstNonEmpty(pr.Title, pr.Name), c.ID, c.Impact),
					strings.Join(failed, "\n\n"), labeled("Tags", tags), labeled("Source", c.Source.Ref))}
			if c.Waiver != nil && c.Waiver.Justification != "" {
				f.Confidence = "low"
				f.Description = joinText(f.Description, "InSpec verdict: waived ("+c.Waiver.Justification+").")
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(pr.Name), Raw: cr})
		}
	}
	return out, nil
}
