package scanners

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Steampipe / Powerpipe benchmark JSON (`steampipe check ... --export
// json`, `powerpipe benchmark run ... --output json`): a tree of groups
// (group_id, title, groups[], controls[]) whose controls (control_id,
// title, description, severity, results[]) have one result per resource
// (status ok/alarm/info/skip/error, reason, resource, dimensions). alarm
// results are findings with the control's severity (medium when it has
// none); error results are kept with low confidence; ok, info and skip are
// not findings. A finding is located at its resource.

type steampipeGroup struct {
	GroupID  string             `json:"group_id"`
	Title    string             `json:"title"`
	Groups   []steampipeGroup   `json:"groups"`
	Controls []steampipeControl `json:"controls"`
}

type steampipeControl struct {
	ControlID   string            `json:"control_id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Tags        map[string]string `json:"tags"`
	Results     []json.RawMessage `json:"results"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "steampipe", Label: "Steampipe / Powerpipe benchmark JSON", Tool: "Steampipe", Category: "compliance", Media: "json", Order: 567,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("group_id", "summary") && p.hasAny("groups", "controls")
		},
		parse: parseSteampipe})
}

func parseSteampipe(raw []byte) ([]importRecord, error) {
	var root steampipeGroup
	if err := json.Unmarshal(raw, &root); err != nil {
		return nil, fmt.Errorf("steampipe: invalid JSON: %w", err)
	}
	var out []importRecord
	var walk func(g steampipeGroup, path []string, depth int) error
	walk = func(g steampipeGroup, path []string, depth int) error {
		if depth > 50 {
			return errors.New("steampipe: benchmark nested too deeply")
		}
		path = append(path, firstNonEmpty(g.Title, g.GroupID))
		for _, c := range g.Controls {
			for i, rr := range c.Results {
				var r struct {
					Status     string `json:"status"`
					Reason     string `json:"reason"`
					Resource   string `json:"resource"`
					Dimensions []struct {
						Key   string `json:"key"`
						Value string `json:"value"`
					} `json:"dimensions"`
				}
				if err := json.Unmarshal(rr, &r); err != nil || r.Status == "" {
					return fmt.Errorf("steampipe: %s: result %d: expected an object with status", c.ControlID, i+1)
				}
				st := strings.ToLower(r.Status)
				if st != "alarm" && st != "error" {
					continue
				}
				var dims []string
				for _, d := range r.Dimensions {
					dims = append(dims, d.Key+"="+d.Value)
				}
				f := Finding{Category: "compliance", RuleID: c.ControlID, Title: firstNonEmpty(c.Title, c.ControlID),
					Severity: firstNonEmpty(normSeverity(c.Severity), "medium"), FilePath: firstNonEmpty(r.Resource, strings.Join(dims, " ")),
					Description: joinText(r.Reason, c.Description, labeled("Benchmark", strings.Join(path, " > ")), labeled("Dimensions", strings.Join(dims, ", ")))}
				if st == "error" {
					f.Severity, f.Confidence = "low", "low"
					f.Description = joinText(f.Description, "The control could not be evaluated (error); it needs a manual review.")
				}
				out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.Join(dims, "|")),
					Raw: rawJSON(map[string]any{"control_id": c.ControlID, "result": json.RawMessage(rr)})})
			}
		}
		for _, sub := range g.Groups {
			if err := walk(sub, path, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	err := walk(root, nil, 0)
	return out, err
}
