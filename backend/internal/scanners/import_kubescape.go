package scanners

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// Kubescape JSON (`kubescape scan ... --format json`, format version v2):
// results[] per resource (resourceID, controls[] with controlID, name,
// status.status, severity and the failed rule paths), resources[] (the
// object and its source file) and summaryDetails.controls (control
// metadata: severity, scoreFactor, category). Failed controls are
// findings; passed, skipped (not evaluated) and irrelevant ones are not.
// Controls excluded by an exception are imported with low confidence.

type kubescapeControl struct {
	ControlID string `json:"controlID"`
	Name      string `json:"name"`
	Status    struct {
		Status    string `json:"status"`
		SubStatus string `json:"subStatus"`
		Info      string `json:"info"`
	} `json:"status"`
	Severity string `json:"severity"`
	Rules    []struct {
		Name  string `json:"name"`
		Paths []struct {
			FailedPath string `json:"failedPath"`
			FixPath    struct {
				Path  string `json:"path"`
				Value string `json:"value"`
			} `json:"fixPath"`
			DeletePath string `json:"deletePath"`
			ReviewPath string `json:"reviewPath"`
		} `json:"paths"`
	} `json:"rules"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "kubescape", Label: "Kubescape JSON", Tool: "Kubescape", Category: "iac", Media: "json", Order: 264,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("summaryDetails", "results") && p.hasAny("resources", "clusterAPIServerInfo", "generationTime")
		},
		parse: parseKubescape})
}

func parseKubescape(raw []byte) ([]importRecord, error) {
	var doc struct {
		SummaryDetails struct {
			Controls map[string]struct {
				Name        string  `json:"name"`
				Severity    string  `json:"severity"`
				ScoreFactor float64 `json:"scoreFactor"`
				Category    struct {
					Name string `json:"name"`
				} `json:"category"`
			} `json:"controls"`
		} `json:"summaryDetails"`
		Resources []struct {
			ResourceID string `json:"resourceID"`
			Object     struct {
				Kind     string `json:"kind"`
				Metadata struct {
					Name      string `json:"name"`
					Namespace string `json:"namespace"`
				} `json:"metadata"`
			} `json:"object"`
			Source struct {
				Path         string `json:"path"`
				RelativePath string `json:"relativePath"`
			} `json:"source"`
		} `json:"resources"`
		Results []struct {
			ResourceID string            `json:"resourceID"`
			Controls   []json.RawMessage `json:"controls"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("kubescape: invalid JSON: %w", err)
	}
	type resource struct{ file, ref string }
	res := map[string]resource{}
	for _, r := range doc.Resources {
		file := r.Source.RelativePath
		if file != "" && r.Source.Path != "" && !path.IsAbs(r.Source.Path) {
			file = path.Join(r.Source.Path, file)
		}
		ref := strings.Trim(r.Object.Metadata.Namespace+"/"+r.Object.Kind+"/"+r.Object.Metadata.Name, "/")
		res[r.ResourceID] = resource{file: file, ref: ref}
	}
	var out []importRecord
	for _, r := range doc.Results {
		rs := res[r.ResourceID]
		if rs.ref == "" {
			rs.ref = kubescapeRef(r.ResourceID)
		}
		for i, cr := range r.Controls {
			var c kubescapeControl
			if err := json.Unmarshal(cr, &c); err != nil || c.ControlID == "" {
				return out, fmt.Errorf("kubescape: %s: control %d: expected an object with controlID", r.ResourceID, i+1)
			}
			st := strings.ToLower(c.Status.Status)
			if st != "failed" && c.Status.SubStatus != "w/exceptions" {
				continue
			}
			meta := doc.SummaryDetails.Controls[c.ControlID]
			f := Finding{Category: "iac", RuleID: c.ControlID, Title: fmt.Sprintf("%s (%s)", firstNonEmpty(c.Name, meta.Name, c.ControlID), rs.ref),
				Severity: firstNonEmpty(normSeverity(c.Severity), normSeverity(meta.Severity), kubescapeScore(meta.ScoreFactor)),
				FilePath: NormalizePath(rs.file)}
			var paths []string
			for _, rule := range c.Rules {
				for _, p := range rule.Paths {
					switch {
					case p.FailedPath != "":
						paths = append(paths, "failed: "+p.FailedPath)
					case p.FixPath.Path != "":
						paths = append(paths, "fix: "+p.FixPath.Path+" = "+p.FixPath.Value)
					case p.DeletePath != "":
						paths = append(paths, "delete: "+p.DeletePath)
					case p.ReviewPath != "":
						paths = append(paths, "review: "+p.ReviewPath)
					}
				}
			}
			f.Description = joinText(firstNonEmpty(c.Name, meta.Name), "Resource: "+rs.ref, "Category: "+meta.Category.Name, strings.Join(paths, "\n"))
			if st != "failed" {
				f.Confidence = "low"
				f.Description = joinText(f.Description, "Excluded by a Kubescape exception; imported for triage.")
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(r.ResourceID), Raw: cr})
		}
	}
	return out, nil
}

// kubescapeScore maps a control's scoreFactor (1-10) to a severity, as
// Kubescape does: 1-3 low, 4-6 medium, 7-8 high, 9-10 critical.
func kubescapeScore(s float64) string {
	switch {
	case s >= 9:
		return "critical"
	case s >= 7:
		return "high"
	case s >= 4:
		return "medium"
	case s > 0:
		return "low"
	}
	return "medium"
}

// kubescapeRef turns "path=.../api=apps/v1/ns/Deployment/web" into
// "ns/Deployment/web".
func kubescapeRef(id string) string {
	parts := strings.Split(id, "/")
	if len(parts) >= 3 {
		return strings.Trim(strings.Join(parts[len(parts)-3:], "/"), "/")
	}
	return id
}
