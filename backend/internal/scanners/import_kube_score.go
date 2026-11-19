package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// kube-score JSON (`kube-score score --output-format json`, output version
// v2): an array of scored Kubernetes objects {object_name, type_meta,
// object_meta, file_name, file_row, checks[]}; each check has check {id,
// name, comment, optional}, grade (1 critical, 5 warning, 7 almost OK, 10
// OK), skipped and comments[] {path (the container, or empty), summary,
// description}. Every comment of a check graded below 10 is a finding:
// critical is high, warning medium, almost OK low. The checks in
// kubeScoreSecurity are iac findings; the reliability checks (probes,
// replicas, disruption budgets, affinity, label values) are code-quality
// findings. kube-score reports the first line of the object, not of the
// field.

// kubeScoreSecurity are the kube-score checks with security impact.
var kubeScoreSecurity = []string{
	"container-security-context-user-group-id", "container-security-context-privileged",
	"container-security-context-readonlyrootfilesystem", "container-seccomp-profile", "container-image-tag",
	"container-image-pull-policy", "container-resources", "container-ephemeral-storage-request-and-limit",
	"pod-networkpolicy", "networkpolicy-targets-pod", "service-type", "environment-variable-key-duplication",
}

type kubeScoreObject struct {
	ObjectName string `json:"object_name"`
	FileName   string `json:"file_name"`
	FileRow    int    `json:"file_row"`
	Checks     []struct {
		Check struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Comment string `json:"comment"`
		} `json:"check"`
		Grade    int  `json:"grade"`
		Skipped  bool `json:"skipped"`
		Comments []struct {
			Path        string `json:"path"`
			Summary     string `json:"summary"`
			Description string `json:"description"`
		} `json:"comments"`
	} `json:"checks"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "kube-score", Label: "kube-score JSON", Tool: "kube-score", Media: "json", Order: 272,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("object_name", "checks") && p.hasAny("type_meta", "file_name")
		},
		parse: parseKubeScore})
}

func parseKubeScore(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("kube-score: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var o kubeScoreObject
		if err := json.Unmarshal(it, &o); err != nil || o.ObjectName == "" {
			return out, fmt.Errorf("kube-score: object %d: expected an object with object_name and checks", i+1)
		}
		for _, c := range o.Checks {
			if c.Skipped || c.Grade >= 10 || c.Check.ID == "" {
				continue
			}
			sev := "low"
			switch {
			case c.Grade <= 1:
				sev = "high"
			case c.Grade <= 5:
				sev = "medium"
			}
			cat := "code-quality"
			if slices.Contains(kubeScoreSecurity, c.Check.ID) {
				cat = "iac"
			}
			for _, cm := range c.Comments {
				subject := o.ObjectName
				if cm.Path != "" {
					subject += " (" + cm.Path + ")"
				}
				title := firstNonEmpty(cm.Summary, c.Check.Name)
				f := Finding{Category: cat, RuleID: c.Check.ID, Title: title, Severity: sev, FilePath: NormalizePath(o.FileName),
					StartLine:   intPtr(o.FileRow),
					Description: joinText(subject+": "+title, cm.Description, "Check: "+c.Check.Name+" ("+c.Check.ID+"). "+c.Check.Comment)}
				raw, _ := json.Marshal(map[string]any{"object_name": o.ObjectName, "file_name": o.FileName, "file_row": o.FileRow,
					"check": c.Check, "grade": c.Grade, "comment": cm})
				out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.Join([]string{o.ObjectName, cm.Path, cm.Summary}, "|")), Raw: raw})
			}
		}
	}
	return out, nil
}
