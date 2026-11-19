package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Trivy Operator reports (`kubectl get vulnerabilityreports -A -o json`,
// also configauditreports): a Kubernetes List (items[]) or one report of
// apiVersion aquasecurity.github.io/v1alpha1. VulnerabilityReport:
// report.artifact (repository, tag), report.registry.server and
// report.vulnerabilities[] (vulnerabilityID, resource, installedVersion,
// fixedVersion, severity, title, score, primaryLink). ConfigAuditReport:
// report.checks[] (checkID, title, severity, success, messages,
// description); passed checks are not findings. Findings are located at
// the workload (namespace/kind/name from the report's labels).

type trivyOperatorReport struct {
	Kind     string `json:"kind"`
	Metadata struct {
		Name      string            `json:"name"`
		Namespace string            `json:"namespace"`
		Labels    map[string]string `json:"labels"`
	} `json:"metadata"`
	Report struct {
		Artifact struct {
			Repository string `json:"repository"`
			Tag        string `json:"tag"`
		} `json:"artifact"`
		Registry struct {
			Server string `json:"server"`
		} `json:"registry"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		Checks          []json.RawMessage `json:"checks"`
	} `json:"report"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "trivy-operator", Label: "Trivy Operator VulnerabilityReport / ConfigAuditReport JSON (kubectl)", Tool: "Trivy Operator",
		Media: "json", Order: 626,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.headHas("aquasecurity.github.io/") &&
				(p.has("report", "apiVersion") || hasKeys(p.firstOf("items"), "report", "apiVersion"))
		},
		parse: parseTrivyOperator})
}

func parseTrivyOperator(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "items")
	if err != nil {
		return nil, fmt.Errorf("trivy operator: invalid JSON: %w", err)
	}
	if items == nil {
		items = []json.RawMessage{raw}
	}
	var out []importRecord
	for i, it := range items {
		var r trivyOperatorReport
		if err := json.Unmarshal(it, &r); err != nil {
			return out, fmt.Errorf("trivy operator: item %d: %w", i+1, err)
		}
		l := r.Metadata.Labels
		workload := strings.Trim(strings.Join([]string{firstNonEmpty(l["trivy-operator.resource.namespace"], r.Metadata.Namespace),
			l["trivy-operator.resource.kind"], firstNonEmpty(l["trivy-operator.resource.name"], r.Metadata.Name)}, "/"), "/")
		image := strings.Trim(strings.Trim(r.Report.Registry.Server+"/"+r.Report.Artifact.Repository, "/")+":"+r.Report.Artifact.Tag, ":")
		container := l["trivy-operator.container.name"]
		for _, vr := range r.Report.Vulnerabilities {
			var v struct {
				ID        string  `json:"vulnerabilityID"`
				Resource  string  `json:"resource"`
				Installed string  `json:"installedVersion"`
				Fixed     string  `json:"fixedVersion"`
				Severity  string  `json:"severity"`
				Title     string  `json:"title"`
				Score     float64 `json:"score"`
				Link      string  `json:"primaryLink"`
				Target    string  `json:"target"`
			}
			if err := json.Unmarshal(vr, &v); err != nil || v.ID == "" {
				return out, fmt.Errorf("trivy operator: %s: expected vulnerabilityID", workload)
			}
			out = append(out, importRecord{F: Finding{Category: "container", RuleID: v.ID, CVE: v.ID, Severity: v.Severity, CVSS: floatPtr(v.Score),
				PackageName: v.Resource, PackageVersion: v.Installed, FixedVersion: v.Fixed, FilePath: firstNonEmpty(workload, image),
				Title:       strings.TrimSpace(fmt.Sprintf("%s in %s %s", v.ID, v.Resource, v.Installed)),
				Description: joinText(v.Title, fmt.Sprintf("Image %s (container %s of %s).", image, container, workload), labeled("Target", v.Target), v.Link)}, Raw: vr})
		}
		for _, cr := range r.Report.Checks {
			var c struct {
				ID          string   `json:"checkID"`
				Title       string   `json:"title"`
				Severity    string   `json:"severity"`
				Success     bool     `json:"success"`
				Messages    []string `json:"messages"`
				Description string   `json:"description"`
				Remediation string   `json:"remediation"`
			}
			if err := json.Unmarshal(cr, &c); err != nil || c.ID == "" {
				return out, fmt.Errorf("trivy operator: %s: expected checkID", workload)
			}
			if c.Success {
				continue
			}
			out = append(out, importRecord{F: Finding{Category: "misconfiguration", RuleID: c.ID, Title: firstNonEmpty(c.Title, c.ID), Severity: c.Severity, FilePath: workload,
				Description: joinText(c.Description, strings.Join(c.Messages, "\n"), labeled("Remediation", c.Remediation))}, SnippetKey: hashOf(strings.Join(c.Messages, "|")), Raw: cr})
		}
	}
	return out, nil
}
