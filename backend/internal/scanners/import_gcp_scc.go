package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Google Cloud Security Command Center findings: `gcloud scc findings list
// <parent> --format=json` (an array of {finding, resource}) or the REST
// list response ({"listFindingsResults": [...]}). INACTIVE findings are no
// longer detected and are not imported; muted findings are kept with low
// confidence. Misconfigurations use the misconfiguration category,
// vulnerabilities sca, threats and observations other.

type sccResult struct {
	Finding struct {
		Name          string `json:"name"`
		CanonicalName string `json:"canonicalName"`
		ResourceName  string `json:"resourceName"`
		State         string `json:"state"`
		Category      string `json:"category"`
		ExternalURI   string `json:"externalUri"`
		Severity      string `json:"severity"`
		Mute          string `json:"mute"`
		FindingClass  string `json:"findingClass"`
		Description   string `json:"description"`
		NextSteps     string `json:"nextSteps"`
		Vulnerability struct {
			Cve struct {
				ID     string `json:"id"`
				Cvssv3 struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssv3"`
			} `json:"cve"`
			OffendingPackage struct {
				PackageName    string `json:"packageName"`
				PackageVersion string `json:"packageVersion"`
			} `json:"offendingPackage"`
			FixedPackage struct {
				PackageVersion string `json:"packageVersion"`
			} `json:"fixedPackage"`
		} `json:"vulnerability"`
		Compliances []struct {
			Standard string   `json:"standard"`
			Version  string   `json:"version"`
			IDs      []string `json:"ids"`
		} `json:"compliances"`
		SourceProperties map[string]any `json:"sourceProperties"`
	} `json:"finding"`
	Resource struct {
		Name               string `json:"name"`
		DisplayName        string `json:"displayName"`
		Type               string `json:"type"`
		ProjectDisplayName string `json:"projectDisplayName"`
		Location           string `json:"location"`
		GcpMetadata        struct {
			ProjectDisplayName string `json:"projectDisplayName"`
		} `json:"gcpMetadata"`
	} `json:"resource"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "gcp-scc", Label: "Google Cloud Security Command Center findings JSON", Tool: "Security Command Center", Category: "other", Media: "json", Order: 456,
		match: func(p *importProbe) bool {
			scc := func(m map[string]json.RawMessage) bool {
				if !hasKeys(m, "finding") {
					return false
				}
				var f map[string]json.RawMessage
				return json.Unmarshal(m["finding"], &f) == nil && hasKeys(f, "name", "category", "state") && hasKeys(f, "resourceName")
			}
			switch p.kind {
			case "object":
				return scc(p.firstOf("listFindingsResults"))
			case "array":
				return scc(p.keys)
			}
			return false
		},
		parse: parseGCPSCC})
}

func parseGCPSCC(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "listFindingsResults")
	if err != nil {
		return nil, fmt.Errorf("gcp-scc: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r sccResult
		if err := json.Unmarshal(it, &r); err != nil || r.Finding.Category == "" {
			return out, fmt.Errorf("gcp-scc: result %d: expected a finding with a category", i+1)
		}
		g := r.Finding
		if strings.EqualFold(g.State, "INACTIVE") {
			continue
		}
		f := Finding{RuleID: g.Category, Title: strings.ReplaceAll(g.Category, "_", " "), Severity: normSeverity(g.Severity),
			FilePath: cspmLocation(g.ResourceName, "gcp", "", "")}
		switch strings.ToUpper(g.FindingClass) {
		case "MISCONFIGURATION", "POSTURE_VIOLATION", "SCC_ERROR":
			f.Category = "misconfiguration"
		case "VULNERABILITY":
			f.Category = "sca"
			f.CVE = firstMatch(cveRe, g.Vulnerability.Cve.ID)
			f.CVSS = floatPtr(g.Vulnerability.Cve.Cvssv3.BaseScore)
			f.PackageName, f.PackageVersion = g.Vulnerability.OffendingPackage.PackageName, g.Vulnerability.OffendingPackage.PackageVersion
			f.FixedVersion = g.Vulnerability.FixedPackage.PackageVersion
			if f.CVE == "" && f.PackageName == "" {
				f.Category = "misconfiguration" // Security Health Analytics vulnerabilities are settings
			}
		default:
			f.Category = "other"
		}
		var comp []string
		for _, c := range g.Compliances {
			comp = append(comp, strings.TrimSpace(c.Standard+" "+c.Version+" "+strings.Join(c.IDs, ", ")))
		}
		note := ""
		if strings.EqualFold(g.Mute, "MUTED") {
			f.Confidence, note = "low", "Security Command Center reports this finding as muted; it is kept for review."
		}
		f.Description = joinText(note, g.Description, labelled("Next steps", g.NextSteps), labelled("Resource", firstNonEmpty(r.Resource.DisplayName, r.Resource.Name)),
			labelled("Resource type", r.Resource.Type), labelled("Project", firstNonEmpty(r.Resource.ProjectDisplayName, r.Resource.GcpMetadata.ProjectDisplayName)),
			labelled("Class", g.FindingClass), labelled("Compliance", strings.Join(comp, "; ")), labelled("Console", g.ExternalURI))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(firstNonEmpty(g.CanonicalName, g.Name)), Raw: it})
	}
	return out, nil
}
