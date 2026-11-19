package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Trivy Kubernetes report JSON (`trivy k8s --format json --report all`):
// {ClusterName, Resources[]} where each resource (namespace, kind, name)
// carries the Results of an ordinary Trivy report. The Trivy parser maps
// each resource's results (image vulnerabilities as container findings,
// misconfigurations as iac, secrets as secrets); the location is the
// resource ("namespace/Kind/name"), the target (image or manifest) is in
// the description. Secret values are removed before the report is stored.

type trivyK8sResource struct {
	Namespace string            `json:"Namespace"`
	Kind      string            `json:"Kind"`
	Name      string            `json:"Name"`
	Results   []json.RawMessage `json:"Results"`
	Error     string            `json:"Error"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "trivy-k8s", Label: "Trivy Kubernetes report JSON (trivy k8s)", Tool: "Trivy", Media: "json", Order: 337,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("ClusterName") && !p.hasAny("Results", "ArtifactName") &&
				(p.has("Resources") || p.has("SchemaVersion"))
		},
		parse:    parseTrivyK8s,
		sanitize: sanitizeTrivyK8s})
}

func sanitizeTrivyK8s(raw []byte) []byte {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	res, _ := doc["Resources"].([]any)
	for _, r := range res {
		m, _ := r.(map[string]any)
		results, _ := m["Results"].([]any)
		for _, x := range results {
			if mm, ok := x.(map[string]any); ok && mm["Secrets"] != nil {
				mm["Secrets"] = redactKeysIn(mm["Secrets"], trivySecretKeys)
			}
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return b
}

func parseTrivyK8s(raw []byte) ([]importRecord, error) {
	var doc struct {
		ClusterName string             `json:"ClusterName"`
		Resources   []trivyK8sResource `json:"Resources"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("trivy-k8s: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, r := range doc.Resources {
		if len(r.Results) == 0 {
			continue
		}
		res := strings.Trim(r.Namespace+"/"+r.Kind+"/"+r.Name, "/")
		sub, err := json.Marshal(map[string]any{"SchemaVersion": 2, "ArtifactName": res, "ArtifactType": "container_image", "Results": r.Results})
		if err != nil {
			return out, fmt.Errorf("trivy-k8s: %w", err)
		}
		recs, err := parseTrivyJSON(sub)
		if err != nil {
			return out, fmt.Errorf("trivy-k8s: %s: %w", res, err)
		}
		for _, rec := range recs {
			target := rec.F.FilePath
			rec.F.FilePath = res
			if doc.ClusterName != "" {
				rec.F.Description = joinText(rec.F.Description, "Cluster: "+doc.ClusterName)
			}
			rec.F.Description = joinText(rec.F.Description, labelled("Resource", res), labelled("Target", target))
			// A resource has several targets (one per container image).
			rec.SnippetKey = hashOf(target + "|" + rec.SnippetKey)
			out = append(out, rec)
		}
	}
	return out, nil
}
