package scanners

import (
	"encoding/json"
	"fmt"
)

// Cloud Custodian IaC results (c7n-left, `c7n-left run -p <policies> -d
// <dir> -o json`): {"results": [...]} with one entry per matched
// resource: policy (name, resource, description, metadata.severity,
// metadata.category), resource (with __tfmeta: filename, path,
// line_start), file_path, file_line_start, file_line_end and code_block.
// Every result is a policy violation; without metadata.severity it is
// medium.

func init() {
	registerImportFormat(ImportFormat{ID: "cloud-custodian", Label: "Cloud Custodian c7n-left JSON", Tool: "Cloud Custodian", Category: "iac", Media: "json", Order: 704,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("results"), "policy", "resource", "file_path")
		},
		parse: parseCloudCustodian})
}

func parseCloudCustodian(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("cloud custodian: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r struct {
			Policy struct {
				Name        string `json:"name"`
				Resource    string `json:"resource"`
				Description string `json:"description"`
				Metadata    struct {
					Severity string `json:"severity"`
					Category string `json:"category"`
				} `json:"metadata"`
			} `json:"policy"`
			Resource struct {
				Meta struct {
					Path string `json:"path"`
				} `json:"__tfmeta"`
			} `json:"resource"`
			FilePath  string `json:"file_path"`
			LineStart int    `json:"file_line_start"`
			LineEnd   int    `json:"file_line_end"`
		}
		if err := json.Unmarshal(it, &r); err != nil || r.Policy.Name == "" {
			return out, fmt.Errorf("cloud custodian: result %d: expected policy.name", i+1)
		}
		f := Finding{Category: "iac", RuleID: r.Policy.Name, Title: firstNonEmpty(r.Policy.Description, r.Policy.Name),
			Severity: firstNonEmpty(normSeverity(r.Policy.Metadata.Severity), "medium"), FilePath: NormalizePath(r.FilePath),
			StartLine: intPtr(r.LineStart), EndLine: intPtr(r.LineEnd),
			Description: joinText(r.Policy.Description, fmt.Sprintf("Policy %s (%s) matched %s.", r.Policy.Name, r.Policy.Resource, r.Resource.Meta.Path),
				labeled("Category", r.Policy.Metadata.Category))}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(r.Resource.Meta.Path), Raw: it})
	}
	return out, nil
}
