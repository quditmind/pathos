package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// CloudSploit (Aqua) JSON output (`--json file.json`): an array of plugin
// results with plugin, category, title, resource, region, status and
// message. CloudSploit has no severity: FAIL is medium, WARN low, UNKNOWN
// info. OK results are passed checks and are not imported.

type cloudsploitResult struct {
	Plugin      string `json:"plugin"`
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Region      string `json:"region"`
	Status      string `json:"status"`
	Message     string `json:"message"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "cloudsploit", Label: "CloudSploit JSON", Tool: "CloudSploit", Category: "other", Media: "json", Order: 457,
		match: func(p *importProbe) bool {
			return p.kind == "array" && p.has("plugin", "category", "title", "resource", "region", "status", "message")
		},
		parse: parseCloudSploit})
}

func parseCloudSploit(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("cloudsploit: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r cloudsploitResult
		if err := json.Unmarshal(it, &r); err != nil || r.Plugin == "" {
			return out, fmt.Errorf("cloudsploit: result %d: expected an object with plugin", i+1)
		}
		f := Finding{Category: "misconfiguration", RuleID: r.Plugin, Title: firstNonEmpty(r.Title, r.Plugin),
			FilePath: cspmLocation(r.Resource, "cloud", "", r.Region)}
		switch strings.ToUpper(strings.TrimSpace(r.Status)) {
		case "OK", "PASS":
			continue
		case "FAIL":
			f.Severity = "medium"
		case "WARN":
			f.Severity = "low"
		default:
			f.Severity = "info"
		}
		if r.Resource == "N/A" {
			f.FilePath = cspmLocation("", "cloud", "", r.Region)
		}
		f.Description = joinText(r.Message, r.Description, labelled("Status", r.Status), labelled("Service", r.Category), labelled("Region", r.Region),
			"CloudSploit reports no severity: FAIL is imported as medium, WARN as low.")
		key := r.Region + "|" + r.Resource
		if r.Resource == "" || r.Resource == "N/A" {
			key += "|" + r.Message // results without a resource differ by message only
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(key), Raw: it})
	}
	return out, nil
}
