package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Snyk IaC JSON (`snyk iac test --json`): one object per scanned file (an
// array for several files) with infrastructureAsCodeIssues[] (id or
// publicId, title, severity, msg: the resource path, lineNumber,
// iacDescription issue/impact/resolve, isIgnored, documentation) and the
// file in targetFile. Ignored issues are kept with low confidence.

type snykIaCIssue struct {
	ID             string `json:"id"`
	PublicID       string `json:"publicId"`
	Title          string `json:"title"`
	Severity       string `json:"severity"`
	Msg            string `json:"msg"`
	Issue          string `json:"issue"`
	Impact         string `json:"impact"`
	Resolve        string `json:"resolve"`
	LineNumber     int    `json:"lineNumber"`
	IsIgnored      bool   `json:"isIgnored"`
	Documentation  string `json:"documentation"`
	SubType        string `json:"subType"`
	IaCDescription struct {
		Issue   string `json:"issue"`
		Impact  string `json:"impact"`
		Resolve string `json:"resolve"`
	} `json:"iacDescription"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "snyk-iac", Label: "Snyk IaC JSON", Tool: "Snyk IaC", Category: "iac", Media: "json", Order: 601,
		match: func(p *importProbe) bool {
			return (p.kind == "object" || p.kind == "array") && p.has("infrastructureAsCodeIssues") && p.hasAny("targetFile", "projectType", "targetFilePath")
		},
		parse: parseSnykIaC})
}

func parseSnykIaC(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("snyk iac: invalid JSON: %w", err)
	}
	if items == nil {
		items = []json.RawMessage{json.RawMessage(raw)}
	}
	var out []importRecord
	for _, it := range items {
		var doc struct {
			TargetFile     string            `json:"targetFile"`
			TargetFilePath string            `json:"targetFilePath"`
			Issues         []json.RawMessage `json:"infrastructureAsCodeIssues"`
		}
		if err := json.Unmarshal(it, &doc); err != nil {
			return out, fmt.Errorf("snyk iac: invalid file result: %w", err)
		}
		for i, ir := range doc.Issues {
			var is snykIaCIssue
			if err := json.Unmarshal(ir, &is); err != nil || firstNonEmpty(is.PublicID, is.ID) == "" {
				return out, fmt.Errorf("snyk iac: %s: issue %d: expected an object with id", doc.TargetFile, i+1)
			}
			f := Finding{Category: "iac", RuleID: firstNonEmpty(is.PublicID, is.ID), Title: firstNonEmpty(is.Title, is.Issue), Severity: is.Severity,
				FilePath: NormalizePath(doc.TargetFile), StartLine: intPtr(is.LineNumber),
				Description: joinText(firstNonEmpty(is.IaCDescription.Issue, is.Issue), labeled("Resource", is.Msg), labeled("Impact", firstNonEmpty(is.IaCDescription.Impact, is.Impact)),
					labeled("Resolution", firstNonEmpty(is.IaCDescription.Resolve, is.Resolve)), is.Documentation)}
			if is.IsIgnored {
				f.Confidence = "low"
				f.Description = joinText(f.Description, "Snyk verdict: ignored.")
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToLower(is.Msg)), Raw: ir})
		}
	}
	return out, nil
}
