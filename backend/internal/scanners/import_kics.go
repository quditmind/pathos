package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// KICS JSON (`kics scan --report-formats json`): queries[] (the failed
// queries, with query_id, query_name, severity, cwe, platform) and their
// files[] (file_name, line, resource, similarity_id, expected and actual
// value). One finding per query and file entry; KICS' similarity_id is the
// identity within the file.

type kicsQuery struct {
	QueryName   string            `json:"query_name"`
	QueryID     string            `json:"query_id"`
	QueryURL    string            `json:"query_url"`
	Severity    string            `json:"severity"`
	Platform    string            `json:"platform"`
	CWE         looseString       `json:"cwe"`
	Category    string            `json:"category"`
	Description string            `json:"description"`
	Files       []json.RawMessage `json:"files"`
}

type kicsFile struct {
	FileName      string `json:"file_name"`
	SimilarityID  string `json:"similarity_id"`
	Line          int    `json:"line"`
	ResourceType  string `json:"resource_type"`
	ResourceName  string `json:"resource_name"`
	IssueType     string `json:"issue_type"`
	SearchKey     string `json:"search_key"`
	ExpectedValue string `json:"expected_value"`
	ActualValue   string `json:"actual_value"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "kics", Label: "KICS JSON", Tool: "KICS", Category: "iac", Media: "json", Order: 260,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("queries") && p.hasAny("kics_version", "queries_total")
		},
		parse: parseKICS})
}

func parseKICS(raw []byte) ([]importRecord, error) {
	var doc struct {
		Queries []json.RawMessage `json:"queries"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("kics: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, qr := range doc.Queries {
		var q kicsQuery
		if err := json.Unmarshal(qr, &q); err != nil || q.QueryID == "" {
			return out, fmt.Errorf("kics: query %d: expected an object with query_id", i+1)
		}
		for _, fr := range q.Files {
			var fl kicsFile
			if err := json.Unmarshal(fr, &fl); err != nil {
				return out, fmt.Errorf("kics: query %s: invalid file entry", q.QueryID)
			}
			f := Finding{Category: "iac", RuleID: q.QueryID, Title: firstNonEmpty(q.QueryName, q.QueryID), Severity: kicsSeverity(q.Severity),
				FilePath: NormalizePath(kicsPath(fl.FileName)), StartLine: intPtr(fl.Line), CWE: []string{string(q.CWE)},
				Description: joinText(q.Description, fmt.Sprintf("Platform: %s; category: %s", q.Platform, q.Category),
					strings.TrimSpace(fmt.Sprintf("Resource: %s %s", fl.ResourceType, fl.ResourceName)),
					"Expected: "+fl.ExpectedValue+"\nActual: "+fl.ActualValue, q.QueryURL)}
			rec := map[string]any{"query_id": q.QueryID, "query_name": q.QueryName, "severity": q.Severity, "platform": q.Platform,
				"cwe": q.CWE, "category": q.Category, "query_url": q.QueryURL, "file": json.RawMessage(fr)}
			out = append(out, importRecord{F: f, SnippetKey: firstNonEmpty(fl.SimilarityID, hashOf(fl.SearchKey)), Raw: rawJSON(rec)})
		}
	}
	return out, nil
}

// kicsSeverity maps KICS' TRACE level (below INFO) to info.
func kicsSeverity(s string) string {
	if strings.EqualFold(s, "trace") {
		return "info"
	}
	return s
}

// kicsPath removes the "../../path/" prefix KICS puts in front of files
// scanned in its container (the documented /path mount).
func kicsPath(p string) string {
	if !strings.HasPrefix(p, "../") {
		return p
	}
	for strings.HasPrefix(p, "../") {
		p = strings.TrimPrefix(p, "../")
	}
	return strings.TrimPrefix(p, "path/")
}
