package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// StackHawk scan results JSON: the "scanCompleted" webhook payload
// ({"service": "StackHawk", "scanCompleted": {"scan", "findings"}}), also
// what the StackHawk API returns for a completed scan. One finding per
// plugin and path: the location is host + path, identity the plugin and
// method. Paths triaged as FALSE_POSITIVE are kept with low confidence,
// RISK_ACCEPTED ones with a note. Built from the published format; not yet
// verified against a real export.

type stackhawkFinding struct {
	PluginID   looseString `json:"pluginId"`
	PluginName string      `json:"pluginName"`
	Severity   string      `json:"severity"`
	Host       string      `json:"host"`
	Category   string      `json:"category"`
	FindingURL string      `json:"findingURL"`
	CWE        looseString `json:"cweId"`
	Paths      []struct {
		Path    string `json:"path"`
		Method  string `json:"method"`
		Status  string `json:"status"`
		PathURL string `json:"pathURL"`
	} `json:"paths"`
}

// stackhawkRecord is the record kept as a finding's original output.
type stackhawkRecord struct {
	Application string `json:"application,omitempty"`
	Env         string `json:"env,omitempty"`
	ScanID      string `json:"scan_id,omitempty"`
	PluginID    string `json:"pluginId"`
	PluginName  string `json:"pluginName"`
	Severity    string `json:"severity"`
	Category    string `json:"category,omitempty"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	Method      string `json:"method,omitempty"`
	Status      string `json:"status,omitempty"`
	PathURL     string `json:"pathURL,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "stackhawk", Label: "StackHawk scan results JSON", Tool: "StackHawk", Category: "dast", Media: "json", Order: 407,
		match: func(p *importProbe) bool {
			var svc string
			return p.kind == "object" && p.has("service", "scanCompleted") && json.Unmarshal(p.keys["service"], &svc) == nil && svc == "StackHawk"
		},
		parse:    parseStackHawk,
		sanitize: sanitizeHTTPJSON})
}

func parseStackHawk(raw []byte) ([]importRecord, error) {
	var doc struct {
		ScanCompleted struct {
			Scan struct {
				ID          string `json:"id"`
				Env         string `json:"env"`
				Application string `json:"application"`
			} `json:"scan"`
			Findings []stackhawkFinding `json:"findings"`
		} `json:"scanCompleted"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("stackhawk: invalid JSON: %w", err)
	}
	sc := doc.ScanCompleted.Scan
	var out []importRecord
	for i, fi := range doc.ScanCompleted.Findings {
		if fi.PluginID == "" && fi.PluginName == "" {
			return out, fmt.Errorf("stackhawk: finding %d: missing pluginId", i+1)
		}
		paths := fi.Paths
		if len(paths) == 0 {
			paths = append(paths, struct {
				Path    string `json:"path"`
				Method  string `json:"method"`
				Status  string `json:"status"`
				PathURL string `json:"pathURL"`
			}{Path: "/"})
		}
		for _, p := range paths {
			url := strings.TrimRight(fi.Host, "/") + "/" + strings.TrimLeft(p.Path, "/")
			f := Finding{Category: "dast", RuleID: firstNonEmpty(string(fi.PluginID), fi.PluginName), Title: firstNonEmpty(fi.PluginName, string(fi.PluginID)),
				Severity: firstNonEmpty(normSeverity(fi.Severity), "info"), FilePath: locationOf("", redactHTTP(url)), CWE: []string{string(fi.CWE)}}
			note := ""
			switch strings.ToUpper(p.Status) {
			case "FALSE_POSITIVE":
				f.Confidence, note = "low", "StackHawk triage marked this path as a false positive; it is kept for review."
			case "RISK_ACCEPTED":
				note = "StackHawk triage marked this path as an accepted risk."
			}
			f.Description = joinText(note, labelled("Category", fi.Category), whereText(p.Method, url, ""), labelled("StackHawk", firstNonEmpty(p.PathURL, fi.FindingURL)))
			rec := stackhawkRecord{Application: sc.Application, Env: sc.Env, ScanID: sc.ID, PluginID: string(fi.PluginID), PluginName: fi.PluginName,
				Severity: fi.Severity, Category: fi.Category, Host: fi.Host, Path: redactHTTP(p.Path), Method: p.Method, Status: p.Status, PathURL: p.PathURL}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(p.Method)), Raw: rawJSON(rec)})
		}
	}
	return out, nil
}
