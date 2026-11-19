package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Retire.js JSON (`retire --outputformat json`): Retire.js 5 writes an
// object with data[]; older versions write the array itself. Each entry is
// a scanned file with results[] (a detected library: component, version)
// and their vulnerabilities[] (severity, identifiers with CVE, githubID,
// summary; cwe; "below", the first version without the vulnerability).
// One finding per library vulnerability.

type retireFile struct {
	File    string `json:"file"`
	Results []struct {
		Component       string            `json:"component"`
		NpmName         string            `json:"npmname"`
		Version         string            `json:"version"`
		Detection       string            `json:"detection"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	} `json:"results"`
}

type retireVuln struct {
	Info        []string `json:"info"`
	Below       string   `json:"below"`
	AtOrAbove   string   `json:"atOrAbove"`
	Severity    string   `json:"severity"`
	CWE         []string `json:"cwe"`
	Identifiers struct {
		Summary  string      `json:"summary"`
		CVE      []string    `json:"CVE"`
		GitHubID string      `json:"githubID"`
		Issue    looseString `json:"issue"`
		Bug      looseString `json:"bug"`
		RetID    looseString `json:"retid"`
	} `json:"identifiers"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "retire-js", Label: "Retire.js JSON", Tool: "Retire.js", Category: "sca", Media: "json", Order: 210,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				return p.has("data") && p.hasAny("start", "messages", "errors") &&
					(hasKeys(p.firstOf("data"), "file", "results") || (p.firstOf("data") == nil && p.has("version", "start")))
			case "array":
				return p.has("file", "results") && len(p.keys) == 2
			}
			return false
		},
		parse: parseRetireJS})
}

func parseRetireJS(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "data")
	if err != nil {
		return nil, fmt.Errorf("retire.js: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var rf retireFile
		if err := json.Unmarshal(it, &rf); err != nil {
			return out, fmt.Errorf("retire.js: entry %d: expected an object with file and results", i+1)
		}
		for _, res := range rf.Results {
			if res.Component == "" {
				return out, fmt.Errorf("retire.js: entry %d: result without component", i+1)
			}
			for _, vr := range res.Vulnerabilities {
				var v retireVuln
				if err := json.Unmarshal(vr, &v); err != nil {
					return out, fmt.Errorf("retire.js: %s: invalid vulnerability", res.Component)
				}
				id := v.Identifiers
				rule := firstNonEmpty(firstMatch(cveRe, id.CVE...), id.GitHubID)
				if rule == "" {
					rule = "retire-" + res.Component + "-" + firstNonEmpty(string(id.RetID), string(id.Issue), string(id.Bug), hashOf(id.Summary)[:12])
				}
				f := Finding{Category: "sca", RuleID: rule, Severity: v.Severity, CWE: v.CWE, CVE: firstMatch(cveRe, id.CVE...),
					PackageName: firstNonEmpty(res.NpmName, res.Component), PackageVersion: res.Version, FixedVersion: v.Below,
					FilePath: NormalizePath(rf.File)}
				f.Title = fmt.Sprintf("%s in %s %s", rule, f.PackageName, res.Version)
				rng := "<" + v.Below
				if v.AtOrAbove != "" {
					rng = ">=" + v.AtOrAbove + " " + rng
				}
				f.Description = joinText(id.Summary, "Vulnerable versions: "+rng, "Detected by "+firstNonEmpty(res.Detection, "Retire.js")+" in "+firstNonEmpty(rf.File, "the scanned project"),
					strings.Join(v.Info, "\n"))
				if id.GitHubID != "" && id.GitHubID != rule {
					f.Description += "\n\nAdvisory: " + id.GitHubID
				}
				out = append(out, importRecord{F: f, Raw: rawJSON(map[string]any{"file": rf.File, "component": res.Component, "version": res.Version, "vulnerability": vr})})
			}
		}
	}
	return out, nil
}
