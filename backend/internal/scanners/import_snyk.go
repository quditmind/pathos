package scanners

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Snyk Open Source JSON (`snyk test --json`): one project object, or an
// array of them with --all-projects. Snyk lists a vulnerability once per
// dependency path; those repeats are one finding (the further paths are
// appended to its description).

type snykProject struct {
	Vulnerabilities   []json.RawMessage `json:"vulnerabilities"`
	DisplayTargetFile string            `json:"displayTargetFile"`
	Path              string            `json:"path"`
	PackageManager    string            `json:"packageManager"`
}

type snykVuln struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	CVSSScore   float64  `json:"cvssScore"`
	CVSSv3      string   `json:"CVSSv3"`
	PackageName string   `json:"packageName"`
	Version     string   `json:"version"`
	FixedIn     []string `json:"fixedIn"`
	From        []string `json:"from"`
	Identifiers struct {
		CVE []string `json:"CVE"`
		CWE []string `json:"CWE"`
	} `json:"identifiers"`
}

func isSnykProject(m map[string]json.RawMessage) bool {
	return hasKeys(m, "vulnerabilities") && (hasKeys(m, "packageManager") || hasKeys(m, "dependencyCount") || hasKeys(m, "displayTargetFile"))
}

func init() {
	registerImportFormat(ImportFormat{ID: "snyk", Label: "Snyk Open Source JSON", Category: "sca", Media: "json", Order: 41,
		match: func(p *importProbe) bool {
			return (p.kind == "object" || p.kind == "array") && isSnykProject(p.keys)
		},
		parse: parseSnykJSON})
}

func parseSnykJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "")
	if err != nil {
		return nil, fmt.Errorf("snyk: invalid JSON: %w", err)
	}
	if items == nil { // a single project object
		items = []json.RawMessage{json.RawMessage(raw)}
	}
	var out []importRecord
	for _, it := range items {
		var p snykProject
		if err := json.Unmarshal(it, &p); err != nil {
			return out, fmt.Errorf("snyk: invalid project: %w", err)
		}
		file := NormalizePath(firstNonEmpty(p.DisplayTargetFile, p.Path))
		seen := map[string]int{}
		for _, vr := range p.Vulnerabilities {
			var v snykVuln
			if err := json.Unmarshal(vr, &v); err != nil || v.ID == "" {
				return out, errors.New("snyk: vulnerability without id")
			}
			k := v.ID + "|" + v.PackageName + "@" + v.Version
			if i, dup := seen[k]; dup {
				if len(v.From) > 0 && len(out[i].F.Description) < 3000 {
					out[i].F.Description += "\nPath: " + strings.Join(v.From, " > ")
				}
				continue
			}
			f := Finding{Category: "sca", RuleID: v.ID, Severity: v.Severity, CVSS: floatPtr(v.CVSSScore), CVSSVector: v.CVSSv3,
				CWE: v.Identifiers.CWE, PackageName: v.PackageName, PackageVersion: v.Version, FilePath: file}
			if len(v.Identifiers.CVE) > 0 {
				f.CVE = v.Identifiers.CVE[0]
			}
			if len(v.FixedIn) > 0 {
				f.FixedVersion = v.FixedIn[0]
			}
			id := v.ID
			if f.CVE != "" {
				id = f.CVE + " (" + v.ID + ")"
			}
			f.Title = fmt.Sprintf("%s in %s %s", id, v.PackageName, v.Version)
			if v.Title != "" {
				f.Title = fmt.Sprintf("%s: %s in %s %s", id, v.Title, v.PackageName, v.Version)
			}
			f.Description = v.Description
			if len(v.From) > 0 {
				f.Description = strings.TrimSpace(f.Description + "\n\nPath: " + strings.Join(v.From, " > "))
			}
			seen[k] = len(out)
			out = append(out, importRecord{F: f, Raw: vr})
		}
	}
	return out, nil
}
