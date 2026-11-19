package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// OSV-Scanner JSON (`osv-scanner --format json`): results[] per source
// (lockfile), packages[] with their vulnerabilities and groups (aliases of
// the same vulnerability, with max_severity, the highest CVSS score). One
// finding per group; without groups, one per vulnerability.

type osvVuln struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Summary  string   `json:"summary"`
	Details  string   `json:"details"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name string `json:"name"`
		} `json:"package"`
		Ranges []struct {
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	DatabaseSpecific struct {
		Severity string   `json:"severity"`
		CWEIDs   []string `json:"cwe_ids"`
	} `json:"database_specific"`
}

type osvPackage struct {
	Package struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	Groups          []struct {
		IDs         []string `json:"ids"`
		Aliases     []string `json:"aliases"`
		MaxSeverity string   `json:"max_severity"`
	} `json:"groups"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "osv-scanner", Label: "OSV-Scanner JSON", Category: "sca", Media: "json", Order: 45,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("results") && hasKeys(p.firstOf("results"), "source", "packages")
		},
		parse: parseOSVScanner})
}

func parseOSVScanner(raw []byte) ([]importRecord, error) {
	var doc struct {
		Results []struct {
			Source struct {
				Path string `json:"path"`
			} `json:"source"`
			Packages []osvPackage `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("osv-scanner: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, res := range doc.Results {
		for _, pkg := range res.Packages {
			byID := map[string]int{}
			vulns := make([]osvVuln, len(pkg.Vulnerabilities))
			for i, vr := range pkg.Vulnerabilities {
				if err := json.Unmarshal(vr, &vulns[i]); err != nil || vulns[i].ID == "" {
					return out, fmt.Errorf("osv-scanner: %s: vulnerability without id", pkg.Package.Name)
				}
				byID[vulns[i].ID] = i
			}
			type group struct {
				ids   []string
				score string
			}
			var groups []group
			for _, g := range pkg.Groups {
				groups = append(groups, group{ids: append(slices.Clone(g.IDs), g.Aliases...), score: g.MaxSeverity})
			}
			if len(groups) == 0 {
				for _, v := range vulns {
					groups = append(groups, group{ids: []string{v.ID}})
				}
			}
			for _, g := range groups {
				// The group's first ID that is in the report is its record.
				idx := -1
				for _, id := range g.ids {
					if i, ok := byID[id]; ok {
						idx = i
						break
					}
				}
				if idx < 0 {
					continue
				}
				v := vulns[idx]
				all := append(append([]string{}, g.ids...), v.Aliases...)
				f := Finding{Category: "sca", RuleID: v.ID, PackageName: pkg.Package.Name, PackageVersion: pkg.Package.Version,
					FilePath: NormalizePath(res.Source.Path), CVE: firstMatch(cveRe, append([]string{v.ID}, all...)...),
					CWE: v.DatabaseSpecific.CWEIDs, Description: strings.TrimSpace(v.Summary + "\n\n" + v.Details)}
				if s, err := strconv.ParseFloat(g.score, 64); err == nil {
					f.CVSS = floatPtr(s)
				}
				for _, s := range v.Severity {
					if strings.HasPrefix(s.Type, "CVSS_V") && vectorVersion(s.Score) != "" {
						f.CVSSVector = s.Score
					}
				}
				f.Severity = normSeverity(v.DatabaseSpecific.Severity)
				if f.CVSS != nil {
					f.Severity = FromScore(*f.CVSS)
				}
				if f.Severity == "" {
					f.Severity = "medium"
					f.Description += "\n\nOSV-Scanner reports no severity for this vulnerability; imported as medium."
				}
				for _, a := range v.Affected {
					if a.Package.Name != pkg.Package.Name {
						continue
					}
					for _, r := range a.Ranges {
						for _, e := range r.Events {
							if fx := e["fixed"]; fx != "" && f.FixedVersion == "" {
								f.FixedVersion = fx
							}
						}
					}
				}
				id := v.ID
				if f.CVE != "" && f.CVE != v.ID {
					id = f.CVE + " (" + v.ID + ")"
				}
				f.Title = fmt.Sprintf("%s in %s %s", id, pkg.Package.Name, pkg.Package.Version)
				out = append(out, importRecord{F: f, Raw: pkg.Vulnerabilities[idx]})
			}
		}
	}
	return out, nil
}
