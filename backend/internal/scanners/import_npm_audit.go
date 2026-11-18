package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// npm audit JSON (`npm audit --json`). Version 2 (npm 7+,
// auditReportVersion 2): "vulnerabilities" maps package names to entries
// whose "via" lists advisory objects (or names of vulnerable dependencies,
// which are reported under their own entry). One finding per advisory
// object. The installed version is not in the report (only the vulnerable
// range), so package_version stays empty and the range is in the
// description. Version 1 (npm 6): "advisories" with findings[].version.

type npmAdvisory struct {
	Source     any      `json:"source"`
	Name       string   `json:"name"`
	Dependency string   `json:"dependency"`
	Title      string   `json:"title"`
	URL        string   `json:"url"`
	Severity   string   `json:"severity"`
	CWE        []string `json:"cwe"`
	CVSS       struct {
		Score        float64 `json:"score"`
		VectorString string  `json:"vectorString"`
	} `json:"cvss"`
	Range string `json:"range"`
}

type npmEntry struct {
	Name         string            `json:"name"`
	Severity     string            `json:"severity"`
	Via          []json.RawMessage `json:"via"`
	Range        string            `json:"range"`
	Nodes        []string          `json:"nodes"`
	FixAvailable json.RawMessage   `json:"fixAvailable"`
}

type npmV1Advisory struct {
	ID               int      `json:"id"`
	Title            string   `json:"title"`
	ModuleName       string   `json:"module_name"`
	Severity         string   `json:"severity"`
	CWE              any      `json:"cwe"`
	CVEs             []string `json:"cves"`
	VulnerableRanges string   `json:"vulnerable_versions"`
	PatchedVersions  string   `json:"patched_versions"`
	Overview         string   `json:"overview"`
	URL              string   `json:"url"`
	GHSA             string   `json:"github_advisory_id"`
	Findings         []struct {
		Version string   `json:"version"`
		Paths   []string `json:"paths"`
	} `json:"findings"`
}

var ghsaRe = regexp.MustCompile(`GHSA(-[23456789cfghjmpqrvwx]{4}){3}`)

func init() {
	registerImportFormat(ImportFormat{ID: "npm-audit", Label: "npm audit JSON", Category: "sca", Media: "json", Order: 43,
		match: func(p *importProbe) bool {
			return p.kind == "object" && (p.has("auditReportVersion", "vulnerabilities") || p.has("advisories", "metadata"))
		},
		parse: parseNpmAudit})
}

func parseNpmAudit(raw []byte) ([]importRecord, error) {
	var doc struct {
		Vulnerabilities map[string]json.RawMessage `json:"vulnerabilities"`
		Advisories      map[string]json.RawMessage `json:"advisories"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("npm audit: invalid JSON: %w", err)
	}
	var out []importRecord
	names := make([]string, 0, len(doc.Vulnerabilities))
	for n := range doc.Vulnerabilities {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		var e npmEntry
		if err := json.Unmarshal(doc.Vulnerabilities[n], &e); err != nil {
			return out, fmt.Errorf("npm audit: %s: %w", n, err)
		}
		pkg := firstNonEmpty(e.Name, n)
		var fix struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		_ = json.Unmarshal(e.FixAvailable, &fix) // false/true or an object
		for _, v := range e.Via {
			var a npmAdvisory
			if json.Unmarshal(v, &a) != nil || a.Title == "" && a.URL == "" {
				continue // the name of a vulnerable dependency
			}
			id := firstNonEmpty(ghsaRe.FindString(a.URL), fmt.Sprintf("npm-%v", a.Source))
			f := Finding{Category: "sca", RuleID: id, Severity: firstNonEmpty(a.Severity, e.Severity), CWE: a.CWE,
				CVSS: floatPtr(a.CVSS.Score), CVSSVector: a.CVSS.VectorString, PackageName: firstNonEmpty(a.Name, pkg),
				FilePath: "package-lock.json"}
			f.Title = fmt.Sprintf("%s: %s in %s", id, a.Title, f.PackageName)
			desc := []string{a.Title, "Vulnerable versions: " + firstNonEmpty(a.Range, e.Range)}
			if len(e.Nodes) > 0 {
				desc = append(desc, "Installed at: "+strings.Join(e.Nodes, ", "))
			}
			switch {
			case fix.Name == f.PackageName && fix.Version != "":
				f.FixedVersion = fix.Version
			case fix.Name != "":
				desc = append(desc, fmt.Sprintf("Fix: upgrade %s to %s", fix.Name, fix.Version))
			case string(e.FixAvailable) == "false":
				desc = append(desc, "No fix available")
			}
			if a.URL != "" {
				desc = append(desc, a.URL)
			}
			f.Description = strings.Join(desc, "\n")
			out = append(out, importRecord{F: f, Raw: rawJSON(map[string]any{"package": pkg, "advisory": v})})
		}
	}
	ids := make([]string, 0, len(doc.Advisories))
	for id := range doc.Advisories {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		var a npmV1Advisory
		if err := json.Unmarshal(doc.Advisories[id], &a); err != nil {
			return out, fmt.Errorf("npm audit: advisory %s: %w", id, err)
		}
		rule := firstNonEmpty(a.GHSA, ghsaRe.FindString(a.URL), "npm-"+id)
		versions := a.Findings
		if len(versions) == 0 {
			versions = append(versions, struct {
				Version string   `json:"version"`
				Paths   []string `json:"paths"`
			}{})
		}
		for _, fv := range versions {
			f := Finding{Category: "sca", RuleID: rule, Severity: a.Severity, CWE: stringsOf(a.CWE), PackageName: a.ModuleName,
				PackageVersion: fv.Version, FilePath: "package-lock.json", FixedVersion: simpleFixed(a.PatchedVersions)}
			if len(a.CVEs) > 0 {
				f.CVE = a.CVEs[0]
			}
			f.Title = fmt.Sprintf("%s: %s in %s %s", firstNonEmpty(f.CVE, rule), a.Title, a.ModuleName, fv.Version)
			f.Description = strings.Join([]string{a.Overview, "Vulnerable versions: " + a.VulnerableRanges, "Patched versions: " + a.PatchedVersions, a.URL}, "\n")
			out = append(out, importRecord{F: f, Raw: doc.Advisories[id]})
		}
	}
	return out, nil
}

// simpleFixed returns the version of a ">=1.2.3" range ("" for anything
// more complex, which is not a single fixed version).
func simpleFixed(r string) string {
	r = strings.TrimSpace(r)
	v, ok := strings.CutPrefix(r, ">=")
	v = strings.TrimSpace(v)
	if !ok || v == "" || strings.ContainsAny(v, " <>|=") {
		return ""
	}
	return v
}
