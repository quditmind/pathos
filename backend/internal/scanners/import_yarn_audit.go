package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// yarn audit JSON Lines. Yarn 1 (`yarn audit --json`): one {"type", "data"}
// object per line; "auditAdvisory" lines carry an npm advisory (the npm
// audit version 1 record: module_name, severity, cves, cwe,
// github_advisory_id, patched_versions, findings[].version) and the
// dependency path it was found on. Yarn repeats an advisory once per path;
// those repeats are one finding with the paths in the description. Other
// line types (info, warning, auditSummary, auditAction) are not findings.
// Yarn 2+ (`yarn npm audit --json`): one {"value": package, "children":
// {ID, Issue, URL, Severity, "Vulnerable Versions", "Tree Versions",
// Dependents}} object per line; one finding per installed version.

var yarnLineTypes = []string{"info", "warning", "error", "auditAdvisory", "auditSummary", "auditAction"}

type yarnBerryAdvisory struct {
	ID           looseString `json:"ID"`
	Issue        string      `json:"Issue"`
	URL          string      `json:"URL"`
	Severity     string      `json:"Severity"`
	Vulnerable   string      `json:"Vulnerable Versions"`
	TreeVersions []string    `json:"Tree Versions"`
	Dependents   []string    `json:"Dependents"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "yarn-audit", Label: "yarn audit JSON Lines (Yarn 1 and Yarn 2+)", Tool: "yarn audit", Category: "sca", Media: "jsonl", Order: 211,
		match: func(p *importProbe) bool {
			if p.kind != "jsonl" && p.kind != "object" {
				return false
			}
			if len(p.keys) == 2 && p.has("type", "data") {
				var t string
				return json.Unmarshal(p.keys["type"], &t) == nil && slices.Contains(yarnLineTypes, t)
			}
			if len(p.keys) == 2 && p.has("value", "children") {
				var c map[string]json.RawMessage
				return json.Unmarshal(p.keys["children"], &c) == nil && hasKeys(c, "ID", "Vulnerable Versions")
			}
			return false
		},
		parse: parseYarnAudit})
}

func parseYarnAudit(raw []byte) ([]importRecord, error) {
	var out []importRecord
	seen := map[string]int{} // advisory|version -> index in out
	err := jsonLines(raw, func(n int, line []byte) error {
		var l struct {
			Type     string          `json:"type"`
			Data     json.RawMessage `json:"data"`
			Value    string          `json:"value"`
			Children json.RawMessage `json:"children"`
		}
		if err := json.Unmarshal(line, &l); err != nil {
			return fmt.Errorf("yarn audit: line %d: invalid JSON", n)
		}
		switch {
		case l.Value != "" && l.Children != nil:
			var a yarnBerryAdvisory
			if err := json.Unmarshal(l.Children, &a); err != nil || (a.ID == "" && a.URL == "") {
				return fmt.Errorf("yarn audit: line %d: expected an advisory with ID", n)
			}
			rule := firstNonEmpty(ghsaRe.FindString(a.URL), "npm-"+string(a.ID))
			versions := a.TreeVersions
			if len(versions) == 0 {
				versions = []string{""}
			}
			for _, v := range versions {
				f := Finding{Category: "sca", RuleID: rule, Severity: a.Severity, PackageName: l.Value, PackageVersion: v,
					FilePath: "yarn.lock", FixedVersion: yarnFixedFromRange(a.Vulnerable)}
				f.Title = fmt.Sprintf("%s: %s in %s %s", rule, a.Issue, l.Value, v)
				f.Description = joinText(a.Issue, "Vulnerable versions: "+a.Vulnerable, yarnDependents(a.Dependents), a.URL)
				out = append(out, importRecord{F: f, Raw: line})
			}
		case l.Type == "auditAdvisory":
			var d struct {
				Resolution struct {
					Path string `json:"path"`
					Dev  bool   `json:"dev"`
				} `json:"resolution"`
				Advisory npmV1Advisory `json:"advisory"`
			}
			if err := json.Unmarshal(l.Data, &d); err != nil || d.Advisory.ModuleName == "" {
				return fmt.Errorf("yarn audit: line %d: auditAdvisory without advisory.module_name", n)
			}
			a := d.Advisory
			rule := firstNonEmpty(a.GHSA, ghsaRe.FindString(a.URL), fmt.Sprintf("npm-%d", a.ID))
			versions := []string{""}
			if len(a.Findings) > 0 {
				versions = versions[:0]
				for _, fv := range a.Findings {
					versions = append(versions, fv.Version)
				}
			}
			for _, v := range versions {
				key := rule + "|" + a.ModuleName + "|" + v
				if i, ok := seen[key]; ok {
					if d.Resolution.Path != "" && !strings.Contains(out[i].F.Description, "\n- "+d.Resolution.Path+"\n") {
						out[i].F.Description = strings.Replace(out[i].F.Description, "Paths:\n", "Paths:\n- "+d.Resolution.Path+"\n", 1)
					}
					continue
				}
				f := Finding{Category: "sca", RuleID: rule, Severity: a.Severity, CWE: stringsOf(a.CWE), PackageName: a.ModuleName,
					PackageVersion: v, FilePath: "yarn.lock", FixedVersion: simpleFixed(a.PatchedVersions), CVE: firstMatch(cveRe, a.CVEs...)}
				f.Title = fmt.Sprintf("%s: %s in %s %s", firstNonEmpty(f.CVE, rule), a.Title, a.ModuleName, v)
				f.Description = joinText(a.Overview, "Vulnerable versions: "+a.VulnerableRanges+"\nPatched versions: "+a.PatchedVersions, a.URL)
				if d.Resolution.Path != "" {
					f.Description += "\n\nPaths:\n- " + d.Resolution.Path + "\n"
				}
				seen[key] = len(out)
				out = append(out, importRecord{F: f, Raw: l.Data})
			}
		}
		return nil
	})
	return out, err
}

// yarnFixedFromRange returns the fixed version of a "<1.2.3" or
// ">=1.0.0 <1.2.3" vulnerable range ("" for anything else, e.g. "<=").
func yarnFixedFromRange(r string) string {
	f := strings.Fields(r)
	if len(f) == 0 {
		return ""
	}
	v, ok := strings.CutPrefix(f[len(f)-1], "<")
	if !ok || v == "" || strings.HasPrefix(v, "=") || strings.Contains(r, "||") {
		return ""
	}
	return v
}

func yarnDependents(d []string) string {
	if len(d) == 0 {
		return ""
	}
	return "Dependents: " + strings.Join(d, ", ")
}
