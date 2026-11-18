package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// pip-audit JSON (`pip-audit -f json`): {"dependencies": [{name, version,
// vulns: [{id, fix_versions, aliases, description}]}], "fixes": []}, or the
// bare dependency array of older releases. The report has no severity:
// findings are imported as medium (stated in the description) until
// vulnerability intelligence enriches them.

type pipAuditDep struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Vulns   []struct {
		ID          string   `json:"id"`
		FixVersions []string `json:"fix_versions"`
		Aliases     []string `json:"aliases"`
		Description string   `json:"description"`
	} `json:"vulns"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "pip-audit", Label: "pip-audit JSON", Category: "sca", Media: "json", Order: 44,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				return p.has("dependencies") && !p.has("reportSchema") && (p.has("fixes") || hasKeys(p.firstOf("dependencies"), "name", "vulns"))
			case "array":
				return p.has("name", "version", "vulns")
			}
			return false
		},
		parse: parsePipAudit})
}

func parsePipAudit(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "dependencies")
	if err != nil {
		return nil, fmt.Errorf("pip-audit: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, it := range items {
		var d pipAuditDep
		if err := json.Unmarshal(it, &d); err != nil {
			return out, fmt.Errorf("pip-audit: invalid dependency: %w", err)
		}
		for i, v := range d.Vulns {
			if v.ID == "" {
				return out, fmt.Errorf("pip-audit: %s: vulnerability without id", d.Name)
			}
			f := Finding{Category: "sca", RuleID: v.ID, Severity: "medium", PackageName: d.Name, PackageVersion: d.Version,
				CVE: firstMatch(cveRe, append([]string{v.ID}, v.Aliases...)...)}
			if len(v.FixVersions) > 0 {
				f.FixedVersion = v.FixVersions[0]
			}
			id := v.ID
			if f.CVE != "" && f.CVE != v.ID {
				id = f.CVE + " (" + v.ID + ")"
			}
			f.Title = fmt.Sprintf("%s in %s %s", id, d.Name, d.Version)
			desc := []string{v.Description, "pip-audit reports no severity; imported as medium."}
			if len(v.Aliases) > 0 {
				desc = append(desc, "Aliases: "+strings.Join(v.Aliases, ", "))
			}
			f.Description = strings.Join(desc, "\n\n")
			out = append(out, importRecord{F: f, Raw: rawJSON(map[string]any{"name": d.Name, "version": d.Version, "vuln": d.Vulns[i]})})
		}
	}
	return out, nil
}
