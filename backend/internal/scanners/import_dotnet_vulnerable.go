package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// `dotnet list package --vulnerable [--include-transitive] --format json`
// (.NET SDK 7.0.200+, report version 1): projects[] with path and
// frameworks[], whose topLevelPackages[] and transitivePackages[] (id,
// resolvedVersion) list vulnerabilities[] (severity, advisoryurl). The
// advisory URL names the GitHub advisory; the report has no CVE, CWE or
// fixed version. A package vulnerable in several target frameworks of a
// project is one finding.

type dotnetPackage struct {
	ID               string `json:"id"`
	RequestedVersion string `json:"requestedVersion"`
	ResolvedVersion  string `json:"resolvedVersion"`
	Vulnerabilities  []struct {
		Severity    string `json:"severity"`
		AdvisoryURL string `json:"advisoryurl"`
	} `json:"vulnerabilities"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "dotnet-vulnerable", Label: "dotnet list package --vulnerable JSON", Tool: "dotnet list package", Category: "sca", Media: "json", Order: 216,
		match: func(p *importProbe) bool {
			if p.kind != "object" || !p.has("version", "projects") || !p.hasAny("parameters", "sources") {
				return false
			}
			var params string
			_ = json.Unmarshal(p.keys["parameters"], &params)
			return strings.Contains(params, "--vulnerable") || hasKeys(p.firstOf("projects"), "path", "frameworks")
		},
		parse: parseDotnetVulnerable})
}

func parseDotnetVulnerable(raw []byte) ([]importRecord, error) {
	var doc struct {
		Projects []struct {
			Path       string `json:"path"`
			Frameworks []struct {
				Framework          string            `json:"framework"`
				TopLevelPackages   []json.RawMessage `json:"topLevelPackages"`
				TransitivePackages []json.RawMessage `json:"transitivePackages"`
			} `json:"frameworks"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("dotnet list package: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, pr := range doc.Projects {
		seen := map[string]int{}
		for _, fw := range pr.Frameworks {
			for _, list := range []struct {
				kind string
				pkgs []json.RawMessage
			}{{"direct", fw.TopLevelPackages}, {"transitive", fw.TransitivePackages}} {
				for _, it := range list.pkgs {
					var p dotnetPackage
					if err := json.Unmarshal(it, &p); err != nil || p.ID == "" {
						return out, fmt.Errorf("dotnet list package: %s: package without id", pr.Path)
					}
					for _, v := range p.Vulnerabilities {
						rule := firstNonEmpty(ghsaRe.FindString(v.AdvisoryURL), v.AdvisoryURL)
						if rule == "" {
							return out, fmt.Errorf("dotnet list package: %s %s: vulnerability without advisoryurl", p.ID, p.ResolvedVersion)
						}
						key := p.ID + "@" + p.ResolvedVersion + "|" + rule
						if i, ok := seen[key]; ok {
							out[i].F.Description += ", " + fw.Framework
							continue
						}
						f := Finding{Category: "sca", RuleID: rule, Severity: v.Severity, PackageName: p.ID,
							PackageVersion: p.ResolvedVersion, FilePath: NormalizePath(pr.Path)}
						f.Title = fmt.Sprintf("%s in %s %s", rule, p.ID, p.ResolvedVersion)
						f.Description = fmt.Sprintf("NuGet package %s %s (%s dependency) has a known vulnerability.\n%s\n\nTarget frameworks: %s",
							p.ID, p.ResolvedVersion, list.kind, v.AdvisoryURL, fw.Framework)
						seen[key] = len(out)
						out = append(out, importRecord{F: f, Raw: rawJSON(map[string]any{"project": pr.Path, "framework": fw.Framework, "package": it})})
					}
				}
			}
		}
	}
	return out, nil
}
