package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Clair v4 vulnerability report JSON (GET /matcher/api/v1/vulnerability_report/{manifest},
// also `clairctl report -o json`): packages, vulnerabilities and
// package_vulnerabilities (package id -> vulnerability ids). One finding
// per package and vulnerability; the location is the manifest digest.

type clairPackage struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
	Source  *struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"source"`
}

type clairVuln struct {
	ID                 string `json:"id"`
	Updater            string `json:"updater"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	Links              string `json:"links"`
	Severity           string `json:"severity"`
	NormalizedSeverity string `json:"normalized_severity"`
	FixedInVersion     string `json:"fixed_in_version"`
	Package            *struct {
		Name string `json:"name"`
	} `json:"package"`
}

// clairRecord is the record kept as a finding's original output.
type clairRecord struct {
	ManifestHash  string       `json:"manifest_hash"`
	Package       clairPackage `json:"package"`
	Vulnerability clairVuln    `json:"vulnerability"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "clair", Label: "Clair v4 vulnerability report JSON", Tool: "Clair", Category: "container", Media: "json", Order: 335,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("manifest_hash", "package_vulnerabilities") && p.hasAny("vulnerabilities", "packages")
		},
		parse: parseClair})
}

func parseClair(raw []byte) ([]importRecord, error) {
	var doc struct {
		ManifestHash           string                  `json:"manifest_hash"`
		Packages               map[string]clairPackage `json:"packages"`
		Vulnerabilities        map[string]clairVuln    `json:"vulnerabilities"`
		PackageVulnerabilities map[string][]string     `json:"package_vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("clair: invalid JSON: %w", err)
	}
	pkgIDs := make([]string, 0, len(doc.PackageVulnerabilities))
	for id := range doc.PackageVulnerabilities {
		pkgIDs = append(pkgIDs, id)
	}
	slices.Sort(pkgIDs)
	loc := firstNonEmpty(doc.ManifestHash, "container image")
	var out []importRecord
	for _, pid := range pkgIDs {
		pkg, ok := doc.Packages[pid]
		if !ok {
			return out, fmt.Errorf("clair: package %q of package_vulnerabilities is not in packages", pid)
		}
		for _, vid := range doc.PackageVulnerabilities[pid] {
			v, ok := doc.Vulnerabilities[vid]
			if !ok {
				return out, fmt.Errorf("clair: vulnerability %q is not in vulnerabilities", vid)
			}
			name := firstNonEmpty(v.Name, v.ID)
			f := Finding{Category: "container", RuleID: name, Title: fmt.Sprintf("%s in %s %s", name, pkg.Name, pkg.Version), FilePath: loc,
				PackageName: pkg.Name, PackageVersion: pkg.Version, FixedVersion: firstFixed(v.FixedInVersion),
				CVE: firstMatch(cveRe, v.Name, v.Links, v.Description), Severity: normSeverity(v.NormalizedSeverity),
				Description: joinText(v.Description, labelled("Vendor severity", v.Severity), labelled("Updater", v.Updater), labelled("Links", v.Links))}
			if f.Severity == "" {
				f.Severity = firstNonEmpty(normSeverity(v.Severity), "info")
			}
			rec := clairRecord{ManifestHash: doc.ManifestHash, Package: pkg, Vulnerability: v}
			rec.Vulnerability.Description = clipText(v.Description, maxEvidenceText)
			out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToLower(pkg.Name + "@" + pkg.Version + "|" + name + "|" + vid)), Raw: rawJSON(rec)})
		}
	}
	return out, nil
}
