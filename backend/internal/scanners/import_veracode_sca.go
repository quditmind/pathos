package scanners

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Veracode SCA agent-based scan JSON (`srcclr scan --json`): records[]
// with libraries[] (name, coordinateType, coordinate1, coordinate2,
// versions[].version) and vulnerabilities[] (cve, title, overview,
// cvssScore, cvss3Score, libraries[] with details[] (versionRange,
// updateToVersion, fixText) and _links.ref pointing to
// /records/N/libraries/M). One finding per vulnerability and affected
// library; CVE numbers without the "CVE-" prefix get it.

func init() {
	registerImportFormat(ImportFormat{ID: "srcclr", Label: "Veracode SCA agent scan JSON (srcclr --json)", Tool: "Veracode SCA", Category: "sca", Media: "json", Order: 616,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("records"), "libraries", "vulnerabilities")
		},
		parse: parseVeracodeSCA})
}

func parseVeracodeSCA(raw []byte) ([]importRecord, error) {
	var doc struct {
		Records []struct {
			Libraries []struct {
				Name     string `json:"name"`
				Coord1   string `json:"coordinate1"`
				Coord2   string `json:"coordinate2"`
				Type     string `json:"coordinateType"`
				Versions []struct {
					Version string `json:"version"`
				} `json:"versions"`
			} `json:"libraries"`
			Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		} `json:"records"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("veracode sca: invalid JSON: %w", err)
	}
	var out []importRecord
	for ri, rec := range doc.Records {
		for i, vr := range rec.Vulnerabilities {
			var v struct {
				CVE       string  `json:"cve"`
				Title     string  `json:"title"`
				Overview  string  `json:"overview"`
				CVSS      float64 `json:"cvssScore"`
				CVSS3     float64 `json:"cvss3Score"`
				Libraries []struct {
					Details []struct {
						VersionRange string `json:"versionRange"`
						UpdateTo     string `json:"updateToVersion"`
						FixText      string `json:"fixText"`
					} `json:"details"`
					Links struct {
						Ref string `json:"ref"`
					} `json:"_links"`
				} `json:"libraries"`
				Links struct {
					HTML string `json:"html"`
				} `json:"_links"`
			}
			if err := json.Unmarshal(vr, &v); err != nil || firstNonEmpty(v.CVE, v.Title) == "" {
				return out, fmt.Errorf("veracode sca: record %d: vulnerability %d: expected cve or title", ri+1, i+1)
			}
			cve := strings.TrimSpace(v.CVE)
			if cve != "" && !strings.HasPrefix(strings.ToUpper(cve), "CVE-") {
				cve = "CVE-" + cve
			}
			for _, l := range v.Libraries {
				name, version, typ := "", "", ""
				parts := strings.Split(strings.Trim(l.Links.Ref, "/"), "/")
				if n := len(parts); n >= 2 && parts[n-2] == "libraries" {
					if j, err := strconv.Atoi(parts[n-1]); err == nil && j >= 0 && j < len(rec.Libraries) {
						lib := rec.Libraries[j]
						name, typ = firstNonEmpty(strings.Trim(lib.Coord1+":"+lib.Coord2, ":"), lib.Name), lib.Type
						if len(lib.Versions) > 0 {
							version = lib.Versions[0].Version
						}
					}
				}
				f := Finding{Category: "sca", RuleID: firstNonEmpty(cve, v.Title), CVE: cve, CVSS: floatPtr(firstScore(v.CVSS3, v.CVSS)),
					PackageName: name, PackageVersion: version, Title: strings.TrimSpace(fmt.Sprintf("%s: %s in %s %s", firstNonEmpty(cve, "Vulnerability"), v.Title, name, version)),
					Description: joinText(v.Overview, labeled("Library type", typ), v.Links.HTML)}
				if f.CVSS != nil {
					f.Severity = FromScore(*f.CVSS)
				}
				for _, d := range l.Details {
					f.FixedVersion = firstNonEmpty(f.FixedVersion, d.UpdateTo)
					f.Description = joinText(f.Description, labeled("Affected versions", d.VersionRange), labeled("Fix", d.FixText))
				}
				out = append(out, importRecord{F: f, Raw: vr})
			}
		}
	}
	return out, nil
}
