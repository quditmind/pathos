package scanners

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// OWASP Dependency-Check JSON (`--format JSON`): dependencies[] with
// fileName, filePath, packages[] (package URLs) and vulnerabilities[]
// (name, severity, cvssv3/cvssv2, cwes, description). The report has no
// fixed versions.

type odcDependency struct {
	FileName string `json:"fileName"`
	FilePath string `json:"filePath"`
	Packages []struct {
		ID string `json:"id"`
	} `json:"packages"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

type odcVuln struct {
	Source      string   `json:"source"`
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	CWEs        []string `json:"cwes"`
	Description string   `json:"description"`
	CVSSv3      *struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssv3"`
	CVSSv2 *struct {
		Score float64 `json:"score"`
	} `json:"cvssv2"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "dependency-check", Label: "OWASP Dependency-Check JSON", Category: "sca", Media: "json", Order: 46,
		match: func(p *importProbe) bool { return p.kind == "object" && p.has("reportSchema", "dependencies") },
		parse: parseDependencyCheck})
}

// purlNameVersion returns the name (last path segment) and version of a
// package URL such as pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1.
func purlNameVersion(purl string) (string, string) {
	p, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", ""
	}
	p, _, _ = strings.Cut(p, "?")
	p, _, _ = strings.Cut(p, "#")
	path, version, _ := strings.Cut(p, "@")
	name := path[strings.LastIndex(path, "/")+1:]
	if n, err := url.PathUnescape(name); err == nil {
		name = n
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	return name, version
}

func parseDependencyCheck(raw []byte) ([]importRecord, error) {
	var doc struct {
		Dependencies []odcDependency `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("dependency-check: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, d := range doc.Dependencies {
		name, version := "", ""
		for _, p := range d.Packages {
			if name, version = purlNameVersion(p.ID); name != "" {
				break
			}
		}
		if name == "" {
			name = d.FileName
		}
		for _, vr := range d.Vulnerabilities {
			var v odcVuln
			if err := json.Unmarshal(vr, &v); err != nil || v.Name == "" {
				return out, fmt.Errorf("dependency-check: %s: vulnerability without name", d.FileName)
			}
			f := Finding{Category: "sca", RuleID: v.Name, Severity: v.Severity, CWE: v.CWEs, PackageName: name, PackageVersion: version,
				FilePath: NormalizePath(firstNonEmpty(d.FilePath, d.FileName)), Description: v.Description}
			switch {
			case v.CVSSv3 != nil && v.CVSSv3.BaseScore > 0:
				f.CVSS, f.CVSSVector = floatPtr(v.CVSSv3.BaseScore), v.CVSSv3.VectorString
				if f.CVSSVector != "" && !strings.HasPrefix(f.CVSSVector, "CVSS:") {
					f.CVSSVector = "CVSS:3.1/" + f.CVSSVector
				}
			case v.CVSSv2 != nil && v.CVSSv2.Score > 0:
				f.CVSS = floatPtr(v.CVSSv2.Score)
			}
			if normSeverity(f.Severity) == "" && f.CVSS != nil {
				f.Severity = FromScore(*f.CVSS)
			}
			f.Title = fmt.Sprintf("%s in %s %s", v.Name, name, version)
			out = append(out, importRecord{F: f, Raw: vr})
		}
	}
	return out, nil
}
