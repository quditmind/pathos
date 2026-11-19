package scanners

import (
	"encoding/json"
	"fmt"
)

// Aqua Security scanner JSON (`scannercli scan ... --jsonfile`, or the
// image scan result from the Aqua console API): image, digest,
// resources[] with resource (format, name, version, path) and
// vulnerabilities[] (name: the CVE or advisory, description,
// aqua_severity, nvd_severity_v3, aqua_score, nvd_score_v3,
// nvd_vectors_v3, fix_version, solution, nvd_url), plus
// vulnerability_summary. Vulnerabilities with an Aqua acknowledgement
// (already_acknowledged) are kept with low confidence.

type aquaVuln struct {
	Name         string  `json:"name"`
	Description  string  `json:"description"`
	AquaSeverity string  `json:"aqua_severity"`
	NVDSeverity  string  `json:"nvd_severity_v3"`
	AquaScore    float64 `json:"aqua_score"`
	NVDScore     float64 `json:"nvd_score_v3"`
	NVDVector    string  `json:"nvd_vectors_v3"`
	FixVersion   string  `json:"fix_version"`
	Solution     string  `json:"solution"`
	NVDURL       string  `json:"nvd_url"`
	Acknowledged bool    `json:"already_acknowledged"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "aqua", Label: "Aqua Security image scan JSON (scannercli --jsonfile)", Tool: "Aqua Security", Category: "container", Media: "json", Order: 605,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("resources"), "resource", "vulnerabilities") && p.hasAny("image", "vulnerability_summary", "digest")
		},
		parse: parseAqua})
}

func parseAqua(raw []byte) ([]importRecord, error) {
	var doc struct {
		Image     string `json:"image"`
		Resources []struct {
			Resource struct {
				Format  string `json:"format"`
				Name    string `json:"name"`
				Version string `json:"version"`
				Path    string `json:"path"`
			} `json:"resource"`
			Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		} `json:"resources"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("aqua: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, res := range doc.Resources {
		for i, vr := range res.Vulnerabilities {
			var v aquaVuln
			if err := json.Unmarshal(vr, &v); err != nil || v.Name == "" {
				return out, fmt.Errorf("aqua: %s: vulnerability %d: expected an object with name", res.Resource.Name, i+1)
			}
			f := Finding{Category: "container", RuleID: v.Name, Severity: firstNonEmpty(normSeverity(v.AquaSeverity), normSeverity(v.NVDSeverity)),
				CVSS: floatPtr(firstScore(v.AquaScore, v.NVDScore)), CVSSVector: v.NVDVector, PackageName: res.Resource.Name,
				PackageVersion: res.Resource.Version, FixedVersion: v.FixVersion, FilePath: firstNonEmpty(res.Resource.Path, doc.Image),
				Title:       fmt.Sprintf("%s in %s %s", v.Name, res.Resource.Name, res.Resource.Version),
				Description: joinText(v.Description, labeled("Solution", v.Solution), labeled("Package type", res.Resource.Format), labeled("Image", doc.Image), v.NVDURL)}
			if v.Acknowledged {
				f.Confidence = "low"
				f.Description = joinText(f.Description, "Aqua verdict: acknowledged.")
			}
			out = append(out, importRecord{F: f, Raw: vr})
		}
	}
	return out, nil
}

// firstScore returns the first positive score.
func firstScore(v ...float64) float64 {
	for _, s := range v {
		if s > 0 {
			return s
		}
	}
	return 0
}
