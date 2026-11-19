package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Lacework API v2 vulnerability search results
// (/api/v2/Vulnerabilities/Containers/search and /Hosts/search):
// {"data": [...]} rows with vulnId, severity, status, featureKey (name,
// namespace, version or version_installed), fixInfo (fix_available,
// fixed_version), cveProps (description, link), and the image (imageId,
// evalCtx.image_info repo and tag) or host (mid, evalCtx.hostname,
// machineTags.Hostname). Rows with status Fixed or Inactive are not
// findings. Container rows use the container category, host rows sca.

type laceworkRow struct {
	VulnID     string          `json:"vulnId"`
	Severity   string          `json:"severity"`
	Status     string          `json:"status"`
	ImageID    string          `json:"imageId"`
	MID        json.RawMessage `json:"mid"`
	FeatureKey struct {
		Name             string `json:"name"`
		Namespace        string `json:"namespace"`
		Version          string `json:"version"`
		VersionInstalled string `json:"version_installed"`
	} `json:"featureKey"`
	FixInfo struct {
		FixAvailable json.RawMessage `json:"fix_available"`
		FixedVersion string          `json:"fixed_version"`
	} `json:"fixInfo"`
	CVEProps struct {
		Description string `json:"description"`
		Link        string `json:"link"`
	} `json:"cveProps"`
	EvalCtx struct {
		Hostname  string `json:"hostname"`
		ImageInfo struct {
			Repo     string   `json:"repo"`
			Registry string   `json:"registry"`
			Tags     []string `json:"tags"`
			Digest   string   `json:"digest"`
		} `json:"image_info"`
	} `json:"evalCtx"`
	MachineTags struct {
		Hostname string `json:"Hostname"`
	} `json:"machineTags"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "lacework", Label: "Lacework vulnerabilities JSON (API v2 Containers/Hosts search)", Tool: "Lacework", Media: "json", Order: 604,
		match: func(p *importProbe) bool {
			return p.kind == "object" && hasKeys(p.firstOf("data"), "vulnId", "featureKey")
		},
		parse: parseLacework})
}

func parseLacework(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "data")
	if err != nil {
		return nil, fmt.Errorf("lacework: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r laceworkRow
		if err := json.Unmarshal(it, &r); err != nil || r.VulnID == "" {
			return out, fmt.Errorf("lacework: row %d: expected an object with vulnId", i+1)
		}
		if st := strings.ToLower(r.Status); st == "fixed" || st == "inactive" {
			continue
		}
		f := Finding{Category: "sca", RuleID: r.VulnID, CVE: r.VulnID, Severity: r.Severity, PackageName: r.FeatureKey.Name,
			PackageVersion: firstNonEmpty(r.FeatureKey.Version, r.FeatureKey.VersionInstalled), FixedVersion: r.FixInfo.FixedVersion}
		if r.ImageID != "" {
			f.Category = "container"
			img := r.EvalCtx.ImageInfo.Repo
			if len(r.EvalCtx.ImageInfo.Tags) > 0 {
				img += ":" + r.EvalCtx.ImageInfo.Tags[0]
			}
			f.FilePath = firstNonEmpty(strings.Trim(img, ":"), r.ImageID)
		} else {
			f.FilePath = firstNonEmpty(r.EvalCtx.Hostname, r.MachineTags.Hostname, "machine "+strings.Trim(string(r.MID), `"`))
		}
		f.Title = fmt.Sprintf("%s in %s %s", r.VulnID, f.PackageName, f.PackageVersion)
		f.Description = joinText(r.CVEProps.Description, fmt.Sprintf("Package %s %s (%s) on %s.", f.PackageName, f.PackageVersion, r.FeatureKey.Namespace, f.FilePath),
			labeled("Fixed version", r.FixInfo.FixedVersion), labeled("Reference", r.CVEProps.Link), "Lacework status: "+r.Status)
		out = append(out, importRecord{F: f, Raw: it})
	}
	return out, nil
}
