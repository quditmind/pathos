package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Harbor vulnerability report JSON: the response of
// GET /api/v2.0/projects/{project}/repositories/{repo}/artifacts/{ref}/additions/vulnerabilities,
// an object keyed by the report MIME type
// ("application/vnd.security.vulnerability.report; version=1.1" or the
// older "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"),
// or the bare report of the pluggable scanner API. One finding per
// vulnerability; the location is the artifact (repository@digest or
// repository:tag), or "container image" when the report names none.

type harborVuln struct {
	ID            string   `json:"id"`
	Package       string   `json:"package"`
	Version       string   `json:"version"`
	FixVersion    string   `json:"fix_version"`
	Severity      string   `json:"severity"`
	Description   string   `json:"description"`
	Links         []string `json:"links"`
	CWEIDs        []string `json:"cwe_ids"`
	PreferredCVSS *struct {
		ScoreV3  float64 `json:"score_v3"`
		ScoreV2  float64 `json:"score_v2"`
		VectorV3 string  `json:"vector_v3"`
		VectorV2 string  `json:"vector_v2"`
	} `json:"preferred_cvss"`
	ArtifactDigests []string `json:"artifact_digests"`
}

type harborReport struct {
	GeneratedAt string `json:"generated_at"`
	Artifact    *struct {
		Repository string `json:"repository"`
		Digest     string `json:"digest"`
		Tag        string `json:"tag"`
	} `json:"artifact"`
	Scanner *struct {
		Name    string `json:"name"`
		Vendor  string `json:"vendor"`
		Version string `json:"version"`
	} `json:"scanner"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
}

func harborIsMIME(k string) bool {
	return strings.HasPrefix(k, "application/vnd.security.vulnerability.report") || strings.HasPrefix(k, "application/vnd.scanner.adapter.vuln.report")
}

func init() {
	registerImportFormat(ImportFormat{ID: "harbor", Label: "Harbor vulnerability report JSON", Tool: "Harbor", Category: "container", Media: "json", Order: 336,
		match: func(p *importProbe) bool {
			if p.kind != "object" {
				return false
			}
			for k := range p.keys {
				if harborIsMIME(k) {
					return true
				}
			}
			return p.has("generated_at", "scanner", "vulnerabilities") && p.hasAny("artifact", "severity")
		},
		parse: parseHarbor})
}

func parseHarbor(raw []byte) ([]importRecord, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(bytes.TrimPrefix(raw, utf8BOM), &top); err != nil {
		return nil, fmt.Errorf("harbor: invalid JSON: %w", err)
	}
	reports := []json.RawMessage{}
	var mimes []string
	for k := range top {
		if harborIsMIME(k) {
			mimes = append(mimes, k)
		}
	}
	slices.Sort(mimes)
	for _, k := range mimes {
		reports = append(reports, top[k])
	}
	if len(mimes) == 0 {
		reports = append(reports, raw)
	}
	var out []importRecord
	for _, r := range reports {
		var rep harborReport
		if err := json.Unmarshal(r, &rep); err != nil {
			return out, fmt.Errorf("harbor: invalid report: %w", err)
		}
		loc := "container image"
		if a := rep.Artifact; a != nil && a.Repository != "" {
			loc = a.Repository
			switch {
			case a.Digest != "":
				loc += "@" + a.Digest
			case a.Tag != "":
				loc += ":" + a.Tag
			}
		}
		scanner := ""
		if rep.Scanner != nil {
			scanner = strings.TrimSpace(rep.Scanner.Name + " " + rep.Scanner.Version)
		}
		for i, it := range rep.Vulnerabilities {
			var v harborVuln
			if err := json.Unmarshal(it, &v); err != nil || v.ID == "" {
				return out, fmt.Errorf("harbor: vulnerability %d: expected an object with id", i+1)
			}
			f := Finding{Category: "container", RuleID: v.ID, CVE: firstMatch(cveRe, v.ID), Title: fmt.Sprintf("%s in %s %s", v.ID, v.Package, v.Version),
				FilePath: loc, PackageName: v.Package, PackageVersion: v.Version, FixedVersion: firstFixed(v.FixVersion),
				Severity: firstNonEmpty(normSeverity(v.Severity), "info"), CWE: v.CWEIDs,
				Description: joinText(v.Description, labelled("Scanner", scanner), labelled("Links", strings.Join(v.Links, "\n")))}
			if c := v.PreferredCVSS; c != nil {
				if c.ScoreV3 > 0 {
					f.CVSS, f.CVSSVector = floatPtr(c.ScoreV3), c.VectorV3
				} else if c.ScoreV2 > 0 {
					f.CVSS, f.CVSSVector = floatPtr(c.ScoreV2), c.VectorV2
				}
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToLower(v.Package + "@" + v.Version + "|" + v.ID)), Raw: it})
		}
	}
	return out, nil
}
