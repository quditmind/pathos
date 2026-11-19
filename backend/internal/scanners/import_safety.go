package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Safety JSON (`safety check --json` in Safety 2, `safety check --output
// json` in Safety 3; report_meta.json_version 1 and 1.1): vulnerabilities[]
// with vulnerability_id, package_name, analyzed_version, vulnerable_spec
// (a string in 1, a list in 1.1), CVE, severity (null with the free
// database; cvssv3/cvssv2 objects with an API key), fixed_versions and,
// in 1.1, analyzed_requirement.found (the requirements file). Safety 3
// prints a deprecation banner after the JSON on stdout; text after the
// JSON document is ignored. Ignored vulnerabilities (ignored_vulnerabilities)
// are imported with low confidence and the reason in the description.
// The newer `safety scan` JSON (account required) is not this format.

type safetyVuln struct {
	VulnerabilityID     string          `json:"vulnerability_id"`
	PackageName         string          `json:"package_name"`
	AnalyzedVersion     string          `json:"analyzed_version"`
	VulnerableSpec      json.RawMessage `json:"vulnerable_spec"`
	Advisory            string          `json:"advisory"`
	CVE                 string          `json:"CVE"`
	Severity            json.RawMessage `json:"severity"`
	FixedVersions       []string        `json:"fixed_versions"`
	MoreInfoURL         string          `json:"more_info_url"`
	IsTransitive        bool            `json:"is_transitive"`
	IgnoredReason       string          `json:"ignored_reason"`
	AnalyzedRequirement struct {
		Found string `json:"found"`
	} `json:"analyzed_requirement"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "safety", Label: "Safety JSON (Safety 2 and 3 check)", Tool: "Safety", Category: "sca", Media: "json", Order: 215,
		match: func(p *importProbe) bool {
			return (p.kind == "object" || p.kind == "stream") && p.has("report_meta", "vulnerabilities") && p.hasAny("scanned_packages", "affected_packages")
		},
		parse: parseSafety})
}

func parseSafety(raw []byte) ([]importRecord, error) {
	var doc struct {
		AffectedPackages map[string]struct {
			Found string `json:"found"`
		} `json:"affected_packages"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		Ignored         []json.RawMessage `json:"ignored_vulnerabilities"`
	}
	// The first JSON document; Safety 3 prints a banner after it.
	if err := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM))).Decode(&doc); err != nil {
		return nil, fmt.Errorf("safety: invalid JSON: %w", err)
	}
	var out []importRecord
	add := func(i int, it json.RawMessage, ignored bool) error {
		var v safetyVuln
		if err := json.Unmarshal(it, &v); err != nil || v.VulnerabilityID == "" || v.PackageName == "" {
			return fmt.Errorf("safety: vulnerability %d: expected an object with vulnerability_id and package_name", i+1)
		}
		spec := ""
		var specs []string
		if json.Unmarshal(v.VulnerableSpec, &specs) == nil {
			spec = strings.Join(specs, ", ")
		} else {
			_ = json.Unmarshal(v.VulnerableSpec, &spec)
		}
		file := v.AnalyzedRequirement.Found
		if file == "" {
			file = doc.AffectedPackages[v.PackageName].Found
		}
		f := Finding{Category: "sca", PackageName: v.PackageName, PackageVersion: v.AnalyzedVersion,
			CVE: firstMatch(cveRe, v.CVE), FilePath: NormalizePath(file)}
		if f.CVE != "" {
			f.RuleID = f.CVE
		} else if strings.HasPrefix(v.VulnerabilityID, "PYSEC") || strings.HasPrefix(v.VulnerabilityID, "GHSA") {
			f.RuleID = v.VulnerabilityID
		} else {
			f.RuleID = "safety-" + v.VulnerabilityID
		}
		if len(v.FixedVersions) > 0 {
			f.FixedVersion = v.FixedVersions[0]
		}
		desc := []string{v.Advisory, "Vulnerable versions: " + spec, "Safety ID " + v.VulnerabilityID + " " + v.MoreInfoURL}
		var sev struct {
			CVSSv3 *struct {
				BaseScore     float64 `json:"base_score"`
				BaseSeverity  string  `json:"base_severity"`
				VectorString  string  `json:"vector_string"`
				VectorVersion string  `json:"version"`
			} `json:"cvssv3"`
			CVSSv2 *struct {
				BaseScore float64 `json:"base_score"`
			} `json:"cvssv2"`
		}
		if json.Unmarshal(v.Severity, &sev) == nil {
			if c := sev.CVSSv3; c != nil {
				f.CVSS, f.Severity, f.CVSSVector = floatPtr(c.BaseScore), c.BaseSeverity, c.VectorString
				if f.CVSSVector != "" && !strings.HasPrefix(f.CVSSVector, "CVSS:") {
					f.CVSSVector = "CVSS:3.1/" + f.CVSSVector
				}
			} else if c := sev.CVSSv2; c != nil {
				f.CVSS = floatPtr(c.BaseScore)
			}
		}
		if f.Severity == "" && f.CVSS == nil {
			f.Severity = "medium"
			desc = append(desc, "Safety reports no severity for this vulnerability (free database); imported as medium.")
		}
		if v.IsTransitive {
			desc = append(desc, "Transitive dependency.")
		}
		if ignored {
			f.Confidence = "low"
			desc = append(desc, "Ignored in Safety: "+firstNonEmpty(v.IgnoredReason, "no reason given"))
		}
		f.Title = fmt.Sprintf("%s in %s %s", firstNonEmpty(f.CVE, "Safety "+v.VulnerabilityID), v.PackageName, v.AnalyzedVersion)
		f.Description = joinText(desc...)
		out = append(out, importRecord{F: f, Raw: it})
		return nil
	}
	for i, it := range doc.Vulnerabilities {
		if err := add(i, it, false); err != nil {
			return out, err
		}
	}
	for i, it := range doc.Ignored {
		if err := add(i, it, true); err != nil {
			return out, err
		}
	}
	return out, nil
}
