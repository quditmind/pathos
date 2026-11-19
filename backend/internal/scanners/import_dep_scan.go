package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OWASP dep-scan VDR (the *.vdr.json report dep-scan 5 and 6 write to its
// reports directory): a CycloneDX document whose metadata.tools names
// owasp-depscan, with vulnerabilities[]: id (CVE, GHSA, ...), bom-ref
// ("id/purl"), description, detail, cwes (numbers), ratings (score,
// severity, vector), affects[].ref (the purl) with versions (affected and
// unaffected = the fix), recommendation, analysis (state, detail) and
// properties (depscan:prioritized, depscan:insights). Other CycloneDX
// documents with vulnerabilities are not detected as dep-scan reports.
// Findings analysed as false positive or not affected have low
// confidence; prioritized ones (reachable or direct, per dep-scan) say so.

type depscanVuln struct {
	ID          string `json:"id"`
	BomRef      string `json:"bom-ref"`
	Description string `json:"description"`
	Detail      string `json:"detail"`
	CWEs        []int  `json:"cwes"`
	Ratings     []struct {
		Score    float64 `json:"score"`
		Severity string  `json:"severity"`
		Vector   string  `json:"vector"`
		Method   string  `json:"method"`
	} `json:"ratings"`
	Affects []struct {
		Ref      string `json:"ref"`
		Versions []struct {
			Version string `json:"version"`
			Status  string `json:"status"`
		} `json:"versions"`
	} `json:"affects"`
	Recommendation string `json:"recommendation"`
	Analysis       struct {
		State  string `json:"state"`
		Detail string `json:"detail"`
	} `json:"analysis"`
	Advisories []struct {
		Title string `json:"title"`
		URL   string `json:"url"`
	} `json:"advisories"`
	Properties []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"properties"`
}

// isDepscanVDR reports a CycloneDX document written by dep-scan.
func isDepscanVDR(p *importProbe) bool {
	if p.kind != "object" || !p.has("bomFormat", "vulnerabilities", "metadata") {
		return false
	}
	var meta struct {
		Tools json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(p.keys["metadata"], &meta) != nil {
		return false
	}
	type tool struct {
		Name string `json:"name"`
	}
	var tools []tool
	var obj struct {
		Components []tool `json:"components"`
	}
	if json.Unmarshal(meta.Tools, &tools) != nil && json.Unmarshal(meta.Tools, &obj) == nil {
		tools = obj.Components
	}
	for _, t := range tools {
		if n := strings.ToLower(t.Name); n == "owasp-depscan" || n == "depscan" || n == "dep-scan" {
			return true
		}
	}
	return false
}

func init() {
	registerImportFormat(ImportFormat{ID: "dep-scan", Label: "OWASP dep-scan VDR (CycloneDX JSON)", Tool: "OWASP dep-scan", Category: "sca", Media: "json", Order: 219,
		match: isDepscanVDR,
		parse: parseDepscan})
}

func parseDepscan(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "vulnerabilities")
	if err != nil {
		return nil, fmt.Errorf("dep-scan: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var v depscanVuln
		if err := json.Unmarshal(it, &v); err != nil || v.ID == "" {
			return out, fmt.Errorf("dep-scan: vulnerability %d: expected an object with id", i+1)
		}
		purl := ""
		if len(v.Affects) > 0 {
			purl = v.Affects[0].Ref
		} else if _, p, ok := strings.Cut(v.BomRef, "/pkg:"); ok {
			purl = "pkg:" + p
		}
		name, version := purlNameVersion(purl)
		if name == "" {
			return out, fmt.Errorf("dep-scan: %s: no affected package (affects[].ref)", v.ID)
		}
		f := Finding{Category: "sca", RuleID: v.ID, CVE: firstMatch(cveRe, v.ID), PackageName: name, PackageVersion: version}
		for _, a := range v.Affects {
			for _, ver := range a.Versions {
				switch {
				case ver.Status == "affected" && f.PackageVersion == "":
					f.PackageVersion = ver.Version
				case ver.Status == "unaffected" && f.FixedVersion == "" && ver.Version != "*":
					f.FixedVersion = ver.Version
				}
			}
		}
		for _, c := range v.CWEs {
			f.CWE = append(f.CWE, fmt.Sprintf("CWE-%d", c))
		}
		if len(v.Ratings) > 0 {
			r := v.Ratings[0]
			f.Severity, f.CVSS, f.CVSSVector = r.Severity, floatPtr(r.Score), r.Vector
			if f.CVSSVector != "" && !strings.HasPrefix(f.CVSSVector, "CVSS:") && strings.HasPrefix(r.Method, "CVSSv3") {
				f.CVSSVector = "CVSS:3.1/" + f.CVSSVector
			}
		}
		if normSeverity(f.Severity) == "" && f.CVSS != nil {
			f.Severity = FromScore(*f.CVSS)
		}
		f.Title = fmt.Sprintf("%s in %s %s", v.ID, name, f.PackageVersion)
		desc := []string{v.Description, v.Detail, v.Recommendation, "Package: " + purl}
		for _, p := range v.Properties {
			switch p.Name {
			case "depscan:prioritized":
				if p.Value == "true" {
					desc = append(desc, "dep-scan prioritized this vulnerability (the package is reachable or a direct dependency).")
				}
			case "depscan:insights":
				desc = append(desc, "dep-scan insights: "+strings.ReplaceAll(p.Value, `\n`, ", "))
			}
		}
		switch v.Analysis.State {
		case "false_positive", "not_affected", "resolved":
			f.Confidence = "low"
			desc = append(desc, "dep-scan analysis: "+v.Analysis.State+" "+v.Analysis.Detail)
		case "":
		default:
			desc = append(desc, "dep-scan analysis: "+v.Analysis.State)
		}
		for _, a := range v.Advisories {
			desc = append(desc, a.Title+": "+a.URL)
		}
		f.Description = joinText(desc...)
		out = append(out, importRecord{F: f, Raw: it})
	}
	return out, nil
}
