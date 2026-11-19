package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Prisma Cloud Compute (Twistlock): the twistcli JSON output (`twistcli
// images scan --output-file`: results[] with vulnerabilities and
// compliances) and the CSV export of the image vulnerability report
// (Monitor > Vulnerabilities > Images, "CSV"). Failed compliance checks
// are findings too (misconfiguration).

type twistlockResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Distro      string `json:"distro"`
	Compliances []struct {
		ID          looseString `json:"id"`
		Title       string      `json:"title"`
		Severity    string      `json:"severity"`
		Description string      `json:"description"`
		Category    string      `json:"category"`
	} `json:"compliances"`
	Vulnerabilities []struct {
		ID             string  `json:"id"`
		Status         string  `json:"status"`
		CVSS           float64 `json:"cvss"`
		Vector         string  `json:"vector"`
		Description    string  `json:"description"`
		Severity       string  `json:"severity"`
		PackageName    string  `json:"packageName"`
		PackageVersion string  `json:"packageVersion"`
		Link           string  `json:"link"`
		FixedIn        string  `json:"fixedIn"`
	} `json:"vulnerabilities"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "twistlock", Label: "Prisma Cloud / Twistlock twistcli JSON", Tool: "Prisma Cloud", Category: "container", Media: "json", Order: 461,
		match: func(p *importProbe) bool {
			if p.kind != "object" || !p.has("results") {
				return false
			}
			r := p.firstOf("results")
			return hasKeys(r, "id", "distro") && (hasKeys(r, "vulnerabilities") || hasKeys(r, "compliances") || hasKeys(r, "vulnerabilityDistribution"))
		},
		parse: parseTwistlockJSON})
	registerImportFormat(ImportFormat{ID: "twistlock-csv", Label: "Prisma Cloud / Twistlock vulnerability CSV", Tool: "Prisma Cloud", Category: "container", Media: "csv", Order: 462,
		match: func(p *importProbe) bool {
			return p.kind == "csv" && headerHas(p.header, "registry", "repository", "tag", "cve_id", "compliance_id", "packages", "fix_status")
		},
		parse: parseTwistlockCSV})
}

func parseTwistlockJSON(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("twistlock: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r twistlockResult
		if err := json.Unmarshal(it, &r); err != nil {
			return out, fmt.Errorf("twistlock: result %d: %w", i+1, err)
		}
		image := firstNonEmpty(r.Name, r.ID, "image")
		for _, v := range r.Vulnerabilities {
			if v.ID == "" {
				return out, fmt.Errorf("twistlock: result %d: vulnerability without id", i+1)
			}
			f := Finding{Category: "container", RuleID: v.ID, Title: v.ID + " in " + v.PackageName, Severity: normSeverity(v.Severity),
				CVE: firstMatch(cveRe, v.ID), CVSS: floatPtr(v.CVSS), CVSSVector: v.Vector, PackageName: v.PackageName, PackageVersion: v.PackageVersion,
				FixedVersion: twistlockFixed(firstNonEmpty(v.FixedIn, v.Status)), FilePath: image}
			if f.Severity == "" && strings.HasPrefix(strings.ToLower(v.Severity), "important") {
				f.Severity = "high"
			}
			f.Description = joinText(v.Description, labelled("Fix status", v.Status), labelled("Distribution", r.Distro), labelled("Reference", v.Link))
			out = append(out, importRecord{F: f, SnippetKey: hashOf(v.PackageName + "@" + v.PackageVersion + "|" + v.ID), Raw: rawJSON(map[string]any{"image": image, "vulnerability": v})})
		}
		for _, c := range r.Compliances {
			id := string(c.ID)
			f := Finding{Category: "misconfiguration", RuleID: "compliance-" + id, Title: firstNonEmpty(c.Title, "Compliance check "+id),
				Severity: normSeverity(c.Severity), FilePath: image, Description: joinText(c.Description, labelled("Category", c.Category))}
			out = append(out, importRecord{F: f, SnippetKey: hashOf("compliance|" + id), Raw: rawJSON(map[string]any{"image": image, "compliance": c})})
		}
	}
	return out, nil
}

// twistlockFixed extracts the version from "fixed in 1.2.11" (several
// versions are listed comma separated; the first is kept).
func twistlockFixed(s string) string {
	s = strings.TrimSpace(s)
	low := strings.ToLower(s)
	if !strings.HasPrefix(low, "fixed in") {
		if strings.Contains(low, " ") {
			return "" // "open", "will not fix", "needed", ...
		}
		return s
	}
	s = strings.TrimSpace(s[len("fixed in"):])
	s, _, _ = strings.Cut(s, ",")
	return strings.TrimSpace(s)
}

func parseTwistlockCSV(raw []byte) ([]importRecord, error) {
	_, rows, err := csvTable(raw)
	if err != nil && len(rows) == 0 {
		return nil, fmt.Errorf("twistlock: %w", err)
	}
	var out []importRecord
	for _, r := range rows {
		cve, comp := r.get("cve_id"), r.get("compliance_id")
		pkg, ver := r.get("packages"), r.get("package_version")
		image := strings.TrimSuffix(strings.Trim(r.get("registry")+"/"+r.get("repository"), "/")+":"+r.get("tag"), ":")
		if strings.Trim(image, "/:") == "" {
			image = firstNonEmpty(r.get("id"), "image")
		}
		f := Finding{Category: "container", Severity: normSeverity(r.get("severity")), CVSS: cvssOf(r.get("cvss")), PackageName: pkg,
			PackageVersion: ver, FixedVersion: twistlockFixed(r.get("fix_status")), FilePath: image}
		if f.Severity == "" && strings.HasPrefix(strings.ToLower(r.get("severity")), "important") {
			f.Severity = "high"
		}
		switch {
		case cve != "":
			f.RuleID, f.CVE, f.Title = cve, firstMatch(cveRe, cve), cve+" in "+pkg
		case comp != "":
			f.Category, f.RuleID, f.Title = "misconfiguration", "compliance-"+comp, firstNonEmpty(r.get("description"), "Compliance check "+comp)
		default:
			return out, fmt.Errorf("twistlock: row %d: no CVE ID or Compliance ID", r.N)
		}
		f.Description = joinText(r.get("description"), labelled("Fix status", r.get("fix_status")), labelled("Distribution", r.get("distro")),
			labelled("Risk factors", r.get("risk_factors")), labelled("Cause", r.get("cause")), labelled("Hosts", r.get("hosts", "hostname")),
			labelled("Clusters", r.get("clusters")))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(pkg + "@" + ver + "|" + f.RuleID + "|" + r.get("source_package")), Raw: rawJSON(r.Orig)})
	}
	return out, err
}
