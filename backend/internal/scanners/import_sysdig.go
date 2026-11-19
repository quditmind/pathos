package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Sysdig Secure vulnerability results: the sysdig-cli-scanner JSON
// (`--json-scan-result`: result.packages[].vulns), the JSON of a Sysdig
// vulnerability report (panels[].data rows) and the vulnerability report
// CSV (the legacy "Vulnerability ID" and the 2025 "Vulnerability Name"
// layouts). Accepted risks are kept with low confidence.

type sysdigCLI struct {
	Scanner struct {
		Name string `json:"name"`
	} `json:"scanner"`
	Result struct {
		Metadata struct {
			PullString string `json:"pullString"`
			ImageID    string `json:"imageId"`
			BaseOs     string `json:"baseOs"`
		} `json:"metadata"`
		Packages []struct {
			Type         string `json:"type"`
			Name         string `json:"name"`
			Version      string `json:"version"`
			Path         string `json:"path"`
			SuggestedFix string `json:"suggestedFix"`
			Vulns        []struct {
				Name     string `json:"name"`
				Severity struct {
					Value string `json:"value"`
				} `json:"severity"`
				CvssScore struct {
					Value struct {
						Score  float64 `json:"score"`
						Vector string  `json:"vector"`
					} `json:"value"`
				} `json:"cvssScore"`
				Exploitable    bool   `json:"exploitable"`
				FixedInVersion string `json:"fixedInVersion"`
				AcceptedRisk   bool   `json:"acceptedRisk"`
			} `json:"vulns"`
		} `json:"packages"`
	} `json:"result"`
}

type sysdigRow struct {
	Image         string  `json:"container_image"`
	ImageID       string  `json:"container_image_id"`
	Cluster       string  `json:"kubernetes_cluster_name"`
	Namespace     string  `json:"kubernetes_namespace_name"`
	Workload      string  `json:"kubernetes_workload_name"`
	PackageName   string  `json:"scan_package_name"`
	PackagePath   string  `json:"scan_package_path"`
	PackageType   string  `json:"scan_package_type"`
	Version       string  `json:"scan_package_version"`
	CVSSScore     float64 `json:"vuln_cvss_score"`
	CVSSVector    string  `json:"vuln_cvss_vector"`
	CVSSVersion   string  `json:"vuln_cvss_version"`
	FixedIn       string  `json:"vuln_fixed_in_version"`
	HasExploit    bool    `json:"vuln_has_exploit"`
	VulnID        string  `json:"vuln_id"`
	RiskAccepted  bool    `json:"vuln_risk_accepted"`
	Severity      string  `json:"vuln_severity"`
	ContainerName string  `json:"kubernetes_pod_container_name"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "sysdig", Label: "Sysdig vulnerability JSON (CLI scanner or report)", Tool: "Sysdig Secure", Category: "container", Media: "json", Order: 463,
		match: func(p *importProbe) bool {
			if p.kind != "object" {
				return false
			}
			if p.has("scanner", "result") {
				var s struct {
					Name string `json:"name"`
				}
				return json.Unmarshal(p.keys["scanner"], &s) == nil && strings.HasPrefix(s.Name, "sysdig")
			}
			return p.has("panels") && p.headHas(`"vuln_id"`, `"scan_package_name"`)
		},
		parse: parseSysdigJSON})
	registerImportFormat(ImportFormat{ID: "sysdig-csv", Label: "Sysdig vulnerability report CSV", Tool: "Sysdig Secure", Category: "container", Media: "csv", Order: 464,
		match: func(p *importProbe) bool {
			if p.kind != "csv" || !headerHas(p.header, "package_name", "package_version", "package_path", "image_id", "risk_accepted") {
				return false
			}
			return headerHas(p.header, "vulnerability_id", "severity") || headerHas(p.header, "vulnerability_name", "vulnerability_severity")
		},
		parse: parseSysdigCSV})
}

func sysdigRecord(vuln, sev string, score float64, vector, pkg, ver, ptype, path, fixed, image string, exploit, accepted bool, extra string, raw json.RawMessage) importRecord {
	f := Finding{Category: "container", RuleID: vuln, Title: vuln + " in " + pkg, Severity: normSeverity(sev), CVE: firstMatch(cveRe, vuln),
		CVSS: floatPtr(score), PackageName: pkg, PackageVersion: ver, FixedVersion: strings.TrimSpace(fixed), FilePath: firstNonEmpty(image, "image")}
	if strings.HasPrefix(vector, "CVSS:") || strings.HasPrefix(vector, "AV:") {
		f.CVSSVector = vector
	}
	note := ""
	if accepted {
		f.Confidence, note = "low", "Sysdig reports this vulnerability as an accepted risk; it is kept for review."
	}
	exp := ""
	if exploit {
		exp = "A public exploit is known."
	}
	f.Description = joinText(note, fmt.Sprintf("%s %s (%s) is affected by %s.", pkg, ver, ptype, vuln), exp, labelled("Path", path),
		labelled("Fixed in", fixed), extra)
	return importRecord{F: f, SnippetKey: hashOf(pkg + "@" + ver + "|" + vuln + "|" + path), Raw: raw}
}

func parseSysdigJSON(raw []byte) ([]importRecord, error) {
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("sysdig: invalid JSON: %w", err)
	}
	var out []importRecord
	if _, ok := probe["panels"]; ok {
		var rep struct {
			Panels []struct {
				Data []json.RawMessage `json:"data"`
			} `json:"panels"`
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			return nil, fmt.Errorf("sysdig: invalid report: %w", err)
		}
		for _, p := range rep.Panels {
			for i, d := range p.Data {
				var r sysdigRow
				if err := json.Unmarshal(d, &r); err != nil || r.VulnID == "" {
					return out, fmt.Errorf("sysdig: row %d: expected vuln_id", i+1)
				}
				if r.CVSSVersion == "2.0" && !strings.HasPrefix(r.CVSSVector, "CVSS:") {
					r.CVSSVector = "" // a v2 vector is not told apart from a v3 one without the prefix
				}
				where := strings.Trim(strings.Join([]string{r.Cluster, r.Namespace, r.Workload, r.ContainerName}, "/"), "/")
				out = append(out, sysdigRecord(r.VulnID, r.Severity, r.CVSSScore, r.CVSSVector, r.PackageName, r.Version, r.PackageType, r.PackagePath,
					r.FixedIn, r.Image, r.HasExploit, r.RiskAccepted, labelled("Workload", where), d))
			}
		}
		return out, nil
	}
	var rep sysdigCLI
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("sysdig: invalid scan result: %w", err)
	}
	image := firstNonEmpty(rep.Result.Metadata.PullString, rep.Result.Metadata.ImageID)
	for _, p := range rep.Result.Packages {
		for _, v := range p.Vulns {
			if v.Name == "" {
				return out, fmt.Errorf("sysdig: package %s: vulnerability without name", p.Name)
			}
			rec := map[string]any{"image": image, "package": map[string]string{"type": p.Type, "name": p.Name, "version": p.Version, "path": p.Path}, "vuln": v}
			out = append(out, sysdigRecord(v.Name, v.Severity.Value, v.CvssScore.Value.Score, v.CvssScore.Value.Vector, p.Name, p.Version, p.Type, p.Path,
				firstNonEmpty(v.FixedInVersion, p.SuggestedFix), image, v.Exploitable, v.AcceptedRisk, labelled("Base OS", rep.Result.Metadata.BaseOs), rawJSON(rec)))
		}
	}
	return out, nil
}

func parseSysdigCSV(raw []byte) ([]importRecord, error) {
	_, rows, err := csvTable(raw)
	if err != nil && len(rows) == 0 {
		return nil, fmt.Errorf("sysdig: %w", err)
	}
	var out []importRecord
	for _, r := range rows {
		vuln := r.get("vulnerability_id", "vulnerability_name")
		if vuln == "" {
			return out, fmt.Errorf("sysdig: row %d: no vulnerability ID", r.N)
		}
		score := 0.0
		if s := cvssOf(r.get("cvss_score")); s != nil {
			score = *s
		}
		vector := r.get("cvss_vector")
		if strings.HasPrefix(r.get("cvss_version"), "2") && !strings.HasPrefix(vector, "CVSS:") {
			vector = ""
		}
		where := strings.Trim(strings.Join([]string{r.get("kubernetes_cluster_name"), r.get("kubernetes_namespace_name"),
			r.get("kubernetes_workload_name"), r.get("kubernetes_container_name")}, "/"), "/")
		out = append(out, sysdigRecord(vuln, r.get("severity", "vulnerability_severity"), score, vector, r.get("package_name"), r.get("package_version"),
			r.get("package_type"), r.get("package_path"), r.get("fix_version", "package_suggested_fix"), r.get("image", "image_name"),
			strings.EqualFold(r.get("public_exploit"), "true"), strings.EqualFold(r.get("risk_accepted"), "true"),
			joinText(labelled("Workload", where), labelled("Reference", r.get("vuln_link"))), rawJSON(r.Orig)))
	}
	return out, err
}
