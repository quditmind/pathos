package scanners

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Black Duck (Synopsys / Black Duck SCA), two published shapes:
//   - the REST API vulnerable BOM components JSON (GET /api/projects/{id}/
//     versions/{id}/vulnerable-bom-components): items[] with componentName,
//     componentVersionName, componentVersionOriginId and
//     vulnerabilityWithRemediation (vulnerabilityName, description,
//     baseScore / overallScore, severity, cweId, remediationStatus,
//     relatedVulnerability);
//   - the project version "Vulnerabilities" report CSV (security.csv in the
//     report archive), one row per component vulnerability with the columns
//     Component name, Component version name, Vulnerability id,
//     Description, Security Risk, Base score, Overall score, CWE Ids,
//     Remediation status, URL, Solution available.
// Vulnerabilities whose remediation status is IGNORED, MITIGATED or
// NOT_AFFECTED are imported with low confidence and the status in the
// description.

type blackduckItem struct {
	ComponentName        string `json:"componentName"`
	ComponentVersionName string `json:"componentVersionName"`
	OriginName           string `json:"componentVersionOriginName"`
	OriginID             string `json:"componentVersionOriginId"`
	Vuln                 struct {
		Name                 string  `json:"vulnerabilityName"`
		Description          string  `json:"description"`
		BaseScore            float64 `json:"baseScore"`
		OverallScore         float64 `json:"overallScore"`
		Severity             string  `json:"severity"`
		Source               string  `json:"source"`
		CWEID                string  `json:"cweId"`
		RemediationStatus    string  `json:"remediationStatus"`
		RelatedVulnerability string  `json:"relatedVulnerability"`
	} `json:"vulnerabilityWithRemediation"`
}

var blackduckCSVColumns = []string{"component name", "component version name", "vulnerability id", "security risk"}

// blackduckColumn normalises a CSV column name ("Component_name" and
// "component name" are the same column).
func blackduckColumn(s string) string {
	return strings.ToLower(strings.TrimSpace(strings.ReplaceAll(s, "_", " ")))
}

func blackduckHeader(h []string) bool {
	for _, c := range blackduckCSVColumns {
		found := false
		for _, x := range h {
			if blackduckColumn(x) == c {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func init() {
	registerImportFormat(ImportFormat{ID: "blackduck", Label: "Black Duck vulnerabilities (JSON or CSV report)", Tool: "Black Duck", Category: "sca", Media: "json", Order: 201,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object":
				return p.has("items") && hasKeys(p.firstOf("items"), "componentName", "vulnerabilityWithRemediation")
			case "csv":
				return blackduckHeader(p.header)
			}
			return false
		},
		parse: parseBlackDuck})
}

// blackduckSuppressed reports remediation statuses that mean "not a risk".
func blackduckSuppressed(status string) bool {
	switch strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(status), " ", "_")) {
	case "IGNORED", "MITIGATED", "NOT_AFFECTED", "PATCHED", "REMEDIATION_COMPLETE":
		return true
	}
	return false
}

func blackduckFinding(comp, version, originID, vulnID, related, desc, sev string, base, overall float64, cwes []string, status, url string) Finding {
	f := Finding{Category: "sca", RuleID: vulnID, Severity: sev, PackageName: comp, PackageVersion: version, CWE: cwes,
		CVE: firstMatch(cveRe, vulnID, related), CVSS: floatPtr(overall)}
	if f.CVSS == nil {
		f.CVSS = floatPtr(base)
	}
	if parts := strings.Split(originID, ":"); len(parts) >= 2 && !strings.Contains(originID, "/") {
		// Maven-style origin ids (group:artifact:version) name the package.
		f.PackageName = parts[len(parts)-2]
	}
	id := vulnID
	if f.CVE != "" && f.CVE != vulnID {
		id = f.CVE + " (" + vulnID + ")"
	}
	f.Title = fmt.Sprintf("%s in %s %s", id, comp, version)
	d := []string{desc, "Component: " + comp + " " + version, "Origin: " + originID, url}
	if status != "" {
		d = append(d, "Remediation status: "+status)
		if blackduckSuppressed(status) {
			f.Confidence = "low"
		}
	}
	f.Description = joinText(d...)
	return f
}

func parseBlackDuck(raw []byte) ([]importRecord, error) {
	b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM))
	if len(b) > 0 && b[0] == '{' {
		items, err := jsonArray(b, "items")
		if err != nil {
			return nil, fmt.Errorf("black duck: invalid JSON: %w", err)
		}
		var out []importRecord
		for i, it := range items {
			var v blackduckItem
			if err := json.Unmarshal(it, &v); err != nil || v.ComponentName == "" || v.Vuln.Name == "" {
				return out, fmt.Errorf("black duck: item %d: expected componentName and vulnerabilityWithRemediation.vulnerabilityName", i+1)
			}
			f := blackduckFinding(v.ComponentName, v.ComponentVersionName, v.OriginID, v.Vuln.Name, v.Vuln.RelatedVulnerability, v.Vuln.Description,
				v.Vuln.Severity, v.Vuln.BaseScore, v.Vuln.OverallScore, []string{v.Vuln.CWEID}, v.Vuln.RemediationStatus, "")
			out = append(out, importRecord{F: f, Raw: it})
		}
		return out, nil
	}
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	header, err := r.Read()
	if err != nil || !blackduckHeader(header) {
		return nil, fmt.Errorf("black duck: CSV without the columns %s", strings.Join(blackduckCSVColumns, ", "))
	}
	col := map[string]int{}
	for i, h := range header {
		col[blackduckColumn(h)] = i
	}
	var out []importRecord
	for n := 2; ; n++ {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, fmt.Errorf("black duck: row %d: %w", n, err)
		}
		get := func(name string) string {
			if i, ok := col[name]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		if get("vulnerability id") == "" || get("component name") == "" {
			return out, fmt.Errorf("black duck: row %d: no component name or vulnerability id", n)
		}
		var base, overall float64
		_, _ = fmt.Sscanf(get("base score"), "%g", &base)
		_, _ = fmt.Sscanf(get("overall score"), "%g", &overall)
		cwes := strings.FieldsFunc(get("cwe ids"), func(r rune) bool { return r == ',' || r == ';' || r == ' ' })
		f := blackduckFinding(get("component name"), get("component version name"), get("channel version origin id"), get("vulnerability id"), "",
			get("description"), get("security risk"), base, overall, cwes, get("remediation status"), get("url"))
		row := map[string]string{}
		for i, h := range header {
			if i < len(rec) && rec[i] != "" {
				row[h] = rec[i]
			}
		}
		out = append(out, importRecord{F: f, Raw: rawJSON(row)})
	}
	return out, nil
}
