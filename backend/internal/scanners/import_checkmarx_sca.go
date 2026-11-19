package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Checkmarx SCA (CxSCA) risk report JSON (risk report API or the
// report from the resolver / UI): Packages[] (id, name, version) and
// Vulnerabilities[] (id, cveName, score, severity, description, cwe,
// packageId, fixResolutionText, isIgnored, references). Key casing
// differs between the API (camelCase) and report exports (PascalCase);
// both are read. Ignored vulnerabilities are kept with low confidence.

func init() {
	registerImportFormat(ImportFormat{ID: "checkmarx-sca", Label: "Checkmarx SCA (CxSCA) risk report JSON", Tool: "Checkmarx SCA", Category: "sca", Media: "json", Order: 615,
		match: func(p *importProbe) bool {
			return p.kind == "object" && (p.has("Vulnerabilities", "Packages") || p.has("vulnerabilities", "packages") && p.hasAny("riskReportSummary", "RiskReportSummary"))
		},
		parse: parseCheckmarxSCA})
}

func parseCheckmarxSCA(raw []byte) ([]importRecord, error) {
	// encoding/json matches keys without regard to case.
	var doc struct {
		Packages []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"packages"`
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("checkmarx sca: invalid JSON: %w", err)
	}
	pkgs := map[string][2]string{}
	for _, p := range doc.Packages {
		pkgs[p.ID] = [2]string{p.Name, p.Version}
	}
	var out []importRecord
	for i, vr := range doc.Vulnerabilities {
		var v struct {
			ID          string          `json:"id"`
			CVE         string          `json:"cveName"`
			Score       float64         `json:"score"`
			Severity    string          `json:"severity"`
			Description string          `json:"description"`
			CWE         string          `json:"cwe"`
			PackageID   string          `json:"packageId"`
			Fix         string          `json:"fixResolutionText"`
			IsIgnored   bool            `json:"isIgnored"`
			References  []string        `json:"references"`
			Recommend   json.RawMessage `json:"recommendations"`
		}
		if err := json.Unmarshal(vr, &v); err != nil || firstNonEmpty(v.CVE, v.ID) == "" {
			return out, fmt.Errorf("checkmarx sca: vulnerability %d: expected id or cveName", i+1)
		}
		pk, ok := pkgs[v.PackageID]
		if !ok {
			pk[0], pk[1] = cxPackage(v.PackageID)
		}
		id := firstNonEmpty(v.CVE, v.ID)
		f := Finding{Category: "sca", RuleID: id, CVE: v.CVE, Severity: v.Severity, CVSS: floatPtr(v.Score), CWE: []string{v.CWE},
			PackageName: pk[0], PackageVersion: pk[1], FixedVersion: v.Fix, FilePath: v.PackageID,
			Title:       fmt.Sprintf("%s in %s %s", id, pk[0], pk[1]),
			Description: joinText(v.Description, labeled("Fix", v.Fix), labeled("References", strings.Join(v.References, "\n")))}
		if v.IsIgnored {
			f.Confidence = "low"
			f.Description = joinText(f.Description, "Checkmarx SCA verdict: ignored.")
		}
		out = append(out, importRecord{F: f, Raw: vr})
	}
	return out, nil
}
