package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Trivy JSON (`trivy fs|image|config --format json`, schema version 2):
// Results[] with Vulnerabilities (sca), Misconfigurations (iac) and Secrets
// (secrets). Secret values are removed before the report is stored.

type trivyReport struct {
	SchemaVersion int    `json:"SchemaVersion"`
	ArtifactName  string `json:"ArtifactName"`
	ArtifactType  string `json:"ArtifactType"`
	Results       []struct {
		Target            string            `json:"Target"`
		Class             string            `json:"Class"`
		Type              string            `json:"Type"`
		Vulnerabilities   []json.RawMessage `json:"Vulnerabilities"`
		Misconfigurations []json.RawMessage `json:"Misconfigurations"`
		Secrets           []json.RawMessage `json:"Secrets"`
	} `json:"Results"`
}

type trivyVuln struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	PkgPath          string   `json:"PkgPath"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	CweIDs           []string `json:"CweIDs"`
	PrimaryURL       string   `json:"PrimaryURL"`
	CVSS             map[string]struct {
		V3Vector  string  `json:"V3Vector"`
		V3Score   float64 `json:"V3Score"`
		V40Vector string  `json:"V40Vector"`
		V40Score  float64 `json:"V40Score"`
	} `json:"CVSS"`
	SeveritySource string `json:"SeveritySource"`
}

type trivyMisconfig struct {
	ID            string   `json:"ID"`
	AVDID         string   `json:"AVDID"`
	Title         string   `json:"Title"`
	Description   string   `json:"Description"`
	Message       string   `json:"Message"`
	Resolution    string   `json:"Resolution"`
	Severity      string   `json:"Severity"`
	Status        string   `json:"Status"`
	References    []string `json:"References"`
	CauseMetadata struct {
		Resource  string `json:"Resource"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
	} `json:"CauseMetadata"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
	EndLine   int    `json:"EndLine"`
}

var trivySecretKeys = []string{"Match", "Code"}

func init() {
	registerImportFormat(ImportFormat{ID: "trivy", Label: "Trivy JSON (fs, image, config)", Media: "json", Order: 20,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("SchemaVersion") && p.hasAny("Results", "ArtifactName")
		},
		parse: parseTrivyJSON,
		sanitize: func(raw []byte) []byte {
			return redactSecretsOf(raw)
		},
	})
}

// redactSecretsOf removes Match and Code (the secret's line) from Trivy's
// Secrets entries only; vulnerability and misconfiguration code context is
// kept.
func redactSecretsOf(raw []byte) []byte {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	results, _ := doc["Results"].([]any)
	for _, r := range results {
		if m, ok := r.(map[string]any); ok && m["Secrets"] != nil {
			m["Secrets"] = redactKeysIn(m["Secrets"], trivySecretKeys)
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		return raw
	}
	return b
}

func parseTrivyJSON(raw []byte) ([]importRecord, error) {
	var rep trivyReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("trivy: invalid JSON: %w", err)
	}
	image := rep.ArtifactType == "container_image"
	var out []importRecord
	for _, res := range rep.Results {
		target := res.Target
		for _, it := range res.Vulnerabilities {
			var v trivyVuln
			if err := json.Unmarshal(it, &v); err != nil {
				return out, fmt.Errorf("trivy: vulnerability: %w", err)
			}
			f := Finding{Category: "sca", RuleID: v.VulnerabilityID, CVE: v.VulnerabilityID, PackageName: v.PkgName,
				PackageVersion: v.InstalledVersion, FixedVersion: firstFixed(v.FixedVersion), Severity: v.Severity, CWE: v.CweIDs,
				Description: strings.TrimSpace(v.Title + "\n\n" + v.Description)}
			if image {
				f.Category = "container"
			}
			f.Title = fmt.Sprintf("%s in %s %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion)
			f.FilePath = NormalizePath(firstNonEmpty(v.PkgPath, target))
			if image {
				f.FilePath = firstNonEmpty(target, rep.ArtifactName)
			}
			// The severity source's score, else the highest (ties by source name).
			srcs := make([]string, 0, len(v.CVSS))
			for src := range v.CVSS {
				srcs = append(srcs, src)
			}
			slices.Sort(srcs)
			var best float64
			for _, src := range srcs {
				c := v.CVSS[src]
				score, vec := c.V3Score, c.V3Vector
				if c.V40Score > 0 {
					score, vec = c.V40Score, c.V40Vector
				}
				if src == v.SeveritySource {
					best, f.CVSSVector = score, vec
					break
				}
				if score > best {
					best, f.CVSSVector = score, vec
				}
			}
			f.CVSS = floatPtr(best)
			snip := ""
			if image {
				snip = hashOf(strings.ToLower(v.PkgName + "@" + v.InstalledVersion + "|" + v.VulnerabilityID))
			}
			out = append(out, importRecord{F: f, SnippetKey: snip, Raw: it})
		}
		for _, it := range res.Misconfigurations {
			var m trivyMisconfig
			if err := json.Unmarshal(it, &m); err != nil {
				return out, fmt.Errorf("trivy: misconfiguration: %w", err)
			}
			if m.Status != "" && !strings.EqualFold(m.Status, "FAIL") {
				continue // passed and exception checks are not findings
			}
			f := Finding{Category: "iac", RuleID: firstNonEmpty(m.AVDID, m.ID), Title: firstNonEmpty(m.Title, m.ID), Severity: m.Severity,
				Description: strings.TrimSpace(m.Message + "\n\n" + m.Description + "\n\nResolution: " + m.Resolution),
				FilePath:    NormalizePath(target), StartLine: intPtr(m.CauseMetadata.StartLine), EndLine: intPtr(m.CauseMetadata.EndLine)}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(m.CauseMetadata.Resource + "|" + m.Message), Raw: it})
		}
		for _, it := range res.Secrets {
			var s trivySecret
			if err := json.Unmarshal(it, &s); err != nil {
				return out, fmt.Errorf("trivy: secret: %w", err)
			}
			f := Finding{Category: "secrets", RuleID: s.RuleID, Title: firstNonEmpty(s.Title, s.RuleID), Severity: firstNonEmpty(s.Severity, "high"),
				Description: "Trivy found a " + firstNonEmpty(s.Category, "secret") + " secret (" + s.RuleID + ")",
				FilePath:    NormalizePath(target), StartLine: intPtr(s.StartLine), EndLine: intPtr(s.EndLine), CWE: []string{"CWE-798"}}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(fmt.Sprint(s.StartLine)), Raw: redactKeys(it, trivySecretKeys...)})
		}
	}
	return out, nil
}

// firstFixed returns the first of a comma-separated list of fixed versions.
func firstFixed(v string) string {
	first, _, _ := strings.Cut(v, ",")
	return strings.TrimSpace(first)
}
