package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// GitLab security report JSON (the report schema shared by every GitLab
// security analyzer: gl-sast-report.json, gl-secret-detection-report.json,
// gl-dependency-scanning-report.json, gl-container-scanning-report.json,
// gl-dast-report.json, gl-coverage-fuzzing-report.json): version,
// vulnerabilities[] and scan.type. One parser serves all report types; the
// gl-* formats are aliases detected by scan.type with the category of their
// report, "gitlab" accepts any report type (each finding keeps its own
// category). Secret detection reports carry the secret in
// raw_source_code_extract, which is removed before the report is stored;
// DAST request and response headers and bodies are never kept in a
// finding's original record.

// gitlabTypes maps scan.type (and the vulnerability category) to the
// PATHOS category.
var gitlabTypes = map[string]string{
	"sast": "sast", "secret_detection": "secrets", "dependency_scanning": "sca", "container_scanning": "container",
	"cluster_image_scanning": "container", "dast": "dast", "api_fuzzing": "api", "coverage_fuzzing": "fuzz",
}

var gitlabSecretKeys = []string{"raw_source_code_extract"}

type gitlabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
}

type gitlabVuln struct {
	ID          string             `json:"id"`
	Category    string             `json:"category"`
	Name        string             `json:"name"`
	Message     string             `json:"message"`
	Description string             `json:"description"`
	CVE         string             `json:"cve"`
	Severity    string             `json:"severity"`
	Confidence  string             `json:"confidence"`
	Solution    string             `json:"solution"`
	Identifiers []gitlabIdentifier `json:"identifiers"`
	Location    struct {
		File       string `json:"file"`
		StartLine  int    `json:"start_line"`
		EndLine    int    `json:"end_line"`
		Class      string `json:"class"`
		Method     string `json:"method"`
		Dependency struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Version string `json:"version"`
		} `json:"dependency"`
		Image           string `json:"image"`
		OperatingSystem string `json:"operating_system"`
		Hostname        string `json:"hostname"`
		Path            string `json:"path"`
		Param           string `json:"param"`
		CrashType       string `json:"crash_type"`
		CrashState      string `json:"crash_state"`
	} `json:"location"`
	CVSSVectors []struct {
		Vector string `json:"vector"`
	} `json:"cvss_vectors"`
	Flags []struct {
		Type        string `json:"type"`
		Origin      string `json:"origin"`
		Description string `json:"description"`
	} `json:"flags"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "gitlab", Label: "GitLab security report JSON (any type)", Tool: "GitLab", Media: "json", Order: 259,
		match: func(p *importProbe) bool { return gitlabScanType(p) != "" },
		parse: parseGitLab, sanitize: sanitizeGitLab})
	for i, a := range []struct{ id, typ, label, tool string }{
		{"gl-sast", "sast", "GitLab SAST report", "GitLab SAST"},
		{"gl-secret-detection", "secret_detection", "GitLab secret detection report", "GitLab Secret Detection"},
		{"gl-dependency-scanning", "dependency_scanning", "GitLab dependency scanning report", "GitLab Dependency Scan"},
		{"gl-container-scanning", "container_scanning", "GitLab container scanning report", "GitLab Container Scan"},
		{"gl-dast", "dast", "GitLab DAST report", "GitLab DAST"},
		{"gl-coverage-fuzzing", "coverage_fuzzing", "GitLab coverage fuzzing report", "GitLab Coverage Fuzzing"},
	} {
		typ := a.typ
		registerImportFormat(ImportFormat{ID: a.id, Label: a.label, Tool: a.tool, Category: gitlabTypes[typ], Media: "json",
			Parser: "gitlab", Order: 250 + i,
			match: func(p *importProbe) bool { return gitlabScanType(p) == typ }})
	}
}

// gitlabScanType returns the report type of a GitLab security report ("" if
// it is none): scan.type, or the first vulnerability's category in reports
// without a scan object.
func gitlabScanType(p *importProbe) string {
	if p.kind != "object" || !p.has("version", "vulnerabilities") {
		return ""
	}
	var scan struct {
		Type     string          `json:"type"`
		Analyzer json.RawMessage `json:"analyzer"`
		Scanner  json.RawMessage `json:"scanner"`
	}
	if p.has("scan") {
		if json.Unmarshal(p.keys["scan"], &scan) != nil || scan.Type == "" || (scan.Scanner == nil && scan.Analyzer == nil) {
			return ""
		}
		return scan.Type
	}
	first := p.firstOf("vulnerabilities")
	var cat string
	if !hasKeys(first, "category", "identifiers", "location") || json.Unmarshal(first["category"], &cat) != nil {
		return ""
	}
	if _, ok := gitlabTypes[cat]; !ok {
		return ""
	}
	return cat
}

func sanitizeGitLab(raw []byte) []byte {
	var doc map[string]json.RawMessage
	if json.Unmarshal(raw, &doc) != nil || doc["vulnerabilities"] == nil {
		return raw
	}
	return redactKeys(raw, gitlabSecretKeys...)
}

// gitlabFixRe finds the fixed version in GitLab's solution text ("Upgrade
// to version 1.2.6 or above.", "Upgrade apk-tools to 2.12.6-r0").
var gitlabFixRe = regexp.MustCompile(`(?i)\bupgrade\s+(?:\S+\s+)?to\s+(?:version\s+)?([0-9][^\s,;]*[0-9a-z])`)

func parseGitLab(raw []byte) ([]importRecord, error) {
	var doc struct {
		Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
		Scan            struct {
			Type string `json:"type"`
		} `json:"scan"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("gitlab: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range doc.Vulnerabilities {
		var v gitlabVuln
		if err := json.Unmarshal(it, &v); err != nil || (v.Name == "" && v.Message == "" && len(v.Identifiers) == 0) {
			return out, fmt.Errorf("gitlab: vulnerability %d: expected an object with name and identifiers", i+1)
		}
		out = append(out, gitlabRecord(v, firstNonEmpty(v.Category, doc.Scan.Type), it))
	}
	return out, nil
}

func gitlabRecord(v gitlabVuln, typ string, it json.RawMessage) importRecord {
	cat := gitlabTypes[typ]
	if cat == "" {
		cat = "other"
	}
	loc := v.Location
	f := Finding{Category: cat, Severity: normSeverity(v.Severity), Confidence: gitlabConfidence(v.Confidence),
		FilePath: NormalizePath(loc.File), StartLine: intPtr(loc.StartLine), EndLine: intPtr(loc.EndLine),
		PackageName: loc.Dependency.Package.Name, PackageVersion: loc.Dependency.Version}
	var cves, advisories []string
	rule := ""
	for _, id := range v.Identifiers {
		val := firstNonEmpty(id.Value, id.Name)
		switch t := strings.ToLower(id.Type); t {
		case "cwe":
			f.CWE = append(f.CWE, "CWE-"+strings.TrimPrefix(strings.ToUpper(val), "CWE-"))
		case "cve":
			cves = append(cves, val)
		case "owasp", "bandit_test_id", "eslint_rule_id", "flawfinder_func_name":
		case "ghsa", "osvdb", "usn", "rhsa", "elsa", "alas":
			advisories = append(advisories, val)
		default:
			if rule == "" {
				rule = val
			}
		}
	}
	f.CVE = firstMatch(cveRe, append(cves, v.CVE)...)
	if cat == "sca" || cat == "container" {
		// The advisory is the rule of a package vulnerability.
		rule = firstNonEmpty(f.CVE, firstNonEmpty(advisories...), rule)
		if m := gitlabFixRe.FindStringSubmatch(v.Solution); m != nil {
			f.FixedVersion = m[1]
		}
	}
	f.RuleID = strings.Join(strings.Fields(firstNonEmpty(rule, firstNonEmpty(advisories...), f.CVE, v.Name)), " ")
	for _, c := range v.CVSSVectors {
		if vectorVersion(c.Vector) != "" {
			f.CVSSVector = c.Vector
			break
		}
	}
	title := strings.Join(strings.Fields(firstNonEmpty(v.Name, v.Message, f.RuleID)), " ")
	snippet := ""
	var where string
	switch typ {
	case "dast", "api_fuzzing":
		f.FilePath = strings.TrimRight(loc.Hostname, "/") + loc.Path
		where = strings.TrimSpace(strings.ToUpper(loc.Method) + " " + f.FilePath)
		if loc.Param != "" {
			where += " (parameter " + loc.Param + ")"
		}
		snippet = hashOf(strings.ToUpper(loc.Method) + "|" + loc.Param)
	case "container_scanning", "cluster_image_scanning":
		f.FilePath = firstNonEmpty(loc.Image, f.FilePath)
		where = strings.TrimSpace(loc.Image + " " + loc.OperatingSystem)
	case "coverage_fuzzing":
		where = "crash state: " + strings.Join(strings.Fields(loc.CrashState), " ")
		snippet = hashOf(loc.CrashType + "|" + loc.CrashState)
	default:
		snippet = hashOf(fmt.Sprintf("%s|%d", loc.Class+loc.Method, loc.StartLine))
	}
	if (cat == "sca" || cat == "container") && f.PackageName != "" && !strings.Contains(title, f.PackageName) {
		title = fmt.Sprintf("%s in %s %s", firstNonEmpty(f.CVE, f.RuleID), f.PackageName, f.PackageVersion)
	}
	f.Title = title
	if cat == "secrets" && len(f.CWE) == 0 {
		f.CWE = []string{"CWE-798"}
	}
	var notes []string
	if f.Severity == "" || strings.EqualFold(v.Severity, "unknown") {
		f.Severity = "medium"
		notes = append(notes, "GitLab reports no severity for this vulnerability (Unknown); imported as medium.")
	}
	for _, fl := range v.Flags {
		if fl.Type == "flagged-as-likely-false-positive" {
			f.Confidence = "low"
			notes = append(notes, "Flagged as a likely false positive by "+firstNonEmpty(fl.Origin, "the analyzer")+": "+fl.Description)
		}
	}
	sol := ""
	if v.Solution != "" {
		sol = "Solution: " + v.Solution
	}
	f.Description = joinText(v.Description, where, sol, strings.Join(notes, "\n"))
	return importRecord{F: f, SnippetKey: snippet, Raw: gitlabRaw(it)}
}

func gitlabConfidence(c string) string {
	switch strings.ToLower(c) {
	case "confirmed", "high":
		return "high"
	case "medium":
		return "medium"
	case "low", "experimental", "ignore":
		return "low"
	}
	return ""
}

// gitlabRaw is the vulnerability without the secret extract and without
// DAST request and response details (only their presence is kept).
func gitlabRaw(it json.RawMessage) json.RawMessage {
	var m map[string]any
	if json.Unmarshal(it, &m) != nil {
		return redactKeys(it, gitlabSecretKeys...)
	}
	if ev, ok := m["evidence"].(map[string]any); ok {
		for _, k := range []string{"request", "response", "source", "supporting_messages"} {
			if ev[k] != nil {
				ev[k] = "[present, not kept]"
			}
		}
	}
	return redactKeys(rawJSON(m), gitlabSecretKeys...)
}
