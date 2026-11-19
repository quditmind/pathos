package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"pathos/internal/platform/logging"
)

// Imported results come from tools PATHOS does not run (other SAST, SCA,
// DAST, IAST and fuzzing tools, CI pipelines). Each tool gets its own
// scanner key "import-<category>-<tool>" so findings keep their provenance,
// auto-resolution stays per tool, and fingerprints can be recomputed from
// the key alone.

// ImportCategories are the categories an import may declare.
var ImportCategories = ToolCategories

var (
	importKeyRe = regexp.MustCompile(`^import-(` + strings.Join(ImportCategories, "|") + `)-([a-z0-9][a-z0-9-]{0,22})$`)
	slugRe      = regexp.MustCompile(`[^a-z0-9]+`)
)

// ImportKey builds the scanner key of an imported tool.
func ImportKey(category, tool string) (string, error) {
	ok := false
	for _, c := range ImportCategories {
		ok = ok || c == category
	}
	if !ok {
		return "", fmt.Errorf("category must be one of %s", strings.Join(ImportCategories, ", "))
	}
	slug := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(strings.TrimSpace(tool)), "-"), "-")
	if len(slug) > 23 {
		slug = strings.Trim(slug[:23], "-")
	}
	if slug == "" {
		return "", errors.New("a tool name is required")
	}
	return "import-" + category + "-" + slug, nil
}

// IsImportKey reports whether key names an imported tool.
func IsImportKey(key string) bool { return importKeyRe.MatchString(key) }

// Resolve returns the catalog scanner for key, or the synthetic scanner of
// an imported tool.
func Resolve(key string) (Scanner, bool) {
	if sc, ok := Lookup(key); ok {
		return sc, true
	}
	if sc, ok := ResolvePlugin(key); ok {
		return sc, true
	}
	m := importKeyRe.FindStringSubmatch(key)
	if m == nil {
		return Scanner{}, false
	}
	return Scanner{Key: key, Name: m[2] + " (imported)", Category: m[1], Decision: "use", Family: "import", OutputFormat: "sarif"}, true
}

// GenericReport is the PATHOS findings JSON format for tools without SARIF
// output (docs/api-reference/imports.md#pathos-findings-json).
type GenericReport struct {
	Tool     string           `json:"tool"`
	Findings []GenericFinding `json:"findings"`
}

// GenericFinding is one finding of a GenericReport.
type GenericFinding struct {
	RuleID         string   `json:"rule_id"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	Confidence     string   `json:"confidence"`
	CWE            []string `json:"cwe"`
	CVE            string   `json:"cve"`
	CVSS           *float64 `json:"cvss"`
	CVSSVector     string   `json:"cvss_vector"`
	FilePath       string   `json:"file_path"`
	StartLine      *int     `json:"start_line"`
	EndLine        *int     `json:"end_line"`
	URL            string   `json:"url"`
	PackageName    string   `json:"package_name"`
	PackageVersion string   `json:"package_version"`
	FixedVersion   string   `json:"fixed_version"`
	// Fingerprint, when the tool has a stable identifier for the finding.
	Fingerprint string `json:"fingerprint"`
}

func decodeGeneric(raw []byte) (GenericReport, error) {
	var rep GenericReport
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rep); err != nil {
		return rep, fmt.Errorf("invalid PATHOS findings JSON: %w", err)
	}
	return rep, nil
}

func parseGeneric(key string, raw []byte) ([]Finding, error) {
	sc, _ := Resolve(key)
	rep, err := decodeGeneric(raw)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for i, g := range rep.Findings {
		if len(out) >= MaxFindingsPerReport {
			return out, errors.New("report truncated: too many findings")
		}
		sev := strings.ToLower(strings.TrimSpace(g.Severity))
		valid := false
		for _, v := range Severities {
			valid = valid || v == sev
		}
		switch {
		case valid:
		case sev == "" && g.CVSS != nil && *g.CVSS >= 0 && *g.CVSS <= 10:
			sev = FromScore(*g.CVSS)
		default:
			return out, fmt.Errorf("finding %d: severity must be critical, high, medium, low or info (or give a cvss score)", i+1)
		}
		title := firstNonEmpty(g.Title, g.RuleID)
		if title == "" {
			return out, fmt.Errorf("finding %d: title or rule_id is required", i+1)
		}
		f := Finding{ScannerKey: key, Category: sc.FindingCategory(), RuleID: truncate(firstNonEmpty(g.RuleID, title), 300), Title: truncate(title, 300),
			Description: logging.RedactString(truncate(g.Description, 4000)), Severity: sev, CWE: g.CWE, CVE: firstMatch(cveRe, g.CVE, g.RuleID, title),
			CVSS: g.CVSS, FilePath: locationOf(g.FilePath, g.URL), StartLine: g.StartLine, EndLine: g.EndLine,
			PackageName: g.PackageName, PackageVersion: g.PackageVersion, FixedVersion: g.FixedVersion}
		if f.CWE == nil {
			f.CWE = []string{}
		}
		if v := vectorVersion(g.CVSSVector); v != "" && len(g.CVSSVector) <= 300 {
			f.CVSSVector, f.CVSSVersion = g.CVSSVector, v
		}
		switch strings.ToLower(g.Confidence) {
		case "high", "medium", "low":
			f.Confidence = strings.ToLower(g.Confidence)
		default:
			f.Confidence = confidenceOf(f.Category, nil)
		}
		snippetKey := hashOf(firstNonEmpty(g.Fingerprint, g.Description+"|"+g.URL))
		if f.Category == "sca" {
			snippetKey = ""
		}
		setFingerprint(&f, snippetKey)
		out = append(out, f)
	}
	return out, nil
}

// locateGeneric finds a finding in a PATHOS findings JSON report.
func locateGeneric(key string, raw []byte, fingerprint string) (*Located, error) {
	fs, err := parseGeneric(key, raw)
	if err != nil && len(fs) == 0 {
		return nil, err
	}
	var doc struct {
		Findings []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	for i, f := range fs {
		if f.Matches(fingerprint) && i < len(doc.Findings) {
			return &Located{Raw: redactJSON(doc.Findings[i])}, nil
		}
	}
	return nil, ErrNotLocated
}

// locationOf keeps URLs (DAST, API findings) intact and normalises paths.
func locationOf(path, url string) string {
	if path != "" {
		return NormalizePath(path)
	}
	if strings.Contains(url, "://") && len(url) <= 1000 {
		return url
	}
	return NormalizePath(url)
}
