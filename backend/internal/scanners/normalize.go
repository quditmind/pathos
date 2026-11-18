package scanners

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"

	"pathos/internal/platform/logging"
)

// Finding is a normalized finding produced from one tool's output.
type Finding struct {
	ScannerKey     string
	Category       string
	RuleID         string
	Title          string
	Description    string
	Severity       string // critical | high | medium | low | info
	CWE            []string
	CVE            string
	CVSS           *float64
	PackageName    string
	PackageVersion string
	FixedVersion   string
	FilePath       string
	// Snippet is code context captured by the worker (redacted).
	Snippet      string
	SnippetStart *int
	StartLine    *int
	EndLine      *int
	Fingerprint  string
	// Confidence is high | medium | low | unknown (see confidenceOf).
	Confidence string
	// CVSSVector and CVSSVersion when the tool reports a vector.
	CVSSVector  string
	CVSSVersion string
}

// confidenceOf estimates how likely a result is a true positive. Tools'
// default "precision: very-high" is not a signal (it is set for every
// rule), so only explicit lower precisions or confidence metadata count;
// otherwise the category decides: version matches of known vulnerable
// packages and policy checks are high, pattern-based secrets and code
// findings medium.
func confidenceOf(category string, props map[string]any) string {
	for _, k := range []string{"confidence", "precision"} {
		if v, ok := props[k].(string); ok {
			switch strings.ToLower(v) {
			case "high":
				if k == "confidence" {
					return "high"
				}
			case "medium":
				return "medium"
			case "low":
				return "low"
			}
		}
	}
	switch category {
	case "sca", "container", "iac", "license", "misconfiguration", "binary":
		return "high"
	case "secrets", "sast":
		return "medium"
	}
	return "unknown"
}

var cvssPrefix = regexp.MustCompile(`^CVSS:(3\.0|3\.1|4\.0)/`)

// vectorVersion returns the CVSS version of a vector ("" if unknown).
func vectorVersion(v string) string {
	if m := cvssPrefix.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	if strings.HasPrefix(v, "AV:") {
		return "2.0"
	}
	return ""
}

// Severities in descending order.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// SeverityRank returns 4 for critical down to 0 for info.
func SeverityRank(s string) int {
	for i, v := range Severities {
		if v == s {
			return len(Severities) - 1 - i
		}
	}
	return 0
}

// FromScore maps a CVSS-style score to a severity.
func FromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	}
	return "info"
}

// NormalizePath makes repository-relative, slash-separated paths and strips
// worker workspace prefixes so fingerprints are stable across runs.
func NormalizePath(p string) string {
	p = strings.TrimPrefix(p, "file://")
	p = strings.ReplaceAll(p, `\`, "/")
	// Workers scan /work/<job>/src; tools report that prefix with or without
	// the leading slash.
	p = workspacePrefix.ReplaceAllString(p, "")
	p = path.Clean("/" + p)
	return strings.TrimPrefix(p, "/")
}

var (
	workspacePrefix = regexp.MustCompile(`^/?work/[^/]+/src/`)
	cweRe           = regexp.MustCompile(`(?i)CWE-(\d{1,5})`)
	cveRe           = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{4,})\b`)
)

// Fingerprint computes the stable identity of a finding. Line numbers are
// deliberately excluded so findings survive code moving around.
func Fingerprint(f Finding, snippetKey string) string {
	family := f.Category
	if family != "sca" {
		family = f.ScannerKey // non-SCA findings are tool-specific
	}
	secondary := ""
	if f.Category == "sca" {
		vuln := f.CVE
		if vuln == "" {
			vuln = f.RuleID
		}
		secondary = strings.ToLower(f.PackageName + "@" + f.PackageVersion + "|" + vuln)
	}
	h := sha256.New()
	for _, part := range []string{family, ruleForFingerprint(f), NormalizePath(f.FilePath), snippetKey, secondary} {
		h.Write([]byte(part))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func ruleForFingerprint(f Finding) string {
	if f.Category == "sca" {
		// Different SCA tools name the same advisory differently; the
		// secondary key carries the vulnerability identity.
		return "sca"
	}
	return f.RuleID
}

// --- SARIF -----------------------------------------------------------------

type sarifLog struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name  string      `json:"name"`
				Rules []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	} `json:"runs"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription *sarifMsg      `json:"shortDescription"`
	FullDescription  *sarifMsg      `json:"fullDescription"`
	Help             *sarifMsg      `json:"help"`
	Properties       map[string]any `json:"properties"`
	DefaultConfig    *struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
}

type sarifMsg struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string   `json:"ruleId"`
	RuleIndex *int     `json:"ruleIndex"`
	Level     string   `json:"level"`
	Message   sarifMsg `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int       `json:"startLine"`
				EndLine   int       `json:"endLine"`
				Snippet   *sarifMsg `json:"snippet"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

// MaxFindingsPerReport bounds work per scanner run.
const MaxFindingsPerReport = 20000

// ParseSARIF parses a SARIF 2.1 log produced by scanner key.
func ParseSARIF(key string, raw []byte) ([]Finding, error) {
	sc, ok := Resolve(key)
	if !ok {
		return nil, fmt.Errorf("unknown scanner %q", key)
	}
	var log sarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		return nil, fmt.Errorf("%s: invalid SARIF: %w", key, err)
	}
	var out []Finding
	for _, run := range log.Runs {
		rules := map[string]sarifRule{}
		for _, r := range run.Tool.Driver.Rules {
			rules[r.ID] = r
		}
		for _, res := range run.Results {
			if len(out) >= MaxFindingsPerReport {
				return out, errors.New("report truncated: too many findings")
			}
			rule := rules[res.RuleID]
			if res.RuleID == "" && res.RuleIndex != nil && *res.RuleIndex < len(run.Tool.Driver.Rules) {
				rule = run.Tool.Driver.Rules[*res.RuleIndex]
				res.RuleID = rule.ID
			}
			f := Finding{ScannerKey: key, Category: sc.FindingCategory(), RuleID: res.RuleID}
			f.Title = firstNonEmpty(textOf(rule.ShortDescription), rule.Name, res.RuleID)
			f.Description = logging.RedactString(truncate(firstNonEmpty(res.Message.Text, textOf(rule.FullDescription), textOf(rule.Help)), 4000))
			snippet := ""
			if len(res.Locations) > 0 {
				loc := res.Locations[0].PhysicalLocation
				f.FilePath = NormalizePath(loc.ArtifactLocation.URI)
				if loc.Region.StartLine > 0 {
					sl := loc.Region.StartLine
					f.StartLine = &sl
					el := max(loc.Region.EndLine, sl)
					f.EndLine = &el
				}
				if loc.Region.Snippet != nil {
					snippet = strings.Join(strings.Fields(loc.Region.Snippet.Text), " ")
				}
			}
			if ctx, ok := res.Properties["pathos_context"].(string); ok && f.Category != "secrets" {
				f.Snippet = truncate(logging.RedactString(ctx), 16000)
				if st, ok := res.Properties["pathos_context_start"].(float64); ok && st > 0 {
					n := int(st)
					f.SnippetStart = &n
				}
			}
			if key == Opengrep && misconfigurationRule(res.RuleID, rule.Properties) {
				f.Category = "misconfiguration"
				if strings.Contains(strings.ToLower(res.RuleID), "secret") {
					// Rules about hard-coded keys match the key itself: keep
					// it out of the stored code context.
					f.Snippet, f.SnippetStart = "", nil
				}
			}
			f.Severity = severityOf(sc, rule, res)
			f.Confidence = confidenceOf(f.Category, rule.Properties)
			for _, k := range []string{"cvssv3_vector", "cvssv40_vector", "cvss_vector"} {
				if v, ok := rule.Properties[k].(string); ok && vectorVersion(v) != "" && len(v) <= 300 {
					f.CVSSVector, f.CVSSVersion = v, vectorVersion(v)
					break
				}
			}
			f.CWE = cwesOf(rule, res)
			f.CVE = firstMatch(cveRe, res.RuleID, f.Title, res.Message.Text)
			if score, ok := scoreOf(rule.Properties, res.Properties); ok {
				f.CVSS = &score
			}
			if f.Category == "sca" || key == TrivyImage {
				f.PackageName, f.PackageVersion, f.FixedVersion = packageOf(key, res)
			}
			applyToolRules(&f, res)
			snippetKey := ""
			switch {
			case f.Category == "sca":
				// Identity is package@version|vulnerability (+ manifest path).
			case key == TrivyImage && f.PackageName != "":
				snippetKey = hashOf(strings.ToLower(f.PackageName + "@" + f.PackageVersion))
			case f.Category == "secrets":
				// Secrets are redacted; distinguish by the (redacted) message
				// and gitleaks' fingerprint-relevant fields.
				snippetKey = hashOf(res.Message.Text + "|" + res.PartialFingerprints["commitSha"] + res.PartialFingerprints["primaryLocationLineHash"])
			case snippet != "":
				snippetKey = hashOf(snippet)
			default:
				snippetKey = hashOf(res.Message.Text)
			}
			f.Fingerprint = Fingerprint(f, snippetKey)
			out = append(out, f)
		}
	}
	return out, nil
}

func severityOf(sc Scanner, rule sarifRule, res sarifResult) string {
	if sc.Category == "secrets" {
		return "high"
	}
	// Tool-provided severity labels (Trivy, Checkov, Opengrep).
	for _, props := range []map[string]any{res.Properties, rule.Properties} {
		for _, k := range []string{"severity", "Severity"} {
			if v, ok := props[k].(string); ok {
				switch strings.ToLower(v) {
				case "critical":
					return "critical"
				case "high", "error":
					return "high"
				case "medium", "moderate", "warning":
					return "medium"
				case "low":
					return "low"
				case "info", "informational", "negligible", "unknown":
					return "info"
				}
			}
		}
	}
	if score, ok := scoreOf(rule.Properties, res.Properties); ok {
		return FromScore(score)
	}
	if sc.Category == "iac" {
		// Checkov marks every failed policy as "error"; without a real
		// severity, medium is the honest default.
		return "medium"
	}
	level := res.Level
	if level == "" && rule.DefaultConfig != nil {
		level = rule.DefaultConfig.Level
	}
	switch level {
	case "error":
		return "high"
	case "warning":
		return "medium"
	case "note":
		return "low"
	}
	return "info"
}

func scoreOf(props ...map[string]any) (float64, bool) {
	for _, p := range props {
		switch v := p["security-severity"].(type) {
		case string:
			if f, err := strconv.ParseFloat(v, 64); err == nil && f >= 0 && f <= 10 {
				return f, true
			}
		case float64:
			if v >= 0 && v <= 10 {
				return v, true
			}
		}
	}
	return 0, false
}

func cwesOf(rule sarifRule, res sarifResult) []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		for _, m := range cweRe.FindAllStringSubmatch(s, -1) {
			id := "CWE-" + m[1]
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	for _, props := range []map[string]any{rule.Properties, res.Properties} {
		if tags, ok := props["tags"].([]any); ok {
			for _, t := range tags {
				if s, ok := t.(string); ok {
					add(s)
				}
			}
		}
		if s, ok := props["cwe"].(string); ok {
			add(s)
		}
		if l, ok := props["cwe"].([]any); ok {
			for _, t := range l {
				if s, ok := t.(string); ok {
					add(s)
				}
			}
		}
	}
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

var (
	trivyPkgRe = regexp.MustCompile(`Package: (\S+)\s*\nInstalled Version: (\S+)(?:\s*\nVulnerability [^\n]*)?(?:[\s\S]*?Fixed Version: (\S+))?`)
	grypePkgRe = regexp.MustCompile(`(?i)package:?\s+([^\s,]+),?\s+version\s+([^\s,]+)`)
	osvPkgRe   = regexp.MustCompile(`Package '([^']+)@([^']+)'`)
)

// packageOf extracts package identity for SCA results.
func packageOf(key string, res sarifResult) (name, version, fixed string) {
	msg := res.Message.Text
	switch key {
	case TrivyFS, TrivyImage:
		if m := trivyPkgRe.FindStringSubmatch(msg); m != nil {
			return m[1], m[2], m[3]
		}
	case Grype:
		if m := grypePkgRe.FindStringSubmatch(msg); m != nil {
			return m[1], strings.TrimSuffix(m[2], "."), ""
		}
	case OSVScanner:
		if m := osvPkgRe.FindStringSubmatch(msg); m != nil {
			return m[1], m[2], ""
		}
	}
	for _, k := range []string{"packageName", "package"} {
		if v, ok := res.Properties[k].(string); ok {
			name = v
		}
	}
	if v, ok := res.Properties["packageVersion"].(string); ok {
		version = v
	}
	return name, version, fixed
}

// misconfigurationRule reports whether an Opengrep rule is a framework
// configuration check: the PATHOS rules "pathos.misconfig.*" and any rule
// whose metadata category (a SARIF tag) is "misconfiguration".
func misconfigurationRule(ruleID string, props map[string]any) bool {
	if strings.HasPrefix(opengrepPrefix.ReplaceAllString(ruleID, ""), "pathos.misconfig.") {
		return true
	}
	if tags, ok := props["tags"].([]any); ok {
		for _, t := range tags {
			if s, ok := t.(string); ok && strings.EqualFold(s, "misconfiguration") {
				return true
			}
		}
	}
	return false
}

// opengrepPrefix matches the path-derived prefix Opengrep adds to rule IDs.
var opengrepPrefix = regexp.MustCompile(`^(?:[a-z0-9_-]+\.)*?(?:rules\.)`)

// applyToolRules adjusts per-tool quirks.
func applyToolRules(f *Finding, res sarifResult) {
	if f.ScannerKey == Opengrep {
		f.RuleID = opengrepPrefix.ReplaceAllString(f.RuleID, "")
		// The rule message is the useful title; the SARIF short description
		// is a generic "Opengrep Finding: <id>".
		if msg := strings.TrimSpace(res.Message.Text); msg != "" {
			if i := strings.Index(msg, ". "); i > 0 {
				msg = msg[:i+1]
			}
			f.Title = msg
		}
	}
	if f.ScannerKey == Zizmor {
		// zizmor reports its own severity and confidence per result.
		switch strings.ToLower(fmt.Sprint(res.Properties["zizmor/severity"])) {
		case "high":
			f.Severity = "high"
		case "medium":
			f.Severity = "medium"
		case "low":
			f.Severity = "low"
		case "informational", "unknown":
			f.Severity = "info"
		}
		switch c := strings.ToLower(fmt.Sprint(res.Properties["zizmor/confidence"])); c {
		case "high", "medium", "low":
			f.Confidence = c
		}
		// "<audit summary>: <detail>" makes a better title than the audit name.
		if msg, _, ok := strings.Cut(res.Message.Text, ": "); ok && msg != "" {
			f.Title = msg
		}
	}
	pkgFinding := f.Category == "sca" || f.ScannerKey == TrivyImage
	if pkgFinding && f.CVE == "" {
		f.CVE = firstMatch(cveRe, f.Description)
	}
	if pkgFinding && f.Title == f.RuleID && f.PackageName != "" {
		f.Title = fmt.Sprintf("%s in %s %s", f.RuleID, f.PackageName, f.PackageVersion)
	}
	f.Title = truncate(logging.RedactString(f.Title), 300)
}

func textOf(m *sarifMsg) string {
	if m == nil {
		return ""
	}
	return m.Text
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s = strings.TrimSpace(s); s != "" {
			return s
		}
	}
	return ""
}

func firstMatch(re *regexp.Regexp, v ...string) string {
	for _, s := range v {
		if m := re.FindStringSubmatch(s); m != nil {
			return strings.ToUpper(m[1])
		}
	}
	return ""
}

func hashOf(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:8])
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// Excluded reports whether a repository-relative path matches any of the
// profile's exclusion globs ("vendor/**", "**/*_test.go", "docs/").
func Excluded(p string, globs []string) bool {
	for _, g := range globs {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if strings.HasSuffix(g, "/") && strings.HasPrefix(p, g) {
			return true
		}
		if matchGlob(g, p) {
			return true
		}
	}
	return false
}

// matchGlob supports '*' (within a segment) and '**' (any number of segments).
func matchGlob(pattern, name string) bool {
	ps, ns := strings.Split(pattern, "/"), strings.Split(name, "/")
	var match func(i, j int) bool
	match = func(i, j int) bool {
		if i == len(ps) {
			return j == len(ns)
		}
		if ps[i] == "**" {
			for k := j; k <= len(ns); k++ {
				if match(i+1, k) {
					return true
				}
			}
			return false
		}
		if j == len(ns) {
			return false
		}
		ok, err := path.Match(ps[i], ns[j])
		return err == nil && ok && match(i+1, j+1)
	}
	return match(0, 0)
}

// Parse dispatches to the parser for a scanner's output format.
func Parse(key string, raw []byte) ([]Finding, error) {
	if key == Grype {
		return ParseGrypeJSON(raw)
	}
	if IsImportKey(key) {
		return parseImported(key, raw)
	}
	if key == Nuclei {
		return ParseNucleiJSONL(raw)
	}
	if key == Actionlint {
		return ParseActionlint(raw)
	}
	if IsNative(key) {
		return ParseNative(key, raw)
	}
	switch key {
	case EndpointCheck:
		return parseEndpoints(raw)
	case Cosign:
		return parseSignature(raw)
	case EndOfLife:
		return nil, errors.New("end-of-life findings come from the intelligence feed, not from scanner output")
	}
	return ParseSARIF(key, raw)
}

type grypeDoc struct {
	Matches []struct {
		Vulnerability struct {
			ID          string `json:"id"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			Fix         struct {
				Versions []string `json:"versions"`
			} `json:"fix"`
			CVSS []struct {
				Type    string `json:"type"`
				Version string `json:"version"`
				Vector  string `json:"vector"`
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
		} `json:"vulnerability"`
		RelatedVulnerabilities []struct {
			ID   string `json:"id"`
			CVSS []struct {
				Metrics struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"metrics"`
			} `json:"cvss"`
		} `json:"relatedVulnerabilities"`
		Artifact struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Type      string `json:"type"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
}

// ParseGrypeJSON parses `grype -o json`, which (unlike its SARIF) carries
// CVE aliases, fix versions and CVSS scores.
func ParseGrypeJSON(raw []byte) ([]Finding, error) {
	var doc grypeDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("grype: invalid JSON: %w", err)
	}
	var out []Finding
	for _, m := range doc.Matches {
		if len(out) >= MaxFindingsPerReport {
			return out, errors.New("report truncated: too many findings")
		}
		v := m.Vulnerability
		f := Finding{ScannerKey: Grype, Category: "sca", RuleID: v.ID, PackageName: m.Artifact.Name, PackageVersion: m.Artifact.Version}
		f.CVE = firstMatch(cveRe, v.ID)
		var score float64
		for _, c := range v.CVSS {
			score = max(score, c.Metrics.BaseScore)
			// Prefer the primary source's vector, then the newest version.
			if ver := vectorVersion(c.Vector); ver != "" && len(c.Vector) <= 300 &&
				(f.CVSSVector == "" || (c.Type == "Primary" && ver >= f.CVSSVersion)) {
				f.CVSSVector, f.CVSSVersion = c.Vector, ver
			}
		}
		f.Confidence = "high"
		for _, rv := range m.RelatedVulnerabilities {
			if f.CVE == "" {
				f.CVE = firstMatch(cveRe, rv.ID)
			}
			for _, c := range rv.CVSS {
				score = max(score, c.Metrics.BaseScore)
			}
		}
		if score > 0 {
			f.CVSS = &score
		}
		switch strings.ToLower(v.Severity) {
		case "critical", "high", "medium", "low":
			f.Severity = strings.ToLower(v.Severity)
		case "negligible":
			f.Severity = "info"
		default:
			f.Severity = FromScore(score)
		}
		if len(v.Fix.Versions) > 0 {
			f.FixedVersion = v.Fix.Versions[0]
		}
		if len(m.Artifact.Locations) > 0 {
			f.FilePath = NormalizePath(m.Artifact.Locations[0].Path)
		}
		id := v.ID
		if f.CVE != "" && f.CVE != v.ID {
			id = f.CVE + " (" + v.ID + ")"
		}
		f.Title = truncate(fmt.Sprintf("%s in %s %s", id, f.PackageName, f.PackageVersion), 300)
		f.Description = truncate(logging.RedactString(v.Description), 4000)
		f.Fingerprint = Fingerprint(f, "")
		out = append(out, f)
	}
	return out, nil
}
