package scanners

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"pathos/internal/platform/logging"
)

// NativeReport is the JSON report of the scanners built into the worker
// (ClamAV client, binary hardening, file licences). The worker writes it;
// the API parses it. The raw report is kept as the scan artifact, so the
// original evidence survives normalization.
type NativeReport struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	// Engine is the external engine's version (ClamAV: engine and
	// signature database).
	Engine   string          `json:"engine,omitempty"`
	Findings []NativeFinding `json:"findings"`
	// Licenses are the file-level licence detections (licensecheck);
	// they become findings only through the licence policy.
	Licenses []FileLicense  `json:"licenses,omitempty"`
	Stats    map[string]int `json:"stats,omitempty"`
}

// NativeFinding is one result of a built-in scanner.
type NativeFinding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	CWE         []string `json:"cwe,omitempty"`
	FilePath    string   `json:"file_path"`
	// Key distinguishes results of one rule in one file (fingerprint);
	// it must be stable across runs (never a version or timestamp).
	Key string `json:"key,omitempty"`
	// Evidence is shown as the finding's code context (no secrets: file
	// hashes, signatures, binary properties).
	Evidence string `json:"evidence,omitempty"`
}

// FileLicense is one licence found in a repository file.
type FileLicense struct {
	Path   string `json:"path"`
	SPDX   string `json:"spdx"`
	Method string `json:"method"` // spdx-tag | license-text
	Line   int    `json:"line,omitempty"`
	// Percent of the file covered by licence text (license-text only).
	Percent float64 `json:"percent,omitempty"`
	// Alternatives are the other licences of an SPDX "OR" expression: the
	// file conflicts with the policy only if every alternative does.
	Alternatives []string `json:"alternatives,omitempty"`
}

// IsNative reports whether key is a built-in worker scanner whose output
// is a NativeReport.
func IsNative(key string) bool {
	return key == ClamAV || key == BinaryHardening || key == LicenseCheck
}

var (
	ruleIDRe = regexp.MustCompile(`^[A-Za-z0-9_./:+-]{1,300}$`)
	spdxRe   = regexp.MustCompile(`^[A-Za-z0-9.+-]{1,100}$`)
)

// ParseNative parses a NativeReport into findings. File licences are not
// findings by themselves (see ParseFileLicenses).
func ParseNative(key string, raw []byte) ([]Finding, error) {
	sc, ok := Lookup(key)
	if !ok {
		return nil, fmt.Errorf("unknown scanner %q", key)
	}
	var rep NativeReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("%s: invalid report: %w", key, err)
	}
	var out []Finding
	for _, nf := range rep.Findings {
		if len(out) >= MaxFindingsPerReport {
			return out, errors.New("report truncated: too many findings")
		}
		if !ruleIDRe.MatchString(nf.RuleID) {
			return out, fmt.Errorf("%s: invalid rule id %q", key, nf.RuleID)
		}
		f := Finding{ScannerKey: key, Category: sc.FindingCategory(), RuleID: nf.RuleID, FilePath: NormalizePath(nf.FilePath)}
		f.Title = truncate(logging.RedactString(firstNonEmpty(nf.Title, nf.RuleID)), 300)
		f.Description = truncate(logging.RedactString(nf.Description), 4000)
		f.Severity = "medium"
		for _, s := range Severities {
			if strings.EqualFold(nf.Severity, s) {
				f.Severity = s
			}
		}
		f.Confidence = confidenceOrDefault(nf.Confidence, "high")
		seen := map[string]bool{}
		for _, c := range nf.CWE {
			if m := cweRe.FindStringSubmatch(c); m != nil && !seen[m[1]] && len(f.CWE) < 10 {
				seen[m[1]] = true
				f.CWE = append(f.CWE, "CWE-"+m[1])
			}
		}
		if ev := strings.TrimSpace(nf.Evidence); ev != "" {
			f.Snippet = truncate(logging.RedactString(ev), 16000)
		}
		setFingerprint(&f, hashOf(nf.Key))
		out = append(out, f)
	}
	return out, nil
}

// ParseFileLicenses returns the valid file-level licence detections of a
// licensecheck report.
func ParseFileLicenses(raw []byte) ([]FileLicense, error) {
	var rep NativeReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("licensecheck: invalid report: %w", err)
	}
	out := make([]FileLicense, 0, len(rep.Licenses))
	seen := map[string]bool{}
	for _, l := range rep.Licenses {
		p := NormalizePath(l.Path)
		if p == "" || len(p) > 1000 || !spdxRe.MatchString(l.SPDX) {
			continue
		}
		if l.Method != "spdx-tag" && l.Method != "license-text" {
			l.Method = "license-text"
		}
		k := p + "\x00" + l.SPDX
		if seen[k] {
			continue
		}
		seen[k] = true
		var alts []string
		for _, a := range l.Alternatives {
			if spdxRe.MatchString(a) && a != l.SPDX && len(alts) < 20 {
				alts = append(alts, a)
			}
		}
		out = append(out, FileLicense{Path: p, SPDX: l.SPDX, Method: l.Method, Line: max(l.Line, 0), Percent: l.Percent, Alternatives: alts})
		if len(out) >= 100000 {
			break
		}
	}
	return out, nil
}

func confidenceOrDefault(c, def string) string {
	switch strings.ToLower(c) {
	case "high", "medium", "low":
		return strings.ToLower(c)
	}
	return def
}
