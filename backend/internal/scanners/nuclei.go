package scanners

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"pathos/internal/platform/logging"
)

// nucleiResult is one line of Nuclei's -jsonl output (with -or -ot: no raw
// request/response, no encoded template).
type nucleiResult struct {
	TemplateID  string   `json:"template-id"`
	MatcherName string   `json:"matcher-name"`
	Type        string   `json:"type"`
	Host        string   `json:"host"`
	URL         string   `json:"url"`
	MatchedAt   string   `json:"matched-at"`
	Extracted   []string `json:"extracted-results"`
	Info        struct {
		Name           string   `json:"name"`
		Description    string   `json:"description"`
		Severity       string   `json:"severity"`
		Tags           []string `json:"tags"`
		Remediation    string   `json:"remediation"`
		Classification struct {
			CVEID       []string `json:"cve-id"`
			CWEID       []string `json:"cwe-id"`
			CVSSScore   float64  `json:"cvss-score"`
			CVSSMetrics string   `json:"cvss-metrics"`
		} `json:"classification"`
	} `json:"info"`
	// DAST (fuzzing) results name the fuzzed parameter.
	FuzzingParameter string `json:"fuzzing_parameter"`
	FuzzingPosition  string `json:"fuzzing_position"`
}

// ParseNucleiJSONL normalises Nuclei JSON Lines output. The location is the
// matched URL; identity is template + matcher + URL (+ fuzzed parameter).
func ParseNucleiJSONL(raw []byte) ([]Finding, error) {
	var out []Finding
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	line := 0
	for sc.Scan() {
		line++
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		if len(out) >= MaxFindingsPerReport {
			return out, errors.New("report truncated: too many findings")
		}
		var r nucleiResult
		if err := json.Unmarshal(b, &r); err != nil {
			return out, fmt.Errorf("nuclei: line %d: invalid JSON: %w", line, err)
		}
		if r.TemplateID == "" {
			return out, fmt.Errorf("nuclei: line %d: missing template-id", line)
		}
		f := Finding{ScannerKey: Nuclei, Category: "dast", RuleID: truncate(r.TemplateID, 300)}
		f.Title = firstNonEmpty(r.Info.Name, r.TemplateID)
		if r.MatcherName != "" {
			f.Title += " (" + r.MatcherName + ")"
		}
		if r.FuzzingParameter != "" {
			f.Title += fmt.Sprintf(" in %s parameter %q", firstNonEmpty(r.FuzzingPosition, "request"), r.FuzzingParameter)
		}
		f.Title = truncate(logging.RedactString(f.Title), 300)
		desc := strings.TrimSpace(r.Info.Description)
		if r.Info.Remediation != "" {
			desc += "\n\nRemediation: " + strings.TrimSpace(r.Info.Remediation)
		}
		if len(r.Extracted) > 0 {
			desc += "\n\nExtracted: " + strings.Join(r.Extracted[:min(len(r.Extracted), 10)], ", ")
		}
		f.Description = truncate(logging.RedactString(strings.TrimSpace(desc)), 4000)
		f.FilePath = locationOf("", firstNonEmpty(r.MatchedAt, r.URL, r.Host))
		switch s := strings.ToLower(r.Info.Severity); s {
		case "critical", "high", "medium", "low", "info":
			f.Severity = s
		default:
			f.Severity = "info"
			if r.Info.Classification.CVSSScore > 0 {
				f.Severity = FromScore(r.Info.Classification.CVSSScore)
			}
		}
		for _, c := range r.Info.Classification.CWEID {
			if m := firstMatch(cweRe, c); m != "" {
				f.CWE = append(f.CWE, "CWE-"+m)
			}
		}
		for _, c := range r.Info.Classification.CVEID {
			if m := firstMatch(cveRe, c); m != "" {
				f.CVE = m
				break
			}
		}
		if r.Info.Classification.CVSSScore > 0 {
			score := r.Info.Classification.CVSSScore
			f.CVSS = &score
		}
		if v := r.Info.Classification.CVSSMetrics; vectorVersion(v) != "" && len(v) <= 300 {
			f.CVSSVector, f.CVSSVersion = v, vectorVersion(v)
		}
		// A matched template is a confirmed response pattern; informational
		// fingerprinting is not evidence of a weakness.
		f.Confidence = "medium"
		if f.Severity == "info" {
			f.Confidence = "low"
		}
		f.Fingerprint = Fingerprint(f, hashOf(r.MatcherName+"|"+r.FuzzingPosition+"|"+r.FuzzingParameter))
		out = append(out, f)
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("nuclei: %w", err)
	}
	return out, nil
}
