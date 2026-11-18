// Package pushprotect implements secret push protection: when a verified
// push webhook arrives for a repository that opted in, the commits of the
// push are read through the SCM API (no clone, no code execution), the
// lines they add are checked against a curated set of high-confidence
// secret patterns, and an alert is raised (notification event
// "secret.pushed").
//
// Only the rule, file, line, commit and a short digest of the match are
// stored. Secret values are never stored, logged or sent anywhere.
package pushprotect

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Rule is one secret pattern. Group selects the secret inside the match
// (0 = the whole match).
type Rule struct {
	ID          string
	Description string
	re          *regexp.Regexp
	group       int
	// minEntropy rejects low-entropy matches (placeholders) when > 0.
	minEntropy float64
}

// Rules are deliberately precise: each pattern has a distinctive prefix or
// structure, so false positives are rare and a push alert is worth acting on.
var Rules = []Rule{
	{ID: "aws-access-key-id", Description: "AWS access key ID", re: regexp.MustCompile(`\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`), group: 1},
	{ID: "aws-secret-access-key", Description: "AWS secret access key",
		re: regexp.MustCompile(`(?i)aws_?secret_?access_?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+]{40})(?:[^A-Za-z0-9/+]|$)`), group: 1, minEntropy: 4.0},
	{ID: "github-token", Description: "GitHub token", re: regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36})\b`), group: 1},
	{ID: "github-fine-grained-pat", Description: "GitHub fine-grained personal access token", re: regexp.MustCompile(`\b(github_pat_[A-Za-z0-9_]{82})\b`), group: 1},
	{ID: "gitlab-token", Description: "GitLab personal access token", re: regexp.MustCompile(`\b(glpat-[A-Za-z0-9_-]{20,})\b`), group: 1},
	{ID: "slack-token", Description: "Slack token", re: regexp.MustCompile(`\b(xox[baprs]-[A-Za-z0-9-]{10,250})\b`), group: 1, minEntropy: 3.0},
	{ID: "slack-webhook", Description: "Slack incoming webhook URL",
		re: regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{20,}`)},
	{ID: "stripe-live-key", Description: "Stripe live secret key", re: regexp.MustCompile(`\b((?:sk|rk)_live_[A-Za-z0-9]{24,99})\b`), group: 1},
	{ID: "google-api-key", Description: "Google API key", re: regexp.MustCompile(`\b(AIza[0-9A-Za-z_-]{35})(?:[^0-9A-Za-z_-]|$)`), group: 1},
	{ID: "private-key", Description: "Private key",
		re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----`)},
	{ID: "npm-token", Description: "npm access token", re: regexp.MustCompile(`\b(npm_[A-Za-z0-9]{36})\b`), group: 1},
	{ID: "pypi-token", Description: "PyPI upload token", re: regexp.MustCompile(`\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})`), group: 1},
	{ID: "azure-storage-key", Description: "Azure storage account key",
		re: regexp.MustCompile(`AccountKey=([A-Za-z0-9+/]{86}==)`), group: 1, minEntropy: 4.0},
}

// Match is one likely secret on an added line. It never carries the value.
type Match struct {
	RuleID      string
	Description string
	Line        int    // line in the new file (0 = unknown)
	Digest      string // first 16 hex characters of SHA-256(value)
}

// placeholder recognizes documentation and test values.
func placeholder(v string) bool {
	l := strings.ToLower(v)
	for _, p := range []string{"example", "xxxxxxxx", "00000000", "placeholder", "dummy", "redacted", "your_", "<"} {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

// entropy is the Shannon entropy in bits per character.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var e float64
	for _, c := range freq {
		p := float64(c) / n
		e -= p * math.Log2(p)
	}
	return e
}

// Digest is the stored de-duplication digest of a value.
func Digest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:16]
}

// ScanLine returns the secrets on one line.
func ScanLine(line string) []Match {
	if len(line) > 8192 {
		line = line[:8192] // minified files: bounded work per line
	}
	var out []Match
	for _, r := range Rules {
		for _, m := range r.re.FindAllStringSubmatch(line, 5) {
			v := m[r.group]
			if placeholder(v) || (r.minEntropy > 0 && entropy(v) < r.minEntropy) {
				continue
			}
			out = append(out, Match{RuleID: r.ID, Description: r.Description, Digest: Digest(v)})
		}
	}
	return out
}

// hunkRe parses "@@ -a,b +c,d @@".
var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// ScanPatch checks the lines a unified diff adds. Removed and context lines
// are ignored: a push that deletes a secret is not alerted on.
func ScanPatch(patch string) []Match {
	var out []Match
	newLine := 0
	seen := map[string]bool{}
	for _, l := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(l, "@@"):
			if m := hunkRe.FindStringSubmatch(l); m != nil {
				n, _ := strconv.Atoi(m[1])
				newLine = n
			}
		case strings.HasPrefix(l, "+++") || strings.HasPrefix(l, "---") || strings.HasPrefix(l, `\`):
		case strings.HasPrefix(l, "+"):
			for _, m := range ScanLine(l[1:]) {
				m.Line = newLine
				key := m.RuleID + "|" + strconv.Itoa(m.Line) + "|" + m.Digest
				if !seen[key] {
					seen[key] = true
					out = append(out, m)
				}
			}
			newLine++
		case strings.HasPrefix(l, "-"):
		default:
			newLine++
		}
	}
	return out
}
