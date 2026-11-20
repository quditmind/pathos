package main

import (
	"math"
	"regexp"
	"strings"
)

// Secrets found in strings and code are replaced before the document is
// written: they never leave the sandbox, never reach the API, the store or
// an AI model.

type secretRule struct {
	kind string
	re   *regexp.Regexp
}

var secretRules = []secretRule{
	{"private_key", regexp.MustCompile(`-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?(-----END[A-Z ]*PRIVATE KEY-----|$)`)},
	{"aws_access_key", regexp.MustCompile(`\b(AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\b`)},
	{"github_token", regexp.MustCompile(`\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b`)},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{"slack_token", regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9-]{10,}\b`)},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"stripe_key", regexp.MustCompile(`\b(sk|rk)_(live|test)_[0-9A-Za-z]{16,}\b`)},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)},
	{"url_credentials", regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]{1,64}:)([^@\s/]{3,128})(@)`)},
	{"assignment", regexp.MustCompile(`(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|token|client[_-]?secret)(\s*[:=]\s*["']?)([^\s"']{6,200})`)},
}

// redact returns s with secrets replaced by [REDACTED:<kind>] and whether
// anything was replaced.
func redact(s string) (string, bool) {
	changed := false
	for _, r := range secretRules {
		if !r.re.MatchString(s) {
			continue
		}
		switch r.kind {
		case "url_credentials":
			s = r.re.ReplaceAllString(s, "${1}[REDACTED:password]${3}")
		case "assignment":
			s = r.re.ReplaceAllStringFunc(s, func(m string) string {
				sub := r.re.FindStringSubmatch(m)
				// Format verbs and placeholders are not values.
				if strings.ContainsAny(sub[3], "%{$<") || !secretLike(sub[3]) {
					return m
				}
				changed = true
				return sub[1] + sub[2] + "[REDACTED:" + strings.ToLower(sub[1]) + "]"
			})
			continue
		default:
			s = r.re.ReplaceAllString(s, "[REDACTED:"+r.kind+"]")
		}
		changed = true
	}
	// A long high-entropy token on its own (an unlabelled key).
	// Encoding alphabets and digit tables are not keys.
	if !changed && len(s) >= 32 && len(s) <= 256 && !strings.ContainsAny(s, " \t\n/\\.:") && entropyOf(s) > 4.5 && hasMix(s) &&
		!strings.Contains(s, "ABCDEF") && !strings.Contains(s, "abcdef") && !strings.Contains(s, "0123456789") {
		return "[REDACTED:high_entropy]", true
	}
	return s, changed
}

// secretLike rejects obvious non-values (identifiers made of one class).
func secretLike(v string) bool {
	return len(v) >= 6 && (hasMix(v) || entropyOf(v) > 3.0)
}

func hasMix(s string) bool {
	var lo, up, dig bool
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z':
			lo = true
		case c >= 'A' && c <= 'Z':
			up = true
		case c >= '0' && c <= '9':
			dig = true
		}
	}
	return dig && (lo || up)
}

// entropyOf is the Shannon entropy in bits per byte.
func entropyOf(s string) float64 {
	if s == "" {
		return 0
	}
	var n [256]int
	for i := 0; i < len(s); i++ {
		n[s[i]]++
	}
	return entropyCounts(n[:], len(s))
}

func entropyCounts(n []int, total int) float64 {
	if total == 0 {
		return 0
	}
	e := 0.0
	for _, c := range n {
		if c == 0 {
			continue
		}
		p := float64(c) / float64(total)
		e -= p * math.Log2(p)
	}
	return math.Round(e*1000) / 1000
}
