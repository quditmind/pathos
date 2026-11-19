package inventory

import (
	"net/url"
	"strings"
	"unicode"
)

// SourceKey normalises a repository location so that the same repository
// reached through different URLs or connections compares equal: host and
// path in lower case, without scheme, credentials, port 443/22, ".git" or
// a trailing slash. SSH forms (git@host:owner/repo.git) are accepted. When
// rawURL is empty or unparsable the key falls back to "<fallbackHost>/<full
// name>". The key is what asset_onboardings is unique on.
func SourceKey(rawURL, fallbackHost, fullName string) string {
	if k := urlKey(rawURL); k != "" {
		return k
	}
	fn := strings.Trim(strings.ToLower(strings.TrimSpace(fullName)), "/")
	fn = strings.TrimSuffix(fn, ".git")
	if fn == "" {
		return ""
	}
	h := strings.ToLower(strings.TrimSpace(fallbackHost))
	if h == "" {
		h = "unknown-host"
	}
	return h + "/" + fn
}

func urlKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// scp-like SSH syntax: git@github.com:owner/repo.git
	if !strings.Contains(raw, "://") {
		if at := strings.Index(raw, "@"); at >= 0 {
			if colon := strings.Index(raw[at:], ":"); colon > 0 {
				raw = "ssh://" + raw[:at+colon] + "/" + raw[at+colon+1:]
			}
		}
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if p := u.Port(); p != "" && p != "443" && p != "80" && p != "22" {
		host += ":" + p
	}
	path := strings.ToLower(strings.Trim(u.Path, "/"))
	path = strings.TrimSuffix(path, ".git")
	// Azure DevOps clone URLs carry "_git"; browser URLs too. Keep as is:
	// both forms contain it.
	if path == "" {
		return ""
	}
	return host + "/" + path
}

// HostOf returns the lower-case host of a URL ("" when unparsable).
func HostOf(raw string) string {
	k := urlKey(raw)
	if i := strings.Index(k, "/"); i > 0 {
		return k[:i]
	}
	return ""
}

// Namespace returns the owner part of a full name ("acme" for
// "acme/payments-api", "group/sub" for "group/sub/repo").
func Namespace(fullName string) string {
	fn := strings.Trim(strings.ToLower(fullName), "/")
	if i := strings.LastIndex(fn, "/"); i > 0 {
		return fn[:i]
	}
	return ""
}

// noiseTokens are dropped before names are compared: they describe the
// kind of component, not the application.
var noiseTokens = map[string]bool{
	"api": true, "app": true, "application": true, "service": true, "svc": true, "web": true, "ui": true,
	"frontend": true, "backend": true, "server": true, "client": true, "repo": true, "the": true,
}

// nameTokens splits a name into lower-case alphanumeric tokens, without
// noise words (unless nothing else is left).
func nameTokens(s string) []string {
	f := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	var out []string
	for _, t := range f {
		if !noiseTokens[t] {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return f
	}
	return out
}

// NameSimilarity compares two names from 0 (unrelated) to 1 (equal after
// normalisation). It is the larger of the token overlap (Jaccard) and the
// edit-distance ratio of the joined tokens, so both "Payments Platform" vs
// "payments-api" and small spelling differences score high.
func NameSimilarity(a, b string) float64 {
	ta, tb := nameTokens(a), nameTokens(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	set := map[string]int{}
	for _, t := range ta {
		set[t] |= 1
	}
	for _, t := range tb {
		set[t] |= 2
	}
	inter := 0
	for _, v := range set {
		if v == 3 {
			inter++
		}
	}
	jac := float64(inter) / float64(len(set))
	ja, jb := strings.Join(ta, ""), strings.Join(tb, "")
	maxLen := max(len([]rune(ja)), len([]rune(jb)))
	lev := 1 - float64(levenshtein(ja, jb))/float64(maxLen)
	// Containment: "payments" inside "paymentsplatform".
	cont := 0.0
	if len(ja) >= 4 && len(jb) >= 4 && (strings.Contains(ja, jb) || strings.Contains(jb, ja)) {
		cont = 0.75
	}
	return max(jac, lev, cont)
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}
