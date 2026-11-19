package scanners

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// APKLeaks JSON (`apkleaks -f app.apk --json -o report.json`):
// {package, results: [{name, matches[]}]}, one entry per pattern of
// APKLeaks' regexes.json. Secret patterns become one finding per match;
// the matched values are replaced by "[REDACTED:<hash>]" before the report
// is stored, and identity uses that hash, so a stored report gives the same
// findings. Endpoint and identifier patterns (LinkFinder, IP and MAC
// addresses, mailto, S3 buckets, Firebase URLs, OAuth client IDs) are one
// info finding per pattern listing the values.

// apkleaksInventory are APKLeaks patterns that find identifiers, not secrets.
var apkleaksInventory = map[string]bool{"LinkFinder": true, "IP_Address": true, "Mac_Address": true, "Mailto": true,
	"Amazon_AWS_S3_Bucket": true, "Firebase": true, "Facebook_ClientID": true, "Twitter_ClientID": true}

var apkleaksRedactedRe = regexp.MustCompile(`^\[REDACTED:([0-9a-f]{16})\]$`)

func init() {
	registerImportFormat(ImportFormat{ID: "apkleaks", Label: "APKLeaks JSON", Tool: "APKLeaks", Category: "mobile", Media: "json", Order: 374,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("package", "results") && len(p.keys) <= 3 && hasKeys(p.firstOf("results"), "name", "matches")
		},
		parse:    parseAPKLeaks,
		sanitize: sanitizeAPKLeaks})
}

type apkleaksReport struct {
	Package string `json:"package"`
	Results []struct {
		Name    string   `json:"name"`
		Matches []string `json:"matches"`
	} `json:"results"`
}

// apkleaksSecretID returns the identity of a matched secret: the hash of
// the value, or the hash kept in place of a redacted value.
func apkleaksSecretID(v string) string {
	if m := apkleaksRedactedRe.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return hashOf(v)
}

func sanitizeAPKLeaks(raw []byte) []byte {
	var doc map[string]any
	if json.Unmarshal(raw, &doc) != nil {
		return raw
	}
	results, _ := doc["results"].([]any)
	for _, r := range results {
		m, _ := r.(map[string]any)
		name, _ := m["name"].(string)
		if m == nil || apkleaksInventory[name] {
			continue
		}
		matches, _ := m["matches"].([]any)
		for i, v := range matches {
			if s, ok := v.(string); ok {
				matches[i] = "[REDACTED:" + apkleaksSecretID(s) + "]"
			}
		}
	}
	b, err := json.Marshal(redactHTTPIn(doc))
	if err != nil {
		return raw
	}
	return b
}

func parseAPKLeaks(raw []byte) ([]importRecord, error) {
	var rep apkleaksReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("apkleaks: invalid JSON: %w", err)
	}
	app := firstNonEmpty(rep.Package, "app.apk")
	var out []importRecord
	for i, r := range rep.Results {
		if r.Name == "" {
			return out, fmt.Errorf("apkleaks: result %d: missing name", i+1)
		}
		label := strings.ReplaceAll(r.Name, "_", " ")
		if apkleaksInventory[r.Name] {
			vals := make([]string, 0, len(r.Matches))
			for _, v := range r.Matches {
				vals = append(vals, redactHTTP(v))
			}
			sort.Strings(vals)
			f := Finding{Category: "mobile", RuleID: "apkleaks:" + r.Name, Title: label + " found in " + app, Severity: "info", FilePath: app,
				Confidence: "medium", Description: joinText(fmt.Sprintf("APKLeaks found %d value(s) of pattern %s in the app.", len(vals), r.Name),
					clipText(strings.Join(vals, "\n"), 4000))}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(r.Name), Raw: rawJSON(map[string]any{"package": rep.Package, "name": r.Name, "matches": vals})})
			continue
		}
		for _, v := range r.Matches {
			id := apkleaksSecretID(v)
			f := Finding{Category: "secrets", RuleID: "apkleaks:" + r.Name, Title: "Possible hard-coded " + label + " in " + app,
				Severity: "high", FilePath: app, CWE: []string{"CWE-798"}, Confidence: "low",
				Description: fmt.Sprintf("APKLeaks matched pattern %s in the decompiled app (value redacted, id %s). Pattern matches are not verified; confirm the value is a live credential and rotate it.", r.Name, id)}
			out = append(out, importRecord{F: f, SnippetKey: id, Raw: rawJSON(map[string]any{"package": rep.Package, "name": r.Name, "match": "[REDACTED:" + id + "]"})})
		}
	}
	return out, nil
}
