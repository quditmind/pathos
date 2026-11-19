package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Anchore Engine / Anchore Enterprise image vulnerabilities:
// `anchore-cli --json image vuln <image> all` ({imageDigest,
// vulnerabilities: [...]}, snake_case) and `anchorectl image
// vulnerabilities <image> -o json` (camelCase, an array or the same
// envelope). One finding per vulnerability and package. Policy evaluation
// output (`anchore-cli evaluate check --detail`) is not a vulnerability
// list and is not supported.

type anchoreVuln struct {
	Vuln           string `json:"vuln"`
	Severity       string `json:"severity"`
	Package        string `json:"package"`
	PackageName    string `json:"package_name"`
	PackageNameC   string `json:"packageName"`
	PackageVersion string `json:"package_version"`
	PackageVerC    string `json:"packageVersion"`
	PackageType    string `json:"package_type"`
	PackageTypeC   string `json:"packageType"`
	PackagePath    string `json:"package_path"`
	PackagePathC   string `json:"packagePath"`
	Fix            string `json:"fix"`
	URL            string `json:"url"`
	Feed           string `json:"feed"`
	FeedGroup      string `json:"feed_group"`
	FeedGroupC     string `json:"feedGroup"`
	NvdData        []struct {
		ID     string `json:"id"`
		CvssV3 struct {
			BaseScore float64 `json:"base_score"`
			BaseC     float64 `json:"baseScore"`
		} `json:"cvss_v3"`
		CvssV3C struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssV3"`
	} `json:"nvd_data"`
	NvdDataC []struct {
		CvssV3 struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"cvssV3"`
	} `json:"nvdData"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "anchore", Label: "Anchore Engine / Enterprise vulnerabilities JSON", Tool: "Anchore", Category: "container", Media: "json", Order: 460,
		match: func(p *importProbe) bool {
			isVuln := func(m map[string]json.RawMessage) bool {
				return hasKeys(m, "vuln", "severity", "package") && (hasKeys(m, "package_name") || hasKeys(m, "packageName"))
			}
			switch p.kind {
			case "object":
				return p.has("imageDigest", "vulnerabilities") && (isVuln(p.firstOf("vulnerabilities")) || len(p.keys) <= 3)
			case "array":
				return isVuln(p.keys)
			}
			return false
		},
		parse: parseAnchore})
}

func parseAnchore(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "vulnerabilities")
	if err != nil {
		return nil, fmt.Errorf("anchore: invalid JSON: %w", err)
	}
	var env struct {
		ImageDigest string `json:"imageDigest"`
	}
	_ = json.Unmarshal(raw, &env)
	var out []importRecord
	for i, it := range items {
		var v anchoreVuln
		if err := json.Unmarshal(it, &v); err != nil || v.Vuln == "" {
			return out, fmt.Errorf("anchore: vulnerability %d: expected an object with vuln", i+1)
		}
		name, ver := firstNonEmpty(v.PackageName, v.PackageNameC), firstNonEmpty(v.PackageVersion, v.PackageVerC)
		path := anchoreNone(firstNonEmpty(v.PackagePath, v.PackagePathC))
		f := Finding{Category: "container", RuleID: v.Vuln, Title: v.Vuln + " in " + firstNonEmpty(name, v.Package), Severity: normSeverity(v.Severity),
			CVE: firstMatch(cveRe, v.Vuln), PackageName: name, PackageVersion: ver, FixedVersion: anchoreNone(v.Fix),
			FilePath: firstNonEmpty(env.ImageDigest, "image") + "@" + firstNonEmpty(v.Package, name+"-"+ver)}
		for _, n := range v.NvdData {
			if s := max(n.CvssV3.BaseScore, n.CvssV3.BaseC, n.CvssV3C.BaseScore); s > 0 {
				f.CVSS = floatPtr(s)
				break
			}
		}
		for _, n := range v.NvdDataC {
			if f.CVSS == nil && n.CvssV3.BaseScore > 0 {
				f.CVSS = floatPtr(n.CvssV3.BaseScore)
			}
		}
		f.Description = joinText(fmt.Sprintf("%s %s (%s) is affected by %s.", name, ver, firstNonEmpty(v.PackageType, v.PackageTypeC), v.Vuln),
			labelled("Path", path), labelled("Fixed in", f.FixedVersion), labelled("Feed", strings.Trim(v.Feed+" "+firstNonEmpty(v.FeedGroup, v.FeedGroupC), " ")),
			labelled("Reference", v.URL))
		out = append(out, importRecord{F: f, SnippetKey: hashOf(name + "@" + ver + "|" + v.Vuln + "|" + path), Raw: it})
	}
	return out, nil
}

// anchoreNone maps Anchore's "None" placeholder to "".
func anchoreNone(s string) string {
	if strings.EqualFold(strings.TrimSpace(s), "none") {
		return ""
	}
	return strings.TrimSpace(s)
}
