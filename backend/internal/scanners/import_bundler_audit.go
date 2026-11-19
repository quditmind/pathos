package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// bundler-audit JSON (`bundle-audit check --format json`, bundler-audit
// 0.8+): version, created_at and results[]. "unpatched_gem" results carry
// the gem (name, version) and the ruby-advisory-db advisory (id, cve, ghsa,
// title, description, cvss_v3, cvss_v2, criticality, patched_versions);
// "insecure_source" results name a gem source fetched over plain HTTP or
// git:// (natural category "other"). The fixed version is the lowest
// ">= x" of patched_versions.

type bundlerAuditResult struct {
	Type string `json:"type"`
	Gem  struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"gem"`
	Source   string `json:"source"`
	Advisory struct {
		ID              string   `json:"id"`
		URL             string   `json:"url"`
		Title           string   `json:"title"`
		Description     string   `json:"description"`
		CVSSv2          float64  `json:"cvss_v2"`
		CVSSv3          float64  `json:"cvss_v3"`
		CVE             string   `json:"cve"`
		GHSA            string   `json:"ghsa"`
		Criticality     string   `json:"criticality"`
		PatchedVersions []string `json:"patched_versions"`
	} `json:"advisory"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "bundler-audit", Label: "bundler-audit JSON", Tool: "bundler-audit", Category: "sca", Media: "json", Order: 217,
		match: func(p *importProbe) bool {
			if p.kind != "object" || !p.has("version", "created_at", "results") {
				return false
			}
			first := p.firstOf("results")
			return first == nil || hasKeys(first, "type") && (hasKeys(first, "gem") || hasKeys(first, "source"))
		},
		parse: parseBundlerAudit})
}

func parseBundlerAudit(raw []byte) ([]importRecord, error) {
	items, err := jsonArray(raw, "results")
	if err != nil {
		return nil, fmt.Errorf("bundler-audit: invalid JSON: %w", err)
	}
	var out []importRecord
	for i, it := range items {
		var r bundlerAuditResult
		if err := json.Unmarshal(it, &r); err != nil {
			return out, fmt.Errorf("bundler-audit: result %d: invalid", i+1)
		}
		switch r.Type {
		case "insecure_source":
			f := Finding{Category: "other", RuleID: "bundler-audit-insecure-source", Severity: "medium", FilePath: "Gemfile.lock",
				Title: "Insecure gem source " + r.Source, CWE: []string{"CWE-319"},
				Description: "Gems are fetched from " + r.Source + " without TLS; an attacker on the network can replace them."}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(r.Source), Raw: it})
		case "unpatched_gem":
			a := r.Advisory
			if a.ID == "" || r.Gem.Name == "" {
				return out, fmt.Errorf("bundler-audit: result %d: unpatched_gem without gem or advisory id", i+1)
			}
			f := Finding{Category: "sca", RuleID: a.ID, Severity: a.Criticality, PackageName: r.Gem.Name, PackageVersion: r.Gem.Version,
				FilePath: "Gemfile.lock", CVSS: floatPtr(a.CVSSv3), FixedVersion: bundlerFixed(a.PatchedVersions, r.Gem.Version)}
			if a.CVE != "" {
				f.CVE = firstMatch(cveRe, "CVE-"+strings.TrimPrefix(a.CVE, "CVE-"))
			}
			f.CVE = firstNonEmpty(f.CVE, firstMatch(cveRe, a.ID))
			if f.CVSS == nil {
				f.CVSS = floatPtr(a.CVSSv2)
			}
			f.CWE = normCWEs([]string{a.Description})
			id := firstNonEmpty(f.CVE, a.ID)
			f.Title = fmt.Sprintf("%s: %s in %s %s", id, a.Title, r.Gem.Name, r.Gem.Version)
			desc := []string{a.Title, "Patched versions: " + strings.Join(a.PatchedVersions, ", "), a.URL}
			if a.GHSA != "" {
				desc = append(desc, "Advisory: GHSA-"+strings.TrimPrefix(a.GHSA, "GHSA-"))
			}
			f.Description = joinText(append(desc, a.Description)...)
			out = append(out, importRecord{F: f, Raw: it})
		default:
			return out, fmt.Errorf("bundler-audit: result %d: unknown type %q", i+1, r.Type)
		}
	}
	return out, nil
}

// bundlerFixed returns the lowest ">= x" version of the patched ranges
// that is above the installed version.
func bundlerFixed(patched []string, installed string) string {
	best := ""
	for _, p := range patched {
		for _, part := range strings.Split(p, ",") {
			v, ok := strings.CutPrefix(strings.TrimSpace(part), ">=")
			v = strings.TrimSpace(v)
			if ok && v != "" && (installed == "" || compareLooseVersions(v, installed) > 0) && (best == "" || compareLooseVersions(v, best) < 0) {
				best = v
			}
		}
	}
	return best
}

// compareLooseVersions compares dotted versions numerically where possible.
func compareLooseVersions(a, b string) int {
	as, bs := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y string
		if i < len(as) {
			x = as[i]
		}
		if i < len(bs) {
			y = bs[i]
		}
		var xn, yn int
		_, ex := fmt.Sscanf(x, "%d", &xn)
		_, ey := fmt.Sscanf(y, "%d", &yn)
		switch {
		case ex == nil && ey == nil && xn != yn:
			if xn < yn {
				return -1
			}
			return 1
		case (ex != nil || ey != nil) && x != y:
			return strings.Compare(x, y)
		}
	}
	return 0
}
