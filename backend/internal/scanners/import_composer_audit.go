package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Composer audit JSON (`composer audit --format=json`): "advisories" maps
// package names to lists of advisories (advisoryId, packageName,
// affectedVersions, title, cve, link, sources, severity); "abandoned" lists
// abandoned packages (not vulnerabilities, not findings). The installed
// version is not in the report (only the affected ranges), so
// package_version stays empty. Advisories without a severity (some
// FriendsOfPHP entries) are imported as medium and the description says so.

type composerAdvisory struct {
	AdvisoryID       string `json:"advisoryId"`
	PackageName      string `json:"packageName"`
	AffectedVersions string `json:"affectedVersions"`
	Title            string `json:"title"`
	CVE              string `json:"cve"`
	Link             string `json:"link"`
	Severity         string `json:"severity"`
	Sources          []struct {
		Name     string `json:"name"`
		RemoteID string `json:"remoteId"`
	} `json:"sources"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "composer-audit", Label: "Composer audit JSON", Tool: "Composer audit", Category: "sca", Media: "json", Order: 213,
		match: func(p *importProbe) bool {
			if p.kind != "object" || !p.has("advisories") || p.has("metadata") {
				return false
			}
			if p.has("abandoned") {
				return true
			}
			var m map[string][]map[string]json.RawMessage
			if json.Unmarshal(p.keys["advisories"], &m) != nil {
				return false
			}
			for _, l := range m {
				return len(l) > 0 && hasKeys(l[0], "advisoryId", "affectedVersions")
			}
			return false
		},
		parse: parseComposerAudit})
}

func parseComposerAudit(raw []byte) ([]importRecord, error) {
	var doc struct {
		Advisories json.RawMessage `json:"advisories"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("composer audit: invalid JSON: %w", err)
	}
	// An object of package -> advisories; PHP encodes an empty one as [].
	byPkg := map[string][]json.RawMessage{}
	if len(doc.Advisories) > 0 && doc.Advisories[0] == '{' {
		if err := json.Unmarshal(doc.Advisories, &byPkg); err != nil {
			return nil, fmt.Errorf("composer audit: advisories: %w", err)
		}
	}
	pkgs := make([]string, 0, len(byPkg))
	for p := range byPkg {
		pkgs = append(pkgs, p)
	}
	slices.Sort(pkgs)
	var out []importRecord
	for _, p := range pkgs {
		for i, it := range byPkg[p] {
			var a composerAdvisory
			if err := json.Unmarshal(it, &a); err != nil || a.AdvisoryID == "" {
				return out, fmt.Errorf("composer audit: %s advisory %d: expected an object with advisoryId", p, i+1)
			}
			ids := []string{a.CVE, a.Link}
			ghsa := ghsaRe.FindString(a.Link)
			for _, s := range a.Sources {
				ids = append(ids, s.RemoteID)
				ghsa = firstNonEmpty(ghsa, ghsaRe.FindString(s.RemoteID))
			}
			f := Finding{Category: "sca", Severity: a.Severity, PackageName: firstNonEmpty(a.PackageName, p), FilePath: "composer.lock",
				CVE: firstMatch(cveRe, ids...)}
			f.RuleID = firstNonEmpty(f.CVE, ghsa, a.AdvisoryID)
			f.Title = fmt.Sprintf("%s: %s in %s", f.RuleID, strings.TrimPrefix(a.Title, f.CVE+": "), f.PackageName)
			desc := []string{a.Title, "Affected versions: " + a.AffectedVersions, "Advisory: " + a.AdvisoryID, a.Link}
			if normSeverity(a.Severity) == "" {
				f.Severity = "medium"
				desc = append(desc, "Composer reports no severity for this advisory; imported as medium.")
			}
			f.Description = joinText(desc...)
			out = append(out, importRecord{F: f, Raw: it})
		}
	}
	return out, nil
}
