package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// cargo-audit JSON (`cargo audit --json`): database, lockfile, settings,
// vulnerabilities.list[] (advisory: RUSTSEC id, aliases, title,
// description, cvss vector; versions.patched; affected.functions;
// package: name, version) and warnings (kind -> list: unmaintained,
// unsound, yanked, notice), each with a package and, except yanked, an
// informational advisory. Vulnerabilities carry a CVSS vector but no score
// or severity: they are imported as medium (the vector is kept and the
// description says so). Warnings are low.

type cargoAuditEntry struct {
	Kind     string `json:"kind"`
	Advisory *struct {
		ID            string   `json:"id"`
		Package       string   `json:"package"`
		Title         string   `json:"title"`
		Description   string   `json:"description"`
		Aliases       []string `json:"aliases"`
		CVSS          string   `json:"cvss"`
		URL           string   `json:"url"`
		Informational string   `json:"informational"`
		Withdrawn     string   `json:"withdrawn"`
	} `json:"advisory"`
	Versions struct {
		Patched []string `json:"patched"`
	} `json:"versions"`
	Affected *struct {
		Functions map[string][]string `json:"functions"`
	} `json:"affected"`
	Package struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "cargo-audit", Label: "cargo-audit JSON", Tool: "cargo-audit", Category: "sca", Media: "json", Order: 218,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("database", "lockfile", "vulnerabilities") && p.hasAny("warnings", "settings")
		},
		parse: parseCargoAudit})
}

func parseCargoAudit(raw []byte) ([]importRecord, error) {
	var doc struct {
		Vulnerabilities struct {
			List []json.RawMessage `json:"list"`
		} `json:"vulnerabilities"`
		Warnings map[string][]json.RawMessage `json:"warnings"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("cargo-audit: invalid JSON: %w", err)
	}
	var out []importRecord
	add := func(it json.RawMessage, warning string) error {
		var e cargoAuditEntry
		if err := json.Unmarshal(it, &e); err != nil || e.Package.Name == "" || (warning == "" && e.Advisory == nil) {
			return fmt.Errorf("cargo-audit: entry without package or advisory")
		}
		f := Finding{Category: "sca", PackageName: e.Package.Name, PackageVersion: e.Package.Version, FilePath: "Cargo.lock",
			FixedVersion: bundlerFixed(e.Versions.Patched, e.Package.Version)}
		var desc []string
		if a := e.Advisory; a != nil {
			f.RuleID, f.CVE, f.CVSSVector = a.ID, firstMatch(cveRe, a.Aliases...), a.CVSS
			id := a.ID
			if f.CVE != "" {
				id = f.CVE + " (" + a.ID + ")"
			}
			f.Title = fmt.Sprintf("%s: %s in %s %s", id, a.Title, e.Package.Name, e.Package.Version)
			desc = append(desc, a.Title, a.Description, a.URL)
			if len(a.Aliases) > 0 {
				desc = append(desc, "Aliases: "+strings.Join(a.Aliases, ", "))
			}
			if a.Withdrawn != "" {
				f.Confidence = "low"
				desc = append(desc, "Advisory withdrawn on "+a.Withdrawn)
			}
		} else {
			f.RuleID = "cargo-" + warning
			f.Title = fmt.Sprintf("%s crate %s %s", warning, e.Package.Name, e.Package.Version)
		}
		desc = append(desc, "Patched versions: "+strings.Join(e.Versions.Patched, "; "))
		if e.Affected != nil && len(e.Affected.Functions) > 0 {
			fns := make([]string, 0, len(e.Affected.Functions))
			for fn := range e.Affected.Functions {
				fns = append(fns, fn)
			}
			slices.Sort(fns)
			desc = append(desc, "Affected functions: "+strings.Join(fns, ", "))
		}
		if warning == "" {
			f.Severity = "medium"
			desc = append(desc, "cargo-audit reports a CVSS vector but no severity; imported as medium.")
		} else {
			f.Severity = "low"
			desc = append(desc, "cargo-audit warning: "+warning)
		}
		f.Description = joinText(desc...)
		out = append(out, importRecord{F: f, Raw: it})
		return nil
	}
	for _, it := range doc.Vulnerabilities.List {
		if err := add(it, ""); err != nil {
			return out, err
		}
	}
	kinds := make([]string, 0, len(doc.Warnings))
	for k := range doc.Warnings {
		kinds = append(kinds, k)
	}
	slices.Sort(kinds)
	for _, k := range kinds {
		for _, it := range doc.Warnings[k] {
			if err := add(it, k); err != nil {
				return out, err
			}
		}
	}
	return out, nil
}
