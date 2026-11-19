package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Xeol JSON (`xeol <image or dir> -o json`): matches[] with Cycle
// (ProductName, ReleaseCycle, Eol: the end-of-life date or "true",
// LatestRelease) and artifact (name, version, type, locations, purl), and
// the scanned source. Xeol reports only end-of-life software and has no
// severity: findings are medium with the "eol" category (when imported
// with category other). Like Grype reports, Xeol reports have a top-level
// "matches"; they are told apart by the Cycle of their matches.

func isXeol(p *importProbe) bool {
	return hasKeys(p.firstOf("matches"), "Cycle", "artifact")
}

func init() {
	registerImportFormat(ImportFormat{ID: "xeol", Label: "Xeol end-of-life JSON", Tool: "Xeol", Media: "json", Order: 611,
		match: func(p *importProbe) bool { return p.kind == "object" && isXeol(p) },
		parse: parseXeol})
}

func parseXeol(raw []byte) ([]importRecord, error) {
	var doc struct {
		Matches []json.RawMessage `json:"matches"`
		Source  struct {
			Type   string          `json:"type"`
			Target json.RawMessage `json:"target"`
		} `json:"source"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("xeol: invalid JSON: %w", err)
	}
	target := ""
	var t struct {
		UserInput string `json:"userInput"`
	}
	if json.Unmarshal(doc.Source.Target, &t) == nil {
		target = t.UserInput
	} else {
		_ = json.Unmarshal(doc.Source.Target, &target)
	}
	var out []importRecord
	for i, mr := range doc.Matches {
		var m struct {
			Cycle struct {
				ProductName       string `json:"ProductName"`
				ReleaseCycle      string `json:"ReleaseCycle"`
				Eol               string `json:"Eol"`
				LatestRelease     string `json:"LatestRelease"`
				LatestReleaseDate string `json:"LatestReleaseDate"`
			} `json:"Cycle"`
			Artifact struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Type      string `json:"type"`
				PURL      string `json:"purl"`
				Locations []struct {
					Path string `json:"path"`
				} `json:"locations"`
			} `json:"artifact"`
		}
		if err := json.Unmarshal(mr, &m); err != nil || m.Cycle.ProductName == "" {
			return out, fmt.Errorf("xeol: match %d: expected Cycle.ProductName", i+1)
		}
		eol := "is end of life"
		if m.Cycle.Eol != "" && m.Cycle.Eol != "true" {
			eol = "reached end of life on " + m.Cycle.Eol
		}
		loc := target
		if len(m.Artifact.Locations) > 0 {
			loc = m.Artifact.Locations[0].Path
		}
		f := Finding{Category: "eol", RuleID: "EOL " + m.Cycle.ProductName + " " + m.Cycle.ReleaseCycle, Severity: "medium",
			Title:       strings.TrimSpace(fmt.Sprintf("%s %s %s", m.Cycle.ProductName, m.Cycle.ReleaseCycle, eol)),
			PackageName: m.Artifact.Name, PackageVersion: m.Artifact.Version, FilePath: firstNonEmpty(loc, m.Artifact.Name),
			Description: joinText(fmt.Sprintf("%s %s (%s package %s %s) %s and no longer receives security fixes.", m.Cycle.ProductName, m.Cycle.ReleaseCycle,
				m.Artifact.Type, m.Artifact.Name, m.Artifact.Version, eol), labeled("Latest release", m.Cycle.LatestRelease), labeled("Package URL", m.Artifact.PURL),
				labeled("Scanned", target), "Xeol reports no severity; end-of-life software is medium.")}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(m.Artifact.Name + "@" + m.Artifact.Version), Raw: mr})
	}
	return out, nil
}
