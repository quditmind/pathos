package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// njsscan JSON (`njsscan --json`): results by rule id under "nodejs" and
// "templates", each with files[] (file_path, match_lines, match_string)
// and metadata (cwe, description, owasp-web, severity ERROR / WARNING /
// INFO). One finding per rule and file location. mobsfscan (import_mobsfscan.go)
// writes the same structure under "results".

type njsscanFile struct {
	FilePath    string `json:"file_path"`
	MatchLines  []int  `json:"match_lines"`
	MatchString string `json:"match_string"`
}

type njsscanRule struct {
	Files       []json.RawMessage `json:"files"`
	RawMetadata json.RawMessage   `json:"metadata"`
	Metadata    struct {
		CWE         string `json:"cwe"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		OWASPWeb    string `json:"owasp-web"`
		OWASPMobile string `json:"owasp-mobile"`
		MASVS       string `json:"masvs"`
		Reference   string `json:"reference"`
	} `json:"-"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "njsscan", Label: "njsscan JSON", Tool: "njsscan", Category: "sast", Media: "json", Order: 152,
		match: func(p *importProbe) bool {
			return p.kind == "object" && (p.has("njsscan_version") || p.has("nodejs", "templates", "errors"))
		},
		parse: func(raw []byte) ([]importRecord, error) { return njsscanParse("njsscan", raw, "nodejs", "templates") }})
}

// njsscanParse parses the rule maps of njsscan and mobsfscan reports in
// the named sections. Rules without files (mobsfscan's app-level checks,
// such as missing root detection) are findings without a location.
func njsscanParse(tool string, raw []byte, sections ...string) ([]importRecord, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("%s: invalid JSON: %w", tool, err)
	}
	var out []importRecord
	for _, sec := range sections {
		if doc[sec] == nil || string(doc[sec]) == "null" {
			continue
		}
		var rules map[string]json.RawMessage
		if err := json.Unmarshal(doc[sec], &rules); err != nil {
			return nil, fmt.Errorf("%s: %s: expected an object of rules: %w", tool, sec, err)
		}
		ids := make([]string, 0, len(rules))
		for id := range rules {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			var r njsscanRule
			if err := json.Unmarshal(rules[id], &r); err != nil || json.Unmarshal(r.RawMetadata, &r.Metadata) != nil {
				return out, fmt.Errorf("%s: rule %s: expected an object with metadata", tool, id)
			}
			md := r.Metadata
			title := md.Description
			if j := strings.Index(title, ". "); j > 0 {
				title = title[:j+1]
			}
			base := Finding{Category: "sast", RuleID: id, Title: firstNonEmpty(title, id), Severity: md.Severity, CWE: []string{md.CWE},
				Description: joinText(md.Description, firstNonEmpty(md.OWASPWeb, md.OWASPMobile), md.MASVS, md.Reference)}
			if len(r.Files) == 0 {
				out = append(out, importRecord{F: base, SnippetKey: hashOf(id), Raw: rules[id]})
				continue
			}
			for _, rf := range r.Files {
				var fl njsscanFile
				if err := json.Unmarshal(rf, &fl); err != nil {
					return out, fmt.Errorf("%s: rule %s: invalid file entry", tool, id)
				}
				f := base
				f.FilePath = NormalizePath(fl.FilePath)
				if n := len(fl.MatchLines); n > 0 {
					f.StartLine, f.EndLine = intPtr(fl.MatchLines[0]), intPtr(fl.MatchLines[n-1])
				}
				// The original record is the rule with this one location.
				rec := map[string]any{"rule_id": id, "files": []json.RawMessage{rf}, "metadata": r.RawMetadata}
				out = append(out, importRecord{F: f, SnippetKey: hashOf(firstNonEmpty(codeIdentity(fl.MatchString), fmt.Sprint(fl.MatchLines))), Raw: rawJSON(rec)})
			}
		}
	}
	return out, nil
}
