package scanners

import (
	"bufio"
	"bytes"
	"errors"
	"strings"
)

// Lynis report (`lynis audit system --report-file lynis-report.dat`): a
// key=value text file. warning[] and suggestion[] lines carry
// "TEST-ID|text|details|solution|"; hostname, os_name and os_version
// describe the audited system, vulnerable_package[] lists the packages
// behind PKGS-7392. Warnings are medium, suggestions low (Lynis has no
// other severity). Findings are located on the audited host.

func init() {
	registerImportFormat(ImportFormat{ID: "lynis", Label: "Lynis report (lynis-report.dat)", Tool: "Lynis", Category: "compliance", Media: "text", Order: 563,
		match: func(p *importProbe) bool {
			return p.kind == "" && p.headHas("lynis_version=") && (p.headHas("# Lynis Report") || p.headHas("report_version_major="))
		},
		parse: parseLynis})
}

func parseLynis(raw []byte) ([]importRecord, error) {
	vals := map[string]string{}
	var vulnerable []string
	type item struct{ kind, id, text, details, solution string }
	var items []item
	sc := bufio.NewScanner(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM)))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "warning[]", "suggestion[]":
			parts := strings.Split(v, "|")
			for len(parts) < 4 {
				parts = append(parts, "")
			}
			it := item{kind: strings.TrimSuffix(k, "[]"), id: strings.TrimSpace(parts[0]), text: strings.TrimSpace(parts[1])}
			if d := strings.TrimSpace(parts[2]); d != "-" {
				it.details = d
			}
			if s := strings.TrimSpace(parts[3]); s != "-" {
				it.solution = strings.TrimPrefix(s, "text:")
			}
			items = append(items, it)
		case "vulnerable_package[]":
			vulnerable = append(vulnerable, v)
		default:
			if _, seen := vals[k]; !seen {
				vals[k] = v
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if vals["lynis_version"] == "" {
		return nil, errors.New("lynis: not a Lynis report (no lynis_version)")
	}
	host := firstNonEmpty(vals["hostname"], strings.TrimSpace(vals["os_name"]+" "+vals["os_version"]))
	var out []importRecord
	for _, it := range items {
		if it.id == "" {
			return out, errors.New("lynis: " + it.kind + " without a test ID")
		}
		f := Finding{Category: "compliance", RuleID: it.id, Title: firstNonEmpty(it.text, it.id), Severity: "low", FilePath: host,
			Description: joinText(it.text, labeled("Details", it.details), labeled("Solution", it.solution),
				"Lynis "+it.kind+" "+it.id+" (https://cisofy.com/lynis/controls/"+it.id+"/)")}
		if it.kind == "warning" {
			f.Severity = "medium"
		}
		if it.id == "PKGS-7392" && len(vulnerable) > 0 {
			f.Description = joinText(f.Description, "Vulnerable packages: "+strings.Join(vulnerable, ", "))
		}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(it.kind + "|" + it.details),
			Raw: rawJSON(map[string]string{"type": it.kind, "test": it.id, "text": it.text, "details": it.details, "solution": it.solution, "hostname": vals["hostname"]})})
	}
	return out, nil
}
