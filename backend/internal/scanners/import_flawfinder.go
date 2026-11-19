package scanners

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Flawfinder CSV (`flawfinder --csv`): one row per hit with File, Line,
// Column, DefaultLevel, Level (0-5, 5 the riskiest), Category, Name,
// Warning, Suggestion, Note, CWEs ("CWE-119!/CWE-120"), Context,
// Fingerprint, ToolVersion and, since 2.0.12, RuleId and HelpUri. Levels map
// 5 critical, 4 high, 3 medium, 2 low, 0-1 info. Identity is Flawfinder's
// fingerprint (a hash of the rule and the line's code), else the context.

var flawfinderLevels = map[string]string{"5": "critical", "4": "high", "3": "medium", "2": "low", "1": "info", "0": "info"}

func init() {
	registerImportFormat(ImportFormat{ID: "flawfinder", Label: "Flawfinder CSV", Tool: "Flawfinder", Category: "sast", Media: "csv", Order: 111,
		match: func(p *importProbe) bool {
			return p.kind == "csv" && flawfinderHas(p.header, "file", "line", "level", "warning", "cwes")
		},
		parse: parseFlawfinderCSV})
}

func flawfinderHas(h []string, cols ...string) bool {
	for _, c := range cols {
		found := false
		for _, x := range h {
			if x == c {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func parseFlawfinderCSV(raw []byte) ([]importRecord, error) {
	raw = bytes.TrimPrefix(raw, utf8BOM)
	cr := csvReader(bytes.NewReader(raw))
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("flawfinder: %w", err)
	}
	header = lowerAll(header)
	if !flawfinderHas(header, "file", "line", "level", "warning") {
		return nil, errors.New("flawfinder: the header row needs File, Line, Level and Warning columns")
	}
	var out []importRecord
	for row := 2; ; row++ {
		rec, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return out, fmt.Errorf("flawfinder: row %d: %w", row, err)
		}
		v := map[string]string{}
		for i, cell := range rec {
			if i < len(header) {
				v[header[i]] = strings.TrimSpace(cell)
			}
		}
		sev, ok := flawfinderLevels[v["level"]]
		if v["file"] == "" || !ok {
			return out, fmt.Errorf("flawfinder: row %d: expected a file and a level 0-5", row)
		}
		line, _ := strconv.Atoi(v["line"])
		rule := firstNonEmpty(v["ruleid"], v["name"])
		f := Finding{Category: "sast", RuleID: rule, Severity: sev, FilePath: NormalizePath(v["file"]), StartLine: intPtr(line),
			Title:       fmt.Sprintf("%s: %s (%s)", v["category"], v["name"], firstNonEmpty(v["cwes"], "no CWE")),
			Description: joinText(v["warning"], labelled("Suggestion", v["suggestion"]), labelled("Note", v["note"]), labelled("Code", v["context"])),
			CWE:         []string{v["cwes"]}}
		out = append(out, importRecord{F: f, SnippetKey: hashOf("flawfinder|" + firstNonEmpty(v["fingerprint"], codeIdentity(v["context"]))), Raw: rawJSON(v)})
	}
	return out, nil
}
