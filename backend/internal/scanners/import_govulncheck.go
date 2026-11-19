package scanners

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// govulncheck JSON (`govulncheck -json ./...`): a stream of (indented) JSON
// messages: config, SBOM, progress, osv (the OSV entry of every
// vulnerability that may apply) and finding. A finding names an OSV entry,
// the fixed version and a trace: its first frame is the vulnerable module
// (module level: the module is required), package (the package is
// imported) or function (the vulnerable symbol is called); the further
// frames are the call path from the scanned code. govulncheck reports the
// same vulnerability at each level it reaches; those are one finding at
// the deepest level. The reachability is kept in the description:
// vulnerabilities whose symbols are called have high confidence, those only
// imported or required low confidence. The Go vulnerability database has
// no severity: findings are medium and the description says so.

type govulnFrame struct {
	Module   string `json:"module"`
	Version  string `json:"version"`
	Package  string `json:"package"`
	Function string `json:"function"`
	Receiver string `json:"receiver"`
	Position *struct {
		Filename string `json:"filename"`
		Line     int    `json:"line"`
		Column   int    `json:"column"`
	} `json:"position"`
}

type govulnFinding struct {
	OSV          string        `json:"osv"`
	FixedVersion string        `json:"fixed_version"`
	Trace        []govulnFrame `json:"trace"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "govulncheck", Label: "govulncheck JSON", Tool: "govulncheck", Category: "sca", Media: "json", Order: 214,
		match: func(p *importProbe) bool {
			if p.kind != "stream" && p.kind != "jsonl" && p.kind != "object" {
				return false
			}
			var c struct {
				Scanner string `json:"scanner_name"`
			}
			return len(p.keys) == 1 && p.has("config") && json.Unmarshal(p.keys["config"], &c) == nil && c.Scanner == "govulncheck"
		},
		parse: parseGovulncheck})
}

// govulnLevel is how deep a trace reaches: 1 module, 2 package, 3 symbol.
func govulnLevel(f govulnFinding) int {
	switch {
	case len(f.Trace) == 0:
		return 0
	case f.Trace[0].Function != "":
		return 3
	case f.Trace[0].Package != "":
		return 2
	}
	return 1
}

func govulnSymbol(fr govulnFrame) string {
	s := fr.Function
	if fr.Receiver != "" {
		s = strings.TrimPrefix(fr.Receiver, "*") + "." + s
	}
	if fr.Package != "" {
		s = fr.Package + "." + s
	}
	if fr.Position != nil && fr.Position.Filename != "" {
		s += fmt.Sprintf(" (%s:%d)", fr.Position.Filename, fr.Position.Line)
	}
	return s
}

func parseGovulncheck(raw []byte) ([]importRecord, error) {
	type osvEntry struct {
		ID               string   `json:"id"`
		Aliases          []string `json:"aliases"`
		Summary          string   `json:"summary"`
		Details          string   `json:"details"`
		DatabaseSpecific struct {
			URL string `json:"url"`
		} `json:"database_specific"`
	}
	osvs := map[string]osvEntry{}
	type group struct {
		best   govulnFinding
		traces []govulnFinding
		raws   []json.RawMessage
	}
	groups := map[string]*group{}
	var order []string
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(raw, utf8BOM)))
	for n := 1; ; n++ {
		var msg struct {
			OSV     json.RawMessage `json:"osv"`
			Finding json.RawMessage `json:"finding"`
		}
		if err := d.Decode(&msg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("govulncheck: message %d: invalid JSON: %w", n, err)
		}
		if msg.OSV != nil {
			var o osvEntry
			if err := json.Unmarshal(msg.OSV, &o); err != nil || o.ID == "" {
				return nil, fmt.Errorf("govulncheck: message %d: osv entry without id", n)
			}
			osvs[o.ID] = o
		}
		if msg.Finding != nil {
			var f govulnFinding
			if err := json.Unmarshal(msg.Finding, &f); err != nil || f.OSV == "" || len(f.Trace) == 0 || f.Trace[0].Module == "" {
				return nil, fmt.Errorf("govulncheck: message %d: finding without osv or trace", n)
			}
			key := f.OSV + "|" + f.Trace[0].Module + "@" + f.Trace[0].Version
			g := groups[key]
			if g == nil {
				g = &group{best: f}
				groups[key] = g
				order = append(order, key)
			}
			if govulnLevel(f) > govulnLevel(g.best) {
				g.best = f
			}
			g.traces = append(g.traces, f)
			g.raws = append(g.raws, msg.Finding)
		}
	}
	var out []importRecord
	for _, key := range order {
		g := groups[key]
		b := g.best
		top := b.Trace[0]
		o := osvs[b.OSV]
		f := Finding{Category: "sca", RuleID: b.OSV, Severity: "medium", PackageName: top.Module, PackageVersion: top.Version,
			FixedVersion: b.FixedVersion, FilePath: "go.mod", CVE: firstMatch(cveRe, o.Aliases...)}
		if top.Module == "stdlib" || top.Module == "toolchain" {
			f.FilePath = ""
		}
		id := b.OSV
		if f.CVE != "" {
			id = f.CVE + " (" + b.OSV + ")"
		}
		f.Title = fmt.Sprintf("%s in %s %s", id, top.Module, top.Version)
		var reach string
		switch govulnLevel(b) {
		case 3:
			f.Confidence = "high"
			var calls []string
			for _, t := range g.traces {
				if govulnLevel(t) < 3 {
					continue
				}
				var path []string
				for _, fr := range t.Trace {
					path = append(path, govulnSymbol(fr))
				}
				if c := strings.Join(path, " <- "); !slices.Contains(calls, c) {
					calls = append(calls, c)
				}
			}
			reach = "Reachability: called. govulncheck found a call path from the scanned code to the vulnerable symbol:\n" + strings.Join(calls, "\n")
		case 2:
			f.Confidence = "low"
			reach = "Reachability: imported, not called. The vulnerable package " + top.Package + " is imported, but govulncheck found no call to its vulnerable symbols."
		default:
			f.Confidence = "low"
			reach = "Reachability: required, not imported. The module is required, but govulncheck found no import of its vulnerable packages."
		}
		aliases := ""
		if len(o.Aliases) > 0 {
			aliases = "Aliases: " + strings.Join(o.Aliases, ", ")
		}
		f.Description = joinText(o.Summary, reach, o.Details, aliases, o.DatabaseSpecific.URL,
			"The Go vulnerability database has no severity; imported as medium.")
		out = append(out, importRecord{F: f, Raw: rawJSON(map[string]any{"osv": b.OSV, "findings": g.raws})})
	}
	return out, nil
}
