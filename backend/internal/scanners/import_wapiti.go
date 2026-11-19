package scanners

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Wapiti JSON report (`wapiti -f json`): vulnerabilities, anomalies and
// additionals, each a map from the classification name to the items found,
// with the classifications (description, solution, references) and the
// scan infos (target). Levels: 4 critical, 3 high, 2 medium, 1 low, 0
// info. One finding per item; identity is the classification, method, path,
// parameter and message. The raw request (with the scan's cookies and
// authorization) is redacted before the report is stored.

type wapitiReport struct {
	Classifications map[string]struct {
		Desc string            `json:"desc"`
		Sol  string            `json:"sol"`
		Ref  map[string]string `json:"ref"`
		WSTG []string          `json:"wstg"`
	} `json:"classifications"`
	Vulnerabilities map[string][]wapitiItem `json:"vulnerabilities"`
	Anomalies       map[string][]wapitiItem `json:"anomalies"`
	Additionals     map[string][]wapitiItem `json:"additionals"`
	Infos           struct {
		Target  string `json:"target"`
		Version string `json:"version"`
	} `json:"infos"`
}

type wapitiItem struct {
	Method      string      `json:"method"`
	Path        string      `json:"path"`
	Info        string      `json:"info"`
	Level       looseString `json:"level"`
	Parameter   string      `json:"parameter"`
	Referer     string      `json:"referer"`
	Module      string      `json:"module"`
	HTTPRequest string      `json:"http_request"`
	CurlCommand string      `json:"curl_command"`
	WSTG        []string    `json:"wstg"`
}

// wapitiRecord is the record kept as a finding's original output.
type wapitiRecord struct {
	Kind           string `json:"kind"`
	Classification string `json:"classification"`
	Target         string `json:"target"`
	wapitiItem
}

func init() {
	registerImportFormat(ImportFormat{ID: "wapiti", Label: "Wapiti JSON report", Tool: "Wapiti", Category: "dast", Media: "json", Order: 301,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("classifications", "vulnerabilities", "infos") && p.hasAny("anomalies", "additionals")
		},
		parse:    parseWapiti,
		sanitize: func(raw []byte) []byte { return g1Sanitize(raw, "auth") },
	})
}

func parseWapiti(raw []byte) ([]importRecord, error) {
	var rep wapitiReport
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("wapiti: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, kind := range []struct {
		name  string
		items map[string][]wapitiItem
	}{{"vulnerability", rep.Vulnerabilities}, {"anomaly", rep.Anomalies}, {"additional", rep.Additionals}} {
		names := make([]string, 0, len(kind.items))
		for n := range kind.items {
			names = append(names, n)
		}
		slices.Sort(names) // map order is random; findings keep a stable order
		for _, name := range names {
			cl := rep.Classifications[name]
			var cwes []string
			for ref := range cl.Ref {
				cwes = append(cwes, ref)
			}
			slices.Sort(cwes)
			for _, it := range kind.items[name] {
				u := g1Resolve(rep.Infos.Target, it.Path)
				f := Finding{Category: "dast", RuleID: name, Title: name, FilePath: locationOf("", g1StripQuery(redactHTTP(u))), CWE: normCWEs(cwes)}
				switch strings.TrimSpace(string(it.Level)) {
				case "4":
					f.Severity = "critical"
				case "3":
					f.Severity = "high"
				case "2":
					f.Severity = "medium"
				case "1":
					f.Severity = "low"
				default:
					f.Severity = "info"
				}
				if kind.name != "vulnerability" {
					f.Description = "Wapiti reports this as an " + kind.name + ", not a confirmed vulnerability."
					f.Confidence = "low"
				}
				f.Description = joinText(f.Description, it.Info, whereText(it.Method, u, it.Parameter), strings.TrimSpace(cl.Desc),
					labelled("Solution", strings.TrimSpace(cl.Sol)), labelled("Request", clipText(redactHTTP(it.HTTPRequest), 1500)))
				rec := wapitiRecord{Kind: kind.name, Classification: name, Target: rep.Infos.Target, wapitiItem: it}
				rec.HTTPRequest, rec.CurlCommand = redactHTTP(g1RedactCmd(it.HTTPRequest)), redactHTTP(g1RedactCmd(it.CurlCommand))
				out = append(out, importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(it.Method) + "|" + it.Parameter + "|" + it.Info + "|" + it.Module),
					Raw: rawJSON(rec)})
			}
		}
	}
	return out, nil
}
