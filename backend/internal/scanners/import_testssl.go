package scanners

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// testssl.sh JSON: the flat array of `--jsonfile` ({id, ip, port,
// severity, finding, cve, cwe}) and the nested `--jsonfile-pretty` object
// (scanResult[] of targets with one array per section). Entries with
// severity LOW, MEDIUM, HIGH or CRITICAL are findings; OK and INFO are
// testssl.sh's own "no issue" results and WARN, DEBUG and FATAL report
// problems of the scan itself, so they are not findings. Identity is the
// check id at host:port.

type testsslEntry struct {
	ID       string      `json:"id"`
	IP       string      `json:"ip,omitempty"`
	Port     looseString `json:"port,omitempty"`
	Severity string      `json:"severity"`
	CVE      string      `json:"cve,omitempty"`
	CWE      string      `json:"cwe,omitempty"`
	Finding  string      `json:"finding"`
	Hint     string      `json:"hint,omitempty"`
}

type testsslPretty struct {
	ScanResult []map[string]json.RawMessage `json:"scanResult"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "testssl", Label: "testssl.sh JSON (--jsonfile or --jsonfile-pretty)", Tool: "testssl.sh", Category: "misconfiguration", Media: "json", Order: 331,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "array":
				return p.has("id", "ip", "port", "severity", "finding")
			case "object":
				return p.has("scanResult") && p.hasAny("Invocation", "openssl", "startTime")
			}
			return false
		},
		parse: parseTestssl})
}

func parseTestssl(raw []byte) ([]importRecord, error) {
	var out []importRecord
	add := func(host, ip, port string, e testsslEntry) {
		sev := ""
		switch strings.ToUpper(strings.TrimSpace(e.Severity)) {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
			sev = strings.ToLower(e.Severity)
		default:
			return
		}
		if e.ID == "" || len(out) >= MaxFindingsPerReport {
			return
		}
		if ip != "" && host == "" {
			host = ip
		}
		e.IP = firstNonEmpty(e.IP, strings.Trim(host+"/"+ip, "/"))
		e.Port = looseString(firstNonEmpty(string(e.Port), port))
		name, _, _ := strings.Cut(e.IP, "/")
		f := Finding{Category: "misconfiguration", RuleID: "testssl." + e.ID, Title: testsslTitle(e), Severity: sev, FilePath: hostLocation(firstNonEmpty(name, host), string(e.Port), ""),
			CWE: strings.Fields(strings.ReplaceAll(e.CWE, ",", " ")), CVE: firstMatch(cveRe, e.CVE), Confidence: "high",
			Description: joinText(fmt.Sprintf("testssl.sh check %s: %s", e.ID, e.Finding), labelled("CVE", e.CVE), labelled("Hint", e.Hint), labelled("Address", e.IP))}
		out = append(out, importRecord{F: f, SnippetKey: hashOf(e.ID), Raw: rawJSON(e)})
	}
	if b := bytes.TrimSpace(bytes.TrimPrefix(raw, utf8BOM)); len(b) > 0 && b[0] == '[' {
		items, err := jsonArray(raw, "")
		if err != nil {
			return nil, fmt.Errorf("testssl: invalid JSON: %w", err)
		}
		for i, it := range items {
			var e testsslEntry
			if err := json.Unmarshal(it, &e); err != nil {
				return out, fmt.Errorf("testssl: entry %d: %w", i+1, err)
			}
			add("", "", "", e)
		}
		return out, nil
	}
	var doc testsslPretty
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("testssl: invalid JSON: %w", err)
	}
	for _, t := range doc.ScanResult {
		var host, ip string
		var port looseString
		_ = json.Unmarshal(t["targetHost"], &host)
		_ = json.Unmarshal(t["ip"], &ip)
		_ = json.Unmarshal(t["port"], &port)
		for k, v := range t {
			if k == "targetHost" || k == "ip" || k == "port" || k == "rDNS" || k == "service" || len(v) == 0 || v[0] != '[' {
				continue
			}
			var entries []testsslEntry
			if json.Unmarshal(v, &entries) != nil {
				continue
			}
			for _, e := range entries {
				add(host, ip, string(port), e)
			}
		}
	}
	// Map iteration order is random: keep a stable order.
	slices.SortStableFunc(out, func(a, b importRecord) int {
		return strings.Compare(a.F.FilePath+"\x00"+a.F.RuleID, b.F.FilePath+"\x00"+b.F.RuleID)
	})
	return out, nil
}

func testsslTitle(e testsslEntry) string {
	f := strings.Join(strings.Fields(e.Finding), " ")
	if len(f) > 120 {
		f = f[:120] + "..."
	}
	if f == "" {
		return "testssl.sh: " + e.ID
	}
	return "testssl.sh " + e.ID + ": " + f
}
