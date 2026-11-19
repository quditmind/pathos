package scanners

import (
	"fmt"
	"strings"
)

// Tenable CSV exports: Nessus and Tenable Vulnerability Management
// (Tenable.io) scan CSV ("Plugin ID, CVE, CVSS, Risk, Host, Protocol, Port,
// Name, Synopsis, Description, Solution, See Also, Plugin Output", plus
// optional CVSS v3 and other columns) and Tenable Security Center
// vulnerability CSV ("Plugin, Plugin Name, Family, Severity, IP Address,
// Protocol, Port, ..."). Nessus writes one row per plugin, host, port and
// CVE; rows of the same plugin, host, port and protocol are merged into one
// finding that lists every CVE. The location is "host:port/protocol".
// Built from the published format; not yet verified against a real export.

func init() {
	registerImportFormat(ImportFormat{ID: "tenable-csv", Label: "Tenable / Nessus CSV export", Tool: "Tenable", Category: "other", Media: "csv", Order: 411,
		match: func(p *importProbe) bool { return p.kind == "csv" && tenableCSVHeader(p.header) },
		parse: parseTenableCSV, sanitize: sanitizeHTTPText})
}

// tenableCSVHeader reports whether a CSV header is a Tenable export.
func tenableCSVHeader(h []string) bool {
	return headerHas(h, "plugin_id", "name", "host", "port", "protocol") && (headerHas(h, "risk") || headerHas(h, "risk_factor") || headerHas(h, "severity")) ||
		headerHas(h, "plugin", "plugin_name", "ip_address", "port", "protocol", "severity")
}

func parseTenableCSV(raw []byte) ([]importRecord, error) {
	h, rows, err := csvTable(raw)
	if err != nil && len(rows) == 0 {
		return nil, fmt.Errorf("tenable-csv: %w", err)
	}
	if !tenableCSVHeader(h) {
		return nil, fmt.Errorf("tenable-csv: the header row is not a Tenable export (Plugin ID, Name, Host, Port, Protocol, Risk)")
	}
	type merged struct {
		rec  importRecord
		cves []string
		orig map[string]string
	}
	var order []string
	byKey := map[string]*merged{}
	for _, r := range rows {
		plugin := r.get("plugin_id", "plugin")
		host := r.get("host", "ip_address", "dns_name", "fqdn")
		name := r.get("name", "plugin_name")
		if plugin == "" || host == "" {
			return nil, fmt.Errorf("tenable-csv: row %d: missing plugin id or host", r.N)
		}
		port, proto := r.get("port"), r.get("protocol")
		key := strings.ToLower(plugin + "|" + host + "|" + port + "|" + proto)
		var cves []string
		for _, c := range strings.FieldsFunc(r.get("cve"), func(c rune) bool { return c == ',' || c == ' ' || c == ';' }) {
			if m := firstMatch(cveRe, c); m != "" {
				cves = append(cves, m)
			}
		}
		if m, ok := byKey[key]; ok {
			for _, c := range cves {
				if !tenableHas(m.cves, c) {
					m.cves = append(m.cves, c)
				}
			}
			continue
		}
		f := Finding{RuleID: plugin, Title: firstNonEmpty(name, "Tenable plugin "+plugin), FilePath: hostLocation(host, port, proto), CWE: []string{}}
		f.Severity = normSeverity(r.get("risk", "severity", "risk_factor"))
		if strings.EqualFold(r.get("risk", "severity", "risk_factor"), "none") {
			f.Severity = "info"
		}
		f.CVSS = cvssOf(r.get("cvss_v3.0_base_score", "cvss3_base_score", "cvss_v3_base_score", "cvssv3"))
		if f.CVSS == nil {
			f.CVSS = cvssOf(r.get("cvss", "cvss_v2.0_base_score", "cvss_base_score", "cvss_v2_base_score"))
		}
		switch v := r.get("cvss3_vector", "cvss_v3_vector", "cvss_v3.0_vector"); {
		case strings.HasPrefix(v, "CVSS:3"):
			f.CVSSVector = v
		case strings.HasPrefix(v, "AV:"):
			f.CVSSVector = "CVSS:3.0/" + v
		default:
			if v2 := strings.TrimPrefix(r.get("cvss_vector", "cvss_v2_vector", "cvss_v2.0_vector"), "CVSS2#"); strings.HasPrefix(v2, "AV:") {
				f.CVSSVector = v2
			}
		}
		for _, x := range strings.Split(r.get("xref", "cross_references"), ",") {
			if k, v, ok := strings.Cut(x, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "CWE") {
				f.CWE = append(f.CWE, strings.TrimSpace(v))
			}
		}
		output := r.get("plugin_output", "plugin_text")
		f.Description = joinText(r.get("synopsis"), r.get("description"), labelled("Solution", r.get("solution", "steps_to_remediate")),
			labelled("Plugin output", clipText(redactHTTP(output), 2000)), labelled("See also", r.get("see_also")))
		orig := make(map[string]string, len(r.Orig))
		for k, v := range r.Orig {
			if strings.EqualFold(k, "Plugin Output") || strings.EqualFold(k, "Plugin Text") {
				v = clipText(redactHTTP(v), maxEvidenceText)
			}
			orig[k] = v
		}
		byKey[key] = &merged{rec: importRecord{F: f, SnippetKey: hashOf(strings.ToLower(proto))}, cves: cves, orig: orig}
		order = append(order, key)
	}
	out := make([]importRecord, 0, len(order))
	for _, k := range order {
		m := byKey[k]
		if len(m.cves) > 0 {
			m.rec.F.CVE = m.cves[0]
			if len(m.cves) > 1 {
				m.rec.F.Description = joinText(m.rec.F.Description, labelled("CVEs", strings.Join(m.cves, ", ")))
			}
			m.orig["CVE"] = strings.Join(m.cves, ",")
		}
		m.rec.Raw = rawJSON(m.orig)
		out = append(out, m.rec)
	}
	return out, err
}

func tenableHas(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
