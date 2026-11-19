package scanners

import (
	"fmt"
	"slices"
	"strings"
)

// Nmap XML (`nmap -oX`): every open port is an info finding (the service
// and the output of non-vulnerability scripts in its description); NSE
// vulnerability results become findings of their own:
//   - scripts using the vulns library (http-vuln-*, ssl-*, smb-vuln-*, the
//     "vuln" category): a table with a "state" of VULNERABLE or LIKELY
//     VULNERABLE (NOT VULNERABLE results are not findings);
//   - vulners: one finding per advisory with its CVSS score;
//   - ssl-enum-ciphers: deprecated protocols (SSLv3, TLS 1.0, 1.1) and a
//     least cipher strength below A.
// The location is host:port/protocol.

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type nmapTable struct {
	Key    string      `xml:"key,attr"`
	Elems  []nmapElem  `xml:"elem"`
	Tables []nmapTable `xml:"table"`
}

func (t nmapTable) elem(key string) string {
	for _, e := range t.Elems {
		if e.Key == key {
			return strings.TrimSpace(e.Value)
		}
	}
	return ""
}

func (t nmapTable) table(key string) (nmapTable, bool) {
	for _, s := range t.Tables {
		if s.Key == key {
			return s, true
		}
	}
	return nmapTable{}, false
}

// values returns the unkeyed elements of t.
func (t nmapTable) values() []string {
	var out []string
	for _, e := range t.Elems {
		if e.Key == "" && strings.TrimSpace(e.Value) != "" {
			out = append(out, strings.TrimSpace(e.Value))
		}
	}
	return out
}

type nmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Elems  []nmapElem  `xml:"elem"`
	Tables []nmapTable `xml:"table"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   string `xml:"portid,attr"`
	State    struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"state"`
	Service struct {
		Name      string   `xml:"name,attr"`
		Product   string   `xml:"product,attr"`
		Version   string   `xml:"version,attr"`
		ExtraInfo string   `xml:"extrainfo,attr"`
		Tunnel    string   `xml:"tunnel,attr"`
		CPE       []string `xml:"cpe"`
	} `xml:"service"`
	Scripts []nmapScript `xml:"script"`
}

type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports       []nmapPort   `xml:"ports>port"`
	HostScripts []nmapScript `xml:"hostscript>script"`
}

// nmapRecord is the record kept as a finding's original output.
type nmapRecord struct {
	Host      string   `json:"host"`
	Address   string   `json:"address,omitempty"`
	Port      string   `json:"port,omitempty"`
	Protocol  string   `json:"protocol,omitempty"`
	State     string   `json:"state,omitempty"`
	Service   string   `json:"service,omitempty"`
	Product   string   `json:"product,omitempty"`
	Version   string   `json:"version,omitempty"`
	CPE       []string `json:"cpe,omitempty"`
	Script    string   `json:"script,omitempty"`
	Output    string   `json:"output,omitempty"`
	VulnKey   string   `json:"vuln_key,omitempty"`
	VulnState string   `json:"vuln_state,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "nmap", Label: "Nmap XML (-oX)", Tool: "Nmap", Category: "other", Media: "xml", Order: 330,
		match: func(p *importProbe) bool { return p.kind == "xml" && p.root == "nmaprun" },
		parse: parseNmapXML})
}

func parseNmapXML(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := eachXMLElement(raw, "nmaprun", "host", func(h *nmapHost) error {
		if len(out) >= MaxFindingsPerReport {
			return nil
		}
		addr, name := "", ""
		for _, a := range h.Addresses {
			if a.AddrType != "mac" && addr == "" {
				addr = a.Addr
			}
		}
		for _, n := range h.Hostnames {
			if name == "" || n.Type == "user" {
				name = n.Name
			}
		}
		host := firstNonEmpty(name, addr)
		if host == "" {
			return nil
		}
		for _, p := range h.Ports {
			if p.State.State != "open" && p.State.State != "open|filtered" {
				continue // closed and filtered ports are not findings
			}
			out = append(out, nmapPortRecords(host, addr, p)...)
		}
		for _, s := range h.HostScripts {
			out = append(out, nmapScriptRecords(host, addr, nmapPort{}, s)...)
		}
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("nmap: %w", err)
	}
	return out, nil
}

func nmapPortRecords(host, addr string, p nmapPort) []importRecord {
	svc := strings.TrimSpace(strings.Join([]string{p.Service.Name, p.Service.Product, p.Service.Version, p.Service.ExtraInfo}, " "))
	svc = strings.Join(strings.Fields(svc), " ")
	loc := hostLocation(host, p.PortID, p.Protocol)
	title := fmt.Sprintf("Open port %s/%s", p.PortID, firstNonEmpty(p.Protocol, "tcp"))
	if svc != "" {
		title += " (" + svc + ")"
	}
	var other []string
	for _, s := range p.Scripts {
		if s.ID != "vulners" && !nmapIsVulnScript(s) {
			other = append(other, s.ID+": "+clipText(strings.TrimSpace(s.Output), 1000))
		}
	}
	desc := joinText(fmt.Sprintf("Nmap found %s open on %s (reason: %s).", firstNonEmpty(p.Protocol, "tcp")+" port "+p.PortID, host, p.State.Reason),
		labelled("Service", svc), labelled("TLS", p.Service.Tunnel), labelled("CPE", strings.Join(p.Service.CPE, ", ")), strings.Join(other, "\n"))
	f := Finding{Category: "other", RuleID: "nmap-open-port", Title: title, Severity: "info", FilePath: loc, Confidence: "high", Description: desc}
	rec := nmapRecord{Host: host, Address: addr, Port: p.PortID, Protocol: p.Protocol, State: p.State.State, Service: p.Service.Name,
		Product: p.Service.Product, Version: p.Service.Version, CPE: p.Service.CPE}
	out := []importRecord{{F: f, SnippetKey: hashOf("port"), Raw: rawJSON(rec)}}
	for _, s := range p.Scripts {
		out = append(out, nmapScriptRecords(host, addr, p, s)...)
	}
	return out
}

// nmapIsVulnScript reports whether a script reports vulns-library results.
func nmapIsVulnScript(s nmapScript) bool {
	if s.ID == "ssl-enum-ciphers" {
		return true
	}
	for _, t := range s.Tables {
		if t.elem("state") != "" && t.elem("title") != "" {
			return true
		}
	}
	return false
}

func nmapScriptRecords(host, addr string, p nmapPort, s nmapScript) []importRecord {
	loc := hostLocation(host, p.PortID, p.Protocol)
	base := nmapRecord{Host: host, Address: addr, Port: p.PortID, Protocol: p.Protocol, Service: p.Service.Name, Product: p.Service.Product,
		Version: p.Service.Version, Script: s.ID}
	var out []importRecord
	switch {
	case s.ID == "vulners":
		// <table key="cpe:..."><table><elem key="id">CVE-...</elem><elem key="cvss">9.8</elem>...
		for _, cpe := range s.Tables {
			for _, v := range cpe.Tables {
				id := v.elem("id")
				if id == "" {
					continue
				}
				f := Finding{Category: "other", RuleID: id, Title: fmt.Sprintf("%s in %s", id, firstNonEmpty(cpe.Key, p.Service.Product)), FilePath: loc,
					CVSS: cvssOf(v.elem("cvss")), CVE: firstMatch(cveRe, id), Confidence: "medium",
					Description: joinText(fmt.Sprintf("The vulners script matched %s (%s) to advisory %s by version.", firstNonEmpty(cpe.Key, "the service"), p.Service.Product, id),
						labelled("Type", v.elem("type")), labelled("Exploit available", v.elem("is_exploit")), labelled("CVSS", v.elem("cvss")))}
				if f.CVSS != nil {
					f.Severity = FromScore(*f.CVSS)
				}
				rec := base
				rec.VulnKey, rec.Output = id, cpe.Key
				out = append(out, importRecord{F: f, SnippetKey: hashOf("vulners|" + cpe.Key + "|" + id), Raw: rawJSON(rec)})
			}
		}
	case s.ID == "ssl-enum-ciphers":
		var old []string
		for _, t := range s.Tables {
			if slices.Contains([]string{"SSLv3", "TLSv1.0", "TLSv1.1"}, t.Key) {
				old = append(old, t.Key)
			}
		}
		rec := base
		rec.Output = clipText(s.Output, maxEvidenceText)
		if len(old) > 0 {
			sev := "medium"
			if slices.Contains(old, "SSLv3") {
				sev = "high"
			}
			f := Finding{Category: "other", RuleID: "ssl-enum-ciphers/deprecated-protocol", Title: "Deprecated TLS protocols enabled: " + strings.Join(old, ", "),
				Severity: sev, FilePath: loc, CWE: []string{"CWE-327"}, Confidence: "high",
				Description: fmt.Sprintf("The server accepts %s, which are deprecated (RFC 8996).", strings.Join(old, ", "))}
			out = append(out, importRecord{F: f, SnippetKey: hashOf("ssl-protocols"), Raw: rawJSON(rec)})
		}
		least := ""
		for _, e := range s.Elems {
			if e.Key == "least strength" {
				least = strings.TrimSpace(e.Value)
			}
		}
		sev := map[string]string{"B": "low", "C": "low", "D": "medium", "E": "medium", "F": "high"}[least]
		if sev != "" {
			var warn []string
			for _, t := range s.Tables {
				if w, ok := t.table("warnings"); ok {
					for _, v := range w.values() {
						if !slices.Contains(warn, v) {
							warn = append(warn, v)
						}
					}
				}
			}
			f := Finding{Category: "other", RuleID: "ssl-enum-ciphers/weak-cipher", Title: "Weak TLS cipher suites (least strength " + least + ")",
				Severity: sev, FilePath: loc, CWE: []string{"CWE-327"}, Confidence: "high",
				Description: joinText("ssl-enum-ciphers graded the weakest accepted cipher suite "+least+".", labelled("Warnings", strings.Join(warn, "; ")))}
			out = append(out, importRecord{F: f, SnippetKey: hashOf("ssl-ciphers"), Raw: rawJSON(rec)})
		}
	default:
		for _, t := range s.Tables {
			state := t.elem("state")
			if state == "" || t.elem("title") == "" {
				continue
			}
			up := strings.ToUpper(state)
			if !strings.Contains(up, "VULNERABLE") || strings.Contains(up, "NOT VULNERABLE") {
				continue
			}
			ids := []string{}
			if it, ok := t.table("ids"); ok {
				ids = it.values()
			}
			cve := firstMatch(cveRe, append(append([]string{t.Key}, ids...), t.elem("title"))...)
			f := Finding{Category: "other", RuleID: s.ID, Title: t.elem("title"), FilePath: loc, CVE: cve, Severity: "high", Confidence: "medium"}
			if strings.Contains(up, "LIKELY") {
				f.Severity, f.Confidence = "medium", "low"
			}
			if sc, ok := t.table("scores"); ok {
				if v := cvssOf(firstNonEmpty(sc.elem("CVSSv3"), sc.elem("CVSS"), sc.elem("CVSSv2"))); v != nil {
					f.CVSS, f.Severity = v, FromScore(*v)
				}
			}
			var descr, refs []string
			if d, ok := t.table("description"); ok {
				descr = d.values()
			}
			if r, ok := t.table("refs"); ok {
				refs = r.values()
			}
			f.Description = joinText(strings.Join(descr, "\n"), "Nmap script "+s.ID+": "+state, labelled("IDs", strings.Join(ids, ", ")),
				labelled("Disclosure date", t.elem("disclosure")), labelled("References", strings.Join(refs, "\n")))
			rec := base
			rec.VulnKey, rec.VulnState, rec.Output = t.Key, state, clipText(s.Output, maxEvidenceText)
			out = append(out, importRecord{F: f, SnippetKey: hashOf(s.ID + "|" + t.Key), Raw: rawJSON(rec)})
		}
	}
	return out
}
