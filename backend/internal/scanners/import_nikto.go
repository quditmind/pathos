package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Nikto reports: JSON (`-Format json`: an array of hosts, older versions a
// single host object) and XML (`-Format xml`: <niktoscans>/<niktoscan>/
// <scandetails>/<item>). Nikto reports no severity: every item is
// imported as low. One finding per item; identity is the Nikto item id,
// URL, method and message (one id covers several checks, e.g. each missing
// security header).

type niktoJSONHost struct {
	Host            string `json:"host"`
	IP              string `json:"ip"`
	Port            string `json:"port"`
	Banner          string `json:"banner"`
	Vulnerabilities []struct {
		ID         looseString `json:"id"`
		OSVDB      looseString `json:"OSVDB"`
		Method     string      `json:"method"`
		URL        string      `json:"url"`
		Msg        string      `json:"msg"`
		References string      `json:"references"`
	} `json:"vulnerabilities"`
}

type niktoXMLItem struct {
	ID          string `xml:"id,attr"`
	OSVDBID     string `xml:"osvdbid,attr"`
	Method      string `xml:"method,attr"`
	Description string `xml:"description"`
	URI         string `xml:"uri"`
	NameLink    string `xml:"namelink"`
	IPLink      string `xml:"iplink"`
	References  string `xml:"references"`
}

type niktoXMLDetails struct {
	TargetIP       string         `xml:"targetip,attr"`
	TargetHostname string         `xml:"targethostname,attr"`
	TargetPort     string         `xml:"targetport,attr"`
	TargetBanner   string         `xml:"targetbanner,attr"`
	SiteName       string         `xml:"sitename,attr"`
	Items          []niktoXMLItem `xml:"item"`
}

// niktoRecord is the record kept as a finding's original output.
type niktoRecord struct {
	Host       string `json:"host"`
	IP         string `json:"ip,omitempty"`
	Port       string `json:"port,omitempty"`
	Banner     string `json:"banner,omitempty"`
	ID         string `json:"id"`
	OSVDB      string `json:"osvdb,omitempty"`
	Method     string `json:"method,omitempty"`
	URL        string `json:"url"`
	Msg        string `json:"msg"`
	References string `json:"references,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "nikto", Label: "Nikto report (JSON or XML)", Tool: "Nikto", Category: "dast", Media: "json", Order: 300,
		match: func(p *importProbe) bool {
			switch p.kind {
			case "object", "array":
				return p.has("host", "port", "vulnerabilities") && p.hasAny("ip", "banner")
			case "xml":
				return p.root == "niktoscans" || p.root == "niktoscan"
			}
			return false
		},
		parse: parseNikto,
	})
}

func parseNikto(raw []byte) ([]importRecord, error) {
	if !g1IsJSON(raw) {
		return parseNiktoXML(raw)
	}
	var hosts []niktoJSONHost
	items, err := jsonArray(raw, "")
	if err != nil || items == nil {
		// A single host object (Nikto 2.1).
		var h niktoJSONHost
		if err := json.Unmarshal(raw, &h); err != nil {
			return nil, fmt.Errorf("nikto: invalid JSON: %w", err)
		}
		hosts = []niktoJSONHost{h}
	} else {
		for i, it := range items {
			var h niktoJSONHost
			if err := json.Unmarshal(it, &h); err != nil {
				return nil, fmt.Errorf("nikto: host %d: %w", i+1, err)
			}
			hosts = append(hosts, h)
		}
	}
	var out []importRecord
	for _, h := range hosts {
		base := niktoBase(firstNonEmpty(h.Host, h.IP), h.Port)
		for _, v := range h.Vulnerabilities {
			rec := niktoRecord{Host: h.Host, IP: h.IP, Port: h.Port, Banner: h.Banner, ID: string(v.ID), OSVDB: string(v.OSVDB),
				Method: v.Method, URL: g1Resolve(base, v.URL), Msg: strings.TrimSpace(v.Msg), References: v.References}
			out = append(out, niktoFinding(rec))
		}
	}
	return out, nil
}

func parseNiktoXML(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := eachXMLElement(raw, "", "scandetails", func(d *niktoXMLDetails) error {
		base := firstNonEmpty(d.SiteName, niktoBase(firstNonEmpty(d.TargetHostname, d.TargetIP), d.TargetPort))
		for _, it := range d.Items {
			uri := strings.TrimSpace(it.URI)
			msg := strings.TrimSpace(it.Description)
			// The XML description repeats the URI: "/admin/: This might be interesting."
			msg = strings.TrimSpace(strings.TrimPrefix(msg, uri+":"))
			rec := niktoRecord{Host: d.TargetHostname, IP: d.TargetIP, Port: d.TargetPort, Banner: d.TargetBanner, ID: it.ID, OSVDB: it.OSVDBID,
				Method: it.Method, URL: firstNonEmpty(it.NameLink, g1Resolve(base, uri)), Msg: msg, References: strings.TrimSpace(it.References)}
			out = append(out, niktoFinding(rec))
		}
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("nikto: %w", err)
	}
	return out, nil
}

// niktoBase is the site URL of a Nikto host (Nikto's JSON does not say
// whether TLS was used; ports 443 and 8443 are taken as HTTPS).
func niktoBase(host, port string) string {
	if host == "" {
		return ""
	}
	scheme := "http"
	if port == "443" || port == "8443" {
		scheme = "https"
	}
	if port == "" || port == "80" && scheme == "http" || port == "443" && scheme == "https" {
		return scheme + "://" + host + "/"
	}
	return scheme + "://" + host + ":" + port + "/"
}

func niktoFinding(rec niktoRecord) importRecord {
	rec.URL = redactHTTP(rec.URL)
	title := rec.Msg
	if title == "" {
		title = "Nikto item " + rec.ID
	}
	f := Finding{Category: "dast", RuleID: firstNonEmpty(rec.ID, title), Title: clipText(title, 250), Severity: "low",
		FilePath: locationOf("", rec.URL)}
	f.Description = joinText(rec.Msg, whereText(rec.Method, rec.URL, ""), labelled("References", rec.References),
		"Nikto reports no severity; the finding is imported as low.")
	return importRecord{F: f, SnippetKey: hashOf(strings.ToUpper(rec.Method) + "|" + rec.Msg), Raw: rawJSON(rec)}
}
