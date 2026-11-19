package scanners

import (
	"fmt"
	"slices"
	"strings"
)

// sslscan XML (`sslscan --xml=FILE`, version 2): one <ssltest> per target.
// Findings: SSLv2/SSLv3 (high) and TLS 1.0/1.1 (medium) enabled; accepted
// cipher suites sslscan rates null or anonymous (high), weak (medium) or
// medium (low), one finding per cipher suite with its protocols;
// Heartbleed; insecure renegotiation; TLS compression; no
// TLS_FALLBACK_SCSV; and certificate problems (self-signed, expired, not
// yet valid, RSA keys under 2048 bits, MD5 or SHA-1 signatures).

type sslscanTest struct {
	Host      string `xml:"host,attr"`
	SNIName   string `xml:"sniname,attr"`
	Port      string `xml:"port,attr"`
	Protocols []struct {
		Type    string `xml:"type,attr"`
		Version string `xml:"version,attr"`
		Enabled string `xml:"enabled,attr"`
	} `xml:"protocol"`
	Fallback *struct {
		Supported string `xml:"supported,attr"`
	} `xml:"fallback"`
	Renegotiation *struct {
		Supported string `xml:"supported,attr"`
		Secure    string `xml:"secure,attr"`
	} `xml:"renegotiation"`
	Compression *struct {
		Supported string `xml:"supported,attr"`
	} `xml:"compression"`
	Heartbleed []struct {
		SSLVersion string `xml:"sslversion,attr"`
		Vulnerable string `xml:"vulnerable,attr"`
	} `xml:"heartbleed"`
	Ciphers []struct {
		Status     string `xml:"status,attr"`
		SSLVersion string `xml:"sslversion,attr"`
		Bits       string `xml:"bits,attr"`
		Cipher     string `xml:"cipher,attr"`
		ID         string `xml:"id,attr"`
		Strength   string `xml:"strength,attr"`
	} `xml:"cipher"`
	Certificates []struct {
		SignatureAlgorithm string `xml:"signature-algorithm"`
		PK                 struct {
			Type string `xml:"type,attr"`
			Bits string `xml:"bits,attr"`
		} `xml:"pk"`
		Subject     string `xml:"subject"`
		Issuer      string `xml:"issuer"`
		SelfSigned  string `xml:"self-signed"`
		NotAfter    string `xml:"not-valid-after"`
		Expired     string `xml:"expired"`
		NotYetValid string `xml:"not-yet-valid"`
	} `xml:"certificates>certificate"`
}

// sslscanRecord is the record kept as a finding's original output.
type sslscanRecord struct {
	Host    string   `json:"host"`
	Port    string   `json:"port"`
	SNIName string   `json:"sniname,omitempty"`
	Check   string   `json:"check"`
	Details []string `json:"details,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "sslscan", Label: "sslscan XML (--xml)", Tool: "sslscan", Category: "other", Media: "xml", Order: 333,
		match: func(p *importProbe) bool {
			if p.kind != "xml" || p.root != "document" {
				return false
			}
			_, web := p.rootAttrs["web"]
			return p.rootAttrs["title"] == "SSLScan Results" || (web && strings.Contains(p.rootAttrs["web"], "sslscan")) || p.rootAttrs["#child"] == "ssltest"
		},
		parse: parseSSLScan})
}

func parseSSLScan(raw []byte) ([]importRecord, error) {
	var out []importRecord
	err := eachXMLElement(raw, "document", "ssltest", func(t *sslscanTest) error {
		loc := hostLocation(t.Host, t.Port, "")
		add := func(check, title, sev, cwe, cve, desc string, details []string) {
			f := Finding{Category: "other", RuleID: "sslscan." + check, Title: title, Severity: sev, FilePath: loc, CVE: cve, Confidence: "high",
				Description: joinText(desc, labelled("Details", strings.Join(details, "\n")))}
			if cwe != "" {
				f.CWE = []string{cwe}
			}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(check), Raw: rawJSON(sslscanRecord{Host: t.Host, Port: t.Port, SNIName: t.SNIName, Check: check, Details: details})})
		}
		for _, p := range t.Protocols {
			if p.Enabled != "1" {
				continue
			}
			name := strings.ToUpper(p.Type) + "v" + p.Version
			sev := ""
			switch {
			case p.Type == "ssl":
				sev = "high"
			case p.Type == "tls" && (p.Version == "1.0" || p.Version == "1.1"):
				sev = "medium"
			}
			if sev != "" {
				add("protocol."+strings.ToLower(name), "Deprecated protocol "+name+" enabled", sev, "CWE-327", "", "The server accepts "+name+", a deprecated protocol (RFC 8996).", nil)
			}
		}
		type weakCipher struct {
			sev, strength, bits string
			protos              []string
		}
		weak := map[string]*weakCipher{}
		var order []string
		for _, c := range t.Ciphers {
			sev := map[string]string{"null": "high", "anonymous": "high", "weak": "medium", "medium": "low"}[strings.ToLower(c.Strength)]
			if sev == "" {
				continue
			}
			w := weak[c.Cipher]
			if w == nil {
				w = &weakCipher{sev: sev, strength: c.Strength, bits: c.Bits}
				weak[c.Cipher] = w
				order = append(order, c.Cipher)
			}
			if !slices.Contains(w.protos, c.SSLVersion) {
				w.protos = append(w.protos, c.SSLVersion)
			}
		}
		for _, name := range order {
			w := weak[name]
			add("cipher."+name, fmt.Sprintf("Cipher suite %s accepted (%s)", name, w.strength), w.sev, "CWE-327", "",
				fmt.Sprintf("sslscan rates the accepted cipher suite %s (%s bits) as %s.", name, w.bits, w.strength), []string{"Protocols: " + strings.Join(w.protos, ", ")})
		}
		var hb []string
		for _, h := range t.Heartbleed {
			if h.Vulnerable == "1" {
				hb = append(hb, h.SSLVersion)
			}
		}
		if len(hb) > 0 {
			add("heartbleed", "Heartbleed (CVE-2014-0160)", "critical", "CWE-125", "CVE-2014-0160", "The server is vulnerable to Heartbleed.", hb)
		}
		if r := t.Renegotiation; r != nil && r.Supported == "1" && r.Secure != "1" {
			add("insecure-renegotiation", "Insecure renegotiation supported", "medium", "CWE-310", "CVE-2009-3555", "The server supports renegotiation without RFC 5746 protection.", nil)
		}
		if c := t.Compression; c != nil && c.Supported == "1" {
			add("compression", "TLS compression enabled (CRIME)", "medium", "CWE-310", "CVE-2012-4929", "TLS compression allows the CRIME attack.", nil)
		}
		if f := t.Fallback; f != nil && f.Supported == "0" {
			add("no-fallback-scsv", "TLS_FALLBACK_SCSV not supported", "low", "CWE-757", "", "The server does not support TLS_FALLBACK_SCSV downgrade protection.", nil)
		}
		for i, c := range t.Certificates {
			sfx := ""
			if i > 0 {
				sfx = fmt.Sprintf(".%d", i+1)
			}
			subj := strings.TrimSpace(c.Subject)
			if strings.TrimSpace(c.SelfSigned) == "true" {
				add("certificate.self-signed"+sfx, "Self-signed certificate ("+subj+")", "medium", "CWE-295", "", "The certificate is self-signed; clients cannot verify the server.", []string{"Issuer: " + c.Issuer})
			}
			if strings.TrimSpace(c.Expired) == "true" {
				add("certificate.expired"+sfx, "Expired certificate ("+subj+")", "high", "CWE-298", "", "The certificate expired on "+c.NotAfter+".", nil)
			}
			if strings.TrimSpace(c.NotYetValid) == "true" {
				add("certificate.not-yet-valid"+sfx, "Certificate not yet valid ("+subj+")", "medium", "CWE-298", "", "The certificate is not valid yet.", nil)
			}
			if strings.EqualFold(c.PK.Type, "RSA") && atoiLoose(c.PK.Bits) > 0 && atoiLoose(c.PK.Bits) < 2048 {
				add("certificate.weak-key"+sfx, "Weak RSA key ("+c.PK.Bits+" bits)", "medium", "CWE-326", "", "The certificate's RSA key is shorter than 2048 bits.", nil)
			}
			if sa := strings.ToLower(c.SignatureAlgorithm); strings.Contains(sa, "md5") || strings.Contains(sa, "sha1") {
				add("certificate.weak-signature"+sfx, "Weak certificate signature ("+c.SignatureAlgorithm+")", "medium", "CWE-328", "", "The certificate is signed with "+c.SignatureAlgorithm+".", nil)
			}
		}
		return nil
	})
	if err != nil {
		return out, fmt.Errorf("sslscan: %w", err)
	}
	return out, nil
}
