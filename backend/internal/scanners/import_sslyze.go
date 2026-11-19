package scanners

import (
	"encoding/json"
	"fmt"
	"strings"
)

// SSLyze JSON (`sslyze --json_out=FILE`, version 5 and later): findings are
// derived from each server's scan_result, since the JSON carries results,
// not verdicts: SSL 2.0/3.0 (high) and TLS 1.0/1.1 (medium) accepted,
// anonymous, NULL, export, RC4 or DES cipher suites, failed certificate
// path validation, SHA-1 signatures in the verified chain, Heartbleed, CCS
// injection, ROBOT, insecure renegotiation, TLS compression (CRIME) and a
// missing TLS_FALLBACK_SCSV. Servers SSLyze could not connect to are
// findings too (info), so a scan that did not happen is visible.

type sslyzeCipher struct {
	CipherSuite struct {
		Name        string `json:"name"`
		IsAnonymous bool   `json:"is_anonymous"`
		KeySize     int    `json:"key_size"`
	} `json:"cipher_suite"`
}

type sslyzeAttempt[T any] struct {
	Status      string `json:"status"`
	ErrorReason string `json:"error_reason"`
	Result      *T     `json:"result"`
}

type sslyzeSuites struct {
	TLSVersionUsed        string         `json:"tls_version_used"`
	IsTLSVersionSupported bool           `json:"is_tls_version_supported"`
	Accepted              []sslyzeCipher `json:"accepted_cipher_suites"`
}

type sslyzeServer struct {
	ServerLocation struct {
		Hostname  string `json:"hostname"`
		Port      int    `json:"port"`
		IPAddress string `json:"ip_address"`
	} `json:"server_location"`
	ConnectivityStatus     string `json:"connectivity_status"`
	ConnectivityErrorTrace string `json:"connectivity_error_trace"`
	ScanResult             *struct {
		CertificateInfo sslyzeAttempt[struct {
			Deployments []struct {
				PathValidation []struct {
					TrustStore struct {
						Name string `json:"name"`
					} `json:"trust_store"`
					ValidationError         string `json:"validation_error"`
					WasValidationSuccessful bool   `json:"was_validation_successful"`
				} `json:"path_validation_results"`
				LeafSubjectMatchesHostname *bool `json:"leaf_certificate_subject_matches_hostname"`
				VerifiedChainHasSHA1       *bool `json:"verified_chain_has_sha1_signature"`
				ReceivedChain              []struct {
					NotValidAfter string `json:"not_valid_after"`
					Subject       struct {
						RFC4514 string `json:"rfc4514_string"`
					} `json:"subject"`
				} `json:"received_certificate_chain"`
			} `json:"certificate_deployments"`
		}] `json:"certificate_info"`
		SSL20 sslyzeAttempt[sslyzeSuites] `json:"ssl_2_0_cipher_suites"`
		SSL30 sslyzeAttempt[sslyzeSuites] `json:"ssl_3_0_cipher_suites"`
		TLS10 sslyzeAttempt[sslyzeSuites] `json:"tls_1_0_cipher_suites"`
		TLS11 sslyzeAttempt[sslyzeSuites] `json:"tls_1_1_cipher_suites"`
		TLS12 sslyzeAttempt[sslyzeSuites] `json:"tls_1_2_cipher_suites"`
		TLS13 sslyzeAttempt[sslyzeSuites] `json:"tls_1_3_cipher_suites"`
		Compr sslyzeAttempt[struct {
			SupportsCompression bool `json:"supports_compression"`
		}] `json:"tls_compression"`
		CCS sslyzeAttempt[struct {
			Vulnerable bool `json:"is_vulnerable_to_ccs_injection"`
		}] `json:"openssl_ccs_injection"`
		SCSV sslyzeAttempt[struct {
			Supports bool `json:"supports_fallback_scsv"`
		}] `json:"tls_fallback_scsv"`
		Heart sslyzeAttempt[struct {
			Vulnerable bool `json:"is_vulnerable_to_heartbleed"`
		}] `json:"heartbleed"`
		Robot sslyzeAttempt[struct {
			Result string `json:"robot_result"`
		}] `json:"robot"`
		Reneg sslyzeAttempt[struct {
			SupportsSecure bool `json:"supports_secure_renegotiation"`
			ClientDoS      bool `json:"is_vulnerable_to_client_renegotiation_dos"`
		}] `json:"session_renegotiation"`
	} `json:"scan_result"`
}

// sslyzeRecord is the record kept as a finding's original output.
type sslyzeRecord struct {
	Host    string   `json:"host"`
	Port    int      `json:"port"`
	IP      string   `json:"ip_address,omitempty"`
	Check   string   `json:"check"`
	Details []string `json:"details,omitempty"`
}

func init() {
	registerImportFormat(ImportFormat{ID: "sslyze", Label: "SSLyze JSON (--json_out)", Tool: "SSLyze", Category: "other", Media: "json", Order: 332,
		match: func(p *importProbe) bool {
			return p.kind == "object" && p.has("server_scan_results") && p.hasAny("sslyze_version", "sslyze_url")
		},
		parse: parseSSLyze})
}

func parseSSLyze(raw []byte) ([]importRecord, error) {
	var doc struct {
		Servers []sslyzeServer `json:"server_scan_results"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("sslyze: invalid JSON: %w", err)
	}
	var out []importRecord
	for _, s := range doc.Servers {
		host := firstNonEmpty(s.ServerLocation.Hostname, s.ServerLocation.IPAddress)
		loc := hostLocation(host, fmt.Sprint(s.ServerLocation.Port), "")
		add := func(check, title, sev, cwe, cve, desc string, details []string) {
			f := Finding{Category: "other", RuleID: "sslyze." + check, Title: title, Severity: sev, FilePath: loc, CVE: cve, Confidence: "high",
				Description: joinText(desc, labelled("Details", clipText(strings.Join(details, "\n"), 2000)))}
			if cwe != "" {
				f.CWE = []string{cwe}
			}
			rec := sslyzeRecord{Host: host, Port: s.ServerLocation.Port, IP: s.ServerLocation.IPAddress, Check: check, Details: details}
			out = append(out, importRecord{F: f, SnippetKey: hashOf(check), Raw: rawJSON(rec)})
		}
		r := s.ScanResult
		if r == nil || (s.ConnectivityStatus != "" && s.ConnectivityStatus != "COMPLETED") {
			add("connectivity", "SSLyze could not scan "+loc, "info", "", "", "The server was not scanned (connectivity status "+
				firstNonEmpty(s.ConnectivityStatus, "unknown")+").", []string{clipText(s.ConnectivityErrorTrace, 1000)})
			continue
		}
		for _, p := range []struct {
			name, sev string
			a         sslyzeAttempt[sslyzeSuites]
		}{{"SSL 2.0", "high", r.SSL20}, {"SSL 3.0", "high", r.SSL30}, {"TLS 1.0", "medium", r.TLS10}, {"TLS 1.1", "medium", r.TLS11}} {
			if p.a.Result != nil && len(p.a.Result.Accepted) > 0 {
				id := strings.ToLower(strings.ReplaceAll(p.name, " ", "_"))
				add(id+"_supported", "Deprecated protocol "+p.name+" accepted", p.sev, "CWE-327", "",
					fmt.Sprintf("The server accepts %d cipher suites over %s, a deprecated protocol (RFC 8996).", len(p.a.Result.Accepted), p.name), sslyzeNames(p.a.Result.Accepted))
			}
		}
		var anon, weak []string
		for _, a := range []sslyzeAttempt[sslyzeSuites]{r.SSL20, r.SSL30, r.TLS10, r.TLS11, r.TLS12, r.TLS13} {
			if a.Result == nil {
				continue
			}
			for _, c := range a.Result.Accepted {
				n := c.CipherSuite.Name
				entry := a.Result.TLSVersionUsed + " " + n
				switch {
				case c.CipherSuite.IsAnonymous || strings.Contains(n, "_anon_"):
					anon = append(anon, entry)
				case strings.Contains(n, "NULL") || strings.Contains(n, "EXPORT") || strings.Contains(n, "RC4") || strings.Contains(n, "_DES_") ||
					strings.Contains(n, "3DES") || (c.CipherSuite.KeySize > 0 && c.CipherSuite.KeySize < 128):
					weak = append(weak, entry)
				}
			}
		}
		if len(anon) > 0 {
			add("anonymous_cipher_suites", "Anonymous TLS cipher suites accepted", "high", "CWE-327", "",
				"Anonymous key exchange does not authenticate the server: an attacker in the path can intercept the connection.", anon)
		}
		if len(weak) > 0 {
			add("weak_cipher_suites", "Weak TLS cipher suites accepted", "medium", "CWE-327", "",
				"The server accepts NULL, export-grade, RC4, DES/3DES or short-key cipher suites.", weak)
		}
		if ci := r.CertificateInfo.Result; ci != nil {
			for i, d := range ci.Deployments {
				var failed []string
				for _, v := range d.PathValidation {
					if !v.WasValidationSuccessful {
						failed = append(failed, v.TrustStore.Name+": "+v.ValidationError)
					}
				}
				subject := ""
				if len(d.ReceivedChain) > 0 {
					subject = d.ReceivedChain[0].Subject.RFC4514
				}
				suffix := ""
				if i > 0 {
					suffix = fmt.Sprintf("_%d", i+1)
				}
				if len(failed) > 0 {
					add("certificate_untrusted"+suffix, "Certificate not trusted ("+firstNonEmpty(subject, "leaf")+")", "high", "CWE-295", "",
						fmt.Sprintf("Certificate path validation failed against %d of %d trust stores.", len(failed), len(d.PathValidation)), failed)
				}
				if d.LeafSubjectMatchesHostname != nil && !*d.LeafSubjectMatchesHostname {
					add("certificate_hostname_mismatch"+suffix, "Certificate does not match the host name", "medium", "CWE-297", "",
						"The leaf certificate's subject does not match "+host+".", []string{subject})
				}
				if d.VerifiedChainHasSHA1 != nil && *d.VerifiedChainHasSHA1 {
					add("certificate_sha1"+suffix, "SHA-1 signature in the certificate chain", "medium", "CWE-328", "", "The verified chain contains a SHA-1 signature.", nil)
				}
			}
		}
		if v := r.Heart.Result; v != nil && v.Vulnerable {
			add("heartbleed", "Heartbleed (CVE-2014-0160)", "critical", "CWE-125", "CVE-2014-0160", "The server is vulnerable to the OpenSSL Heartbleed bug.", nil)
		}
		if v := r.CCS.Result; v != nil && v.Vulnerable {
			add("openssl_ccs_injection", "OpenSSL CCS injection (CVE-2014-0224)", "high", "CWE-326", "CVE-2014-0224", "The server is vulnerable to OpenSSL CCS injection.", nil)
		}
		if v := r.Robot.Result; v != nil && strings.HasPrefix(v.Result, "VULNERABLE") {
			add("robot", "ROBOT attack ("+v.Result+")", "high", "CWE-203", "CVE-2017-13099", "The server's RSA key exchange leaks a padding oracle (ROBOT).", []string{v.Result})
		}
		if v := r.Reneg.Result; v != nil {
			if !v.SupportsSecure {
				add("insecure_renegotiation", "Secure renegotiation not supported", "medium", "CWE-310", "CVE-2009-3555", "The server does not support RFC 5746 secure renegotiation.", nil)
			}
			if v.ClientDoS {
				add("client_renegotiation_dos", "Client-initiated renegotiation DoS", "medium", "CWE-400", "", "The server accepts many client-initiated renegotiations.", nil)
			}
		}
		if v := r.Compr.Result; v != nil && v.SupportsCompression {
			add("tls_compression", "TLS compression enabled (CRIME)", "medium", "CWE-310", "CVE-2012-4929", "TLS compression allows the CRIME attack.", nil)
		}
		if v := r.SCSV.Result; v != nil && !v.Supports {
			add("no_fallback_scsv", "TLS_FALLBACK_SCSV not supported", "low", "CWE-757", "", "The server does not support TLS_FALLBACK_SCSV downgrade protection.", nil)
		}
	}
	return out, nil
}

func sslyzeNames(cs []sslyzeCipher) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.CipherSuite.Name)
	}
	return out
}
