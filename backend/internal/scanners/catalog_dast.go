package scanners

import "slices"

// The worker-dast family image (workers/dast): tools that test authorized
// web application (url) and API (api) scan targets. Every one contacts the
// target (network: target, so the target needs an authorization
// statement); the intrusive ones (attacks, fuzzing, injection probes) also
// need the target's intrusive testing flag. They run through the image's
// dast-run helper, which confines them to the target host, the egress proxy
// and the target's rate limit. They never run in repository scan profiles.
//
// sqlmap and Nikto are in the image only when it is built with WITH_SQLMAP
// or WITH_NIKTO (licence terms, see workers/dast/Dockerfile); their catalog
// entries are "restricted" so repository profiles never offer them, and
// they run only where an operator built them in.

// dastTool is a catalog entry of the worker-dast image.
func dastTool(key, name, cat, lic, decision, homepage, notes string, attacks bool) Scanner {
	opts := []func(*Scanner){target, format("json"), home(homepage), note(notes)}
	if attacks {
		opts = append(opts, intrusive)
	} else {
		opts = append(opts, contacts("target"))
	}
	return s(key, name, cat, lic, decision, "dast", opts...)
}

// dastCatalog are the worker-dast tools; "zap" (the full active scan) and
// "schemathesis" were catalogued before the image existed and are updated
// in place.
var dastCatalog = []Scanner{
	dastTool("zap-baseline", "OWASP ZAP baseline scan", "dast", "Apache-2.0", "use", "https://www.zaproxy.org",
		"worker-dast image: spider and passive scan rules only (no attacks); ZAP traditional JSON report", false),
	dastTool("zap", "OWASP ZAP full scan", "dast", "Apache-2.0", "use", "https://www.zaproxy.org",
		"worker-dast image: spider, passive and active scan rules (automation framework); intrusive", true),
	dastTool("zap-api-scan", "OWASP ZAP API scan", "api", "Apache-2.0", "use", "https://www.zaproxy.org",
		"worker-dast image: imports the API target's OpenAPI document, then passive and active scan rules; intrusive", true),
	dastTool("wapiti", "Wapiti", "dast", "GPL-2.0-only", "use", "https://github.com/wapiti-scanner/wapiti",
		"worker-dast image: crawler and attack modules (injection, XSS, redirect, CRLF, upload); modules that contact third parties are not used; intrusive", true),
	dastTool("dalfox", "Dalfox", "dast", "MIT", "use", "https://github.com/hahwul/dalfox",
		"worker-dast image: XSS in the target URL's parameters and those it finds on the page (no crawling); intrusive", true),
	dastTool("ffuf", "ffuf", "dast", "MIT", "use", "https://github.com/ffuf/ffuf",
		"worker-dast image: content discovery with a small built-in wordlist at the target's rate limit; intrusive", true),
	dastTool("sqlmap", "sqlmap", "database", "GPL-2.0-or-later", "restricted", "https://sqlmap.org",
		"Opt-in build of the worker-dast image (WITH_SQLMAP): sqlmap's licence treats software that runs it and parses its results as a derived work. "+
			"Detection only (--batch --risk=1 --level=1; never dumps data, reads or writes files or runs commands); intrusive", true),
	dastTool("nikto", "Nikto", "dast", "LicenseRef-Nikto", "restricted", "https://github.com/sullo/nikto",
		"Opt-in build of the worker-dast image (WITH_NIKTO): GPL-3.0 code, but its test databases may be distributed only with the full Nikto package. "+
			"All test categories except denial of service; intrusive", true),
	dastTool("testssl", "testssl.sh", "misconfiguration", "GPL-2.0-only", "use", "https://testssl.sh",
		"worker-dast image: TLS protocols, ciphers, certificate and known TLS vulnerabilities of https targets", false),
	dastTool("sslyze", "SSLyze", "misconfiguration", "AGPL-3.0-only", "use", "https://github.com/nabla-c0d3/sslyze",
		"worker-dast image: TLS configuration of https targets", false),
	dastTool("schemathesis", "Schemathesis", "api", "MIT", "use", "https://github.com/schemathesis/schemathesis",
		"worker-dast image: property-based testing of API targets from their OpenAPI document (examples, coverage, fuzzing and stateful phases); intrusive", true),
	dastTool("arjun", "Arjun", "dast", "AGPL-3.0-only", "use", "https://github.com/s0md3v/Arjun",
		"worker-dast image: discovers hidden HTTP parameters of the target URL (passive third-party sources are never used); intrusive", true),
}

// dastScanTypes are the scan types the worker-dast tools add themselves to.
var dastScanTypes = map[string][]string{
	"dast":          {"zap-baseline", "zap-api-scan", "wapiti", "dalfox", "ffuf", "sqlmap", "nikto", "arjun"},
	"api":           {"zap-api-scan"},
	"database":      {"sqlmap"},
	"configuration": {"testssl", "sslyze", "nikto"},
	"crypto":        {"testssl", "sslyze"},
	"fuzzing":       {"ffuf", "schemathesis"},
}

func init() {
	for _, sc := range dastCatalog {
		if i := dastCatalogIndex(sc.Key); i >= 0 {
			Catalog[i] = sc
		} else {
			Catalog = append(Catalog, sc)
		}
	}
	for id, keys := range dastScanTypes {
		dastAddScanTypeTools(id, keys...)
	}
}

// dastCatalogIndex returns the position of key in Catalog, or -1.
func dastCatalogIndex(key string) int {
	for i, sc := range Catalog {
		if sc.Key == key {
			return i
		}
	}
	return -1
}

// dastAddScanTypeTools adds catalog keys to a scan type's tool list (once).
func dastAddScanTypeTools(id string, keys ...string) {
	for i := range ScanTypes {
		if ScanTypes[i].ID != id {
			continue
		}
		for _, k := range keys {
			if !slices.Contains(ScanTypes[i].Tools, k) {
				ScanTypes[i].Tools = append(ScanTypes[i].Tools, k)
			}
		}
		return
	}
	panic("dastAddScanTypeTools: unknown scan type " + id)
}
