package scanners

import (
	"slices"
	"strings"
	"testing"
)

// Fixtures of the DAST and API tool formats (testdata/imports). Real runs
// were made on 2026-11-19 against a small local test application (a Python
// http.server script with a reflected XSS parameter, an SQL injection over
// SQLite, an /admin path and an OpenAPI 3 description with an endpoint
// returning 500) on an internal Docker network without internet access.
// Every scan was given the cookie "session=a3cookiesecret" and the header
// "Authorization: Bearer a3bearertokensecret123"; the application sets the
// cookie "session=a3sessionsecret". The tests check these never survive
// sanitisation.
//
//   - nikto.json, nikto-xml.xml: ghcr.io/sullo/nikto:latest (Nikto 2.5.0), -Format json / xml, unmodified.
//   - wapiti.json: Wapiti 3.3.2 (pip install wapiti3 in python:3.13-slim; there is no official image), -f json, unmodified.
//   - arachni.json: arachni/arachni:latest (Arachni 1.5.1, the last release), arachni_reporter --reporter=json, unmodified.
//   - sqlmap.csv: sqlmap 1.10.11 (pip install sqlmap; no official image), -m targets --results-file, unmodified.
//   - dalfox.json: hahwul/dalfox:latest (Dalfox 3.3.0), --format json --include-all, unmodified.
//   - dalfox-v2.json: built from the Dalfox 2 JSON output format (model.PoC fields, https://github.com/hahwul/dalfox), not a real run.
//   - ffuf.json: ffuf v2.1.0 built from its Go module (no official image), -of json, unmodified.
//   - wfuzz.json: ghcr.io/xmendez/wfuzz:latest, -f out.json,json, unmodified.
//   - schemathesis.json, schemathesis-junit.xml: schemathesis/schemathesis:stable (4.33.4), --report json,junit, unmodified.
//   - w3af.xml: built from the xml_file output plugin templates (root.tpl, scan_info.tpl, finding.tpl,
//     http_transaction.tpl in https://github.com/andresriancho/w3af); w3af is no longer maintained and was not run.
//   - restler.json, restler-bugs.json: built from RESTler's bug bucket writer (BugDetail, Bug and Bugs.json in
//     restler/utils/logger.py, https://github.com/microsoft/restler-fuzzer); RESTler was not run.

var g1Secrets = []string{"a3cookiesecret", "a3bearertokensecret123", "a3sessionsecret", "a3formpasswordsecret"}

// g1CheckClean checks a fixture's planted credentials are absent from the
// sanitised report, from every located record and from finding text.
func g1CheckClean(t *testing.T, file, format, key string) {
	t.Helper()
	raw := readImportFixture(t, file)
	stored := SanitizeImport(format, raw)
	if DetectImportFormat(stored) != format {
		t.Fatalf("%s: sanitised report detected as %q", file, DetectImportFormat(stored))
	}
	orig, err := ParseImport(key, format, raw)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := ParseImport(key, format, stored)
	if err != nil || len(clean) != len(orig) {
		t.Fatalf("%s: sanitised parse: %v %d/%d", file, err, len(clean), len(orig))
	}
	for _, s := range g1Secrets {
		if strings.Contains(string(stored), s) {
			t.Errorf("%s: %q in the stored report", file, s)
		}
	}
	for i, f := range orig {
		if f.Fingerprint != clean[i].Fingerprint {
			t.Errorf("%s: finding %d: identity depends on redacted values", file, i)
		}
		for _, src := range [][]byte{raw, stored} {
			loc, err := LocateImport(key, format, src, f.Fingerprint)
			if err != nil {
				t.Fatalf("%s: locate %d: %v", file, i, err)
			}
			for _, s := range g1Secrets {
				if strings.Contains(string(loc.Raw), s) || strings.Contains(f.Title+f.Description+f.FilePath, s) {
					t.Errorf("%s: finding %d exposes %q", file, i, s)
				}
			}
		}
	}
}

func TestImportNikto(t *testing.T) {
	fs := checkImport(t, "nikto.json", "nikto", "import-dast-nikto", 9)
	if f := fs[0]; f.Severity != "low" || f.FilePath != "http://target:8080/" || f.RuleID != "95" || f.Category != "dast" ||
		f.Title != "Cookie session created without the httponly flag." {
		t.Errorf("cookie: %+v", f)
	}
	if f := fs[8]; f.FilePath != "http://target:8080/admin/" || f.RuleID != "001551" {
		t.Errorf("admin: %+v", f)
	}
	xs := checkImport(t, "nikto-xml.xml", "nikto", "import-dast-nikto", 9)
	// The same scan as XML gives the same findings.
	for i := range xs {
		if !slices.ContainsFunc(fs, func(f Finding) bool { return f.Fingerprint == xs[i].Fingerprint }) {
			t.Errorf("xml finding %d (%s) differs from the JSON report", i, xs[i].Title)
		}
	}
	if DetectImportFormat([]byte(`[{"host":"a","port":"80","vulnerabilities":[]}]`)) == "nikto" {
		t.Error("host/port/vulnerabilities alone are not Nikto")
	}
}

func TestImportWapiti(t *testing.T) {
	fs := checkImport(t, "wapiti.json", "wapiti", "import-dast-wapiti", 9)
	bySev := map[string]Finding{}
	for _, f := range fs {
		bySev[f.RuleID+"|"+f.Severity] = f
	}
	sqli, ok := bySev["SQL Injection|critical"]
	if !ok || sqli.FilePath != "http://target:8080/user" || !slices.Contains(sqli.CWE, "CWE-89") || !strings.Contains(sqli.Description, `parameter "id"`) {
		t.Errorf("sqli: %+v", sqli)
	}
	if xss, ok := bySev["Reflected Cross Site Scripting|medium"]; !ok || !slices.Contains(xss.CWE, "CWE-79") {
		t.Errorf("xss: %+v", xss)
	}
	n := 0
	for _, f := range fs {
		if f.RuleID == "Internal Server Error" {
			n++
			if f.Confidence != "low" || f.Severity != "high" || !strings.Contains(f.Description, "anomaly") {
				t.Errorf("anomaly: %+v", f)
			}
		}
	}
	if n != 3 {
		t.Errorf("%d anomalies", n)
	}
	g1CheckClean(t, "wapiti.json", "wapiti", "import-dast-wapiti")
}

func TestImportArachni(t *testing.T) {
	fs := checkImport(t, "arachni.json", "arachni", "import-dast-arachni", 2)
	if f := fs[0]; f.Severity != "high" || f.RuleID != "xss" || !slices.Equal(f.CWE, []string{"CWE-79"}) || f.FilePath != "http://target:8080/search" ||
		!strings.Contains(f.Description, `parameter "q"`) {
		t.Errorf("xss: %+v", f)
	}
	if f := fs[1]; f.Severity != "info" || f.FilePath != "http://target:8080/user" {
		t.Errorf("interesting response: %+v", f)
	}
	g1CheckClean(t, "arachni.json", "arachni", "import-dast-arachni")
	untrusted := []byte(`{"version":"1.5.1","seed":"x","options":{},"sitemap":{},"issues":[{"name":"Blind SQL Injection","severity":"high","cwe":89,"trusted":false,"digest":1,"check":{"shortname":"sql_injection_timing"},"vector":{"url":"http://t/a","method":"get","affected_input_name":"id"}}],"plugins":{}}`)
	if g, err := ParseImport("import-dast-arachni", "", untrusted); err != nil || len(g) != 1 || g[0].Confidence != "low" || !strings.Contains(g[0].Description, "untrusted") {
		t.Errorf("untrusted issue: %v %+v", err, g)
	}
}

func TestImportSqlmap(t *testing.T) {
	fs := checkImport(t, "sqlmap.csv", "sqlmap", "import-dast-sqlmap", 1)
	if f := fs[0]; f.Severity != "high" || f.FilePath != "http://target:8080/user" || !slices.Equal(f.CWE, []string{"CWE-89"}) ||
		!strings.Contains(f.Description, "boolean-based blind, error-based, time-based blind, UNION query") || f.Title != `SQL injection in GET parameter "id"` {
		t.Errorf("%+v", f)
	}
	tok := []byte("Target URL,Place,Parameter,Technique(s),Note(s)\nhttp://t/x?token=a3bearertokensecret123&id=1,GET,id,B,\n")
	if g, err := ParseImport("import-dast-sqlmap", "", tok); err != nil || len(g) != 1 || strings.Contains(g[0].Description, "a3bearer") {
		t.Errorf("token in URL: %v %+v", err, g)
	}
	if strings.Contains(string(SanitizeImport("sqlmap", tok)), "a3bearer") {
		t.Error("stored report keeps the token")
	}
}

func TestImportDalfox(t *testing.T) {
	fs := checkImport(t, "dalfox.json", "dalfox", "import-dast-dalfox", 1)
	if f := fs[0]; f.Severity != "high" || f.Confidence != "high" || f.RuleID != "xss-verified" || f.FilePath != "http://target:8080/search" ||
		!slices.Equal(f.CWE, []string{"CWE-79"}) {
		t.Errorf("v3: %+v", f)
	}
	g1CheckClean(t, "dalfox.json", "dalfox", "import-dast-dalfox")
	v2 := checkImport(t, "dalfox-v2.json", "dalfox", "import-dast-dalfox", 2)
	if v2[0].RuleID != "xss-verified" || v2[1].RuleID != "xss-reflected" || v2[1].Confidence != "low" || v2[1].Severity != "medium" {
		t.Errorf("v2: %+v", v2)
	}
	g1CheckClean(t, "dalfox-v2.json", "dalfox", "import-dast-dalfox")
	// A separator object first is still Dalfox 2.
	if DetectImportFormat([]byte(`[{},{"type":"V","inject_type":"inHTML","poc_type":"plain","method":"GET","data":"http://t/?q=1","param":"q"}]`)) != "dalfox" {
		t.Error("leading empty object")
	}
}

func TestImportFfufWfuzz(t *testing.T) {
	fs := checkImport(t, "ffuf.json", "ffuf", "import-dast-ffuf", 4)
	for _, f := range fs {
		if f.Severity != "info" || f.RuleID != "ffuf-match" || !strings.HasPrefix(f.FilePath, "http://target:8080/") {
			t.Errorf("ffuf: %+v", f)
		}
	}
	if fs[3].Title != "Content discovered: http://target:8080/admin (HTTP 200)" {
		t.Errorf("title: %q", fs[3].Title)
	}
	g1CheckClean(t, "ffuf.json", "ffuf", "import-dast-ffuf")

	ws := checkImport(t, "wfuzz.json", "wfuzz", "import-dast-wfuzz", 4)
	if ws[1].FilePath != "http://target:8080/admin" || ws[1].Severity != "info" || !strings.Contains(ws[1].Description, "Payload: admin") {
		t.Errorf("wfuzz: %+v", ws[1])
	}
	post := []byte(`[{"chars":1,"code":200,"payload":"x","lines":1,"location":"","method":"POST","post_data":[{"parameter":"password","value":"a3formpasswordsecret"},{"parameter":"user","value":"bob"}],"server":"","url":"http://t/login","words":1}]`)
	stored := string(SanitizeImport("wfuzz", post))
	if strings.Contains(stored, "a3formpasswordsecret") || !strings.Contains(stored, "bob") {
		t.Errorf("wfuzz post data: %s", stored)
	}
	if g, _ := ParseImport("import-dast-wfuzz", "wfuzz", post); len(g) != 1 || strings.Contains(g[0].Description, "a3formpassword") {
		t.Errorf("wfuzz description: %+v", g)
	}
}

func TestImportW3af(t *testing.T) {
	fs := checkImport(t, "w3af.xml", "w3af", "import-dast-w3af", 3)
	if f := fs[0]; f.Severity != "high" || f.RuleID != "sqli/SQL injection" || !slices.Equal(f.CWE, []string{"CWE-89"}) || f.FilePath != "http://target:8080/user" {
		t.Errorf("sqli: %+v", f)
	}
	if fs[1].Severity != "medium" || fs[2].Severity != "info" {
		t.Errorf("severities: %+v", fs)
	}
	g1CheckClean(t, "w3af.xml", "w3af", "import-dast-w3af")
	if !strings.Contains(string(SanitizeImport("w3af", readImportFixture(t, "w3af.xml"))), `content="target:8080"`) {
		t.Error("non-secret headers are kept")
	}
}

func TestImportSchemathesis(t *testing.T) {
	fs := checkImport(t, "schemathesis.json", "schemathesis", "import-api-schemathesis", 6)
	if f := fs[0]; f.RuleID != "ST101" || f.Severity != "critical" || f.FilePath != "/api/items" || f.Title != "Server error (GET /api/items)" {
		t.Errorf("json: %+v", f)
	}
	js := checkImport(t, "schemathesis-junit.xml", "schemathesis", "import-api-schemathesis", 6)
	codes := map[string]string{}
	for _, f := range js {
		codes[f.RuleID+" "+f.FilePath] = f.Severity
	}
	if codes["ST101 /api/items"] != "critical" || codes["ST201 /api/users/{id}"] != "medium" || codes["ST204 /api/users/{id}"] != "medium" {
		t.Errorf("junit: %v", codes)
	}
	g1CheckClean(t, "schemathesis-junit.xml", "schemathesis", "import-api-schemathesis")
	// A JUnit report of another tool is not Schemathesis.
	junit := []byte(`<?xml version="1.0"?><testsuites><testsuite name="pytest" tests="1"><testcase name="test_x"><failure message="ST101">x</failure></testcase></testsuite></testsuites>`)
	if DetectImportFormat(junit) != "" {
		t.Errorf("generic JUnit detected as %q", DetectImportFormat(junit))
	}
}

func TestImportRestler(t *testing.T) {
	fs := checkImport(t, "restler.json", "restler", "import-api-restler", 1)
	if f := fs[0]; f.RuleID != "main_driver/500" || f.Severity != "medium" || f.FilePath != "/api/blog/posts/{postId}" ||
		!strings.Contains(f.Description, "PUT /api/blog/posts/5882 HTTP/1.1") {
		t.Errorf("detail: %+v", f)
	}
	g1CheckClean(t, "restler.json", "restler", "import-api-restler")
	bs := checkImport(t, "restler-bugs.json", "restler", "import-api-restler", 2)
	if bs[1].Severity != "high" || bs[1].Confidence != "low" || bs[1].FilePath != "UseAfterFreeChecker_20x_1.json" {
		t.Errorf("index: %+v", bs[1])
	}
	if DetectImportFormat([]byte(`{"bugs":[{"id":1,"title":"x"}]}`)) == "restler" {
		t.Error("a generic bug list is not RESTler")
	}
}
