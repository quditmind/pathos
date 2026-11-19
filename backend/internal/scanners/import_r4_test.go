package scanners

import (
	"slices"
	"strings"
	"testing"
)

// Group 4 import formats: commercial DAST, API and infrastructure scanners.
// No real exports of these commercial tools were available, so every
// fixture was written by hand from the vendor's published format, with
// example.test hosts, documentation addresses and planted fake secrets; the
// shapes were cross-checked against the open-source DefectDojo parsers and
// their unit-test samples (github.com/DefectDojo/django-DefectDojo,
// unittests/scans/<tool>, read for structure only). Every format is "built
// from the published format; not yet verified against a real export".
//
//   acunetix.xml, acunetix-360.json: Acunetix XML export (DefectDojo
//     unittests/scans/acunetix/*.xml) and Acunetix 360 JSON
//     (acunetix360_one_finding.json), which has the Invicti JSON layout.
//   invicti.json: Invicti / Netsparker Enterprise JSON report (DefectDojo
//     unittests/scans/invicti, netsparker).
//   invicti-xml.xml: Invicti Enterprise XML report, element paths from
//     https://docs.plextrac.com/plextrac-documentation/product-documentation-1/integrations-and-file-imports/invicti
//     and https://www.invicti.com/support/lists-invicti (field names follow
//     the JSON report in kebab case).
//   appspider.xml: Rapid7 AppSpider VulnerabilitiesSummary.xml (DefectDojo
//     unittests/scans/appspider/one_vuln.xml).
//   qualys-was.xml: Qualys WAS scan report XML (DefectDojo
//     unittests/scans/qualys_webapp).
//   qualys-vm.xml: Qualys VMDR ASSET_DATA_REPORT XML (DefectDojo
//     unittests/scans/qualys/Qualys_Sample_Report.xml;
//     https://qualysguard.qualys.com/asset_data_report.dtd).
//   insightappsec.json: Rapid7 InsightAppSec API vulnerability page, schema
//     from https://help.rapid7.com/insightappsec/en-us/api/v1/insightappsec-api-v1.json
//     (Vulnerability, RootCause, Variance, Exchange).
//   appscan-dast.xml: HCL AppScan xml-report (DefectDojo
//     unittests/scans/hcl_appscan, ibm_app/testfire.xml).
//   burp-enterprise.json: Burp REST API scan resource GET /v0.1/scan/{id}
//     (DefectDojo unittests/scans/burp_api).
//   burp-enterprise-graphql.json: Burp Suite DAST GraphQL issues of a scan,
//     https://portswigger.net/burp/extensibility/dast/graphql-api/issue.html
//   stackhawk.json: StackHawk scanCompleted webhook payload (DefectDojo
//     unittests/scans/stackhawk).
//   42crunch.json: 42Crunch API Security Audit JSON report (DefectDojo
//     unittests/scans/crunch42, fortytwocrunch).
//   tenable-csv.csv, tenable-csv-sc.csv: Nessus / Tenable Vulnerability
//     Management CSV and Tenable Security Center CSV (DefectDojo
//     unittests/scans/tenable).
//   nexpose.xml: Rapid7 Nexpose / InsightVM XML Export 2.0 (DefectDojo
//     unittests/scans/nexpose).

// g4NoSecrets checks that planted secrets are absent from the sanitised
// report, from located records and from the findings' text.
func g4NoSecrets(t *testing.T, file, format, key string, secrets ...string) {
	t.Helper()
	raw := readImportFixture(t, file)
	for _, s := range secrets {
		if !strings.Contains(string(raw), s) {
			t.Fatalf("%s: fixture does not contain the planted secret %q", file, s)
		}
	}
	clean := SanitizeImport(format, raw)
	if got := DetectImportFormat(clean); got != format {
		t.Fatalf("%s: sanitised report detected as %q", file, got)
	}
	fs, err := ParseImport(key, format, raw)
	if err != nil {
		t.Fatal(err)
	}
	cfs, err := ParseImport(key, format, clean)
	if err != nil || len(cfs) != len(fs) {
		t.Fatalf("%s: sanitised report: %v, %d findings (want %d)", file, err, len(cfs), len(fs))
	}
	for i, f := range fs {
		if cfs[i].Fingerprint != f.Fingerprint {
			t.Errorf("%s: finding %d: identity depends on redacted values", file, i)
		}
		for _, src := range [][]byte{raw, clean} {
			loc, err := LocateImport(key, format, src, f.Fingerprint)
			if err != nil {
				t.Fatalf("%s: locate %d: %v", file, i, err)
			}
			for _, s := range secrets {
				if strings.Contains(string(loc.Raw), s) {
					t.Errorf("%s: finding %d: located record contains %q", file, i, s)
				}
			}
		}
		for _, s := range secrets {
			if strings.Contains(f.Title+f.Description+f.FilePath, s) {
				t.Errorf("%s: finding %d: text contains %q", file, i, s)
			}
		}
	}
	for _, s := range secrets {
		if strings.Contains(string(clean), s) {
			t.Errorf("%s: sanitised report contains %q", file, s)
		}
	}
}

func TestImportAcunetix(t *testing.T) {
	fs := checkImport(t, "acunetix.xml", "acunetix", "import-dast-acunetix", 3)
	sqli := fs[0]
	if sqli.Severity != "high" || sqli.FilePath != "https://shop.example.test/product.php" || !slices.Equal(sqli.CWE, []string{"CWE-89"}) ||
		sqli.CVSSVector != "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" || sqli.CVSS == nil || *sqli.CVSS != 9.8 ||
		sqli.RuleID != "/Scripts/PerScheme/Sql_Injection.script" || !strings.Contains(sqli.Description, `(parameter "id")`) ||
		!strings.Contains(sqli.Description, "SQL syntax") || sqli.Category != "dast" {
		t.Errorf("sqli: %+v", sqli)
	}
	if js := fs[1]; js.CVE != "CVE-2020-11022" || js.Severity != "medium" || js.CVSSVersion != "3.1" || js.FilePath != "https://shop.example.test/js/jquery.min.js" {
		t.Errorf("js library: %+v", js)
	}
	if fp := fs[2]; fp.Confidence != "low" || !strings.Contains(fp.Description, "false positive") || fp.FilePath != "https://shop.example.test" ||
		!strings.Contains(fp.Description, "Web Server") {
		t.Errorf("false positive item: %+v", fp)
	}
	g4NoSecrets(t, "acunetix.xml", "acunetix", "import-dast-acunetix", "acu-cookie-secret-123", "acu-bearer-token-abcdef")

	js := checkImport(t, "acunetix-360.json", "acunetix", "import-dast-acunetix", 2)
	if c := js[0]; c.Severity != "medium" || c.Confidence != "high" || !slices.Equal(c.CWE, []string{"CWE-1004"}) || c.CVSSVersion != "3.0" ||
		c.FilePath != "https://shop.example.test/auth/login.php" || c.RuleID != "CookieNotMarkedAsHttpOnly" || strings.Contains(c.Description, "<p>") {
		t.Errorf("acunetix 360 cookie: %+v", c)
	}
	if v := js[1]; v.Severity != "info" || v.Confidence != "low" || !strings.Contains(v.Description, "false positive") {
		t.Errorf("acunetix 360 best practice false positive: %+v", v)
	}
	g4NoSecrets(t, "acunetix-360.json", "acunetix", "import-dast-acunetix", "a360-request-cookie-secret", "a360-response-cookie-secret")
}

func TestImportInvicti(t *testing.T) {
	fs := checkImport(t, "invicti.json", "invicti", "import-dast-invicti", 2)
	sqli := fs[0]
	if sqli.Severity != "critical" || sqli.Confidence != "high" || !slices.Equal(sqli.CWE, []string{"CWE-89"}) || sqli.CVSS == nil || *sqli.CVSS != 10 ||
		sqli.CVSSVersion != "3.1" || sqli.RuleID != "BooleanSqlInjection" || !strings.Contains(sqli.Description, `(parameter "id")`) ||
		!strings.HasPrefix(sqli.FilePath, "https://api.example.test/artist.php") {
		t.Errorf("sqli: %+v", sqli)
	}
	if old := fs[1]; old.Severity != "high" || old.Confidence != "high" || !strings.Contains(old.Description, "CVE-2021-41773") {
		t.Errorf("out of date: %+v", old)
	}
	g4NoSecrets(t, "invicti.json", "invicti", "import-dast-invicti", "aW52aWN0aTpzZWNyZXQtcGFzc3dvcmQ=", "invicti-session-cookie-1",
		"invicti-session-cookie-2", "invicti-param-token-xyz")

	xs := checkImport(t, "invicti-xml.xml", "invicti", "import-dast-invicti", 2)
	if x := xs[0]; x.Severity != "high" || x.Confidence != "high" || !slices.Equal(x.CWE, []string{"CWE-79"}) || x.CVSS == nil || *x.CVSS != 6.1 ||
		x.CVSSVersion != "3.1" || !strings.Contains(x.Description, `(parameter "q")`) || x.RuleID != "CrossSiteScripting" {
		t.Errorf("xml xss: %+v", x)
	}
	if x := xs[1]; x.Severity != "low" || x.Confidence != "medium" || !strings.Contains(x.Description, "accepted risk") {
		t.Errorf("xml accepted risk: %+v", x)
	}
	g4NoSecrets(t, "invicti-xml.xml", "invicti", "import-dast-invicti", "invicti-xml-cookie-secret", "invicti-xml-set-cookie-secret",
		"invicti-xml-password-value")
}

func TestImportAppSpider(t *testing.T) {
	fs := checkImport(t, "appspider.xml", "appspider", "import-dast-appspider", 2)
	if c := fs[0]; c.Severity != "low" || c.Confidence != "high" || !slices.Equal(c.CWE, []string{"CWE-525"}) ||
		c.FilePath != "https://bank.example.test/search.aspx" || strings.Contains(c.Description, "N/A") {
		t.Errorf("cache: %+v", c)
	}
	if s := fs[1]; s.Severity != "high" || s.Confidence != "medium" || !slices.Equal(s.CWE, []string{"CWE-89"}) ||
		!strings.Contains(s.Description, `POST https://bank.example.test/doLogin (parameter "uid")`) {
		t.Errorf("sqli: %+v", s)
	}
	g4NoSecrets(t, "appspider.xml", "appspider", "import-dast-appspider", "R0VUIC9zZWFyY2guYXNweD90eHRTZWFyY2g9d2F0ZXIgSFRUUC8xLjENCkhvc3Q6IGJhbmsuZXhhbXBsZS50ZXN0DQpDb29raWU6IEFTUC5ORVRfU2Vzc2lvbklkPWFwcHNwaWRlci1jb29raWUtc2VjcmV0")
	// The redacted traffic stays readable in the stored report.
	clean := string(SanitizeImport("appspider", readImportFixture(t, "appspider.xml")))
	for _, s := range []string{"appspider-cookie-secret", "appspider-set-cookie-secret", "YXBwc3BpZGVyOmF1dGgtc2VjcmV0", "appspider-form-password"} {
		if strings.Contains(clean, s) || strings.Contains(appspiderAllDecoded(clean), s) {
			t.Errorf("stored report keeps %q", s)
		}
	}
	if !strings.Contains(appspiderAllDecoded(clean), "Host: bank.example.test") {
		t.Error("redacted traffic must stay decodable")
	}
}

// appspiderAllDecoded decodes every base64 traffic element of a report.
func appspiderAllDecoded(doc string) string {
	var b strings.Builder
	for _, m := range appspiderB64Re.FindAllStringSubmatch(doc, -1) {
		b.WriteString(appspiderDecode(m[2]))
	}
	return b.String()
}

func TestImportQualysWAS(t *testing.T) {
	fs := checkImport(t, "qualys-was.xml", "qualys-was", "import-dast-qualys-was", 3)
	if p := fs[0]; p.Severity != "low" || p.RuleID != "QID-150004" || p.Title != "Path-Based Vulnerability" || !slices.Equal(p.CWE, []string{"CWE-22"}) ||
		p.FilePath != "https://store.example.test/backup/" || p.CVSS == nil || *p.CVSS != 2.1 {
		t.Errorf("path: %+v", p)
	}
	if x := fs[1]; x.Severity != "critical" || x.Confidence != "low" || !strings.Contains(x.Description, "ignored (False Positive)") ||
		!strings.Contains(x.Description, `(parameter "q")`) {
		t.Errorf("ignored xss: %+v", x)
	}
	if ig := fs[2]; ig.Severity != "info" || ig.FilePath != "https://store.example.test/" || !strings.Contains(ig.Description, "Links crawled") {
		t.Errorf("information gathered: %+v", ig)
	}
	g4NoSecrets(t, "qualys-was.xml", "qualys-was", "import-dast-qualys-was", "qualys-request-cookie-secret", "qualys-bearer-token-secret",
		"SFRUUC8xLjEgMjAwIE9LClNldC1Db29raWU6IEpTRVNTSU9OSUQ9cXVhbHlzLXNldC1jb29raWUtc2VjcmV0")
}

func TestImportQualysVM(t *testing.T) {
	fs := checkImport(t, "qualys-vm.xml", "qualys-vm", "import-other-qualys-vm", 3)
	if ig := fs[0]; ig.Severity != "info" || ig.FilePath != "192.0.2.20" || ig.RuleID != "QID-6" {
		t.Errorf("information gathered: %+v", ig)
	}
	ssh := fs[1]
	if ssh.Severity != "critical" || ssh.CVE != "CVE-2024-6387" || ssh.FilePath != "192.0.2.20:22/tcp" || ssh.CVSS == nil || *ssh.CVSS != 8.1 ||
		ssh.CVSSVector != "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" || ssh.Confidence != "high" || ssh.Category != "other" {
		t.Errorf("regreSSHion: %+v", ssh)
	}
	if fs[2].FilePath != "192.0.2.20:2222/tcp" {
		t.Errorf("second port: %+v", fs[2])
	}
}

func TestImportInsightAppSec(t *testing.T) {
	fs := checkImport(t, "insightappsec.json", "insightappsec", "import-dast-insightappsec", 2)
	s := fs[0]
	if s.Severity != "high" || s.Confidence != "high" || s.RuleID != "SQLI-BLIND-BOOLEAN" || s.CVSS == nil || *s.CVSS != 8.1 || s.CVSSVersion != "3.1" ||
		s.FilePath != "https://portal.example.test/api/orders" || !strings.Contains(s.Description, `GET https://portal.example.test/api/orders (parameter "orderId")`) {
		t.Errorf("sqli: %+v", s)
	}
	if b := fs[1]; b.Severity != "info" || b.Confidence != "low" || !strings.Contains(b.Description, "false positive") {
		t.Errorf("false positive: %+v", b)
	}
	g4NoSecrets(t, "insightappsec.json", "insightappsec", "import-dast-insightappsec", "ias-original-bearer-token", "ias-cookie-secret",
		"ias-set-cookie-secret", "ias-attack-bearer-token")
	// A bare array of vulnerabilities is accepted too.
	arr := []byte(`[{"id":"1","root_cause":{"url":"https://a.example.test/","method":"GET"},"severity":"LOW","status":"UNREVIEWED","variances":[{"attack":{"id":"X"}}]}]`)
	if DetectImportFormat(arr) != "insightappsec" {
		t.Error("array form")
	}
}

func TestImportAppScanDAST(t *testing.T) {
	fs := checkImport(t, "appscan-dast.xml", "appscan-dast", "import-dast-appscan", 2)
	x := fs[0]
	if x.Severity != "high" || x.Title != "Cross-Site Scripting" || !slices.Equal(x.CWE, []string{"CWE-79"}) || x.CVSS == nil || *x.CVSS != 6.1 ||
		x.CVSSVector != "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" || x.FilePath != "https://bank.example.test/bank/queryxpath.jsp" ||
		!strings.Contains(x.Description, `GET https://bank.example.test/bank/queryxpath.jsp (parameter "query")`) ||
		!strings.Contains(x.Description, "hazardous character injection") {
		t.Errorf("xss: %+v", x)
	}
	if l := fs[1]; l.Severity != "medium" || l.FilePath != "http://bank.example.test/doLogin" || !slices.Equal(l.CWE, []string{"CWE-523"}) {
		t.Errorf("login: %+v", l)
	}
	g4NoSecrets(t, "appscan-dast.xml", "appscan-dast", "import-dast-appscan", "appscan-cookie-group-secret", "appscan-traffic-cookie-secret",
		"YXBwc2NhbjphcHBzY2FuLXNlY3JldA==", "appscan-set-cookie-secret", "appscan-form-password")
	if DetectImportFormat([]byte(`<xml-report><title>Unrelated</title></xml-report>`)) == "appscan-dast" {
		t.Error("a generic <xml-report> is not AppScan")
	}
}

func TestImportBurpEnterprise(t *testing.T) {
	fs := checkImport(t, "burp-enterprise.json", "burp-enterprise", "import-dast-burp-dast", 2)
	x := fs[0]
	if x.Severity != "high" || x.Confidence != "high" || x.RuleID != "2097920" || x.FilePath != "https://shop.example.test/search" ||
		!strings.Contains(x.Description, "/search [q parameter]") || strings.Contains(x.Description, "<b>") {
		t.Errorf("xss: %+v", x)
	}
	if h := fs[1]; h.Severity != "low" || h.Confidence != "low" || !strings.Contains(h.Description, "false positive") {
		t.Errorf("false positive: %+v", h)
	}
	g4NoSecrets(t, "burp-enterprise.json", "burp-enterprise", "import-dast-burp-dast",
		"R0VUIC9zZWFyY2g/cT0lM0NzY3JpcHQlM0UgSFRUUC8yDQpIb3N0OiBzaG9wLmV4YW1wbGUudGVzdA0KQ29va2llOiBzZXNzaW9uPWJ1cnAtZW50LWNvb2tpZS1zZWNyZXQ")
	loc, _ := LocateImport("import-dast-burp-dast", "burp-enterprise", readImportFixture(t, "burp-enterprise.json"), x.Fingerprint)
	if s := string(loc.Raw); !strings.Contains(s, "Host: shop.example.test") || strings.Contains(s, "burp-ent-cookie-secret") ||
		strings.Contains(s, "burp-ent-bearer-token-1") || strings.Contains(s, "burp-ent-set-cookie-secret") {
		t.Errorf("decoded, redacted evidence: %s", s)
	}

	gs := checkImport(t, "burp-enterprise-graphql.json", "burp-enterprise", "import-dast-burp-dast", 1)
	if g := gs[0]; g.Severity != "high" || g.Confidence != "medium" || !slices.Equal(g.CWE, []string{"CWE-89"}) || g.RuleID != "1049088" ||
		g.FilePath != "https://api.example.test/orders" {
		t.Errorf("graphql: %+v", g)
	}
	g4NoSecrets(t, "burp-enterprise-graphql.json", "burp-enterprise", "import-dast-burp-dast", "burp-graphql-cookie-secret", "burp-graphql-set-cookie-secret")
	if DetectImportFormat([]byte(`{"data":{"scan":{"id":"1"}}}`)) == "burp-enterprise" {
		t.Error("a GraphQL response without issues is not detected")
	}
}

func TestImportStackHawk(t *testing.T) {
	fs := checkImport(t, "stackhawk.json", "stackhawk", "import-dast-stackhawk", 3)
	if s := fs[0]; s.Severity != "high" || s.RuleID != "40018" || s.Title != "SQL Injection" || !strings.HasPrefix(s.FilePath, "https://orders.example.test/api/orders") {
		t.Errorf("sqli GET: %+v", s)
	}
	if fs[1].FilePath != "https://orders.example.test/api/orders" || !strings.Contains(fs[1].Description, "POST") {
		t.Errorf("sqli POST: %+v", fs[1])
	}
	if c := fs[2]; c.Severity != "low" || c.Confidence != "low" || !strings.Contains(c.Description, "false positive") {
		t.Errorf("false positive: %+v", c)
	}
	g4NoSecrets(t, "stackhawk.json", "stackhawk", "import-dast-stackhawk", "stackhawk-query-token")
	if DetectImportFormat([]byte(`{"service": "Not StackHawk", "scanCompleted": {}}`)) == "stackhawk" {
		t.Error("another service's payload is not StackHawk")
	}
}

func Test42Crunch(t *testing.T) {
	fs := checkImport(t, "42crunch.json", "42crunch", "import-api-42crunch", 4)
	// Issues are sorted by section, then issue id.
	if a := fs[0]; a.RuleID != "v3-global-securityscheme-apikey-inheader" || a.Severity != "info" || a.FilePath != "openapi#/components/securitySchemes/ApiKey" {
		t.Errorf("global apikey: %+v", a)
	}
	if o := fs[1]; o.Severity != "medium" || o.FilePath != "openapi#/paths/~1orders/get/security/0/ApiKey" || !strings.Contains(o.Description, "GET /orders") {
		t.Errorf("operation apikey: %+v", o)
	}
	if d := fs[2]; d.Severity != "low" || d.RuleID != "v3-response-schema-undefined" || !strings.Contains(d.Description, "Section: data") {
		t.Errorf("data: %+v", d)
	}
	if d := fs[3]; d.Severity != "high" || d.FilePath != "openapi#/paths/~1orders/post/requestBody/content/application~1json/schema" {
		t.Errorf("data: %+v", d)
	}
	bare := []byte(`{"index":["/paths/~1a/get"],"assessmentVersion":"3.1.6","security":{"issues":{"x":{"description":"X","criticality":5,"issues":[{"pointer":0}]}}}}`)
	if DetectImportFormat(bare) != "42crunch" {
		t.Fatal("bare report")
	}
	if b, err := ParseImport("import-api-42crunch", "", bare); err != nil || len(b) != 1 || b[0].Severity != "critical" || b[0].FilePath != "openapi#/paths/~1a/get" {
		t.Errorf("bare: %v %+v", err, b)
	}
}

func TestImportTenableCSV(t *testing.T) {
	fs := checkImport(t, "tenable-csv.csv", "tenable-csv", "import-other-tenable", 3)
	if i := fs[0]; i.Severity != "info" || i.FilePath != "192.0.2.30:80/tcp" || i.RuleID != "10107" {
		t.Errorf("info: %+v", i)
	}
	a := fs[1] // two CVE rows merged
	if a.Severity != "critical" || a.CVE != "CVE-2024-38474" || !strings.Contains(a.Description, "CVE-2024-38474, CVE-2024-38476") ||
		a.CVSS == nil || *a.CVSS != 9.8 || a.CVSSVersion != "3.0" || !slices.Equal(a.CWE, []string{"CWE-20"}) || a.FilePath != "192.0.2.30:443/tcp" {
		t.Errorf("apache: %+v", a)
	}
	if s := fs[2]; s.Severity != "medium" || s.CVSSVector != "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N" || s.CVE != "CVE-2023-48795" {
		t.Errorf("terrapin: %+v", s)
	}
	g4NoSecrets(t, "tenable-csv.csv", "tenable-csv", "import-other-tenable", "tenable-plugin-output-secret")

	sc := checkImport(t, "tenable-csv-sc.csv", "tenable-csv", "import-other-tenable", 2)
	if m := sc[0]; m.Severity != "critical" || m.FilePath != "192.0.2.40:1433/tcp" || m.CVSS == nil || *m.CVSS != 10 || m.CVSSVersion != "3.0" ||
		m.Title != "Microsoft SQL Server Unsupported Version Detection (remote check)" {
		t.Errorf("security center: %+v", m)
	}
	// The generic CSV format accepts the same header but is tried last.
	p := newImportProbe(readImportFixture(t, "tenable-csv.csv"))
	if f, _ := LookupImportFormat("csv"); f.match == nil || !f.match(p) {
		t.Log("generic CSV does not accept the Tenable header")
	}
	if DetectImportFormat([]byte("title,severity,host,port\nx,low,h,1\n")) != "csv" {
		t.Error("a generic CSV with host and port columns stays generic")
	}
}

func TestImportNexpose(t *testing.T) {
	fs := checkImport(t, "nexpose.xml", "nexpose", "import-other-nexpose", 3)
	if i := fs[0]; i.Severity != "low" || i.FilePath != "192.0.2.50" || i.CVE != "CVE-1999-0524" || i.Confidence != "high" {
		t.Errorf("icmp: %+v", i)
	}
	a := fs[1]
	if a.Severity != "critical" || a.CVE != "CVE-2021-41773" || a.FilePath != "192.0.2.50:443/tcp" || a.Confidence != "medium" ||
		a.CVSS == nil || *a.CVSS != 7.5 || a.CVSSVersion != "2.0" || !strings.Contains(a.Description, "Apache HTTPD 2.4.49") {
		t.Errorf("apache: %+v", a)
	}
	if c := fs[2]; c.Severity != "medium" || c.Confidence != "low" || !slices.Equal(c.CWE, []string{"CWE-614"}) {
		t.Errorf("cookie: %+v", c)
	}
	g4NoSecrets(t, "nexpose.xml", "nexpose", "import-other-nexpose", "nexpose-cookie-secret")
}

// TestImportGroup4Neighbours checks near-identical reports go to the right
// format.
func TestImportGroup4Neighbours(t *testing.T) {
	for doc, want := range map[string]string{
		// Invicti layout written by Acunetix 360 vs Invicti / Netsparker.
		`{"Generated":"x","Target":{"ScanId":"1","Url":"https://a.example.test/"},"Vulnerabilities":[{"Url":"https://a.example.test/","Severity":"Low","Name":"N","HttpRequest":{"Content":"X-Scanner: Acunetix360"}}]}`:           "acunetix",
		`{"Generated":"x","Target":{"ScanId":"1","Url":"https://a.example.test/"},"Vulnerabilities":[{"Url":"https://a.example.test/","Severity":"Low","Name":"N","HttpRequest":{"Content":"X-Scanner: Netsparker Enterprise"}}]}`: "invicti",
		`<netsparker-enterprise generated="x"><target><url>https://a.example.test/</url></target><vulnerabilities/></netsparker-enterprise>`:                                                                                       "invicti",
		// Qualys WAS vs Qualys VM.
		`<WAS_WEBAPP_REPORT><HEADER/><RESULTS/></WAS_WEBAPP_REPORT>`:   "qualys-was",
		`<ASSET_DATA_REPORT><HEADER/><HOST_LIST/></ASSET_DATA_REPORT>`: "qualys-vm",
		// Nessus XML stays nessus; Nexpose XML 2.0 is nexpose.
		`<NessusClientData_v2><Report name="r"/></NessusClientData_v2>`: "nessus",
		`<NexposeReport version="2.0"><scans/><nodes/></NexposeReport>`: "nexpose",
		// Burp XML stays burp; the Burp REST API JSON is burp-enterprise.
		`<issues burpVersion="2024.1"><issue/></issues>`:                    "burp",
		`{"task_id":"1","scan_status":"succeeded","issue_events":[]}`:       "burp-enterprise",
		`{"service":"StackHawk","scanCompleted":{"scan":{},"findings":[]}}`: "stackhawk",
		`<VulnSummary><VulnList/></VulnSummary>`:                            "appspider",
	} {
		if got := DetectImportFormat([]byte(doc)); got != want {
			t.Errorf("%.60s...: detected %q, want %q", doc, got, want)
		}
	}
	// Formats that are not Group 4 reports are not taken.
	for _, doc := range []string{
		`{"data":[{"id":1}],"metadata":{}}`,
		`{"Target":{"Url":"x"},"Vulnerabilities":[]}`,
		`{"report":{"score":1}}`,
		`<ScanGroup><Other/></ScanGroup>`,
		"Plugin ID,Name,Host\n1,x,h\n",
	} {
		if got := DetectImportFormat([]byte(doc)); got != "" && got != "csv" {
			t.Errorf("%q detected as %q", doc, got)
		}
	}
	// Empty reports of a named format are valid.
	for f, doc := range map[string]string{
		"stackhawk":       `{"service":"StackHawk","scanCompleted":{"findings":[]}}`,
		"insightappsec":   `{"data":[],"metadata":{}}`,
		"burp-enterprise": `{"scan_metrics":{},"issue_events":[]}`,
		"42crunch":        `{"report":{"index":[],"security":{"issues":{}},"score":100}}`,
		"appspider":       `<VulnSummary><VulnList/></VulnSummary>`,
		"nexpose":         `<NexposeReport version="2.0"><nodes/></NexposeReport>`,
	} {
		if fs, err := ParseImport("import-other-x", f, []byte(doc)); err != nil || len(fs) != 0 {
			t.Errorf("%s: empty report: %v %d", f, err, len(fs))
		}
	}
}
