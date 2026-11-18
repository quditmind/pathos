package scanners

import (
	"os"
	"slices"
	"strings"
	"testing"
)

func readImportFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/imports/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// checkImport parses a fixture with detection and with the explicit format,
// checks stable fingerprints and that every finding's record is located.
func checkImport(t *testing.T, file, format, key string, want int) []Finding {
	t.Helper()
	raw := readImportFixture(t, file)
	if got := DetectImportFormat(raw); got != format {
		t.Fatalf("%s: detected %q, want %q", file, got, format)
	}
	fs, err := ParseImport(key, format, raw)
	if err != nil || len(fs) != want {
		t.Fatalf("%s: %v, %d findings (want %d): %+v", file, err, len(fs), want, fs)
	}
	again, err := ParseImport(key, "", raw)
	if err != nil || len(again) != len(fs) {
		t.Fatalf("%s: detected parse: %v", file, err)
	}
	seen := map[string]bool{}
	for i, f := range fs {
		if f.Fingerprint != again[i].Fingerprint || f.Fingerprint == "" {
			t.Errorf("%s: finding %d: unstable fingerprint", file, i)
		}
		if seen[f.Fingerprint] {
			t.Errorf("%s: finding %d: duplicate fingerprint", file, i)
		}
		seen[f.Fingerprint] = true
		if f.ScannerKey != key || f.Title == "" || f.RuleID == "" || f.FilePath == "" || !slices.Contains(Severities, f.Severity) {
			t.Errorf("%s: finding %d incomplete: %+v", file, i, f)
		}
		loc, err := LocateImport(key, format, raw, f.Fingerprint)
		if err != nil || len(loc.Raw) < 3 {
			t.Errorf("%s: finding %d not located: %v", file, i, err)
		}
	}
	return fs
}

func TestImportZAP(t *testing.T) {
	fs := checkImport(t, "zap.json", "zap", "import-dast-zap", 3)
	csp := fs[0]
	if csp.Severity != "medium" || csp.Confidence != "high" || csp.FilePath != "https://shop.example.test/" || !slices.Equal(csp.CWE, []string{"CWE-693"}) ||
		csp.Category != "dast" || csp.RuleID != "10038-1" || strings.Contains(csp.Description, "<p>") {
		t.Errorf("csp: %+v", csp)
	}
	if fs[1].FilePath != "https://shop.example.test/cart" {
		t.Errorf("second instance: %+v", fs[1])
	}
	fp := fs[2]
	if fp.Severity != "low" || fp.Confidence != "low" || !strings.Contains(fp.Description, "false positive") || !strings.Contains(fp.Description, `"q"`) {
		t.Errorf("false positive alert must be kept with low confidence: %+v", fp)
	}

	xs := checkImport(t, "zap-xml.xml", "zap", "import-dast-zap", 2)
	sqli := xs[0]
	if sqli.Severity != "high" || sqli.Confidence != "medium" || !slices.Equal(sqli.CWE, []string{"CWE-89"}) ||
		sqli.FilePath != "https://api.example.test/orders?id=1" || !strings.Contains(sqli.Description, "SQL injection may be possible.") {
		t.Errorf("sqli: %+v", sqli)
	}
	// An alert without instances is a finding of the site.
	if xs[1].Severity != "info" || xs[1].FilePath != "https://api.example.test" || len(xs[1].CWE) != 0 {
		t.Errorf("no-instance alert: %+v", xs[1])
	}
	// An explicit import category other than "other" wins over the natural one.
	if o, _ := ParseImport("import-sast-zap", "zap", readImportFixture(t, "zap.json")); o[0].Category != "sast" {
		t.Errorf("import category: %+v", o[0])
	}
}

func TestImportBurp(t *testing.T) {
	raw := readImportFixture(t, "burp.xml")
	fs := checkImport(t, "burp.xml", "burp", "import-dast-burp", 2)
	xss := fs[0]
	if xss.Severity != "high" || xss.Confidence != "high" || xss.FilePath != "https://shop.example.test/search" ||
		!slices.Equal(xss.CWE, []string{"CWE-79", "CWE-116"}) || xss.RuleID != "2097920" || strings.Contains(xss.Description, "<b>") {
		t.Errorf("xss: %+v", xss)
	}
	if fs[1].Severity != "info" || fs[1].Confidence != "medium" {
		t.Errorf("info issue: %+v", fs[1])
	}
	loc, _ := LocateImport("import-dast-burp", "burp", raw, xss.Fingerprint)
	if s := string(loc.Raw); strings.Contains(s, "R0VUIC9zZWFyY2g") || strings.Contains(s, "secretvalue") || !strings.Contains(s, `"request_responses":1`) {
		t.Errorf("request/response bodies must not be kept: %s", s)
	}
}

func TestImportNessus(t *testing.T) {
	fs := checkImport(t, "nessus.nessus", "nessus", "import-other-nessus", 3)
	if fs[0].Severity != "info" || fs[0].FilePath != "192.0.2.5:0/tcp" {
		t.Errorf("informational item: %+v", fs[0])
	}
	apache := fs[1]
	if apache.Severity != "critical" || apache.CVE != "CVE-2024-38476" || apache.CVSS == nil || *apache.CVSS != 9.8 ||
		apache.CVSSVersion != "3.0" || apache.FilePath != "192.0.2.5:443/tcp" || apache.RuleID != "201198" ||
		!slices.Equal(apache.CWE, []string{"CWE-20"}) || !strings.Contains(apache.Title, "< 2.4.60") {
		t.Errorf("apache: %+v", apache)
	}
	ssh := fs[2]
	if ssh.Severity != "medium" || ssh.CVSSVector != "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" || !slices.Equal(ssh.CWE, []string{"CWE-327"}) {
		t.Errorf("ssh: %+v", ssh)
	}
}

func TestImportOpenVAS(t *testing.T) {
	fs := checkImport(t, "openvas.xml", "openvas", "import-other-openvas", 3)
	ssh := fs[0]
	if ssh.Severity != "high" || ssh.CVE != "CVE-2024-6387" || !slices.Equal(ssh.CWE, []string{"CWE-364"}) || ssh.FilePath != "192.0.2.7:22/tcp" ||
		ssh.CVSSVersion != "3.1" || ssh.Confidence != "high" || !strings.Contains(ssh.Description, "9.8p1") || ssh.RuleID != "1.3.6.1.4.1.25623.1.0.170001" {
		t.Errorf("openssh: %+v", ssh)
	}
	if fs[1].Severity != "low" || fs[1].FilePath != "192.0.2.7 general/tcp" || fs[1].CVSSVersion != "2.0" {
		t.Errorf("tcp timestamps: %+v", fs[1])
	}
	if fs[2].Confidence != "low" || !strings.Contains(fs[2].Description, "false positive") {
		t.Errorf("false positive kept: %+v", fs[2])
	}
	// A GMP response wrapping the report is recognised too.
	wrapped := []byte(`<get_reports_response status="200" status_text="OK"><report id="r1"><report id="r1"><results><result id="x"><name>Test</name><host>192.0.2.9</host><port>80/tcp</port><nvt oid="1.2.3"><name>Test</name></nvt><threat>Medium</threat><severity>5.0</severity></result></results></report></report></get_reports_response>`)
	if DetectImportFormat(wrapped) != "openvas" {
		t.Error("get_reports_response detection")
	}
	if w, err := ParseImport("import-other-openvas", "", wrapped); err != nil || len(w) != 1 || w[0].Severity != "medium" {
		t.Errorf("wrapped: %v %+v", err, w)
	}
	if DetectImportFormat([]byte(`<report><title>Quarterly</title></report>`)) == "openvas" {
		t.Error("a generic <report> document is not OpenVAS")
	}
}

func TestImportCheckmarx(t *testing.T) {
	fs := checkImport(t, "checkmarx.xml", "checkmarx", "import-sast-checkmarx", 3)
	sqli := fs[0]
	if sqli.Severity != "high" || sqli.FilePath != "src/main/java/com/example/OrderDao.java" || sqli.StartLine == nil || *sqli.StartLine != 42 ||
		!slices.Equal(sqli.CWE, []string{"CWE-89"}) || sqli.Title != "SQL Injection" || !strings.Contains(sqli.Description, "OrderController.java:27") {
		t.Errorf("sqli: %+v", sqli)
	}
	fp := fs[1]
	if fp.Confidence != "low" || !strings.Contains(fp.Description, "false positive") || !strings.Contains(fp.Description, "Not Exploitable") {
		t.Errorf("false positive kept: %+v", fp)
	}
	if fs[2].Severity != "medium" || !strings.Contains(fs[2].Description, "Confirmed") {
		t.Errorf("xss: %+v", fs[2])
	}
	loc, _ := LocateImport("import-sast-checkmarx", "checkmarx", readImportFixture(t, "checkmarx.xml"), sqli.Fingerprint)
	if !strings.Contains(string(loc.Raw), "OrderController.java") || !strings.Contains(string(loc.Raw), "-1823745521") {
		t.Errorf("record keeps the path: %s", loc.Raw)
	}
	// Identity follows the similarity ID, not the line.
	moved := strings.Replace(string(readImportFixture(t, "checkmarx.xml")), `Line="42"`, `Line="57"`, 1)
	m, _ := ParseImport("import-sast-checkmarx", "checkmarx", []byte(moved))
	if m[0].Fingerprint != sqli.Fingerprint {
		t.Error("fingerprint must survive code moving")
	}
}

func TestImportXMLSafety(t *testing.T) {
	laughs := `<?xml version="1.0"?>
<!DOCTYPE CxXMLResults [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<CxXMLResults><Query name="&lol3;" Severity="High"><Result FileName="a.java" Line="1"/></Query></CxXMLResults>`
	if fs, err := ParseImport("import-sast-cx", "checkmarx", []byte(laughs)); err == nil || len(fs) != 0 {
		t.Errorf("entity expansion must fail: %v %+v", err, fs)
	}
	xxe := `<?xml version="1.0"?>
<!DOCTYPE issues [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<issues burpVersion="1"><issue><type>1</type><name>&xxe;</name><host>https://x.test</host><path>/</path><severity>High</severity></issue></issues>`
	fs, err := ParseImport("import-dast-burp", "burp", []byte(xxe))
	if err == nil {
		t.Error("external entity must fail")
	}
	for _, f := range fs {
		if strings.Contains(f.Title+f.Description, "root:") {
			t.Fatal("external entity expanded")
		}
	}
	for _, format := range []string{"openvas", "nessus", "zap"} {
		doc := `<?xml version="1.0"?><!DOCTYPE report [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><report format_id="x"><report><results><result><name>&xxe;</name><host>1.2.3.4</host></result></results></report></report>`
		if format == "nessus" {
			doc = `<?xml version="1.0"?><!DOCTYPE NessusClientData_v2 [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><NessusClientData_v2><Report><ReportHost name="h"><ReportItem pluginID="1" pluginName="&xxe;" severity="1" port="1" protocol="tcp"/></ReportHost></Report></NessusClientData_v2>`
		}
		if format == "zap" {
			doc = `<?xml version="1.0"?><!DOCTYPE OWASPZAPReport [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><OWASPZAPReport><site name="https://x"><alerts><alertitem><pluginid>1</pluginid><name>&xxe;</name><riskcode>1</riskcode></alertitem></alerts></site></OWASPZAPReport>`
		}
		fs, err := ParseImport("import-other-x", format, []byte(doc))
		if err == nil {
			t.Errorf("%s: external entity must fail", format)
		}
		for _, f := range fs {
			if strings.Contains(f.Title+f.Description, "root:") {
				t.Fatalf("%s: external entity expanded", format)
			}
		}
	}
	sjis := `<?xml version="1.0" encoding="Shift_JIS"?><CxXMLResults><Query name="q" Severity="High"><Result FileName="a.java" Line="1"/></Query></CxXMLResults>`
	if _, err := ParseImport("import-sast-cx", "checkmarx", []byte(sjis)); err == nil {
		t.Error("unsupported encodings are rejected")
	}
	latin1 := "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><CxXMLResults><Query name=\"Caf\xe9_Query\" Severity=\"High\"><Result FileName=\"a.java\" Line=\"1\"/></Query></CxXMLResults>"
	if fs, err := ParseImport("import-sast-cx", "checkmarx", []byte(latin1)); err != nil || len(fs) != 1 || fs[0].Title != "Café Query" {
		t.Errorf("latin1: %v %+v", err, fs)
	}
}

func TestMarkupToText(t *testing.T) {
	got := markupToText("<p>One &amp; two</p><ul><li>a</li><li>b</li></ul>")
	if got != "One & two\na\nb" {
		t.Errorf("%q", got)
	}
	if c := clipText(strings.Repeat("é", 10), 5); !strings.HasSuffix(c, "[truncated]") || strings.ContainsRune(c, '�') {
		t.Errorf("%q", c)
	}
}
