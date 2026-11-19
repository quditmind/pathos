package scanners

import (
	"archive/zip"
	"bytes"
	"os"
	"strings"
	"testing"
)

// Fixtures of the SAST and code quality import formats
// (testdata/imports). Sources:
//
//   - bearer.json: real run of bearer/bearer:latest (Bearer 2.1.3,
//     `bearer scan --format json`) on a small Express sample.
//   - brakeman.json: real run of Brakeman 6.2.2 (gem install in
//     ruby:3.3-slim, `brakeman -f json`) on a minimal Rails 6.1 app.
//   - horusec.json: real run of horuszup/horusec-cli:latest (Horusec
//     v2.8.0, `horusec start -o json --disable-docker`) on a small JS and
//     Java sample (the hard-coded password is a dummy value).
//   - cppcheck.xml: real run of Cppcheck 2.17.1 (Debian package in
//     python:3.12-slim, `--enable=all --xml --xml-version=2`) on a small C
//     file.
//   - flawfinder.csv: real run of Flawfinder 2.0.20 (pip install in
//     python:3.12-slim, `flawfinder --csv`) on the same C file.
//   - spotbugs.xml: real run of SpotBugs 4.8.6 with FindSecBugs 1.13.0
//     (eclipse-temurin:21-jdk, `-xml:withMessages`) on a compiled Java
//     class.
//   - pmd.xml: real run of PMD 7.7.0 (eclipse-temurin:21-jdk, `pmd check
//     -f xml` with the security, bestpractices and errorprone categories)
//     on the same Java class.
//   - fortify.fvdl, veracode.xml, coverity.json, appscan-source.ozasmt,
//     klocwork.json, klocwork-api.jsonl: commercial tools, built from the
//     vendors' published formats (FVDL schema, detailedreport.xsd,
//     cov-format-errors JSON v7, AppScan Source assessment XML, kwcheck
//     list JSON and the Klocwork Web API search output); not verified
//     against real exports.

func TestImportSASTFormats(t *testing.T) {
	runImportCases(t, []importCase{
		{file: "fortify.fvdl", format: "fortify", count: 2, checks: map[int]want{
			0: {sev: "critical", cwe: "CWE-89", file: "src/main/java/com/acme/OrderDao.java", line: 14, rule: "SQL Injection"},
			1: {sev: "high", cwe: "CWE-916", line: 18, rule: "Weak Cryptographic Hash"},
		}},
		{file: "veracode.xml", format: "veracode", count: 4, checks: map[int]want{
			0: {sev: "critical", cwe: "CWE-89", file: "com/acme/OrderDao.java", line: 14},
			1: {sev: "medium", cwe: "CWE-327", line: 18},
			2: {sev: "medium", cwe: "CWE-614", file: "https://shop.example/login"},
			3: {sev: "critical", cve: "CVE-2021-44228", cwe: "CWE-502", pkg: "log4j-core", ver: "2.14.1"},
		}, cats: map[int]string{0: "sast", 2: "dast", 3: "sca"}},
		{file: "coverity.json", format: "coverity", count: 2, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-89", file: "src/main/java/com/acme/OrderDao.java", line: 14, rule: "SQLI"},
			1: {sev: "medium", cwe: "CWE-476", line: 13, rule: "FORWARD_NULL"},
		}, cats: map[int]string{0: "sast", 1: "other"}},
		{file: "appscan-source.ozasmt", format: "appscan-source", count: 3, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-89", file: "src/main/java/com/acme/OrderDao.java", line: 14, rule: "Validation.Required.SQL"},
			1: {sev: "medium", cwe: "CWE-327", line: 18},
			2: {sev: "low", cwe: "CWE-338", line: 24},
		}},
		{file: "klocwork.json", format: "klocwork", count: 3, checks: map[int]want{
			0: {sev: "critical", cwe: "CWE-788", file: "src/vuln.c", line: 13, rule: "ABV.GENERAL"},
			1: {sev: "high", cwe: "CWE-120", line: 7, rule: "SV.STRBO.UNBOUND_COPY"},
			2: {sev: "high", rule: "MLK.MUST"},
		}},
		{file: "klocwork-api.jsonl", format: "klocwork", count: 2, checks: map[int]want{
			0: {sev: "critical", file: "builds/app/src/vuln.c", rule: "SV.TAINTED.INJECTION"},
			1: {sev: "low", rule: "MISRA.FUNC.UNUSEDPAR"},
		}, cats: map[int]string{0: "sast", 1: "other"}},
		{file: "horusec.json", format: "horusec", count: 5, checks: map[int]want{
			0: {sev: "critical", cwe: "CWE-798", file: "config.js", line: 2, rule: "HS-LEAKS-26"},
			1: {sev: "high", file: "config.js", line: 5, rule: "HS-JAVASCRIPT-4"},
		}, cats: map[int]string{0: "secrets", 1: "sast"}, secrets: []string{"Sup3rS3cretPassw0rd!"}},
		{file: "bearer.json", format: "bearer", count: 5, checks: map[int]want{
			0: {sev: "critical", cwe: "CWE-95", file: "app.js", line: 5, rule: "javascript_lang_eval_user_input"},
			1: {sev: "high", cwe: "CWE-79", line: 7},
			4: {sev: "medium", rule: "javascript_lang_weak_hash_md5", line: 6},
		}},
		{file: "brakeman.json", format: "brakeman", count: 4, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-77", file: "app/controllers/users_controller.rb", line: 4, rule: "Execute"},
		}},
		{file: "cppcheck.xml", format: "cppcheck", count: 8, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-788", file: "vuln.c", line: 13, rule: "arrayIndexOutOfBounds"},
			1: {sev: "high", cwe: "CWE-401", line: 17, rule: "memleak"},
			2: {sev: "low", cwe: "CWE-398", rule: "constParameterPointer"},
		}, cats: map[int]string{0: "sast", 2: "other"}},
		{file: "spotbugs.xml", format: "spotbugs", count: 11, checks: map[int]want{
			0:  {sev: "high", cwe: "CWE-440", file: "com/acme/OrderDao.java", line: 24, rule: "DMI_RANDOM_USED_ONLY_ONCE"},
			7:  {sev: "medium", cwe: "CWE-89", file: "com/acme/OrderDao.java", line: 14, rule: "SQL_INJECTION_JDBC"},
			10: {sev: "high", cwe: "CWE-328", line: 18, rule: "WEAK_MESSAGE_DIGEST_MD5"},
		}, cats: map[int]string{0: "other", 7: "sast", 10: "sast"}},
		{file: "pmd.xml", format: "pmd", count: 5, checks: map[int]want{
			0: {sev: "low", file: "src/main/java/com/acme/OrderDao.java", line: 13, rule: "CloseResource"},
			4: {sev: "medium", line: 30, rule: "SystemPrintln"},
		}, cats: map[int]string{0: "other"}},
		{file: "flawfinder.csv", format: "flawfinder", count: 5, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-120", file: "vuln.c", line: 7, rule: "FF1001"},
			2: {sev: "high", cwe: "CWE-78", line: 16, rule: "FF1044"},
			3: {sev: "low", cwe: "CWE-119", line: 6},
		}},
	})
}

func TestImportFortifyFPR(t *testing.T) {
	fvdl := readImport(t, "fortify.fvdl")
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string][]byte{"audit.xml": []byte("<Audit/>"), "audit.fvdl": fvdl} {
		w, _ := zw.Create(name)
		_, _ = w.Write(body)
	}
	_ = zw.Close()
	fpr := buf.Bytes()
	want, _ := ParseImport("import-sast-fortify", "fortify", fvdl)
	got, err := ParseImport("import-sast-fortify", "fortify", fpr)
	if err != nil || len(got) != len(want) || got[0].Fingerprint != want[0].Fingerprint {
		t.Fatalf("FPR: %v %d", err, len(got))
	}
	if loc, err := LocateImport("import-sast-fortify", "fortify", fpr, got[1].Fingerprint); err != nil || !strings.Contains(string(loc.Raw), "Weak Cryptographic Hash") {
		t.Errorf("locate in FPR: %v", err)
	}
	// An archive without audit.fvdl is an error.
	buf.Reset()
	zw = zip.NewWriter(&buf)
	w, _ := zw.Create("audit.xml")
	_, _ = w.Write([]byte("<Audit/>"))
	_ = zw.Close()
	if _, err := ParseImport("import-sast-fortify", "fortify", buf.Bytes()); err == nil {
		t.Error("FPR without audit.fvdl accepted")
	}
}

func TestImportSASTNotes(t *testing.T) {
	// Veracode: the fixed flaw is not imported, the accepted mitigation is
	// low confidence and noted.
	fs, _ := ParseImport("import-sast-veracode", "veracode", readImport(t, "veracode.xml"))
	for _, f := range fs {
		if f.FilePath == "com/acme/Legacy.java" {
			t.Error("fixed Veracode flaw imported")
		}
	}
	if fs[1].Confidence != "low" || !strings.Contains(fs[1].Description, "Mitigate by Design") {
		t.Errorf("mitigation: %+v", fs[1])
	}
	// Coverity triage, Klocwork status: low confidence, noted.
	cov, _ := ParseImport("import-other-cov", "coverity", readImport(t, "coverity.json"))
	if cov[1].Confidence != "low" || !strings.Contains(cov[1].Description, "False Positive") {
		t.Errorf("coverity triage: %+v", cov[1])
	}
	kw, _ := ParseImport("import-sast-kw", "klocwork", readImport(t, "klocwork.json"))
	if kw[2].Confidence != "low" || !strings.Contains(kw[2].Description, "Not a Problem") {
		t.Errorf("klocwork status: %+v", kw[2])
	}
	// Cppcheck's own diagnostics are not findings.
	cpp, _ := ParseImport("import-other-cpp", "cppcheck", readImport(t, "cppcheck.xml"))
	for _, f := range cpp {
		if f.RuleID == "missingIncludeSystem" || f.RuleID == "checkersReport" {
			t.Errorf("diagnostic imported: %s", f.RuleID)
		}
	}
}

func TestImportSASTEmptyAndMalformed(t *testing.T) {
	for doc, f := range map[string]string{
		`{"type":"Coverity issues","formatVersion":7,"issues":[]}`:                                             "coverity",
		`{"version":"v2.8.0","status":"success","analysisVulnerabilities":null}`:                               "horusec",
		`{"scan_info":{"app_path":"/app"},"warnings":[],"ignored_warnings":[],"errors":[]}`:                    "brakeman",
		`<?xml version="1.0"?><results version="2"><cppcheck version="2.17.1"/><errors></errors></results>`:    "cppcheck",
		"File,Line,Column,DefaultLevel,Level,Category,Name,Warning,Suggestion,Note,CWEs,Context,Fingerprint\n": "flawfinder",
		`<FVDL version="1.12"><Vulnerabilities/></FVDL>`:                                                       "fortify",
		`<detailedreport report_format_version="1.5"></detailedreport>`:                                        "veracode",
		`<AssessmentRun name="x"><FindingDataPool/></AssessmentRun>`:                                           "appscan-source",
		`<BugCollection version="4.8.6"><Project/></BugCollection>`:                                            "spotbugs",
		`<pmd version="7.7.0"></pmd>`:                                                                          "pmd",
	} {
		if got := DetectImportFormat([]byte(doc)); got != f {
			t.Errorf("%s: detected %q, want %q", doc, got, f)
		}
		if fs, err := ParseImport("import-other-x", f, []byte(doc)); err != nil || len(fs) != 0 {
			t.Errorf("%s: %v %d", f, err, len(fs))
		}
	}
	for f, doc := range map[string]string{
		"coverity":       `{"type":"Coverity issues","issues":[{"mergeKey":"x"}]}`,
		"horusec":        `{"analysisVulnerabilities":[{"vulnerabilities":{"file":"a.js"}}]}`,
		"brakeman":       `{"scan_info":{},"warnings":[{"file":"a.rb"}]}`,
		"bearer":         `{"high":[{"cwe_ids":["79"],"fingerprint":"x"}]}`,
		"klocwork":       `[{"severityCode":1,"file":"a.c","status":"Analyze"}]`,
		"flawfinder":     "File,Line,Level,Warning,CWEs\na.c,1,9,x,CWE-1\n",
		"cppcheck":       `<results version="2"><cppcheck/><errors><error severity="error"/></errors></results>`,
		"fortify":        `<FVDL><Vulnerabilities><Vulnerability><ClassInfo/></Vulnerability></Vulnerabilities></FVDL>`,
		"veracode":       `<detailedreport><severity level="5"><category><cwe><staticflaws><flaw severity="5"/></staticflaws></cwe></category></severity></detailedreport>`,
		"spotbugs":       `<BugCollection><BugInstance priority="1"/></BugCollection>`,
		"pmd":            `<pmd><file name="a.java"><violation beginline="1">x</violation></file></pmd>`,
		"appscan-source": `<AssessmentRun><FindingDataPool><FindingData id="1" vtype="9"/></FindingDataPool></AssessmentRun>`,
	} {
		if _, err := ParseImport("import-other-x", f, []byte(doc)); err == nil {
			t.Errorf("%s: malformed record accepted", f)
		}
	}
}

// TestImportSASTFormatsDoNotOverlap checks each of these matchers accepts
// its own fixtures and no other fixture in testdata/imports (detection
// order is tested by TestImportFixturesDetectOnlyAsTheirFormat).
func TestImportSASTFormatsDoNotOverlap(t *testing.T) {
	ids := []string{"fortify", "veracode", "coverity", "appscan-source", "klocwork", "horusec", "bearer", "brakeman",
		"spotbugs", "pmd", "cppcheck", "flawfinder"}
	entries, err := os.ReadDir("testdata/imports")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		raw, err := os.ReadFile("testdata/imports/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		p := newImportProbe(raw)
		for _, id := range ids {
			own := e.Name() == id || strings.HasPrefix(e.Name(), id+".") || strings.HasPrefix(e.Name(), id+"-")
			f, ok := importFormats[id]
			if !ok {
				t.Fatalf("%s not registered", id)
			}
			if got := f.match(p); got != own {
				t.Errorf("%s: matcher of %s says %v", e.Name(), id, got)
			}
		}
	}
}

func TestImportBearerSecretsAreRemoved(t *testing.T) {
	raw := []byte(`{"high":[{"cwe_ids":["798"],"id":"javascript_lang_hardcoded_secret","title":"Hard-coded secret","line_number":3,` +
		`"filename":"config.js","source":{"start":3,"end":3},"sink":{"start":3,"end":3,"content":"const key = \"sk_live_DUMMYSECRET123\""},` +
		`"fingerprint":"abc_0","code_extract":"const key = \"sk_live_DUMMYSECRET123\""}]}`)
	stored := SanitizeImport("bearer", raw)
	if strings.Contains(string(stored), "DUMMYSECRET") || !strings.Contains(string(stored), "config.js") {
		t.Fatalf("stored: %s", stored)
	}
	fs, err := ParseImport("import-other-bearer", "", stored)
	if err != nil || len(fs) != 1 || fs[0].Category != "secrets" || fs[0].CWE[0] != "CWE-798" {
		t.Fatalf("%v %+v", err, fs)
	}
	orig, _ := ParseImport("import-other-bearer", "bearer", raw)
	if orig[0].Fingerprint != fs[0].Fingerprint {
		t.Error("identity depends on the secret")
	}
	loc, err := LocateImport("import-other-bearer", "bearer", raw, fs[0].Fingerprint)
	if err != nil || strings.Contains(string(loc.Raw), "DUMMYSECRET") {
		t.Errorf("located record: %v %s", err, loc.Raw)
	}
}
