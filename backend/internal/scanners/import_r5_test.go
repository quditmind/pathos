package scanners

import (
	"slices"
	"strings"
	"testing"
)

// Cloud posture, container, IAST and bug bounty import formats. None of
// these fixtures comes from a real run: the open-source tools (Prowler,
// ScoutSuite, CloudSploit) need a cloud account and the others are
// commercial services. Each fixture was written by hand from the published
// format, using the documentation and the open-source DefectDojo parser
// test samples (github.com/DefectDojo/django-DefectDojo, unittests/scans)
// to learn the structure. Account IDs, hosts and secrets are fake; secrets
// are planted to test redaction.
//
//	prowler.json, prowler-v3.json, prowler-csv.csv  Prowler OCSF output (docs.prowler.com, "Reporting"), Prowler 3 JSON and CSV; DefectDojo prowler and aws_prowler_v3plus samples
//	scoutsuite.js                                   ScoutSuite scoutsuite_results_*.js (github.com/nccgroup/ScoutSuite); DefectDojo scout_suite samples
//	asff.json                                       AWS Security Finding Format (docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)
//	inspector2.json                                 Amazon Inspector ListFindings (docs.aws.amazon.com/inspector/v2/APIReference/API_Finding.html)
//	defender-cloud.json                             Defender for Cloud Assessments - List (learn.microsoft.com/rest/api/defenderforcloud/assessments/list)
//	gcp-scc.json                                    Security Command Center ListFindingsResult / Finding (docs.cloud.google.com/security-command-center/docs/reference/rest)
//	cloudsploit.json                                CloudSploit --json output (github.com/aquasecurity/cloudsploit); DefectDojo cloudsploit samples
//	anchore.json, anchore-anchorectl.json           anchore-cli image vuln --json and anchorectl image vulnerabilities -o json; DefectDojo anchore_engine and anchorectl_vulns samples
//	twistlock.json, twistlock-csv.csv               twistcli images scan output and the Prisma Cloud Compute vulnerability CSV; DefectDojo twistlock samples
//	sysdig.json, sysdig-report.json, sysdig-csv*.csv sysdig-cli-scanner --json-scan-result and Sysdig report JSON and CSV; DefectDojo sysdig_cli and sysdig_reports samples
//	contrast.csv                                    Contrast Assess vulnerability CSV export; DefectDojo contrast samples
//	hackerone.json, hackerone-csv.csv               HackerOne API GET /v1/reports (api.hackerone.com/customer-resources) and the report CSV export; DefectDojo h1 samples
//	bugcrowd.csv                                    Bugcrowd submissions CSV export; DefectDojo bugcrowd samples
//	intigriti.json                                  Intigriti external API submissions; DefectDojo intigriti samples

func TestImportProwler(t *testing.T) {
	fs := checkImport(t, "prowler.json", "prowler", "import-other-prowler", 2) // PASS skipped
	aa := fs[0]
	if aa.Category != "misconfiguration" || aa.Severity != "low" || aa.RuleID != "accessanalyzer_enabled" ||
		aa.FilePath != "arn:aws:accessanalyzer:eu-west-1:123456789012:analyzer/unknown" || !strings.Contains(aa.Description, "CIS-3.0: 1.20") ||
		!strings.Contains(aa.Description, "is not enabled") {
		t.Errorf("ocsf: %+v", aa)
	}
	if s3 := fs[1]; s3.Severity != "high" || s3.Confidence != "low" || !strings.Contains(s3.Description, "muted") {
		t.Errorf("muted finding kept with low confidence: %+v", s3)
	}
	v3 := checkImport(t, "prowler-v3.json", "prowler", "import-other-prowler", 1)
	if v3[0].Severity != "medium" || v3[0].RuleID != "ec2_ebs_default_encryption" || v3[0].FilePath != "arn:aws:ec2:eu-west-1:123456789012:volume" {
		t.Errorf("v3: %+v", v3[0])
	}
	c := checkImport(t, "prowler-csv.csv", "prowler-csv", "import-other-prowler", 1) // MANUAL and PASS skipped
	if c[0].Severity != "high" || c[0].RuleID != "cloudtrail_multi_region_enabled" || c[0].FilePath != "arn:aws:cloudtrail:eu-west-1:123456789012:trail" ||
		!strings.Contains(c[0].Description, "No CloudTrail trails") {
		t.Errorf("csv: %+v", c[0])
	}
	// A declared category applies to every finding.
	if d, _ := ParseImport("import-iac-prowler", "prowler", readImportFixture(t, "prowler.json")); d[0].Category != "iac" {
		t.Errorf("declared category: %+v", d[0])
	}
}

func TestImportScoutSuite(t *testing.T) {
	fs := checkImport(t, "scoutsuite.js", "scoutsuite", "import-other-scoutsuite", 3) // the rule without flagged items is skipped
	ssh := fs[0]
	if ssh.Severity != "high" || ssh.RuleID != "ec2-security-group-opens-SSH-port-to-all" || ssh.Category != "misconfiguration" ||
		!strings.Contains(ssh.FilePath, "sg-0123456789abcdef0") || strings.HasSuffix(ssh.FilePath, "TCP-22") || !strings.Contains(ssh.Description, "CIS Amazon") {
		t.Errorf("ssh: %+v", ssh)
	}
	if fs[1].FilePath == ssh.FilePath || fs[2].Severity != "medium" || fs[2].FilePath != "s3.buckets.example-logs-bucket" {
		t.Errorf("items: %+v %+v", fs[1], fs[2])
	}
	// The JSON document alone (without the JavaScript assignment) is accepted.
	js := readImportFixture(t, "scoutsuite.js")
	if DetectImportFormat(scoutJSON(js)) != "scoutsuite" {
		t.Error("plain JSON results not detected")
	}
}

func TestImportASFF(t *testing.T) {
	fs := checkImport(t, "asff.json", "asff", "import-other-security-hub", 2) // PASSED and ARCHIVED skipped
	iam := fs[0]
	if iam.Category != "misconfiguration" || iam.Severity != "medium" || iam.RuleID != "IAM.5" || iam.FilePath != "arn:aws:iam::123456789012:user/deploy" {
		t.Errorf("control: %+v", iam)
	}
	v := fs[1]
	if v.Category != "container" || v.CVE != "CVE-2023-2650" || v.PackageName != "openssl" || v.PackageVersion != "1.1.1n-0+deb11u4" ||
		v.FixedVersion != "0:1.1.1n-0+deb11u5" || v.CVSS == nil || *v.CVSS != 6.5 || v.CVSSVersion != "3.1" || v.RuleID != "CVE-2023-2650" {
		t.Errorf("inspector via security hub: %+v", v)
	}
	// A bare array of ASFF findings is accepted too.
	arr := []byte(`[{"SchemaVersion":"2018-10-08","Id":"x","ProductArn":"arn:aws:securityhub:eu-west-1::product/aws/guardduty","GeneratorId":"g","AwsAccountId":"123456789012","Title":"t","Severity":{"Normalized":75},"Resources":[{"Type":"AwsEc2Instance","Id":"i-1"}]}]`)
	if DetectImportFormat(arr) != "asff" {
		t.Error("array of findings not detected")
	}
	if a, err := ParseImport("import-other-security-hub", "asff", arr); err != nil || len(a) != 1 || a[0].Severity != "high" {
		t.Errorf("normalized severity: %v %+v", err, a)
	}
}

func TestImportInspector2(t *testing.T) {
	fs := checkImport(t, "inspector2.json", "inspector2", "import-other-inspector", 3) // CLOSED skipped
	pkg := fs[0]
	if pkg.Category != "container" || pkg.CVE != "CVE-2021-3744" || pkg.PackageName != "linux" || pkg.PackageVersion != "4.19.118-2" ||
		pkg.FixedVersion != "0:4.19.232-1" || pkg.CVSS == nil || *pkg.CVSS != 5.5 || pkg.Severity != "medium" {
		t.Errorf("package: %+v", pkg)
	}
	code := fs[1]
	if code.Category != "sast" || code.FilePath != "orders/handler.py" || code.StartLine == nil || *code.StartLine != 42 ||
		!slices.Equal(code.CWE, []string{"CWE-89"}) || code.Confidence != "low" || code.RuleID != "python-sql-injection" {
		t.Errorf("code: %+v", code)
	}
	if n := fs[2]; n.Category != "other" || n.FilePath != "i-0123456789abcdef0" || !strings.Contains(n.Description, "TCP 22-22") {
		t.Errorf("network: %+v", n)
	}
	// The list-findings envelope parses with the format named. Detection of
	// {"findings": [...]} is taken by PATHOS findings JSON, which is checked
	// first (see the report to the lead).
	env := []byte(`{"findings":` + string(readImportFixture(t, "inspector2.json")) + `}`)
	if e, err := ParseImport("import-other-inspector", "inspector2", env); err != nil || len(e) != 3 {
		t.Errorf("envelope: %v %d", err, len(e))
	}
}

func TestImportDefenderCloud(t *testing.T) {
	raw := readImportFixture(t, "defender-cloud.json")
	fs := checkImport(t, "defender-cloud.json", "defender-cloud", "import-other-defender", 2) // Healthy and NotApplicable skipped
	st := fs[0]
	if st.Severity != "high" || st.Category != "misconfiguration" || !strings.HasSuffix(st.FilePath, "storageAccounts/shopdata") ||
		st.RuleID != "1c5de8e1-f68d-6a17-e0d2-ec259c42768c" || st.Title != "Storage accounts should restrict network access" {
		t.Errorf("assessment: %+v", st)
	}
	if fs[1].Severity != "medium" || !strings.Contains(fs[1].Description, "no assessment metadata") {
		t.Errorf("no metadata: %+v", fs[1])
	}
	if strings.Contains(string(SanitizeImport("defender-cloud", raw)), "partner-secret-value") {
		t.Error("partner secret kept in the stored report")
	}
	if loc, _ := LocateImport("import-other-defender", "defender-cloud", raw, st.Fingerprint); strings.Contains(string(loc.Raw), "partner-secret-value") {
		t.Error("partner secret in the located record")
	}
	// Azure Resource Graph rows (lower-case type) in its response envelope.
	arg := []byte(`{"count":1,"data":[{"id":"/subscriptions/s/resourceGroups/r/providers/Microsoft.Web/sites/w/providers/Microsoft.Security/assessments/a1","name":"a1","type":"microsoft.security/assessments","properties":{"displayName":"Web apps should only be accessible over HTTPS","status":{"code":"Unhealthy"},"resourceDetails":{"Source":"Azure","Id":"/subscriptions/s/resourceGroups/r/providers/Microsoft.Web/sites/w"},"metadata":{"severity":"Medium"}}}]}`)
	if DetectImportFormat(arg) != "defender-cloud" {
		t.Error("resource graph rows not detected")
	}
	if a, err := ParseImport("import-other-defender", "", arg); err != nil || len(a) != 1 || a[0].Severity != "medium" {
		t.Errorf("resource graph: %v %+v", err, a)
	}
}

func TestImportGCPSCC(t *testing.T) {
	fs := checkImport(t, "gcp-scc.json", "gcp-scc", "import-other-scc", 3) // INACTIVE skipped
	if b := fs[0]; b.Category != "misconfiguration" || b.Severity != "high" || b.RuleID != "PUBLIC_BUCKET_ACL" ||
		b.FilePath != "//storage.googleapis.com/example-shop-uploads" || !strings.Contains(b.Description, "cis 1.3 5.1") {
		t.Errorf("misconfiguration: %+v", b)
	}
	if v := fs[1]; v.Category != "sca" || v.CVE != "CVE-2024-5535" || v.PackageName != "openssl" || v.FixedVersion != "3.0.14" ||
		v.Severity != "critical" || v.CVSS == nil || *v.CVSS != 9.1 {
		t.Errorf("vulnerability: %+v", v)
	}
	if th := fs[2]; th.Category != "other" || th.Confidence != "low" || !strings.Contains(th.Description, "muted") {
		t.Errorf("muted threat: %+v", th)
	}
	list := []byte(`{"listFindingsResults":` + string(readImportFixture(t, "gcp-scc.json")) + `,"totalSize":4}`)
	if DetectImportFormat(list) != "gcp-scc" {
		t.Error("REST list response not detected")
	}
}

func TestImportCloudSploit(t *testing.T) {
	fs := checkImport(t, "cloudsploit.json", "cloudsploit", "import-other-cloudsploit", 3) // OK skipped
	if fs[0].Severity != "medium" || fs[0].RuleID != "openSSH" || !strings.Contains(fs[0].FilePath, "sg-0123456789abcdef0") {
		t.Errorf("fail: %+v", fs[0])
	}
	if fs[1].Severity != "low" || fs[2].Severity != "info" || fs[2].FilePath != "cloud/ap-south-1" {
		t.Errorf("warn/unknown: %+v %+v", fs[1], fs[2])
	}
}

func TestImportAnchore(t *testing.T) {
	fs := checkImport(t, "anchore.json", "anchore", "import-container-anchore", 2)
	if v := fs[0]; v.Category != "container" || v.CVE != "CVE-2024-5535" || v.PackageName != "libssl3" || v.PackageVersion != "3.0.13-1~deb12u1" ||
		v.FixedVersion != "3.0.14-1~deb12u1" || v.Severity != "critical" || v.CVSS == nil || *v.CVSS != 9.1 ||
		!strings.HasPrefix(v.FilePath, "sha256:91f5c377") {
		t.Errorf("cli: %+v", v)
	}
	if v := fs[1]; v.FixedVersion != "" || !strings.Contains(v.Description, "BOOT-INF/lib/jackson-databind-2.9.7.jar") {
		t.Errorf("no fix: %+v", v)
	}
	ctl := checkImport(t, "anchore-anchorectl.json", "anchore", "import-container-anchore", 2)
	if ctl[0].Severity != "info" || ctl[1].PackageName != "libsystemd0" || ctl[1].FixedVersion != "232-25+deb9u10" {
		t.Errorf("anchorectl: %+v", ctl)
	}
}

func TestImportTwistlock(t *testing.T) {
	fs := checkImport(t, "twistlock.json", "twistlock", "import-container-prisma-cloud", 3)
	if v := fs[0]; v.CVE != "CVE-2024-5535" || v.FixedVersion != "3.0.14-1~deb12u1" || v.CVSS == nil || *v.CVSS != 9.1 ||
		v.FilePath != "registry.example.test/shop/api:1.4.2" || v.Severity != "critical" || v.CVSSVersion != "3.1" {
		t.Errorf("vulnerability: %+v", v)
	}
	if fs[1].FixedVersion != "" || fs[2].RuleID != "compliance-41" || fs[2].Severity != "high" {
		t.Errorf("no fix / compliance: %+v %+v", fs[1], fs[2])
	}
	if o, _ := ParseImport("import-other-prisma-cloud", "twistlock", readImportFixture(t, "twistlock.json")); o[2].Category != "misconfiguration" || o[0].Category != "container" {
		t.Errorf("natural categories: %+v", o)
	}
	c := checkImport(t, "twistlock-csv.csv", "twistlock-csv", "import-container-prisma-cloud", 2)
	if c[0].CVE != "CVE-2020-24977" || c[0].FixedVersion != "2.9.10-r4" || c[0].PackageName != "libxml2" || c[0].FilePath != "registry.example.test/shop/web:2.0.1" ||
		c[0].CVSS == nil || *c[0].CVSS != 6.5 {
		t.Errorf("csv vulnerability: %+v", c[0])
	}
	if c[1].RuleID != "compliance-41" || c[1].Severity != "high" {
		t.Errorf("csv compliance: %+v", c[1])
	}
}

func TestImportSysdig(t *testing.T) {
	fs := checkImport(t, "sysdig.json", "sysdig", "import-container-sysdig", 3)
	if v := fs[0]; v.CVE != "CVE-2023-50782" || v.PackageName != "cryptography" || v.FixedVersion != "42.0.0" || v.Severity != "high" ||
		v.FilePath != "registry.example.test/shop/worker:3.1" || v.CVSSVersion != "3.1" {
		t.Errorf("cli: %+v", v)
	}
	if fs[1].Confidence != "low" || !strings.Contains(fs[1].Description, "accepted risk") || !strings.Contains(fs[2].Description, "public exploit") {
		t.Errorf("accepted risk / exploit: %+v %+v", fs[1], fs[2])
	}
	r := checkImport(t, "sysdig-report.json", "sysdig", "import-container-sysdig", 1)
	if r[0].CVE != "CVE-2022-48303" || r[0].Severity != "high" || !strings.Contains(r[0].Description, "prod-eu/shop/shop-api/api") {
		t.Errorf("report: %+v", r[0])
	}
	c := checkImport(t, "sysdig-csv.csv", "sysdig-csv", "import-container-sysdig", 2)
	if c[0].Severity != "critical" || c[0].FixedVersion != "2.9.8" || c[0].CVSS == nil || *c[0].CVSS != 9.8 || c[1].Confidence != "low" {
		t.Errorf("csv: %+v", c)
	}
	n := checkImport(t, "sysdig-csv-2025.csv", "sysdig-csv", "import-container-sysdig", 1)
	if n[0].CVE != "CVE-2023-4911" || n[0].PackageName != "libc6" || n[0].Severity != "high" || n[0].FilePath != "registry.example.test/shop/api:1.4.2" {
		t.Errorf("2025 csv: %+v", n[0])
	}
}

func TestImportContrast(t *testing.T) {
	raw := readImportFixture(t, "contrast.csv")
	fs := checkImport(t, "contrast.csv", "contrast", "import-other-contrast", 2) // Fixed skipped
	sqli := fs[0]
	if sqli.Severity != "critical" || sqli.RuleID != "sql-injection" || !slices.Equal(sqli.CWE, []string{"CWE-89"}) || sqli.FilePath != "shop-api/api/orders" ||
		!strings.Contains(sqli.Description, "GET /api/orders?id=1") {
		t.Errorf("sqli: %+v", sqli)
	}
	if fs[1].Confidence != "low" || !strings.Contains(fs[1].Description, "Not a Problem") {
		t.Errorf("not a problem: %+v", fs[1])
	}
	assertNoSecrets(t, "contrast", "import-other-contrast", raw, fs, "planted-token-123456", "planted-password-xyz")
}

func TestImportHackerOne(t *testing.T) {
	raw := readImportFixture(t, "hackerone.json")
	fs := checkImport(t, "hackerone.json", "hackerone", "import-other-hackerone", 2) // resolved skipped
	idor := fs[0]
	if idor.Severity != "high" || idor.CVSS == nil || *idor.CVSS != 7.5 || !slices.Equal(idor.CWE, []string{"CWE-639"}) ||
		idor.FilePath != "https://shop.example.test" || idor.RuleID != "cwe-639" || !strings.Contains(idor.Description, "GET /api/orders/1002") {
		t.Errorf("idor: %+v", idor)
	}
	if fs[1].Confidence != "low" || !strings.Contains(fs[1].Description, "duplicate") {
		t.Errorf("duplicate: %+v", fs[1])
	}
	assertNoSecrets(t, "hackerone", "import-other-hackerone", raw, fs, "planted-session-cookie-1", "planted-bearer-token-abcdef")
	c := checkImport(t, "hackerone-csv.csv", "hackerone-csv", "import-other-hackerone", 2)
	if c[0].Severity != "low" || c[0].FilePath != "shop.example.test" || c[1].CVE != "CVE-2020-11022" || c[1].Confidence != "low" {
		t.Errorf("csv: %+v", c)
	}
}

func TestImportBugcrowd(t *testing.T) {
	raw := readImportFixture(t, "bugcrowd.csv")
	fs := checkImport(t, "bugcrowd.csv", "bugcrowd", "import-other-bugcrowd", 2) // resolved skipped
	if s := fs[0]; s.Severity != "critical" || s.RuleID != "Server-Side Injection > SQL Injection" || !slices.Equal(s.CWE, []string{"CWE-89"}) ||
		s.FilePath != "https://shop.example.test/products?filter=1" || !strings.Contains(s.Description, "Host: shop.example.test") {
		t.Errorf("p1: %+v", s)
	}
	if fs[1].Severity != "info" || fs[1].Confidence != "low" {
		t.Errorf("not applicable: %+v", fs[1])
	}
	assertNoSecrets(t, "bugcrowd", "import-other-bugcrowd", raw, fs, "planted-php-session-42", "planted-api-key-77")
}

func TestImportIntigriti(t *testing.T) {
	raw := readImportFixture(t, "intigriti.json")
	fs := checkImport(t, "intigriti.json", "intigriti", "import-other-intigriti", 2) // resolved skipped
	if s := fs[0]; s.Severity != "critical" || !slices.Equal(s.CWE, []string{"CWE-200"}) || s.FilePath != "https://shop.example.test/reset" ||
		s.CVSSVersion != "3.1" || strings.Contains(s.Description, "<p>") || !strings.Contains(s.Description, "follow the external link") {
		t.Errorf("exceptional: %+v", s)
	}
	if fs[1].Severity != "low" || fs[1].Confidence != "low" || !strings.Contains(fs[1].Description, "Out of scope") {
		t.Errorf("out of scope: %+v", fs[1])
	}
	assertNoSecrets(t, "intigriti", "import-other-intigriti", raw, fs, "planted-reset-token-999", "planted-intigriti-bearer-123")
}

// assertNoSecrets checks planted secrets are absent from the stored
// (sanitised) report, the findings' text and the located records, and
// that identity does not depend on them.
func assertNoSecrets(t *testing.T, format, key string, raw []byte, fs []Finding, secrets ...string) {
	t.Helper()
	stored := SanitizeImport(format, raw)
	clean, err := ParseImport(key, format, stored)
	if err != nil || len(clean) != len(fs) {
		t.Fatalf("%s: sanitised report: %v, %d findings", format, err, len(clean))
	}
	for i, f := range fs {
		if clean[i].Fingerprint != f.Fingerprint {
			t.Errorf("%s: finding %d: identity depends on redacted values", format, i)
		}
		for _, src := range [][]byte{raw, stored} {
			loc, err := LocateImport(key, format, src, f.Fingerprint)
			if err != nil {
				t.Fatalf("%s: locate: %v", format, err)
			}
			for _, s := range secrets {
				if strings.Contains(string(loc.Raw), s) {
					t.Errorf("%s: %q in the located record", format, s)
				}
			}
		}
		for _, s := range secrets {
			if strings.Contains(f.Title+f.Description+f.FilePath, s) {
				t.Errorf("%s: %q in finding %d", format, s, i)
			}
		}
	}
	for _, s := range secrets {
		if strings.Contains(string(stored), s) {
			t.Errorf("%s: %q in the stored report", format, s)
		}
	}
}

// TestImportG5Neighbours checks near-identical shapes are told apart.
func TestImportG5Neighbours(t *testing.T) {
	for doc, want := range map[string]string{
		// Grype has "matches"; Anchore vulnerabilities do not.
		`{"matches":[],"source":{"type":"image"}}`:                                  "grype",
		`{"imageDigest":"sha256:1","vulnerabilities":[]}`:                           "anchore",
		`{"imageDigest":"sha256:1","vulnerability_type":"os","vulnerabilities":[]}`: "anchore",
		// Snyk's "vulnerabilities" carries packageManager.
		`{"vulnerabilities":[],"ok":true,"dependencyCount":3,"packageManager":"npm"}`: "snyk",
		// Twistlock results need distro; other "results" documents are not taken.
		`{"results":[{"id":"x","name":"n","vulnerabilities":[]}]}`: "",
		// Harbor reports are keyed by their MIME type, not "results".
		`{"application/vnd.security.vulnerability.report; version=1.1":{"vulnerabilities":[]}}`: "",
		// Sysdig needs its scanner name.
		`{"scanner":{"name":"trivy"},"result":{}}`: "",
		// An empty ASFF envelope; other "Findings" documents with more keys are not taken.
		`{"Findings":[]}`: "asff",
		`{"Findings":[],"Summary":{},"Version":"1"}`: "",
		// A HackerOne JSON:API document of another type.
		`{"data":[{"id":"1","type":"program","attributes":{},"relationships":{}}]}`: "",
		// Intigriti needs code, state and severity objects.
		`{"records":[{"code":"x","title":"t"}]}`: "",
	} {
		got := DetectImportFormat([]byte(doc))
		mine := []string{"prowler", "scoutsuite", "asff", "inspector2", "defender-cloud", "gcp-scc", "cloudsploit", "anchore", "twistlock",
			"sysdig", "contrast", "hackerone", "intigriti"}
		if (want != "" && got != want) || (want == "" && slices.Contains(mine, got)) {
			t.Errorf("%s: detected %q, want %q", doc, got, want)
		}
	}
	// Bugcrowd and Intigriti and HackerOne CSVs; the generic CSV keeps its own.
	bugcrowd := "reference_number,bounty_code,title,priority,vrt_lineage,substate,bug_url\nr1,b,T,2,X,unresolved,https://a.example\n"
	if DetectImportFormat([]byte(bugcrowd)) != "bugcrowd" {
		t.Error("bugcrowd CSV")
	}
	if DetectImportFormat([]byte("title,severity,priority,bug_url\nT,high,2,https://a.example\n")) != "csv" {
		t.Error("a generic CSV with some Bugcrowd columns stays generic")
	}
	if DetectImportFormat([]byte("CHECK_ID;CHECK_TITLE;STATUS;SEVERITY\nx;y;FAIL;high\n")) == "prowler-csv" {
		t.Error("prowler CSV needs its provider and resource columns")
	}
	// Prowler OCSF vs other OCSF producers and ASFF vs Inspector: the
	// fixtures of each are matched by exactly one detector
	// (TestImportFixturesMatchOneFormat); an Inspector finding is not ASFF.
	if DetectImportFormat(readImportFixture(t, "inspector2.json")) != "inspector2" || DetectImportFormat(readImportFixture(t, "asff.json")) != "asff" {
		t.Error("inspector2 / asff")
	}
	// Malformed records are errors.
	for f, doc := range map[string]string{
		"prowler":   `[{"Status":"FAIL"}]`,
		"asff":      `{"Findings":[{"Title":"x"}]}`,
		"anchore":   `[{"severity":"High"}]`,
		"bugcrowd":  "reference_number,bounty_code,title,priority,vrt_lineage,substate,bug_url\n,b,,2,X,unresolved,u\n",
		"intigriti": `{"records":[{"title":"x"}]}`,
	} {
		if _, err := ParseImport("import-other-x", f, []byte(doc)); err == nil {
			t.Errorf("%s: malformed record accepted", f)
		}
	}
	// Empty reports of a named format are complete results.
	for f, doc := range map[string]string{"prowler": `[]`, "cloudsploit": `[]`, "asff": `{"Findings":[]}`, "inspector2": `{"findings":[]}`,
		"defender-cloud": `{"value":[]}`, "gcp-scc": `[]`, "anchore": `[]`, "twistlock": `{"results":[]}`, "hackerone": `{"data":[]}`, "intigriti": `{"records":[]}`} {
		if fs, err := ParseImport("import-other-x", f, []byte(doc)); err != nil || len(fs) != 0 {
			t.Errorf("%s: empty report: %v %d", f, err, len(fs))
		}
	}
}
