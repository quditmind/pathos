package scanners

import (
	"slices"
	"strings"
	"testing"
)

// Import formats added in PATHOS 2.0 wave B (Order 500-799): named SARIF
// formats, compliance, cloud / CNAPP / EDR, commercial DAST and
// pentest services, and more open-source tools.
//
// Fixtures from a real run (docker run of the tool's official image or
// package, with the version pinned, against the small samples described
// in the docs: vulnerable Python/JS/C/C#/Kotlin/Ruby/PowerShell code,
// Terraform, a Kubernetes deployment, an Ansible playbook, a GitHub
// workflow, an OpenAPI file, an nginx configuration, a Python package, a
// local test web service and a local sshd; trimmed to a few results):
//
//	sarif-semgrep (Semgrep 1.140.0), devskim (DevSkim 1.0.67), psscriptanalyzer (PSScriptAnalyzer 1.24.0, ConvertToSARIF 1.0.0),
//	roslyn (.NET SDK 8, Microsoft.CodeAnalysis.NetAnalyzers, AnalysisMode All), infer (Infer 1.2.0), clang-analyzer (clang 19.1.7),
//	sarif-eslint (ESLint 9.39.1, @microsoft/eslint-formatter-sarif 3.1.0), sarif-brakeman (Brakeman 7.1.1), datadog-sast
//	(datadog-static-analyzer 0.7.3), detekt (1.23.8), sarif-kics (KICS 2.2.1), sarif-tfsec (tfsec 1.28.14), sarif-checkov
//	(Checkov 3.2.494), ansible-lint (25.11.0), sarif-zizmor (zizmor 1.16.3), spectral (Spectral CLI 6.15.0), sarif-grype
//	(Grype 0.102.0), sarif-trivy (Trivy 0.67.2), sarif-osv-scanner and sarif-gitleaks (the core scanner test reports),
//	openscap-xccdf and openscap-arf (OpenSCAP 1.4.6, SCAP Security Guide, Fedora 43 container, trimmed to four rules),
//	inspec (InSpec 5.22.80), lynis-report.dat (Lynis 3.1.4, Debian 13 container), kube-score (1.20.0), kubesec (2.14.2),
//	kubeaudit (0.22.2), datree (1.9.19, offline mode), cloud-custodian (c7n-left 0.3.33), nuclei-json (Nuclei 3.4.10),
//	trufflehog-v2 (truffleHog 2.2.1), git-secrets and git-secrets-history (git-secrets 1.3.0), arjun (Arjun 2.2.7),
//	gixy (gixy-ng 0.2.11), regula (Regula 3.2.1), ssh-audit (3.3.0), guarddog (GuardDog 2.7.1).
//
// xeol.json is Xeol's own JSON presenter test snapshot (xeol-io/xeol,
// TestJsonImgsPresenter.golden): Xeol cannot be run any more because its
// end-of-life database server (data.xeol.io) no longer resolves.
//
// All other fixtures were written by hand from the published format
// (vendor API references and schemas, the vendors' SDKs and the
// DefectDojo parser test samples) and are not verified against a real
// export: codeql, msvc-analyze, sonarlint, pysa and mariana-trench (from
// the SAPP SARIF exporter source), sarif-fortify, sarif-veracode,
// sarif-mend-sast, pvs-studio, binskim, sarif-snyk-iac, cis-cat,
// qualys-pc, aws-config*, azure-policy, steampipe, wiz-*, orca, lacework,
// aqua, snyk-container, snyk-iac, crowdstrike-spotlight, defender-vm,
// qualys-cs, tenable-was, insightvm, kiuwan*, checkmarx-one,
// checkmarx-sca, srcclr, fod, appscan-cloud, detectify, intruder,
// probely, edgescan, pentest-tools, appknox, immuniweb, trivy-operator.
// Hosts, accounts and secrets in them are fake.

func TestImportSARIFNamedFormats(t *testing.T) {
	for file, c := range map[string]struct {
		format, tool, cat string
		n                 int
	}{
		"codeql.sarif": {"codeql", "CodeQL", "sast", 2}, "sarif-semgrep.sarif": {"sarif-semgrep", "Semgrep", "sast", 4},
		"devskim.sarif": {"devskim", "DevSkim", "sast", 4}, "psscriptanalyzer.sarif": {"psscriptanalyzer", "PSScriptAnalyzer", "code-quality", 4},
		"msvc-analyze.sarif": {"msvc-analyze", "MSVC Code Analysis", "sast", 2}, "roslyn.sarif": {"roslyn", "Roslyn Analyzers", "code-quality", 4},
		"sonarlint.sarif": {"sonarlint", "SonarLint", "code-quality", 2}, "infer.sarif": {"infer", "Infer", "sast", 1},
		"pysa.sarif": {"pysa", "Pysa", "sast", 2}, "mariana-trench.sarif": {"mariana-trench", "Mariana Trench", "mobile", 2},
		"clang-analyzer.sarif": {"clang-analyzer", "Clang Static Analyzer", "sast", 1}, "sarif-eslint.sarif": {"sarif-eslint", "ESLint", "sast", 3},
		"sarif-brakeman.sarif": {"sarif-brakeman", "Brakeman", "sast", 4}, "sarif-fortify.sarif": {"sarif-fortify", "Fortify SCA", "sast", 2},
		"sarif-veracode.sarif": {"sarif-veracode", "Veracode", "sast", 2}, "sarif-mend-sast.sarif": {"sarif-mend-sast", "Mend", "sast", 2},
		"datadog-sast.sarif": {"datadog-sast", "Datadog SAST", "sast", 2}, "detekt.sarif": {"detekt", "detekt", "code-quality", 4},
		"pvs-studio.sarif": {"pvs-studio", "PVS-Studio", "sast", 2}, "binskim.sarif": {"binskim", "BinSkim", "binary", 2},
		"sarif-snyk-iac.sarif": {"sarif-snyk-iac", "Snyk IaC", "iac", 2}, "sarif-kics.sarif": {"sarif-kics", "KICS", "iac", 3},
		"sarif-tfsec.sarif": {"sarif-tfsec", "tfsec", "iac", 3}, "sarif-checkov.sarif": {"sarif-checkov", "Checkov", "iac", 3},
		"ansible-lint.sarif": {"ansible-lint", "ansible-lint", "iac", 3}, "sarif-zizmor.sarif": {"sarif-zizmor", "zizmor", "cicd", 3},
		"spectral.sarif": {"spectral", "Spectral", "api", 3}, "sarif-grype.sarif": {"sarif-grype", "Grype", "sca", 3},
		"sarif-trivy.sarif": {"sarif-trivy", "Trivy", "", 4}, "sarif-osv-scanner.sarif": {"sarif-osv-scanner", "OSV-Scanner", "sca", 5},
		"sarif-gitleaks.sarif": {"sarif-gitleaks", "Gitleaks", "secrets", 1},
		// SARIF formats registered before 2.0 wave B are detected by their driver too.
		"snyk-code.sarif": {"snyk-code", "Snyk Code", "sast", 2}, "docker-scout.sarif": {"docker-scout", "Docker Scout", "container", 2},
	} {
		raw := readImportFixture(t, file)
		if got := DetectImportFormat(raw); got != c.format {
			t.Errorf("%s: detected %q, want %q", file, got, c.format)
			continue
		}
		f, _ := LookupImportFormat(c.format)
		if f.Tool != c.tool || f.Category != c.cat || f.Media != "sarif" || !SameImportParser(c.format, "sarif") {
			t.Errorf("%s: format %+v", file, f)
		}
		cat := firstNonEmpty(c.cat, "other")
		key, err := ImportKey(cat, f.Tool)
		if err != nil {
			t.Fatal(err)
		}
		stored := SanitizeImport(c.format, raw)
		fs, err := ParseImport(key, c.format, stored)
		again, _ := ParseImport(key, "", stored)
		if err != nil || len(fs) != c.n || len(again) != c.n {
			t.Errorf("%s: %v, %d findings, want %d", file, err, len(fs), c.n)
			continue
		}
		seen := map[string]bool{}
		for i, x := range fs {
			if x.Category != cat || x.FilePath == "" || x.Title == "" || x.ScannerKey != key || !slices.Contains(Severities, x.Severity) ||
				x.Fingerprint != again[i].Fingerprint || seen[x.Fingerprint] {
				t.Errorf("%s: finding %d: %+v", file, i, x)
			}
			seen[x.Fingerprint] = true
			if loc, err := LocateImport(key, c.format, stored, x.Fingerprint); err != nil || len(loc.Raw) < 3 {
				t.Errorf("%s: finding %d not located: %v", file, i, err)
			}
		}
	}
	// Logs of an unknown tool, or of several tools, stay generic SARIF.
	for _, doc := range []string{
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Some Scanner"}},"results":[]}]}`,
		`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},"results":[]},{"tool":{"driver":{"name":"ESLint"}},"results":[]}]}`,
		`{"version":"2.1.0","runs":[]}`,
	} {
		if got := DetectImportFormat([]byte(doc)); got != "sarif" {
			t.Errorf("%s: detected %q", doc, got)
		}
	}
	// Several runs of one tool are its format; the driver name is compared without case.
	if got := DetectImportFormat([]byte(`{"runs":[{"tool":{"driver":{"name":"codeql"}}},{"tool":{"driver":{"name":"CodeQL"}}}]}`)); got != "codeql" {
		t.Errorf("two CodeQL runs: %q", got)
	}
}

func TestImportSARIFGitleaksSnippetsRemoved(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks","rules":[{"id":"generic-api-key","shortDescription":{"text":"Generic API Key"}}]}},` +
		`"results":[{"ruleId":"generic-api-key","message":{"text":"generic-api-key has detected secret for file app.cfg."},"locations":[{"physicalLocation":` +
		`{"artifactLocation":{"uri":"app.cfg"},"region":{"startLine":3,"snippet":{"text":"api_key = FIXTURE_NOT_A_REAL_KEY_42"}}}}]}]}]}`
	raw := []byte(doc)
	clean := SanitizeImport("sarif-gitleaks", raw)
	if strings.Contains(string(clean), "FIXTURE_NOT_A_REAL_KEY_42") || !strings.Contains(string(clean), "[REDACTED]") {
		t.Fatalf("snippet kept: %s", clean)
	}
	a, err := ParseImport("import-secrets-gitleaks", "", raw)
	b, err2 := ParseImport("import-secrets-gitleaks", "", clean)
	if err != nil || err2 != nil || len(a) != 1 || len(b) != 1 || a[0].Fingerprint != b[0].Fingerprint {
		t.Errorf("identity depends on the snippet: %v %v %+v %+v", err, err2, a, b)
	}
}

func TestImportFormatsB5(t *testing.T) {
	runImportCases(t, []importCase{
		// Compliance.
		{file: "openscap-xccdf.xml", format: "openscap", count: 2, checks: map[int]want{
			0: {sev: "high", rule: "xccdf_org.ssgproject.content_rule_rpm_verify_permissions", file: "c2908399b057"}}},
		{file: "openscap-arf.xml", format: "openscap", count: 2, checks: map[int]want{
			1: {sev: "high", rule: "xccdf_org.ssgproject.content_rule_ensure_gpgcheck_globally_activated"}}},
		{file: "cis-cat.xml", format: "cis-cat", count: 2, checks: map[int]want{
			0: {sev: "medium", file: "app-01.example.test"}, 1: {sev: "high", rule: "xccdf_org.cisecurity.benchmarks_rule_5.1.20_Ensure_sshd_PermitRootLogin_is_disabled"}}},
		{file: "inspec.json", format: "inspec", count: 2, checks: map[int]want{0: {sev: "high", rule: "ssh-01"}, 1: {sev: "medium", rule: "tmp-01"}}},
		{file: "lynis-report.dat", format: "lynis", count: 10, checks: map[int]want{
			0: {sev: "low", rule: "LYNIS", file: "cf3b0edf9605"}, 7: {sev: "medium", rule: "PKGS-7392"}, 8: {sev: "medium", rule: "LOGG-2138"}}},
		{file: "aws-config.json", format: "aws-config", count: 2, checks: map[int]want{
			0: {sev: "medium", rule: "s3-bucket-public-read-prohibited", file: "AWS::S3::Bucket/example-logs"}, 1: {rule: "restricted-ssh"}}},
		{file: "aws-config-by-resource.json", format: "aws-config", count: 1, checks: map[int]want{0: {file: "AWS::EC2::Instance/i-0123456789abcdef0"}}},
		{file: "azure-policy.json", format: "azure-policy", count: 2, checks: map[int]want{
			0: {sev: "medium", rule: "/providers/Microsoft.Authorization/policyDefinitions/34c877ad-507e-4c82-993e-3452a6e0ad3c"}, 1: {sev: "high"}}},
		{file: "qualys-pc.xml", format: "qualys-pc", count: 2, checks: map[int]want{
			0: {sev: "medium", rule: "QPC-1071", file: "app-01.example.test"}, 1: {sev: "low", rule: "QPC-3891", file: "10.0.1.21"}}},
		{file: "steampipe.json", format: "steampipe", count: 3, checks: map[int]want{
			0: {sev: "critical", file: "arn:aws:::123456789012"}, 1: {sev: "low"}, 2: {sev: "high", file: "arn:aws:s3:::example-logs"}}},
		// Cloud, CNAPP and EDR.
		{file: "wiz-issues.json", format: "wiz", count: 2, cats: map[int]string{0: "misconfiguration"}, checks: map[int]want{
			0: {sev: "high", rule: "wc-id-1335", file: "arn:aws:ec2:eu-west-1:123456789012:instance/i-0123456789abcdef0"}, 1: {sev: "medium", rule: "s3-002"}}},
		{file: "wiz-vulns.json", format: "wiz", count: 2, cats: map[int]string{0: "sca"}, checks: map[int]want{
			0: {sev: "high", cve: "CVE-2024-6387", pkg: "openssh-server", ver: "1:9.2p1-2+deb12u2", fixed: "1:9.2p1-2+deb12u3"}}},
		{file: "orca.json", format: "orca", count: 3, checks: map[int]want{0: {sev: "medium", file: "ci-deploy-role"}, 1: {sev: "high"}, 2: {sev: "low"}}},
		{file: "lacework.json", format: "lacework", count: 2, cats: map[int]string{0: "container", 1: "sca"}, checks: map[int]want{
			0: {sev: "medium", cve: "CVE-2024-2511", file: "registry.example.test/app:1.4.2", fixed: "3.0.13-1~deb12u1"},
			1: {sev: "critical", file: "bastion-01.example.test", ver: "1:8.9p1-3ubuntu0.7"}}},
		{file: "aqua.json", format: "aqua", count: 3, checks: map[int]want{
			0: {sev: "medium", cve: "CVE-2024-2511", pkg: "openssl", file: "registry.example.test/app:1.4.2"}, 1: {sev: "high", fixed: "4.17.21"}}},
		{file: "snyk-container.json", format: "snyk-container", count: 2, checks: map[int]want{
			0: {sev: "low", cve: "CVE-2024-2511", cwe: "CWE-1325", pkg: "openssl"}, 1: {sev: "critical", cve: "CVE-2023-45853"}}},
		{file: "snyk-iac.json", format: "snyk-iac", count: 3, checks: map[int]want{
			0: {sev: "medium", rule: "SNYK-CC-K8S-1", file: "k8s/deployment.yaml", line: 21}, 2: {sev: "high", file: "tf/main.tf", line: 3}}},
		{file: "crowdstrike-spotlight.json", format: "crowdstrike-spotlight", count: 1, checks: map[int]want{
			0: {sev: "high", cve: "CVE-2024-6387", cwe: "CWE-364", file: "bastion-01"}}},
		{file: "defender-vm.json", format: "defender-vm", count: 2, checks: map[int]want{
			0: {sev: "critical", cve: "CVE-2024-38063", file: "app-01.example.test", pkg: "windows_server_2022"}, 1: {sev: "high", file: "laptop-17"}}},
		{file: "qualys-cs.json", format: "qualys-cs", count: 2, checks: map[int]want{
			0: {sev: "high", rule: "QID-178573", cve: "CVE-2024-2511", pkg: "openssl", fixed: "3.0.13-1~deb12u1"}, 1: {sev: "critical"}}},
		{file: "tenable-was.json", format: "tenable-was", count: 2, checks: map[int]want{
			0: {sev: "high", rule: "98104", cwe: "CWE-79", file: "https://shop.example.test/search?q=1"}, 1: {sev: "low"}}},
		{file: "insightvm.json", format: "insightvm", count: 3, cats: map[int]string{0: "sca"}, checks: map[int]want{
			0: {sev: "medium", cve: "CVE-2024-6387", file: "web-01.example.test:22/tcp"}, 2: {file: "web-01.example.test:443/tcp"}}},
		{file: "kiuwan.json", format: "kiuwan", count: 3, cats: map[int]string{0: "sast", 2: "code-quality"}, checks: map[int]want{
			0: {sev: "critical", cwe: "CWE-89", line: 42, file: "src/main/java/com/example/UserDao.java"}, 1: {sev: "medium"}, 2: {sev: "low"}}},
		{file: "kiuwan-sca.json", format: "kiuwan-sca", count: 2, checks: map[int]want{
			0: {sev: "high", cve: "CVE-2021-30468", pkg: "org.apache.cxf:cxf-rt-rs-json-basic", ver: "3.3.5"}, 1: {sev: "critical"}}},
		{file: "checkmarx-one.json", format: "checkmarx-one", count: 3, cats: map[int]string{0: "sast", 1: "sca", 2: "iac"}, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-89", file: "py/app.py", line: 9}, 1: {cve: "CVE-2021-23337", pkg: "lodash", ver: "4.17.20", fixed: "4.17.21"},
			2: {file: "tf/main.tf", line: 3}}},
		{file: "checkmarx-sca.json", format: "checkmarx-sca", count: 2, checks: map[int]want{
			0: {sev: "high", cve: "CVE-2021-23337", pkg: "lodash", ver: "4.17.20", fixed: "4.17.21", cwe: "CWE-94"}, 1: {sev: "medium", pkg: "minimist"}}},
		{file: "srcclr.json", format: "srcclr", count: 2, checks: map[int]want{
			0: {sev: "high", cve: "CVE-2021-23337", pkg: "lodash", ver: "4.17.20", fixed: "4.17.21"}, 1: {pkg: "minimist", fixed: "1.2.6"}}},
		{file: "fod.json", format: "fod", count: 2, cats: map[int]string{0: "sast", 1: "dast"}, checks: map[int]want{
			0: {sev: "critical", cwe: "CWE-89", file: "src/main/java/com/example/UserDao.java", line: 42}, 1: {file: "https://app.example.test/search?q="}}},
		{file: "appscan-cloud.json", format: "appscan-cloud", count: 3, cats: map[int]string{0: "sast", 1: "dast", 2: "sca"}, checks: map[int]want{
			0: {sev: "high", line: 42, cwe: "CWE-89"}, 1: {file: "https://app.example.test/search"}, 2: {cve: "CVE-2021-23337", pkg: "lodash"}}},
		{file: "trivy-operator.json", format: "trivy-operator", count: 3, cats: map[int]string{0: "container", 2: "misconfiguration"}, checks: map[int]want{
			0: {sev: "critical", cve: "CVE-2023-45853", file: "shop/ReplicaSet/web-6d4cf56db6"}, 2: {sev: "high", rule: "KSV017"}}},
		{file: "xeol.json", format: "xeol", count: 3, cats: map[int]string{0: "eol"}, checks: map[int]want{
			1: {sev: "medium", pkg: "package-1", ver: "1.1.1", file: "/foo/bar/somefile-1.txt"}}},
		// DAST and pentest services.
		{file: "detectify.json", format: "detectify", count: 2, secrets: []string{"FIXTURE-not-a-real-session"}, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-79"}, 1: {sev: "low"}}},
		{file: "intruder.json", format: "intruder", count: 3, cats: map[int]string{0: "sca", 2: "misconfiguration"}, checks: map[int]want{
			0: {sev: "high", cve: "CVE-2024-6387", file: "bastion.example.test:22/tcp"}, 2: {sev: "medium", file: "shop.example.test:443/tcp"}}},
		{file: "probely.json", format: "probely", count: 2, secrets: []string{"FIXTURE-not-a-real-session"}, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-89", rule: "sql-injection"}, 1: {sev: "low"}}},
		{file: "edgescan.json", format: "edgescan", count: 2, checks: map[int]want{0: {sev: "medium", cwe: "CWE-79"}, 1: {sev: "critical", cve: "CVE-2024-6387"}}},
		{file: "pentest-tools.json", format: "pentest-tools", count: 2, checks: map[int]want{
			0: {sev: "critical", cve: "CVE-2021-41773", file: "target 12345:80/tcp"}, 1: {sev: "low"}}},
		{file: "appknox.json", format: "appknox", count: 2, checks: map[int]want{0: {sev: "high", cwe: "CWE-312"}, 1: {sev: "low"}}},
		{file: "immuniweb.xml", format: "immuniweb", count: 2, secrets: []string{"FIXTURE-not-a-real-session"}, checks: map[int]want{
			0: {sev: "critical", cwe: "CWE-94", file: "https://shop.example.test/contributions"}, 1: {sev: "info"}}},
		// Open-source tools (real runs).
		{file: "kubesec.json", format: "kubesec", count: 16, checks: map[int]want{0: {sev: "high", rule: "Privileged"}, 2: {sev: "info"}}},
		{file: "kubeaudit.jsonl", format: "kubeaudit", count: 10, checks: map[int]want{0: {sev: "medium", rule: "AppArmorAnnotationMissing", file: "Deployment/web"}}},
		{file: "datree.json", format: "datree", count: 9, checks: map[int]want{0: {sev: "medium", rule: "CONTAINERS_INCORRECT_RUNASUSER_VALUE_LOWUID", line: 21}}},
		{file: "cloud-custodian.json", format: "cloud-custodian", count: 2, checks: map[int]want{
			0: {sev: "high", rule: "s3-no-public-acl", line: 1, endLine: 4}, 1: {sev: "critical"}}},
		{file: "nuclei-json.json", format: "nuclei-json", count: 2, checks: map[int]want{1: {sev: "medium", rule: "b5-debug-trace", cwe: "CWE-209"}}},
		{file: "trufflehog-v2.jsonl", format: "trufflehog-v2", count: 1, secrets: []string{"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZmdoaWprbG1ub3BxcnN0"},
			checks: map[int]want{0: {sev: "high", file: "deploy.yml", rule: "High Entropy"}}},
		{file: "git-secrets.txt", format: "git-secrets", count: 2, secrets: []string{"FIXTURE-not-a-real-password-123", "Zm9vYmFyYmF6cXV4"},
			checks: map[int]want{0: {file: "deploy.yml", line: 1}, 1: {file: "settings.py", line: 2}}},
		{file: "git-secrets-history.txt", format: "git-secrets", count: 2, secrets: []string{"FIXTURE-not-a-real-password-123", "Zm9vYmFyYmF6cXV4"},
			checks: map[int]want{1: {sev: "high", file: "settings.py", line: 2}}},
		{file: "arjun.json", format: "arjun", count: 2, checks: map[int]want{0: {sev: "info", file: "http://b5-web:8000/"}}},
		{file: "gixy.json", format: "gixy", count: 6, checks: map[int]want{0: {sev: "medium", rule: "add_header_redefinition"}, 1: {sev: "high"}}},
		{file: "regula.json", format: "regula", count: 3, checks: map[int]want{0: {sev: "high", rule: "FG_R00229", line: 1}}},
		{file: "ssh-audit.json", format: "ssh-audit", count: 11, checks: map[int]want{0: {sev: "medium", rule: "ssh-kex: ecdh-sha2-nistp256", file: "b5-sshd:22"}}},
		{file: "guarddog.json", format: "guarddog", count: 4, checks: map[int]want{1: {sev: "medium", rule: "exec-base64", file: "setup.py", line: 9}}},
	})
}

// TestImportB5Verdicts checks the records that are not findings or are
// kept with low confidence.
func TestImportB5Verdicts(t *testing.T) {
	low := func(file, format string, wantLow []int) {
		t.Helper()
		f, _ := LookupImportFormat(format)
		fs, err := ParseImport("import-"+firstNonEmpty(f.Category, "other")+"-x", format, SanitizeImport(format, readImportFixture(t, file)))
		if err != nil {
			t.Fatalf("%s: %v", file, err)
		}
		for i, x := range fs {
			if got := x.Confidence == "low"; got != slices.Contains(wantLow, i) {
				t.Errorf("%s: finding %d confidence %q", file, i, x.Confidence)
			}
		}
	}
	low("wiz-issues.json", "wiz", []int{1})            // REJECTED (RESOLVED skipped)
	low("wiz-vulns.json", "wiz", []int{1})             // IGNORED
	low("orca.json", "orca", []int{2})                 // closed
	low("aqua.json", "aqua", []int{1})                 // acknowledged
	low("snyk-iac.json", "snyk-iac", []int{1})         // ignored
	low("azure-policy.json", "azure-policy", []int{1}) // Exempt (Compliant skipped)
	low("qualys-pc.xml", "qualys-pc", []int{1})        // Error (Passed skipped)
	low("steampipe.json", "steampipe", []int{1})       // error (ok skipped)
	low("qualys-cs.json", "qualys-cs", []int{1})       // potential and exempted
	low("tenable-was.json", "tenable-was", []int{1})   // accepted (FIXED skipped)
	low("insightvm.json", "insightvm", []int{2})       // exception (remediated skipped)
	low("kiuwan.json", "kiuwan", []int{1})             // muted
	low("kiuwan-sca.json", "kiuwan-sca", []int{1})     // muted
	low("checkmarx-one.json", "checkmarx-one", []int{1})
	low("checkmarx-sca.json", "checkmarx-sca", []int{1})
	low("fod.json", "fod", []int{1})                                // suppressed (closed skipped)
	low("appscan-cloud.json", "appscan-cloud", []int{2})            // noise (Fixed skipped)
	low("detectify.json", "detectify", []int{1})                    // accepted risk (patched skipped)
	low("intruder.json", "intruder", []int{1})                      // snoozed occurrence
	low("probely.json", "probely", []int{1})                        // accepted (fixed skipped)
	low("pentest-tools.json", "pentest-tools", []int{1})            // false positive (fixed skipped)
	low("cis-cat.xml", "cis-cat", nil)                              // pass skipped
	low("crowdstrike-spotlight.json", "crowdstrike-spotlight", nil) // closed skipped
	low("lacework.json", "lacework", nil)                           // Fixed skipped
	low("edgescan.json", "edgescan", nil)                           // closed skipped
	low("immuniweb.xml", "immuniweb", nil)                          // fixed skipped
	low("appknox.json", "appknox", nil)                             // passed (risk 0) skipped
	low("trivy-operator.json", "trivy-operator", nil)               // passed check skipped
	low("regula.json", "regula", nil)                               // PASS skipped
}

// TestImportB5DetectionExclusions checks the formats that share keys with
// older ones.
func TestImportB5DetectionExclusions(t *testing.T) {
	for file, want := range map[string]string{
		"../grype.json": "grype", "xeol.json": "xeol", // both have "matches"
		"snyk.json": "snyk", "snyk-all-projects.json": "snyk", "snyk-container.json": "snyk-container", "snyk-iac.json": "snyk-iac",
		"nuclei.jsonl": "nuclei", "nuclei-json.json": "nuclei-json",
		"trufflehog.jsonl": "trufflehog", "trufflehog-v2.jsonl": "trufflehog-v2",
		"openscap-xccdf.xml": "openscap", "cis-cat.xml": "cis-cat",
	} {
		if got := DetectImportFormat(readImportFixture(t, file)); got != want {
			t.Errorf("%s: detected %q, want %q", file, got, want)
		}
	}
	// A Snyk Container report is parsed by the Snyk parser.
	if !SameImportParser("snyk-container", "snyk") || !SameImportParser("cis-cat", "openscap") {
		t.Error("parsers")
	}
}

// TestImportFormatTotals computes the number of formats and of distinct
// tools, and checks that 2.0 wave B (Order 500-799) adds at least 60
// tools that had no import format before.
func TestImportFormatTotals(t *testing.T) {
	all := ImportFormats()
	tools, before, added := map[string]bool{}, map[string]bool{}, map[string]bool{}
	nb := 0
	for _, f := range all {
		if f.Tool == "" {
			continue
		}
		tools[f.Tool] = true
		if f.Order < 500 || f.Order > 799 {
			before[f.Tool] = true
		}
	}
	for _, f := range all {
		if f.Order >= 500 && f.Order <= 799 {
			nb++
			if f.Tool != "" && !before[f.Tool] {
				added[f.Tool] = true
			}
		}
	}
	t.Logf("import formats: %d (%d added in wave B); distinct tools: %d (%d new)", len(all), nb, len(tools), len(added))
	if len(added) < 60 {
		t.Errorf("only %d new tools", len(added))
	}
}
