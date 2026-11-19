package scanners

import (
	"slices"
	"strings"
	"testing"
)

// AI/LLM, mobile and fuzzing import formats.
//
// Fixture sources:
//   - modelscan.json: real run, modelscan 0.8.8 (pip, python:3.11-slim), 2026-11-19, against
//     three pickles created for the test (os.system and builtins.exec in __reduce__, one clean).
//   - promptfoo.json: real run, promptfoo 0.126.0 (npm, node:26.13.1-alpine, --network none),
//     2026-11-19: `promptfoo eval` of a local config with the built-in echo provider (no model
//     API); the test cases carry red-team style metadata (pluginId, severity) written by hand,
//     as `promptfoo redteam` would. The planted key in the prompt is fake.
//   - garak.jsonl: see TestImportGarak.
//   - libfuzzer.log: real run, clang 19.1.7 libFuzzer + AddressSanitizer (debian:trixie-slim,
//     --network none), 2026-11-19, fuzzing a 20-line C sample with a deliberate heap overflow.
//   - mobsf-android.json, mobsf-ios.json: real MobSF exports (v3.6.7 Android "InsecureShop",
//     v3.7.9 iOS sample) from DefectDojo's parser test data
//     (github.com/DefectDojo/django-DefectDojo, unittests/scans/mobsf, BSD-3-Clause), trimmed;
//     the network_security finding, the open Firebase URL, the keystore file entry and a fake
//     Stripe key were added by hand in MobSF 3.x/4.x shapes from MobSF's source.
//   - apkleaks.json: built from the published format (apkleaks/apkleaks.py: {package,
//     results[{name, matches}]}, pattern names from config/regexes.json); values are fake.
//   - clusterfuzzlite.sarif: built from the published format (google/oss-fuzz
//     infra/cifuzz/sarif_utils.py) for the libFuzzer crash above.
//   - nowsecure.sarif: built from the published format (nowsecure/nowsecure-action
//     src/nowsecure-sarif.ts and its test snapshot); the second result was added by hand.
//   - docker-scout.sarif: built from the published format (Docker docs: `docker scout cves
//     --format sarif`); not verified against a real export (Docker Scout needs a Docker account).

func TestImportModelScan(t *testing.T) {
	fs := checkImport(t, "modelscan.json", "modelscan", "import-other-modelscan", 2)
	exec := fs[0]
	if exec.Severity != "critical" || exec.FilePath != "loader.pkl" || exec.Category != "malware" || exec.RuleID != "modelscan:PickleUnsafeOpScan:builtins.exec" ||
		!slices.Equal(exec.CWE, []string{"CWE-502"}) || exec.Confidence != "high" {
		t.Errorf("exec: %+v", exec)
	}
	if fs[1].FilePath != "evil_model.pkl" || !strings.Contains(fs[1].Title, "system") {
		t.Errorf("system: %+v", fs[1])
	}
	// Scan errors are kept as info findings.
	doc := `{"summary":{"modelscan_version":"0.8.8","input_path":"m"},"issues":[],"errors":[{"category":"DEPENDENCY","description":"tensorflow is not installed","source":"m/model.h5"}]}`
	if DetectImportFormat([]byte(doc)) != "modelscan" {
		t.Fatal("detection of an issue-free report")
	}
	es, err := ParseImport("import-other-modelscan", "modelscan", []byte(doc))
	if err != nil || len(es) != 1 || es[0].Severity != "info" || es[0].FilePath != "m/model.h5" {
		t.Errorf("errors: %v %+v", err, es)
	}
	// A generic {summary, issues} document is not ModelScan.
	if DetectImportFormat([]byte(`{"summary":{},"issues":[]}`)) == "modelscan" {
		t.Error("generic summary/issues")
	}
}

func TestImportPromptfoo(t *testing.T) {
	raw := readImportFixture(t, "promptfoo.json")
	stored := SanitizeImport("promptfoo", raw)
	const secret = "sk-ant-FIXTUREnotArealKEY0000000000"
	if strings.Contains(string(stored), secret) {
		t.Fatal("stored report keeps the planted key")
	}
	fs := checkImport(t, "promptfoo.json", "promptfoo", "import-other-promptfoo", 2) // the passing test case is not a finding
	inj := fs[0]
	if inj.RuleID != "promptfoo:prompt-injection" || inj.Severity != "high" || inj.FilePath != "echo" ||
		!strings.Contains(inj.Title, "prompt injection asks for the admin key") || !strings.Contains(inj.Description, "not contain") {
		t.Errorf("injection: %+v", inj)
	}
	if fs[1].RuleID != "promptfoo:pii:direct" || fs[1].Severity != "medium" {
		t.Errorf("pii: %+v", fs[1])
	}
	for _, f := range fs {
		if strings.Contains(f.Title+f.Description, secret) {
			t.Error("finding text keeps the key")
		}
		for _, src := range [][]byte{raw, stored} {
			loc, err := LocateImport("import-other-promptfoo", "promptfoo", src, f.Fingerprint)
			if err != nil || strings.Contains(string(loc.Raw), secret) {
				t.Errorf("located record: %v", err)
			}
		}
	}
	// Identity does not depend on the redacted text.
	again, _ := ParseImport("import-other-promptfoo", "promptfoo", stored)
	if len(again) != 2 || again[0].Fingerprint != inj.Fingerprint {
		t.Error("fingerprint changes after sanitising")
	}
	// Provider credentials in the config are removed.
	cfg := `{"evalId":"e","results":{"version":3,"results":[]},"config":{"providers":[{"id":"openai:gpt-4o","config":{"apiKey":"not-a-real-openai-key-123"}}]}}`
	if strings.Contains(string(SanitizeImport("promptfoo", []byte(cfg))), "not-a-real-openai-key") {
		t.Error("provider apiKey kept")
	}
	// Errors are not verdicts; no-assertion failures fall back to the assertion type.
	errDoc := `{"evalId":"e","config":{},"results":{"version":3,"results":[
		{"success":false,"failureReason":2,"error":"provider timeout","provider":{"id":"p"},"testCase":{"description":"x"}},
		{"success":false,"failureReason":1,"provider":{"id":"p"},"testIdx":1,"gradingResult":{"pass":false,"reason":"r","componentResults":[{"pass":false,"reason":"r","assertion":{"type":"llm-rubric"}}]},"testCase":{"description":"rubric"}}]}}`
	if es, err := ParseImport("import-other-promptfoo", "", []byte(errDoc)); err != nil || len(es) != 1 || es[0].RuleID != "promptfoo:assertion:llm-rubric" {
		t.Errorf("errors and assertions: %v %+v", err, es)
	}
}

func TestImportLibFuzzer(t *testing.T) {
	fs := checkImport(t, "libfuzzer.log", "libfuzzer", "import-other-libfuzzer", 1)
	c := fs[0]
	if c.Severity != "high" || c.RuleID != "libfuzzer:heap-buffer-overflow" || c.FilePath != "work/src/parse_header.c" || c.StartLine == nil || *c.StartLine != 10 ||
		!slices.Equal(c.CWE, []string{"CWE-122"}) || !strings.Contains(c.Title, "in parse_header") ||
		!strings.Contains(c.Description, "crash-55f7f67088a7fd5236244657c6c009fd097119cf") || !strings.Contains(c.Description, "WRITE of size 35") ||
		strings.Contains(c.Description, "allocated by") {
		t.Errorf("crash: %+v", c)
	}
	// Jazzer (published format: the exception block Jazzer prints) and a
	// libFuzzer timeout, in one log.
	log := `INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 7

== Java Exception: com.code_intelligence.jazzer.api.FuzzerSecurityIssueCritical: OS Command Injection
Executable 'jazze' was called with arguments [x]
	at com.code_intelligence.jazzer.sanitizers.OsCommandInjection.processImplStartHook(OsCommandInjection.kt:47)
	at java.base/java.lang.ProcessImpl.start(ProcessImpl.java:1)
	at com.example.ExampleFuzzer.fuzzerTestOneInput(ExampleFuzzer.java:31)
DEDUP_TOKEN: e7f1a2b3c4d5e6f7
== libFuzzer crashing input ==
MS: 1 CopyPart-; base unit: 0
artifact_prefix='./'; Test unit written to ./crash-0a1b2c
==22== ERROR: libFuzzer: timeout after 25 seconds
    #0 0x4a1b2c in parse_body /src/proj/body.c:88:5
SUMMARY: libFuzzer: timeout
`
	if DetectImportFormat([]byte(log)) != "libfuzzer" {
		t.Fatal("jazzer log detection")
	}
	js, err := ParseImport("import-other-libfuzzer", "libfuzzer", []byte(log))
	if err != nil || len(js) != 2 {
		t.Fatalf("%v %+v", err, js)
	}
	if j := js[0]; j.Severity != "critical" || j.FilePath != "ExampleFuzzer.java" || *j.StartLine != 31 || !strings.Contains(j.Title, "OS Command Injection") ||
		!strings.Contains(j.Description, "crash-0a1b2c") {
		t.Errorf("jazzer: %+v", j)
	}
	if to := js[1]; to.Severity != "low" || to.RuleID != "libfuzzer:timeout" || to.FilePath != "src/proj/body.c" {
		t.Errorf("timeout: %+v", to)
	}
	// Plain text and other logs are not fuzzer logs.
	for _, s := range []string{"ERROR: something failed\n", "INFO: Seed: 1\n#2 INITED cov: 3\nDone 100 runs\n"} {
		if DetectImportFormat([]byte(s)) == "libfuzzer" {
			t.Errorf("%q detected as libfuzzer", s)
		}
	}
}

func TestImportMobSF(t *testing.T) {
	raw := readImportFixture(t, "mobsf-android.json")
	stored := SanitizeImport("mobsf", raw)
	const secret = "sk_live_FIXTURE_NOT_A_REAL_KEY_"
	if strings.Contains(string(stored), secret) || strings.Contains(string(stored), "us-east-1:7e9426f7") {
		t.Fatal("stored report keeps a secret value")
	}
	if !strings.Contains(string(stored), "stripe_secret_key") {
		t.Fatal("secret key name lost")
	}
	// 3 rules x 2 files (logging, external storage) or 1 file, 3 manifest,
	// 1 network, 4 certificate, 1 file, 2 secrets, 2 dangerous permissions,
	// 1 open Firebase.
	fs := checkImport(t, "mobsf-android.json", "mobsf", "import-other-mobsf", 19)
	byRule := map[string][]Finding{}
	for _, f := range fs {
		byRule[f.RuleID] = append(byRule[f.RuleID], f)
	}
	if l := byRule["mobsf:android_logging"]; len(l) != 2 || l[0].Severity != "info" || l[0].StartLine == nil || *l[0].StartLine != 138 ||
		!slices.Equal(l[0].CWE, []string{"CWE-532"}) || l[0].FilePath != "com/bumptech/glide/Glide.java" || l[0].Category != "sast" {
		t.Errorf("code: %+v", l)
	}
	if m := byRule["mobsf:manifest:clear_text_traffic"]; len(m) != 1 || m[0].Severity != "high" || m[0].FilePath != "AndroidManifest.xml" || strings.Contains(m[0].Title, "<br>") {
		t.Errorf("manifest: %+v", m)
	}
	if c := byRule["mobsf:certificate:Application signed with debug certificate"]; len(c) != 1 || c[0].Severity != "high" {
		t.Errorf("certificate: %+v", c)
	}
	s := byRule["mobsf:secret"]
	if len(s) != 2 || s[1].Category != "secrets" || !strings.Contains(s[1].Title, "stripe_secret_key") || s[1].Confidence != "low" {
		t.Fatalf("secrets: %+v", s)
	}
	clean, _ := ParseImport("import-other-mobsf", "mobsf", stored)
	for i := range fs {
		if clean[i].Fingerprint != fs[i].Fingerprint {
			t.Errorf("finding %d: fingerprint depends on the secret value", i)
		}
		if strings.Contains(fs[i].Description+fs[i].Title, secret) {
			t.Error("secret in finding text")
		}
		loc, err := LocateImport("import-other-mobsf", "mobsf", raw, fs[i].Fingerprint)
		if err != nil || strings.Contains(string(loc.Raw), secret) {
			t.Errorf("located record %d: %v", i, err)
		}
	}
	if fb := byRule["mobsf:firebase-open"]; len(fb) != 1 || fb[0].FilePath != "https://insecureshop-test.firebaseio.com" {
		t.Errorf("firebase: %+v", fb)
	}
	if p := byRule["mobsf:permission:android.permission.READ_EXTERNAL_STORAGE"]; len(p) != 1 || p[0].Severity != "low" {
		t.Errorf("permission: %+v", p)
	}

	// iOS: 2 binary findings, 2 Mach-O weaknesses (passed checks skipped), 1 plist file.
	is := checkImport(t, "mobsf-ios.json", "mobsf", "import-other-mobsf", 5)
	if is[0].RuleID != "mobsf:binary:Binary makes use of insecure API(s)" || is[0].Severity != "high" || !slices.Equal(is[0].CWE, []string{"CWE-676"}) ||
		is[0].FilePath != "bitbar-ios-sample.ipa" || is[0].CVSS == nil || *is[0].CVSS != 6 {
		t.Errorf("ios binary: %+v", is[0])
	}
	// The older MobSF shapes (manifest list with stat/desc, ATS list).
	old := `{"title":"Static Analysis","version":"v3.1.6 Beta","file_name":"a.apk","app_type":"apk","md5":"x","package_name":"p",
		"code_analysis":{"android_insecure_random":{"files":{"a/B.java":"12"},"metadata":{"cwe":"CWE-330","description":"Insecure random","severity":"high"}}},
		"manifest_analysis":[{"title":"<strong>Debug</strong> enabled","stat":"high","desc":"d","name":"debug"}],
		"ats_analysis":[{"issue":"Insecure communication allowed","status":"insecure","description":"NSAllowsArbitraryLoads"},{"issue":"ok","status":"secure","description":""}]}`
	if DetectImportFormat([]byte(old)) != "mobsf" {
		t.Fatal("old shape detection")
	}
	os, err := ParseImport("import-other-mobsf", "mobsf", []byte(old))
	if err != nil || len(os) != 3 || os[1].Title != "Debug enabled" || os[2].RuleID != "mobsf:ats:Insecure communication allowed" || os[2].Severity != "high" {
		t.Errorf("old shape: %v %+v", err, os)
	}
}

func TestImportAPKLeaks(t *testing.T) {
	raw := readImportFixture(t, "apkleaks.json")
	stored := SanitizeImport("apkleaks", raw)
	secrets := []string{"AKIAEXAMPLEFAKE12345", "AIzaSyFAKE-fake_FAKEfakeFAKEfake012345", "abc123secret"}
	for _, s := range secrets {
		if strings.Contains(string(stored), s) {
			t.Errorf("stored report keeps %q", s)
		}
	}
	if !strings.Contains(string(stored), "/api/v1/orders") {
		t.Error("endpoints are kept")
	}
	// 3 secret matches, 2 inventories (IP addresses, LinkFinder).
	fs := checkImport(t, "apkleaks.json", "apkleaks", "import-other-apkleaks", 5)
	if fs[0].Category != "secrets" || fs[0].Severity != "high" || fs[0].FilePath != "com.example.shop" || fs[0].RuleID != "apkleaks:Amazon_AWS_Access_Key_ID" {
		t.Errorf("aws: %+v", fs[0])
	}
	if fs[1].Fingerprint == fs[2].Fingerprint {
		t.Error("two keys of one pattern are distinct findings")
	}
	if l := fs[4]; l.Severity != "info" || l.RuleID != "apkleaks:LinkFinder" || !strings.Contains(l.Description, "/api/v1/users") {
		t.Errorf("linkfinder: %+v", l)
	}
	clean, _ := ParseImport("import-other-apkleaks", "apkleaks", stored)
	for i := range fs {
		if clean[i].Fingerprint != fs[i].Fingerprint {
			t.Errorf("finding %d: identity depends on the secret", i)
		}
		for _, s := range secrets {
			if strings.Contains(fs[i].Title+fs[i].Description, s) {
				t.Errorf("finding %d text keeps %q", i, s)
			}
		}
		loc, _ := LocateImport("import-other-apkleaks", "apkleaks", raw, fs[i].Fingerprint)
		for _, s := range secrets {
			if loc == nil || strings.Contains(string(loc.Raw), s) {
				t.Errorf("located record %d keeps %q", i, s)
			}
		}
	}
	// Other {package, results} documents are not APKLeaks.
	if DetectImportFormat([]byte(`{"package":"x","results":[{"name":"a","value":1}]}`)) == "apkleaks" {
		t.Error("generic package/results")
	}
}

func TestImportSARIFAliasesG3(t *testing.T) {
	for _, c := range []struct {
		file, format, key string
		n                 int
	}{
		{"clusterfuzzlite.sarif", "clusterfuzzlite", "import-other-clusterfuzzlite", 1},
		{"nowsecure.sarif", "nowsecure", "import-other-nowsecure", 2},
		{"docker-scout.sarif", "docker-scout", "import-container-docker-scout", 2},
	} {
		raw := readImportFixture(t, c.file)
		if got := DetectImportFormat(raw); !SameImportParser(got, c.format) {
			t.Errorf("%s detected as %q", c.file, got)
		}
		f, ok := LookupImportFormat(c.format)
		if !ok || f.Tool == "" {
			t.Fatalf("%s not registered", c.format)
		}
		fs, err := ParseImport(c.key, c.format, raw)
		if err != nil || len(fs) != c.n {
			t.Errorf("%s: %v %d findings", c.file, err, len(fs))
			continue
		}
		for _, x := range fs {
			if x.Title == "" || x.FilePath == "" || !slices.Contains(Severities, x.Severity) {
				t.Errorf("%s: incomplete %+v", c.file, x)
			}
		}
	}
	if f, _ := LookupImportFormat("docker-scout"); f.Category != "container" {
		t.Error("docker scout category")
	}
	cf, _ := ParseImport("import-other-clusterfuzzlite", "clusterfuzzlite", readImportFixture(t, "clusterfuzzlite.sarif"))
	if cf[0].RuleID != "heap-buffer-overflow" || cf[0].Severity != "high" || cf[0].FilePath != "src/parse_header.c" || *cf[0].StartLine != 11 {
		t.Errorf("clusterfuzzlite: %+v", cf[0])
	}
}

// garak.jsonl and garak-hitlog.jsonl: real run, garak 0.17.1 (pip, python:3.11-slim,
// --network none), 2026-11-19, with the built-in test.Repeat generator (echoes the prompt)
// and the probes encoding.InjectBase64 (passes) and promptinject.HijackHateHumans (fails);
// the report is trimmed to two evaluated attempts per probe and the hit log to three hits.
func TestImportGarak(t *testing.T) {
	fs := checkImport(t, "garak.jsonl", "garak", "import-other-garak", 1)
	g := fs[0]
	if g.RuleID != "garak:promptinject.HijackHateHumans/promptinject.AttackRogueString" || g.Severity != "high" || g.FilePath != "test.Repeat" ||
		!strings.Contains(g.Description, "100.0% (256 of 256") || !strings.Contains(g.Description, "I hate humans") || !strings.Contains(g.Description, "owasp:llm01") {
		t.Errorf("garak: %+v", g)
	}
	hs := checkImport(t, "garak-hitlog.jsonl", "garak", "import-other-garak", 1)
	if hs[0].Fingerprint != g.Fingerprint || !strings.Contains(hs[0].Description, "3 successful attack") {
		t.Errorf("hit log finding must have the report's identity: %+v", hs[0])
	}
	// Credentials in the run configuration are removed; numbers stay.
	cfg := `{"entry_type":"start_run setup","_config.version":"0.17.1","plugins.generators.openai.OpenAIGenerator.api_key":"not-a-real-key-123","run.generations":1}` + "\n" +
		`{"entry_type":"init","garak_version":"0.17.1"}` + "\n"
	clean := string(SanitizeImport("garak", []byte(cfg)))
	if strings.Contains(clean, "not-a-real-key-123") || !strings.Contains(clean, `"run.generations":1`) {
		t.Errorf("sanitised: %s", clean)
	}
	if fs, err := ParseImport("import-other-garak", "", []byte(cfg)); err != nil || len(fs) != 0 {
		t.Errorf("a report without failures: %v %d", err, len(fs))
	}
	if DetectImportFormat([]byte(`{"entry_type":"x","tool":"other"}`+"\n")) == "garak" {
		t.Error("an entry_type document of another tool")
	}
}
