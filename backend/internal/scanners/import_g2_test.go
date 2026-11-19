package scanners

import (
	"strings"
	"testing"
)

// Fixtures of the code-quality, linter and secret-scanner imports. Unless
// noted they are real tool output, produced by running the tool in a
// throwaway container against a small sample (vulnerable PHP, Node,
// Android Java, Elixir/Phoenix, shell, Python and Go files, and a
// directory with randomly generated fake secrets), then trimmed to a few
// records with paths made relative:
//
//   - phpstan.json: PHPStan 2 (composer:latest, phpstan/phpstan), analyse --level=9 --error-format=json
//   - psalm.json: Psalm 6 (composer:latest, vimeo/psalm), --taint-analysis --output-format=json
//   - njsscan.json: njsscan 1.0.2 (python:3.12-slim, pip), --json
//   - mobsfscan.json: mobsfscan 1.2.0 (python:3.12-slim, pip), --json
//   - sobelow.json: Sobelow 0.19.0 (elixir:1.18, mix archive), --format json --private
//   - shellcheck.json, shellcheck-plain.json: ShellCheck 0.11.0 (koalaman/shellcheck:stable), -f json1 and -f json
//   - ruff.json: Ruff 0.17.5 (python:3.12-slim, pip), check --select ALL --output-format json
//   - pylint.json, pylint-json2.json: Pylint 4.1.4 (python:3.12-slim, pip), --output-format=json and json2
//   - golangci-lint.json: golangci-lint 2.15.0 (golangci/golangci-lint), run --enable gosec --output.json.path stdout
//   - codacy.json: Codacy Analysis CLI (codacy/codacy-analysis-cli:latest), analyze --tool bandit --format json
//   - detect-secrets.json: detect-secrets 1.5.0 (python:3.12-slim, pip), scan --all-files
//   - kingfisher.json: Kingfisher 2.19.1 (ghcr.io/mongodb/kingfisher), scan --format json --no-validate
//   - noseyparker.json, noseyparker.jsonl: Nosey Parker 0.24.0 (ghcr.io/praetorian-inc/noseyparker), report --format json
//     (directory scan) and --format jsonl (scan of a git repository: git provenance)
//   - whispers.json: Whispers 2.4.0 (python:3.12-slim, pip), -o report.json
//   - talisman.json: Talisman 1.37.0 (official release binary in alpine:3), --scan of a git repository
//
// Built from the published format only (no real export available):
//
//   - ggshield.json: from the JSON output schema in the ggshield 1.56.1 source
//     (verticals/secret/output/schemas.py); a real scan needs a GitGuardian API key
//   - sonarcloud.json: from the SonarQube Cloud Web API documentation of api/issues/search
func TestImportG2Formats(t *testing.T) {
	kfSecrets := []string{"fJBd0Kh8oOOL8dKLzdocJ2is", "sk_live_FIXTURE_NOT_A_REAL_KEY_", "AKIAI44QH8DHBEXAMPLE", "FIXTURE-not-a-real-aws-secret-key-000000"}
	npSecrets := append([]string{"QUtJQUk0NFFIOERIQkVYQU1QTEU=", "Sup3rS3cretFakePassw0rd", "U3VwM3JTM2NyZXRGYWtlUGFzc3cwcmQ="}, kfSecrets...)
	runImportCases(t, []importCase{
		{file: "phpstan.json", format: "phpstan", count: 6, checks: map[int]want{
			1: {sev: "low", file: "src/user.php", line: 4, rule: "binaryOp.invalid"},
		}, cats: map[int]string{0: "code-quality"}},
		{file: "psalm.json", format: "psalm", count: 4, checks: map[int]want{
			0: {sev: "low", file: "src/user.php", line: 4, rule: "PossiblyInvalidOperand"},
			1: {sev: "high", cwe: "CWE-79", file: "src/user.php", line: 5, rule: "TaintedHtml"},
		}, cats: map[int]string{0: "code-quality", 1: "sast"}},
		{file: "njsscan.json", format: "njsscan", count: 2, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-95", file: "app.js", line: 8, rule: "eval_nodejs"},
			1: {sev: "high", cwe: "CWE-78", line: 5, rule: "generic_os_command_exec"},
		}},
		{file: "mobsfscan.json", format: "mobsfscan", count: 2, checks: map[int]want{
			0: {sev: "info", cwe: "CWE-919", rule: "android_root_detection"},
			1: {sev: "medium", cwe: "CWE-327", file: "app/src/main/java/com/acme/Main.java", line: 7, rule: "weak_hash"},
		}},
		{file: "sobelow.json", format: "sobelow", count: 6, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-22", file: "lib/demo_web/controllers/page_controller.ex", line: 5, rule: "Traversal.SendFile"},
			3: {sev: "medium", cwe: "CWE-352", file: "lib/demo_web/router.ex", line: 4, rule: "Config.CSRF"},
			5: {sev: "high", cwe: "CWE-78", line: 9, rule: "CI.OS"},
		}},
		{file: "shellcheck.json", format: "shellcheck", count: 8, checks: map[int]want{
			0: {sev: "low", file: "deploy.sh", line: 3, rule: "SC2115"},
			2: {sev: "medium", line: 4, rule: "SC2045"},
			3: {sev: "info", rule: "SC2006"},
		}, cats: map[int]string{0: "code-quality"}},
		{file: "shellcheck-plain.json", format: "shellcheck", count: 4, checks: map[int]want{
			0: {sev: "low", file: "deploy.sh", line: 3, rule: "SC2115"},
		}},
		{file: "ruff.json", format: "ruff", count: 6, checks: map[int]want{
			1: {sev: "low", file: "home/runner/work/app/app/app.py", line: 1, rule: "F401"},
			2: {sev: "high", cwe: "CWE-78", line: 8, rule: "S602"},
			3: {sev: "medium", cwe: "CWE-502", line: 9, rule: "S301"},
		}, cats: map[int]string{1: "code-quality", 2: "sast"}},
		{file: "pylint.json", format: "pylint", count: 4, checks: map[int]want{
			0: {sev: "info", file: "app.py", line: 1, rule: "missing-module-docstring"},
			2: {sev: "medium", cwe: "CWE-95", line: 13, endLine: 13, rule: "eval-used"},
		}, cats: map[int]string{0: "code-quality", 2: "sast"}},
		{file: "pylint-json2.json", format: "pylint", count: 8, checks: map[int]want{
			2: {sev: "medium", cwe: "CWE-95", file: "app.py", line: 13, rule: "eval-used"},
		}},
		{file: "golangci-lint.json", format: "golangci-lint", count: 8, checks: map[int]want{
			0: {sev: "low", file: "main.go", line: 13, rule: "errcheck"},
			4: {sev: "medium", cwe: "CWE-89", line: 12, rule: "G202"},
		}, cats: map[int]string{0: "code-quality", 4: "sast", 6: "code-quality"}},
		{file: "codacy.json", format: "codacy", count: 7, checks: map[int]want{
			0: {sev: "medium", cwe: "CWE-502", file: "app.py", line: 9, rule: "Bandit_B301"},
			6: {sev: "high", cwe: "CWE-78", line: 8, rule: "Bandit_B602"},
		}, cats: map[int]string{0: "sast"}},
		{file: "sonarcloud.json", format: "sonarcloud", count: 2, checks: map[int]want{
			0: {sev: "high", file: "src/components/Banner.jsx", line: 27, rule: "javascript:S5247"},
			1: {sev: "low", file: "src/util/format.js", line: 8},
		}, cats: map[int]string{0: "sast", 1: "code-quality"}},
		{file: "detect-secrets.json", format: "detect-secrets", count: 4, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-798", file: "config/settings.py", line: 2, rule: "AWS Access Key"},
			3: {line: 4, rule: "Secret Keyword"},
		}, secrets: []string{"d70eab08607a4d05faa2d0d6647206599e9abc65", "05ea5f73962f3cc16a9cb524d4d15ba57d5f7ae9"}},
		{file: "kingfisher.json", format: "kingfisher", count: 3, checks: map[int]want{
			1: {sev: "high", cwe: "CWE-798", file: "config/app.env", line: 2, rule: "betterleaks.stripe-access-token"},
		}, secrets: kfSecrets},
		{file: "noseyparker.json", format: "noseyparker", count: 6, checks: map[int]want{
			0: {sev: "high", cwe: "CWE-798", file: "config/app.env", line: 3, rule: "np.aws.6"},
			3: {file: "config/id_rsa", rule: "np.pem.1"},
		}, secrets: npSecrets},
		{file: "noseyparker.jsonl", format: "noseyparker", count: 6, checks: map[int]want{
			2: {sev: "high", file: "config/settings.py", line: 4, rule: "np.generic.5"},
		}, secrets: npSecrets},
		{file: "ggshield.json", format: "ggshield", count: 2, checks: map[int]want{
			0: {sev: "critical", cwe: "CWE-798", file: "config/app.env", line: 2, rule: "Stripe Keys"},
			1: {sev: "high", line: 3, endLine: 4, rule: "AWS Keys"},
		}, secrets: kfSecrets},
		{file: "whispers.json", format: "whispers", count: 8, checks: map[int]want{
			0: {sev: "low", cwe: "CWE-538", file: "config/id_rsa", rule: "file-known"},
			3: {sev: "critical", cwe: "CWE-798", file: "config/app.env", line: 2, rule: "apikey-known"},
		}, secrets: kfSecrets},
		{file: "talisman.json", format: "talisman", count: 8, checks: map[int]want{
			0: {sev: "low", cwe: "CWE-538", file: "config/app.env", rule: "talisman-filename"},
			1: {sev: "high", cwe: "CWE-798", rule: "talisman-filecontent"},
		}, secrets: append([]string{"SA1xOxmpxzJBX0McVTp3F3P8fgNk7uNTDvXAusFzprrm7rj"}, kfSecrets...)},
	})
}

// Every finding of a G2 fixture has its own identity (no two findings of
// a report merge).
func TestImportG2DistinctFingerprints(t *testing.T) {
	for _, n := range []string{"phpstan.json", "psalm.json", "njsscan.json", "mobsfscan.json", "sobelow.json", "shellcheck.json", "ruff.json",
		"pylint-json2.json", "golangci-lint.json", "codacy.json", "detect-secrets.json", "kingfisher.json", "noseyparker.jsonl",
		"ggshield.json", "whispers.json", "talisman.json"} {
		raw := readImport(t, n)
		fs, err := ParseImport("import-other-x", "", raw)
		if err != nil {
			t.Fatal(n, err)
		}
		seen := map[string]int{}
		for i, f := range fs {
			if j, dup := seen[f.Fingerprint]; dup {
				t.Errorf("%s: findings %d and %d have the same fingerprint", n, j, i)
			}
			seen[f.Fingerprint] = i
		}
	}
}

func TestImportG2EmptyAndMalformed(t *testing.T) {
	// Empty reports with the tool's envelope are detected and valid.
	for doc, f := range map[string]string{
		`{"totals":{"errors":0,"file_errors":0},"files":[],"errors":[]}`:                                                               "phpstan",
		`{"errors":[],"njsscan_version":"1.0.2","nodejs":{},"templates":{}}`:                                                           "njsscan",
		`{"errors":[],"mobsfscan_version":"1.2.0","results":{}}`:                                                                       "mobsfscan",
		`{"findings":{"high_confidence":[],"medium_confidence":[],"low_confidence":[]},"sobelow_version":"0.19.0","total_findings":0}`: "sobelow",
		`{"comments":[]}`: "shellcheck",
		`{"messages":[],"statistics":{"messageTypeCount":{},"modulesLinted":1,"score":10}}`:                              "pylint",
		`{"Issues":[],"Report":{"Linters":[]}}`:                                                                          "golangci-lint",
		`{"version":"1.5.0","plugins_used":[],"filters_used":[],"results":{},"generated_at":"x"}`:                        "detect-secrets",
		`{"findings":[],"metadata":{"kingfisher_version":"2.19.1"}}`:                                                     "kingfisher",
		`{"id":"/repo","type":"path_scan","total_incidents":0,"total_occurrences":0,"secrets_engine_version":"2.120.0"}`: "ggshield",
		`{"summary":{"types":{"filecontent":0,"filesize":0,"filename":0}},"results":[]}`:                                 "talisman",
	} {
		if got := DetectImportFormat([]byte(doc)); got != f {
			t.Errorf("%s: detected %q, want %q", doc, got, f)
		}
		if fs, err := ParseImport("import-other-x", f, []byte(doc)); err != nil || len(fs) != 0 {
			t.Errorf("%s: %v %d", f, err, len(fs))
		}
	}
	// Array formats: an empty array is only accepted with a named format.
	for _, f := range []string{"psalm", "ruff", "pylint", "codacy", "noseyparker", "whispers", "shellcheck"} {
		if fs, err := ParseImport("import-other-x", f, []byte(`[]`)); err != nil || len(fs) != 0 {
			t.Errorf("%s: empty report: %v %d", f, err, len(fs))
		}
	}
	// Malformed records are errors, not silently skipped.
	for f, doc := range map[string]string{
		"phpstan":       `{"totals":{},"files":{"a.php":{"messages":[{"line":1}]}}}`,
		"psalm":         `[{"severity":"error","line_from":1,"file_name":"a.php","link":"x"}]`,
		"njsscan":       `{"njsscan_version":"1","nodejs":{"r":{"files":[]}}}`,
		"sobelow":       `{"sobelow_version":"1","findings":{"high_confidence":[{"file":"a.ex"}]}}`,
		"shellcheck":    `{"comments":[{"file":"a.sh","line":1}]}`,
		"ruff":          `[{"code":"F401","filename":"a.py","location":{}}]`,
		"pylint":        `[{"type":"error","path":"a.py","message-id":"E1"}]`,
		"golangci-lint": `{"Issues":[{"Text":"x"}],"Report":{}}`,
		"codacy":        `[{"Other":{}}]`,
		"kingfisher":    `{"findings":[{"finding":{"path":"a"}}],"metadata":{"kingfisher_version":"1"}}`,
		"noseyparker":   `[{"finding_id":"x","matches":[]}]`,
		"ggshield":      `{"entities_with_incidents":[{"filename":"a","incidents":[{"policy":"x"}]}],"total_incidents":1,"total_occurrences":1}`,
		"whispers":      `[{"key":"k","value":"v","file":"a","severity":"High"}]`,
		"talisman":      `{"summary":{},"results":[{"filename":"a","failure_list":[{"message":"x"}]}]}`,
	} {
		if _, err := ParseImport("import-other-x", f, []byte(doc)); err == nil {
			t.Errorf("%s: malformed record accepted", f)
		}
	}
	// PATHOS findings JSON keeps its detection; reports of other tools
	// with a "findings" field are not taken for it.
	if got := DetectImportFormat([]byte(`{"tool":"x","findings":[]}`)); got != "pathos" {
		t.Errorf("pathos detected as %q", got)
	}
	if got := DetectImportFormat([]byte(`{"findings":[]}`)); got != "pathos" {
		t.Errorf("pathos detected as %q", got)
	}
}

// Kingfisher writes a summary object after the report; it is kept when the
// report is sanitised.
func TestImportKingfisherKeepsSummary(t *testing.T) {
	raw := readImport(t, "kingfisher.json")
	clean := SanitizeImport("kingfisher", raw)
	if !strings.Contains(string(clean), `"findings_by_rule"`) || !strings.Contains(string(clean), "betterleaks.aws-access-token") {
		t.Errorf("summary or findings lost: %s", clean)
	}
}

// Talisman reports quote secrets in filecontent messages; filename
// messages are kept.
func TestImportTalismanScrub(t *testing.T) {
	clean := string(SanitizeImport("talisman", readImport(t, "talisman.json")))
	if !strings.Contains(clean, `failed checks against the pattern`) || !strings.Contains(clean, "Potential secret pattern: [REDACTED]") {
		t.Errorf("scrubbed report: %s", clean)
	}
}
