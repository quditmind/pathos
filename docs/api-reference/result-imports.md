---
title: Result and SBOM imports
section: api-reference
order: 25
version: "1.1"
updated: 2026-11-19
summary: Import findings from 153 formats (SARIF, Semgrep, Snyk, SonarQube, ZAP, Burp, Trivy, Gitleaks, Nessus, OpenVAS, Checkmarx, Fortify, Veracode, GitLab security reports, KICS, CSV and more) and SBOMs (CycloneDX, SPDX), and list past imports.
---
# Result and SBOM imports

Custom Opengrep detection rules are described in [Scanners, scan profiles and custom rules](scan-configuration.md#custom-rules).

## Importing results

`POST /api/v1/imports/results` (`scans.run` on the repository), `multipart/form-data`:

| Field | Required | Description |
|---|---|---|
| `file` | yes | The report, at most 64 MiB; gzip is detected automatically |
| `repository_id` | yes | Target repository |
| `format` | no | One of the format IDs [below](#supported-formats). Omitted: detected from the content. When given, the content must agree (`422` *the file is X, not Y*); an empty report (for example `[]`) is only accepted with a named format |
| `tool` | for generic formats | Tool name, e.g. `Snyk Code`. Results are stored under the scanner key `import-<category>-<tool>` (here `import-sast-snyk-code`). Tool-specific formats default to their tool (`Trivy`, `OWASP ZAP`, ...); SARIF, PATHOS findings JSON and CSV need it |
| `category` | no | Any finding category except `eol`: `sast`, `sca`, `secrets`, `iac`, `container`, `license`, `dast`, `api`, `iast`, `mobile`, `fuzz`, `malware`, `misconfiguration`, `binary`, `crypto`, `cicd`, `ai`, `runtime`, `compliance`, `database`, `code-quality`, `supply-chain`, `other`. Default: the format's category, else `other`. With `other`, each finding keeps its natural category (Trivy vulnerabilities `sca`, misconfigurations `iac`, secrets `secrets`) |
| `commit_sha`, `branch` | no | The commit and branch the tool analysed |
| `resolve_missing` | no | `true` when the file is the tool's complete result for the repository: findings from this tool that are no longer reported are marked fixed. Default `false` (partial imports never resolve anything) |

Each import becomes a scan execution with trigger `import` (it appears under **Scans** with its Scan ID). Its results go through the normal pipeline:

- the profile's severity threshold and exclusions are applied
- findings are de-duplicated (cross-tool for dependency findings), risk-scored, queued for AI and Human Eye review per configuration, and kept with the raw report; the tool's own record of each finding (redacted) becomes the finding's original output
- nothing is dropped: records the tool marks as false positives or not exploitable (ZAP confidence 0, Checkmarx *FalsePositive*, OpenVAS false positives, SonarQube resolutions other than *closed*) are imported with `low` confidence and the tool's verdict in the description, for triage in PATHOS

Responses:

- `201`: the import record (`status`, `records`, `scan_job_id`, `scan_key`, `format`, `tool`, `category`, `sha256`)
- `400`: unknown `format` or `category`, or no `tool` for a generic format
- `422 invalid_report`: the file cannot be parsed, its format is not recognised (`format: "unknown"`) or does not match `format`. The failed import is recorded too.
- `409`: a scan of the repository is running, or the repository is archived

### Supported formats

`GET /api/v1/imports/formats` (any signed-in user or token) returns `{ "results": [{ "id", "label", "tool", "category", "media" }], "sbom": [...], "categories": [...] }`.

| `format` | Tool output | Detected by | Default category |
|---|---|---|---|
| `sarif` | SARIF 2.1 from any tool | `runs` | `other` |
| `snyk-code` | Snyk Code (`snyk code test --sarif`), and Snyk Open Source SARIF (`snyk test --sarif`, import with category `sca`) | SARIF (`runs`) | `sast` |
| `grype` | Grype JSON (`grype -o json`) | `matches` | `sca` |
| `pathos` | [PATHOS findings JSON](#pathos-findings-json) | `findings` | `other` |
| `semgrep` | Semgrep or Opengrep JSON (`semgrep scan --json`) | `results[].check_id` | `sast` |
| `snyk` | Snyk Open Source JSON (`snyk test --json`, also `--all-projects`) | `vulnerabilities` with `packageManager` | `sca` |
| `sonarqube` | SonarQube issues API JSON (`/api/issues/search`, also `/api/hotspots/search`) | `issues[].rule` and `component` | `sast` |
| `zap` | OWASP ZAP JSON report and XML report | `site` with `@version`, or `<OWASPZAPReport>` | `dast` |
| `burp` | Burp Suite XML issue export | `<issues burpVersion>` | `dast` |
| `trivy` | Trivy JSON (`trivy fs`, `image` or `config` with `--format json`): vulnerabilities, misconfigurations, secrets | `SchemaVersion` with `Results` | per finding |
| `gitleaks` | Gitleaks JSON (`--report-format json`) | array of objects with `RuleID` and `File` | `secrets` |
| `trufflehog` | TruffleHog JSON lines (`--json`) | `DetectorName` and `SourceMetadata` | `secrets` |
| `checkov` | Checkov JSON (`-o json`), one or several frameworks | `check_type` and `results` | `iac` |
| `bandit` | Bandit JSON (`-f json`) | `results[].test_id` | `sast` |
| `gosec` | Gosec JSON (`-fmt json`) | `Issues` with `Stats` | `sast` |
| `eslint` | ESLint JSON (`-f json`), e.g. with eslint-plugin-security | array of `filePath` and `messages` | `sast` |
| `npm-audit` | npm audit JSON (`npm audit --json`), report versions 1 and 2 | `auditReportVersion` or `advisories` | `sca` |
| `pip-audit` | pip-audit JSON (`-f json`) | `dependencies[].vulns` | `sca` |
| `osv-scanner` | OSV-Scanner JSON (`--format json`) | `results[].source` and `packages` | `sca` |
| `dependency-check` | OWASP Dependency-Check JSON (`-f JSON`) | `reportSchema` and `dependencies` | `sca` |
| `nessus` | Nessus `.nessus` (v2) export | `<NessusClientData_v2>` | `other` |
| `openvas` | OpenVAS / Greenbone XML report | `<report>` or `<get_reports_response>` of the Greenbone format | `other` |
| `nuclei` | Nuclei JSON lines (`-jsonl`) | `template-id` | `dast` |
| `checkmarx` | Checkmarx CxSAST XML report | `<CxXMLResults>` | `sast` |
| `csv` | [Generic CSV](#generic-csv) | a header with `title` and `severity` columns | `other` |
| `fortify` | Fortify SCA FVDL XML (`audit.fvdl`), or the FPR file that contains it (an FPR must be imported with `format=fortify`). *Built from the published format; not yet verified against a real export* | `<FVDL>` | `sast` |
| `veracode` | Veracode detailed report XML (static, dynamic and SCA flaws). *Built from the published format; not yet verified against a real export* | `<detailedreport>` | per finding |
| `coverity` | Coverity JSON (`cov-format-errors --json-output-v7` or `-v10`). *Built from the published format; not yet verified against a real export* | `issues[].checkerName` and `mergeKey` | per finding |
| `appscan-source` | HCL AppScan Source assessment XML (`.ozasmt`). *Built from the published format; not yet verified against a real export* | `<AssessmentRun>` | `sast` |
| `klocwork` | Klocwork JSON (`kwcheck list -F json`, Web API `search` JSON lines). *Built from the published format; not yet verified against a real export* | `code`, `severityCode` and `file` | per finding |
| `horusec` | Horusec JSON (`horusec start -o json`) | `analysisVulnerabilities` | per finding |
| `bearer` | Bearer CLI JSON (`bearer scan --format json`) | object of severity arrays with `id`, `cwe_ids`, `fingerprint` | per finding |
| `brakeman` | Brakeman JSON (`brakeman -f json`) | `scan_info` and `warnings` | `sast` |
| `spotbugs` | SpotBugs / FindSecBugs XML (`-xml:withMessages`) | `<BugCollection>` | per finding |
| `pmd` | PMD XML (`pmd check -f xml`) | `<pmd>` | per finding |
| `cppcheck` | Cppcheck XML v2 (`--xml --xml-version=2`) | `<results version="2">` with `<cppcheck>` | per finding |
| `flawfinder` | Flawfinder CSV (`flawfinder --csv`) | CSV header with `File`, `Line`, `Level`, `Warning`, `CWEs` | `sast` |
| `phpstan` | PHPStan JSON (`phpstan analyse --error-format=json`) | `totals` and `files` | per finding |
| `psalm` | Psalm JSON (`psalm --output-format=json`, also `--taint-analysis`) | array of `type`, `severity`, `line_from`, `file_name` | per finding |
| `njsscan` | njsscan JSON (`njsscan --json`) | `njsscan_version` (or `nodejs`, `templates`, `errors`) | `sast` |
| `mobsfscan` | mobsfscan JSON (`mobsfscan --json`) | `mobsfscan_version` and `results` | `sast` |
| `sobelow` | Sobelow JSON (`mix sobelow --format json`) | `sobelow_version` and `findings` | `sast` |
| `shellcheck` | ShellCheck JSON (`shellcheck -f json1`, also `-f json`) | `comments` only, or array of `file`, `line`, `column`, `level`, numeric `code`, `message` | per finding |
| `ruff` | Ruff JSON (`ruff check --output-format json`) | array of `code`, `filename`, `location`, `message` | per finding |
| `pylint` | Pylint JSON (`--output-format=json` or `json2`) | array of `symbol`, `message-id`, `path`, `type`; or `messages` with `statistics` | per finding |
| `golangci-lint` | golangci-lint JSON (v2 `--output.json.path`, v1 `--out-format json`) | `Issues` and `Report` (without gosec's `Stats`) | per finding |
| `codacy` | Codacy Analysis CLI JSON (`codacy-analysis-cli analyze --format json`); Codacy CLI v2 SARIF imports as `sarif` | array of `{"Issue": ...}` / `{"FileError": ...}` | per finding |
| `sonarcloud` | SonarQube Cloud (SonarCloud) issues API JSON (`/api/issues/search`, `/api/hotspots/search`), parsed like `sonarqube`. *Built from the published format; not yet verified against a real export* | as `sonarqube` (detected as `sonarqube`) | `sast` |
| `detect-secrets` | detect-secrets JSON / baseline (`detect-secrets scan`) | `results` and `plugins_used` | `secrets` |
| `kingfisher` | Kingfisher JSON (`kingfisher scan --format json`) | `findings` with `metadata.kingfisher_version` or a `kingfisher.*` audit | `secrets` |
| `noseyparker` | Nosey Parker JSON or JSON Lines (`noseyparker report --format json\|jsonl`) | `finding_id`, `rule_name`, `matches` | `secrets` |
| `ggshield` | GitGuardian ggshield JSON (`ggshield secret scan ... --json`). *Built from the published format; not yet verified against a real export* | `total_incidents`, `total_occurrences` with `entities_with_incidents` / `scans` / `secrets_engine_version` | `secrets` |
| `whispers` | Whispers JSON (`whispers -o report.json`) | array of `rule_id`, `key`, `value`, `file`, `severity` | `secrets` |
| `talisman` | Talisman JSON report (`talisman --scan`, `talisman_reports/data/report.json`) | `summary` and `results[].failure_list` | `secrets` |
| `mend` | Mend (WhiteSource) vulnerability report JSON (legacy API / Unified Agent) and platform API 3.0 dependency findings. *Built from the published format; not yet verified against a real export* | `vulnerabilities[].library`, or `response[].vulnerability` and `component` | `sca` |
| `blackduck` | Black Duck vulnerable BOM components API JSON, and the Vulnerabilities report CSV (`security.csv`). *Built from the published format; not yet verified against a real export* | `items[].vulnerabilityWithRemediation`, or CSV columns Component name, Component version name, Vulnerability id, Security Risk | `sca` |
| `jfrog-xray` | JFrog Xray vulnerabilities report export JSON (Reports API). *Built from the published format; not yet verified against a real export* | `rows[].issue_id` and `vulnerable_component` | `sca` |
| `nexus-iq` | Sonatype Nexus IQ report API JSON (raw and policy reports). *Built from the published format; not yet verified against a real export* | `components[].componentIdentifier` with `securityData` or `violations` | `sca` |
| `dependency-track` | Dependency-Track Finding Packaging Format (FPF, `/api/v1/finding/project/{uuid}/export`). *Built from the published format; not yet verified against a real export* | `meta.application` "Dependency-Track" with `findings` | `sca` |
| `dependabot` | GitHub Dependabot alerts REST API JSON (`/repos/{owner}/{repo}/dependabot/alerts`). *Built from the published format; not yet verified against a real export* | array of `number`, `state`, `security_advisory`, `dependency` | `sca` |
| `retire-js` | Retire.js JSON (`retire --outputformat json`) | `data[].file` and `results` (or an array of them) | `sca` |
| `yarn-audit` | yarn audit JSON lines: Yarn 1 `yarn audit --json`, Yarn 2+ `yarn npm audit --json` | `type`/`data` lines, or `value`/`children` with `Vulnerable Versions` | `sca` |
| `pnpm-audit` | pnpm audit JSON (`pnpm audit --json`) | `actions`, `advisories`, `muted`, `metadata` without `runId` | `sca` |
| `composer-audit` | Composer audit JSON (`composer audit --format=json`) | `advisories` with `abandoned` (or `advisoryId` entries) | `sca` |
| `govulncheck` | govulncheck JSON (`govulncheck -json ./...`), with call-trace reachability | `config.scanner_name` "govulncheck" | `sca` |
| `safety` | Safety JSON (Safety 2 `safety check --json`, Safety 3 `safety check --output json`) | `report_meta` and `vulnerabilities` | `sca` |
| `dotnet-vulnerable` | `dotnet list package --vulnerable [--include-transitive] --format json` | `version`, `projects[].frameworks`, `parameters` | `sca` |
| `bundler-audit` | bundler-audit JSON (`bundle-audit check --format json`) | `version`, `created_at`, `results[].type` | `sca` |
| `cargo-audit` | cargo-audit JSON (`cargo audit --json`) | `database`, `lockfile`, `vulnerabilities` | `sca` |
| `dep-scan` | OWASP dep-scan VDR (`*.vdr.json`, CycloneDX). *Built from the published format; not yet verified against a real export* | CycloneDX whose `metadata.tools` names owasp-depscan | `sca` |
| `gl-sast` | GitLab SAST report (`gl-sast-report.json`) | `version`, `vulnerabilities`, `scan.type` `sast` | `sast` |
| `gl-secret-detection` | GitLab secret detection report (`gl-secret-detection-report.json`) | `scan.type` `secret_detection` | `secrets` |
| `gl-dependency-scanning` | GitLab dependency scanning report (`gl-dependency-scanning-report.json`) | `scan.type` `dependency_scanning` | `sca` |
| `gl-container-scanning` | GitLab container scanning report (`gl-container-scanning-report.json`) | `scan.type` `container_scanning` | `container` |
| `gl-dast` | GitLab DAST report (`gl-dast-report.json`). *Built from the published format; not yet verified against a real export* | `scan.type` `dast` | `dast` |
| `gl-coverage-fuzzing` | GitLab coverage fuzzing report (`gl-coverage-fuzzing-report.json`). *Built from the published format; not yet verified against a real export* | `scan.type` `coverage_fuzzing` | `other` |
| `gitlab` | Any GitLab security report (also `api_fuzzing`, `cluster_image_scanning`); the `gl-*` formats are this parser with the category of their report type | `version`, `vulnerabilities` and `scan.type` | per finding |
| `kics` | KICS JSON (`kics scan --report-formats json`) | `queries` with `kics_version` | `iac` |
| `tfsec` | tfsec JSON (`tfsec --format json`) | `results[].rule_id`, `long_id` and `location` | `iac` |
| `terrascan` | Terrascan JSON (`terrascan scan -o json`) | `results.violations` and `scan_summary` | `iac` |
| `kube-linter` | KubeLinter JSON (`kube-linter lint --format json`) | `Checks`, `Reports` and `Summary` | `iac` |
| `kubescape` | Kubescape JSON (`kubescape scan --format json`, format v2) | `summaryDetails`, `results` and `resources` | `iac` |
| `cfn-lint` | cfn-lint JSON (`cfn-lint -f json`) | array of `Filename`, `Level`, `Location`, `Rule` | `iac` |
| `cfn-nag` | cfn_nag JSON (`cfn_nag_scan --output-format json`) | array of `filename` and `file_results` | `iac` |
| `hadolint` | Hadolint JSON (`hadolint -f json`) | array of `code` (a string), `level`, `line`, `message`, `file` | `iac` |
| `tflint` | TFLint JSON (`tflint --format json`) | only `issues` and `errors` | `iac` |
| `conftest` | Conftest JSON (`conftest test -o json`) | array of `filename`, `namespace`, `successes` | `iac` |
| `polaris` | Polaris audit JSON (`polaris audit --format json`) | `PolarisOutputVersion` and `Results` | per finding |
| `kube-bench` | kube-bench JSON (`kube-bench run --json`) | `Controls` with `Totals` | `other` |
| `poutine` | poutine JSON (`poutine analyze_local\|analyze_repo\|analyze_org --format json`) | `findings`, `rules` and `packages` | `other` |
| `legitify` | Legitify JSON (`legitify analyze --output-format json`, default flattened scheme). *Built from the published format; not yet verified against a real export* | `type` and `content` only | `other` |
| `scorecard` | OpenSSF Scorecard JSON (`scorecard --format json --show-details`) | `repo`, `scorecard` and `checks` | `other` |

What is mapped, where the tool reports it: severity (each tool's scale mapped to critical, high, medium, low, info; CVSS when there is no label), CWE, CVE (or the advisory id), CVSS score and vector, file and line or URL / host:port, package, installed and fixed version, the tool's confidence, and the rule. Notes per tool:

- **pip-audit** reports no severity: findings are `medium` and the description says so. **npm audit** reports the vulnerable range, not the installed version. **Checkov** findings without a severity (the open-source edition) are `medium`.
- **ESLint**: every rule message is imported (the report does not say which rules are security rules; import the output of a security rule set). Messages without a rule (parse errors) are not findings. **SonarQube** issues with status *CLOSED* no longer exist in the code and are not imported.
- **TruffleHog** verified secrets are `critical`, unverified ones `high`. **Gitleaks** secrets are `high`.
- **Nessus** severity 0 items are imported as `info`.
- **Burp** and **ZAP**: the request and response bodies are never kept (they can contain credentials); only their presence is recorded.

**Secrets in reports.** Gitleaks, TruffleHog and Trivy report the secrets they find in plain text. PATHOS removes these values (`Secret`, `Match`, `Line`; `Raw`, `RawV2`, `Redacted`, `SecretParts`; Trivy's secret `Match` and `Code`) **before** the report is parsed or stored. Finding identity never depends on them. The import's `sha256` is that of the uploaded file.

**XML.** XML reports are parsed without DTD processing: external entities and external DTDs are never resolved, only the five predefined XML entities are known (documents using other entities are rejected), nesting depth is bounded, and only UTF-8, US-ASCII and ISO-8859-1 / Windows-1252 encodings are accepted.

#### Notes on the formats added in 2.0

Rows marked *built from the published format; not yet verified against a real export* were written from the vendor's schema or documentation because no real report was available (commercial products, or tools that need an account or a deployed target). All other formats were tested with reports produced by running the tool.

Severity and verdicts:

- **Fortify**: severity is Fortify's priority (Impact and likelihood = Accuracy × Confidence × Probability / 25: critical when both are at least 2.5, high when only Impact is, medium when only likelihood is, otherwise low); InstanceSeverity when the rule metadata is missing. Identity is the InstanceID.
- **Veracode**: severity 5 critical, 4 high, 3 medium, 2 and 1 low, 0 info. Static flaws are `sast`, dynamic flaws `dast` (at their URL), component CVEs `sca`. Flaws with `remediation_status="Fixed"` are not imported (like closed SonarQube issues); mitigated flaws have `low` confidence and the mitigation text.
- **Coverity**: impact gives the severity; SECURITY issues are `sast`, quality-only issues `other`; a triage of False Positive or Intentional gives `low` confidence.
- **AppScan Source**: severity 0–3 is high, medium, low, info; Definitive, Suspect and Scan Coverage findings have high, medium and low confidence.
- **Klocwork**: severityCode 1 critical, 2 high, 3 medium, 4 low, 5 and above info. Fixed issues are not imported; Ignore, Not a Problem and Defer give `low` confidence. MISRA and AUTOSAR checkers are `other`.
- **Horusec**: findings in the Leaks language are `secrets` (their `code` is removed). False Positive, Risk Accepted and Corrected give `low` confidence.
- **Brakeman** has no severity: its confidence (High, Medium, Weak) sets severity and confidence. Ignored warnings are imported with `low` confidence.
- **SpotBugs** priority 1–3 is high, medium, low; SECURITY and MALICIOUS_CODE bugs are `sast`, others `other`. **PMD** priority 1 high, 2 medium, 3–4 low, 5 info; the Security ruleset is `sast`, others `other`. **Cppcheck** error high, warning medium, style, performance and portability low; its own diagnostics (missing includes, checkers report) are not findings. **Flawfinder** level 5 critical, 4 high, 3 medium, 2 low, 0–1 info.
- **PHPStan** has no severity (all `low`, category `other`). **Psalm** taint issues are `high` `sast` with their CWE and taint trace; other issues `low` or `info` `other`. **ShellCheck** error medium, warning low, info and style info (`other`). **Ruff** S rules (flake8-bandit) are `sast` with Bandit's CWE and severity; other rules `low` `other`. **Pylint** eval-used and exec-used are `sast`; everything else `other`. **golangci-lint** gosec issues are `sast` with gosec's CWE; other linters `other`. **Codacy** Security patterns are `sast`; others `other`. **Sobelow** reports a confidence, not a severity: the severity and CWE come from the vulnerability class.
- **Secret scanners**: secrets are `high`, `critical` when the tool says the secret is valid (detect-secrets `is_verified`, Kingfisher active, ggshield `valid`); Whispers and Talisman keep their own severity. Audited non-secrets, rejected Nosey Parker matches and Talisman warnings are imported with `low` confidence.
- **govulncheck**: each vulnerability is reported once, at the deepest level it reaches. The description says whether vulnerable code is called (with the call path; `high` confidence), only imported or only required (`low` confidence). The Go vulnerability database has no severity: findings are `medium`.
- **No severity in the report**: Safety's free database, Composer advisories with `severity: null` and cargo-audit vulnerabilities (which have only a CVSS vector, kept) are `medium`, and the description says so. cargo-audit warnings (unmaintained, unsound, yanked) are `low`. **Nexus IQ** threat level 8–10 critical, 4–7 high, 2–3 medium, 1 low, 0 info; licence violations are `license`.
- **No installed version**: Composer audit and Dependabot report the affected range; `dotnet list package` gives no CVE, CWE or fixed version, only the advisory URL. **yarn 1** repeats of an advisory on several dependency paths are one finding listing the paths.
- **Tool verdicts kept for triage** (`low` confidence, verdict in the description): Dependency-Track false positive, not affected or suppressed; Mend ignored; Black Duck ignored, mitigated, not affected or patched; Nexus waived or grandfathered; dep-scan false positive, not affected or resolved; Safety ignored; Dependabot dismissed (fixed alerts are not imported); tfsec ignored (`tfsec:ignore`); Terrascan skipped violations; Kubescape exceptions; Conftest exceptions (`info`).
- **GitLab reports**: severity `Unknown` (coverage fuzzing always) is imported as `medium` with a note; analyzer confidence maps to PATHOS confidence; a vulnerability flagged as a likely false positive has `low` confidence. The fixed version of dependency and container findings is read from the solution text. DAST findings are located at their URL; request and response headers and bodies are not kept in the finding's original output.
- **KubeLinter** has no severity or line numbers: checks granting host or root access (privileged containers, host namespaces, docker.sock, sensitive host mounts, ...) are `high`, others `medium`. **Polaris** danger is `high`, warning `medium`; Security checks are `iac`, Efficiency and Reliability checks `other`; the audit has no file names. **Kubescape** uses the control's severity (or its scoreFactor); the file is relative to the scanned directory. **kube-bench** has no severity: FAIL is `medium`, WARN (manual check) `low` with `low` confidence; PASS and INFO are not findings. **cfn_nag** FAIL is `high`, WARN `medium`. **cfn-lint** E rules `high`, W `medium`, I `info`. **Hadolint** style is `info`. **TFLint** notice is `low`.
- **CI/CD and posture tools** (poutine, Legitify, OpenSSF Scorecard, kube-bench) use the `other` category. **Scorecard**: every check below 10 is a finding with the check's documented risk level (one level lower when the score is 5 or more); `-1` (inconclusive) is not a finding; the warnings with their files and lines are in the description. **Legitify** FAILED violations are findings, located at the GitHub or GitLab entity's link; only the default flattened output scheme can be imported.
- **DeepSource** is not supported: it has no documented report export.

Secrets in the new formats are removed before the report is stored and from each finding's original output, and identity never depends on them: GitLab secret detection `raw_source_code_extract`; detect-secrets `hashed_secret`; Kingfisher `snippet`, `dependent_captures`, `validate_command`, `blast_radius_command`, `response`; Nosey Parker `groups` and `snippet`; ggshield `match`; Whispers `value`; Talisman the text after the first colon of `filecontent` messages; Bearer `code_extract` and `sink.content` of secret findings; Horusec `code` of Leaks findings.

### DAST, API, infrastructure, cloud, container, mobile, runtime, AI, pentest and fuzzing formats

These formats work like the ones above. Detection tries every tool-specific format before the generic CSV format, and exactly one detector accepts each test report. The **Test report** column says how the format was checked: *real run* means the test report was produced by running the tool against a local test service; *published format* means the format was **built from the published format; not yet verified against a real export**.

| `format` | Tool output | Detected by | Default category | Test report |
|---|---|---|---|---|
| `nikto` | Nikto JSON or XML (`-Format json` / `xml`) | `host`, `port`, `vulnerabilities` with `ip` or `banner`; or `<niktoscans>` / `<niktoscan>` | `dast` | real run (Nikto 2.5.0) |
| `wapiti` | Wapiti JSON (`-f json`) | `classifications`, `vulnerabilities`, `infos` | `dast` | real run (Wapiti 3.3.2) |
| `arachni` | Arachni JSON (`arachni_reporter --reporter=json`) | `issues`, `sitemap`, `options` | `dast` | real run (Arachni 1.5.1) |
| `sqlmap` | sqlmap results CSV (`--results-file`, multiple-target mode) | header `Target URL`, `Place`, `Parameter`, `Technique(s)` | `dast` | real run (sqlmap 1.10.11) |
| `dalfox` | Dalfox JSON (`--format json`), versions 2 and 3 | `findings` with `meta.dalfox_version`; or objects with `type`, `inject_type`, `param` | `dast` | real run (Dalfox 3.3.0); the version 2 shape: published format |
| `ffuf` | ffuf JSON (`-of json`) | `commandline`, `results`, `config` | `dast` | real run (ffuf 2.1.0) |
| `wfuzz` | Wfuzz JSON (`-f file,json`) | objects with `chars`, `code`, `payload`, `words`, `url` | `dast` | real run |
| `w3af` | w3af XML report (`xml_file` plugin) | `<w3af-run>` | `dast` | published format |
| `schemathesis` | Schemathesis JSON report and JUnit XML (`--report json,junit`) | `schemathesis_version` with `failures`; or JUnit XML with `<testsuite name="schemathesis">` | `other` | real run (Schemathesis 4.33.4) |
| `restler` | RESTler bug buckets (per-bug JSON files or `Bugs.json`) | `checker_name`, `request_sequence`, `verb`, `endpoint`; or `bugs` with `filepath` and `checker_name` | `other` | published format |
| `acunetix` | Acunetix XML export and Acunetix 360 JSON | `<ScanGroup>` with `<Scan>`; or the Invicti JSON layout naming Acunetix 360 | `dast` | published format |
| `invicti` | Invicti / Netsparker JSON or XML report | `Target` and `Vulnerabilities`; or `<invicti-enterprise>`, `<netsparker-enterprise>`, `<invicti>`, `<netsparker>` | `dast` | published format |
| `appspider` | Rapid7 AppSpider `VulnerabilitiesSummary.xml` | `<VulnSummary>` | `dast` | published format |
| `qualys-was` | Qualys WAS XML report | `<WAS_SCAN_REPORT>` or `<WAS_WEBAPP_REPORT>` | `dast` | published format |
| `insightappsec` | Rapid7 InsightAppSec vulnerabilities JSON (API) | `data[]` with `root_cause`, `variances`, `severity` | `dast` | published format |
| `appscan-dast` | HCL AppScan Standard / Enterprise / ASoC XML report | `<xml-report>` of AppScan | `dast` | published format |
| `burp-enterprise` | Burp Suite DAST / Enterprise GraphQL issues, and Burp REST API scan JSON | `issue_events` with `scan_metrics` or `task_id`; or GraphQL `data.scan` with issues | `dast` | published format |
| `stackhawk` | StackHawk scan results JSON | `"service": "StackHawk"` with `scanCompleted` | `dast` | published format |
| `42crunch` | 42Crunch API Security Audit JSON | `index`, `security` and `assessmentVersion` or `score` | `other` | published format |
| `nmap` | Nmap XML (`-oX`): open ports and NSE vulnerability scripts | `<nmaprun>` | `other` | real run (Nmap 7.98); vulners script output: published format |
| `qualys-vm` | Qualys VMDR scan report XML (`ASSET_DATA_REPORT`) | `<ASSET_DATA_REPORT>` | `other` | published format |
| `tenable-csv` | Tenable.io / Nessus CSV export, and Tenable.sc CSV | header with Plugin ID, Name, Host, Port, Protocol and Risk (or Plugin, Plugin Name, IP Address, Severity) | `other` | published format |
| `nexpose` | Rapid7 Nexpose / InsightVM XML Export 2.0 | `<NexposeReport>` | `other` | published format |
| `testssl` | testssl.sh JSON (`--jsonfile` or `--jsonfile-pretty`) | objects with `id`, `ip`, `port`, `severity`, `finding`; or `scanResult` | `other` | real run (testssl.sh 3.2.5) |
| `sslyze` | SSLyze JSON (`--json_out`) | `server_scan_results` with `sslyze_version` or `sslyze_url` | `other` | real run (SSLyze 6.3.1) |
| `sslscan` | sslscan XML (`--xml`) | `<document title="SSLScan Results">` or `<document>` with `<ssltest>` | `other` | real run (sslscan 2.1.6) |
| `wazuh` | Wazuh vulnerability detection: alerts (JSON lines) and `wazuh-states-vulnerabilities` documents | `vulnerability-detector` alerts; or `vulnerability`, `package`, `agent` | `other` | published format |
| `prowler` | Prowler JSON (OCSF `-M json-ocsf`, or Prowler 3 JSON) | `finding_info`, `metadata`, `status_code`, `cloud`; or `CheckID`, `CheckTitle`, `StatusExtended` | `other` | published format |
| `prowler-csv` | Prowler CSV (`-M csv`) | header `check_id`, `check_title`, `status`, `severity`, `provider` and a resource column | `other` | published format |
| `scoutsuite` | ScoutSuite results (`scoutsuite_results_*.js` or its JSON) | `scoutsuite_results` with `provider_code`; or `provider_code`, `services`, `last_run` | `other` | published format |
| `asff` | AWS Security Hub findings, ASFF (`get-findings`) | `Findings[]` with `SchemaVersion`, `ProductArn`, `AwsAccountId`, `GeneratorId` | `other` | published format |
| `inspector2` | Amazon Inspector findings JSON (`aws inspector2 list-findings`) | findings with `findingArn`, `awsAccountId`, `type`, `resources` | `other` | published format |
| `defender-cloud` | Microsoft Defender for Cloud assessments JSON (REST, `az security assessment list`, Resource Graph) | items of type `Microsoft.Security/assessments` | `other` | published format |
| `gcp-scc` | Google Cloud Security Command Center findings (`gcloud scc findings list --format json`) | `finding` with `name`, `category`, `state`, `resourceName` | `other` | published format |
| `cloudsploit` | CloudSploit JSON | `plugin`, `category`, `title`, `resource`, `region`, `status`, `message` | `other` | published format |
| `dockle` | Dockle JSON (`-f json`) | `summary` (`fatal`, `warn`, `pass`) and `details` | `container` | real run (Dockle 0.4.15) |
| `clair` | Clair v4 vulnerability report JSON | `manifest_hash` and `package_vulnerabilities` | `container` | published format |
| `harbor` | Harbor vulnerability report JSON (API) | the vulnerability report media type key, or `generated_at`, `scanner`, `vulnerabilities` | `container` | published format |
| `trivy-k8s` | Trivy Kubernetes report JSON (`trivy k8s --format json`) | `ClusterName` with `Resources` | per finding | published format |
| `anchore` | Anchore Engine / Enterprise vulnerabilities JSON (`anchore-cli`, `anchorectl`) | `vuln`, `severity`, `package` items | `container` | published format |
| `twistlock` | Prisma Cloud / Twistlock `twistcli` JSON | `results[]` with `id`, `distro` | `container` | published format |
| `twistlock-csv` | Prisma Cloud / Twistlock vulnerability CSV | header `registry`, `repository`, `tag`, `cve_id`, `compliance_id`, `packages`, `fix_status` | `container` | published format |
| `sysdig` | Sysdig Secure vulnerability JSON (CLI scanner or report) | `scanner.name` of Sysdig with `result`; or report panels | `container` | published format |
| `sysdig-csv` | Sysdig Secure vulnerability report CSV | header `package_name`, `package_version`, `package_path`, `image_id`, `risk_accepted` | `container` | published format |
| `docker-scout` | Docker Scout (`docker scout cves --format sarif`) | SARIF (`runs`) | `container` | published format |
| `mobsf` | MobSF static analysis JSON (Android and iOS) | `code_analysis`, `app_type`, `md5` | `other` | real MobSF exports from the DefectDojo test corpus, trimmed and extended by hand |
| `apkleaks` | APKLeaks JSON (`--json`) | `package` and `results` with `name`, `matches` | `other` | published format |
| `nowsecure` | NowSecure (SARIF) | SARIF (`runs`) | `other` | published format |
| `contrast` | Contrast Assess vulnerabilities CSV export | header `vulnerability_name`, `vulnerability_id`, `rule_name`, `severity`, `status`, `application_name`, `request_uri` | `other` | published format |
| `falco` | Falco JSON alerts (`json_output`) | `rule`, `priority`, `output` with `output_fields` or `time` | `other` | published format |
| `tetragon` | Tetragon JSON events (export) | `node_name`, `time` and a Tetragon event key | `other` | published format |
| `tracee` | Tracee JSON events (signature detections) | `eventName` with `processName` or `eventId` and `metadata` or `args` | `other` | published format |
| `garak` | garak report or hit log (JSON lines) | `entry_type` with a garak marker; or `attempt_id`, `probe`, `detector`, `generator` | `other` | real run (garak 0.17.1, test generator) |
| `promptfoo` | promptfoo eval / red-team results JSON (`-o results.json`) | `evalId` and `results` with `config` or `shareableUrl` | `other` | real run (promptfoo 0.126.0, echo provider); red-team metadata added by hand |
| `modelscan` | ProtectAI ModelScan JSON (`-r json`) | `summary`, `issues` and `modelscan_version` | `other` | real run (ModelScan 0.8.8) |
| `hackerone` | HackerOne reports API JSON | `data[]` of type `report` with `attributes` and `relationships` | `other` | published format |
| `hackerone-csv` | HackerOne reports CSV | header `id`, `title`, `severity_rating`, `state`, `substate`, `weakness`, `reported_at` | `other` | published format |
| `bugcrowd` | Bugcrowd submissions CSV | header `reference_number`, `bounty_code`, `title`, `priority`, `vrt_lineage`, `substate`, `bug_url` | `other` | published format |
| `intigriti` | Intigriti submissions JSON (API) | `records[]` with `code`, `title`, `severity`, `state` | `other` | published format |
| `clusterfuzzlite` | ClusterFuzzLite / CIFuzz crash results (SARIF) | SARIF (`runs`) | `other` | published format |
| `libfuzzer` | libFuzzer / Jazzer crash log (text: sanitizer report, `SUMMARY:`, `== Java Exception:`) | `==ERROR:` with a sanitizer or libFuzzer error, or a Jazzer exception | `other` | real run (clang 19 libFuzzer with AddressSanitizer); Jazzer: published format |

SARIF-based formats (`docker-scout`, `nowsecure`, `clusterfuzzlite`) are detected as `sarif`; name the format to get its default category. With category `other`, findings keep their natural category: cloud posture checks are `misconfiguration`, host and image package vulnerabilities `sca` or `container`, ModelScan detections `malware`, MobSF secrets `secrets`.

Notes per tool:

- **Not findings** (the raw report is still stored): passed checks (Prowler PASS and MANUAL, ScoutSuite rules without flagged items, Security Hub PASSED or ARCHIVED, CloudSploit OK, Dockle PASS/SKIP, testssl.sh OK/INFO), closed or inactive cloud findings (Inspector CLOSED, Security Command Center INACTIVE), healthy Defender assessments, resolved bug bounty reports and fixed Contrast results, closed or filtered Nmap ports, NSE results that are NOT VULNERABLE, Tetragon `process_exec`/`process_exit` events (an audit trail, not policy matches) and Tracee events that are not signature detections.
- **Kept with `low` confidence** and the tool's verdict in the description: Acunetix, Invicti, Burp, InsightAppSec and StackHawk false positives, Qualys ignored items, Arachni untrusted issues, Wapiti anomalies, RESTler bugs that did not reproduce, muted or suppressed cloud findings, accepted risks, and rejected bug bounty reports (duplicate, not applicable, informative, out of scope).
- **No severity in the report**: Nikto items are `low`; ffuf and Wfuzz hits are content discovery, imported as `info`; CloudSploit FAIL is `medium` and WARN `low`; garak failures are `high` when at least half of the attempts succeeded, otherwise `medium`; Schemathesis JUnit failures take the severity of their check.
- **SSLyze** and **sslscan** report results, not verdicts: deprecated protocols, weak cipher suites, certificate problems and known TLS vulnerabilities become findings. **Nmap** open ports are `info` findings; NSE vulnerability scripts give `high` (VULNERABLE) or `medium` (LIKELY VULNERABLE).
- **Runtime events** (Falco, Tetragon, Tracee) with the same rule, process and resource become one finding with the event count and first and last time.

**HTTP evidence and secrets in these reports.** Requests and responses are kept only after redaction: the values of `Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, API key and CSRF token headers, credential-like parameters (`password`, `token`, `api_key`, `session`, ...) and token-shaped values are replaced by `[REDACTED]`, in the stored report and in the findings. Base64-encoded traffic (AppSpider, Qualys WAS, Burp, w3af) is decoded, redacted and encoded again. MobSF and APKLeaks secret values are replaced by a hash; garak and promptfoo provider keys, Falco/Tetragon/Tracee environment variables and credential arguments, and secret fields of cloud reports are removed. Finding identity never depends on the removed values.

### Generic CSV

One finding per row; the first row names the columns (case-insensitive, spaces or underscores; comma, semicolon or tab separated). `title` and `severity` are required columns; `severity` may be empty in a row that has `cvss`.

| Column (aliases) | Field |
|---|---|
| `title` (`name`, `summary`) | Title |
| `severity` (`risk`) | `critical`, `high`, `medium`, `low`, `info` (also `moderate`, `informational`, ...) |
| `description` (`details`) | Description |
| `rule_id` (`rule`, `check_id`, `id`) | Rule; defaults to the title |
| `cwe` | `CWE-79` or `79`; several separated by commas, semicolons, vertical bars or spaces |
| `cve` (`vulnerability_id`) | CVE |
| `cvss` (`cvss_score`), `cvss_vector` | Score 0–10 and vector |
| `file_path` (`file`, `path`, `location`), `start_line` (`line`), `end_line` | Code location |
| `url` (`endpoint`) | Location when there is no file (DAST) |
| `package_name` (`package`, `component`), `package_version` (`version`, `installed_version`), `fixed_version` (`fix_version`) | Dependency |
| `confidence` | `high`, `medium`, `low` |
| `fingerprint` (`unique_id`) | Stable identifier of the finding across imports |
| `category` | Category of the row (used when the import category is `other`) |

Other columns are kept in the finding's original output.

### PATHOS findings JSON

For tools without SARIF output (IAST, fuzzers, custom scripts):

```json
{
  "tool": "contrast",
  "findings": [
    {
      "rule_id": "sql-injection",
      "title": "SQL injection in /api/orders",
      "description": "Untrusted data reaches a JDBC query",
      "severity": "high",
      "confidence": "high",
      "cwe": ["CWE-89"],
      "cve": "",
      "cvss": 8.1,
      "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
      "file_path": "src/main/java/OrderDao.java",
      "start_line": 42,
      "url": "https://app.example/api/orders",
      "package_name": "", "package_version": "", "fixed_version": "",
      "fingerprint": "tool-stable-id-123"
    }
  ]
}
```

- `title` (or `rule_id`) and `severity` (or `cvss`) are required. Unknown fields are rejected.
- `url` is used as the location when there is no `file_path` (DAST).
- `fingerprint`, when given, keeps the finding's identity stable across imports.

## Importing SBOMs

`POST /api/v1/imports/sbom` (`scans.run`), `multipart/form-data`: `file` (CycloneDX JSON or SPDX 2.x JSON, at most 64 MiB) and `repository_id`, plus an optional `tool`.

- The SBOM replaces the repository's component inventory, marked `source: import`.
- [Licence policies](supply-chain.md#licence-policies) apply immediately (**SBOM inventory**, dashboard).
- `422 invalid_sbom` is returned for unrecognised or empty SBOMs.

## Import history

`GET /api/v1/imports/history?repository_id=&kind=results|sbom` (`scans.read`) lists the 200 latest imports in the caller's scope.

To import from a pipeline, use the [`pathos` CLI and the CI templates](../user-guide/ci-cd-integration.md).
