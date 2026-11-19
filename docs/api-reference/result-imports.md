---
title: Result and SBOM imports
section: api-reference
order: 25
version: "1.1"
updated: 2026-11-19
summary: Import findings from 25 formats (SARIF, Semgrep, Snyk, SonarQube, ZAP, Burp, Trivy, Gitleaks, Nessus, OpenVAS, Checkmarx, CSV and more) and SBOMs (CycloneDX, SPDX), and list past imports.
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
| `category` | no | `sast`, `sca`, `secrets`, `iac`, `container`, `license`, `dast`, `other`. Default: the format's category, else `other`. With `other`, each finding keeps its natural category (Trivy vulnerabilities `sca`, misconfigurations `iac`, secrets `secrets`) |
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

What is mapped, where the tool reports it: severity (each tool's scale mapped to critical, high, medium, low, info; CVSS when there is no label), CWE, CVE (or the advisory id), CVSS score and vector, file and line or URL / host:port, package, installed and fixed version, the tool's confidence, and the rule. Notes per tool:

- **pip-audit** reports no severity: findings are `medium` and the description says so. **npm audit** reports the vulnerable range, not the installed version. **Checkov** findings without a severity (the open-source edition) are `medium`.
- **ESLint**: every rule message is imported (the report does not say which rules are security rules; import the output of a security rule set). Messages without a rule (parse errors) are not findings. **SonarQube** issues with status *CLOSED* no longer exist in the code and are not imported.
- **TruffleHog** verified secrets are `critical`, unverified ones `high`. **Gitleaks** secrets are `high`.
- **Nessus** severity 0 items are imported as `info`.
- **Burp** and **ZAP**: the request and response bodies are never kept (they can contain credentials); only their presence is recorded.

**Secrets in reports.** Gitleaks, TruffleHog and Trivy report the secrets they find in plain text. PATHOS removes these values (`Secret`, `Match`, `Line`; `Raw`, `RawV2`, `Redacted`; Trivy's secret `Match` and `Code`) **before** the report is parsed or stored. Finding identity never depends on them. The import's `sha256` is that of the uploaded file.

**XML.** XML reports are parsed without DTD processing: external entities and external DTDs are never resolved, only the five predefined XML entities are known (documents using other entities are rejected), nesting depth is bounded, and only UTF-8, US-ASCII and ISO-8859-1 / Windows-1252 encodings are accepted.

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
