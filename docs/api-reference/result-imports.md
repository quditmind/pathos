---
title: Result and SBOM imports, custom rules
section: api-reference
order: 8
version: "1.0"
updated: 2026-11-17
summary: Import findings from any tool (SARIF 2.1, Grype JSON, PATHOS findings JSON) and SBOMs (CycloneDX, SPDX), and manage custom Opengrep detection rules.
---
# Result and SBOM imports, custom rules

## Importing results

`POST /api/v1/imports/results` (`scans.run` on the repository), `multipart/form-data`:

| Field | Required | Description |
|---|---|---|
| `file` | yes | The report, at most 64 MiB; gzip is detected automatically |
| `repository_id` | yes | Target repository |
| `tool` | yes | Tool name, e.g. `Snyk Code`. Results are stored under the scanner key `import-<category>-<tool>` (here `import-sast-snyk-code`) |
| `category` | no | `sast`, `sca`, `secrets`, `iac`, `container`, `license`, `dast`, `other` (default `other`) |
| `commit_sha`, `branch` | no | The commit and branch the tool analysed |
| `resolve_missing` | no | `true` when the file is the tool's complete result for the repository: findings from this tool that are no longer reported are marked fixed. Default `false` (partial imports never resolve anything) |

The format is detected from the content:

| Format | Detected by |
|---|---|
| SARIF 2.1 | `runs` |
| Grype JSON | `matches` |
| PATHOS findings JSON (below) | `findings` |

Each import becomes a scan execution with trigger `import` (it appears under **Scans** with its Scan ID). Its results go through the normal pipeline:

- the profile's severity threshold and exclusions are applied
- findings are de-duplicated (cross-tool for dependency findings), risk-scored, queued for AI and Human Eye review per configuration, and kept with the raw report

Responses:

- `201`: the import record (`status`, `records`, `scan_job_id`, `scan_key`, `format`, `sha256`)
- `422 invalid_report`: the file cannot be parsed. The failed import is recorded too.
- `409`: a scan of the repository is running

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
- Licence policies apply immediately (**SBOM inventory**, dashboard).
- `422 invalid_sbom` is returned for unrecognised or empty SBOMs.

`GET /api/v1/imports/history?repository_id=&kind=results|sbom` lists the 200 latest imports in the caller's scope.

## Custom rules

Opengrep (Semgrep-compatible) rule files.

**How they run:**

- Enabled files run in every new scan alongside the PATHOS baseline rules.
- Each scan's configuration snapshot records the rule file versions (`custom_rules: [{id, name, version}]`).
- The worker receives exactly those versions.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/custom-rules` | `scanners.read` | Rule files (without content) |
| `GET` | `/api/v1/custom-rules/{id}` | `scanners.read` | With content |
| `GET` | `/api/v1/custom-rules/{id}/versions` | `scanners.read` | Saved versions |
| `POST` | `/api/v1/custom-rules/validate` | `profiles.manage` | `{ content }` → `{ valid, rule_ids }` or `422 invalid_rules` |
| `POST` | `/api/v1/custom-rules` | `profiles.manage` | `{ name, description, content, enabled }` |
| `PUT` | `/api/v1/custom-rules/{id}` | `profiles.manage` | Any of the fields plus `change_note`; content or enabled changes create a new version |
| `DELETE` | `/api/v1/custom-rules/{id}` | `profiles.manage` | New scans stop using the file |

Validation runs without executing anything. It requires:

- a `rules:` list (at most 200 rules)
- for each rule: an `id` (unique across enabled files, not starting with the reserved `pathos.`), a `message`, a `severity` (ERROR, WARNING or INFO), non-empty `languages`, and a pattern (`pattern`, `patterns`, `pattern-either`, `pattern-regex`, or taint mode with `pattern-sources` and `pattern-sinks`)
