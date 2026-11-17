---
title: Supply chain and pull request checks
section: api-reference
order: 9.5
version: "1.0"
updated: 2026-11-18
summary: SBOM export (CycloneDX and SPDX), package health from deps.dev, malicious packages, build artifact targets and pull request checks with commit statuses.
---
# Supply chain and pull request checks

## SBOM export

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/repositories/{id}/sbom` | `findings.read` | The latest scan's CycloneDX SBOM (Syft). Without one (for example an imported SBOM), CycloneDX 1.5 generated from the inventory |
| `GET` | `/api/v1/repositories/{id}/sbom?format=spdx` | `findings.read` | SPDX 2.3 JSON generated from the inventory: one package per component (purl as an external reference, SPDX licence expression or `NOASSERTION`), `DESCRIBES` for the roots and `DEPENDS_ON` for every dependency edge |
| `GET` | `/api/v1/repositories/{id}/sbom?format=cyclonedx` | `findings.read` | Same as without `format` |

`404 no_sbom` when the repository has no inventory; `400` for any other `format`. Files are sent as attachments (`*.spdx.json`, `*.cdx.json`).

## Package health

Package health comes from the `depsdev` intelligence feed ([Risk and vulnerability intelligence](risk-intelligence.md)). The feed is **off by default**: it sends the names of the packages in the inventories (npm, PyPI, Go, Cargo, NuGet, Maven) to `api.deps.dev`, and private package names are sent too. Turn it on with `PUT /api/v1/intel/feeds/depsdev {"enabled": true}` or run it once with `POST /api/v1/intel/feeds/depsdev/run`. Each run refreshes up to 500 packages not refreshed in the last 7 days. There is no file import.

`GET /api/v1/repositories/{id}/dependencies` then returns per component:

| Field | Meaning |
|---|---|
| `latest_version` | The registry's default (latest) version |
| `outdated` | The component's version is lower than `latest_version` (numeric comparison; unparseable versions are never outdated) |
| `deprecated` | The registry marks this version deprecated |
| `scorecard` | OpenSSF Scorecard (0–10) of the source repository (direct dependencies) |
| `provenance` | `verified` (SLSA provenance verified by deps.dev), `unverified`, `none` (checked, no attestation) or absent (not checked; only direct dependencies are) |
| `provenance_source` | The source repository named by the provenance |

`stats` adds `outdated` and `deprecated` counts. A root component whose version is newer than the public package of the same name gets no health data (the public package is someone else's).

## Malicious packages

Findings from OSV `MAL-*` advisories (or titled as malicious code or malware) have `malicious: true`. Their risk uses the KEV likelihood weight and treats them as reachable: a malicious package runs when it is installed. Filter with `GET /api/v1/findings?malicious=true`. Findings also carry `introduced_commit`, the commit of the first scan that detected them.

## Build artifact targets

`POST /api/v1/scan-targets/artifact` (`multipart/form-data`: `file`, `repository_id`, optional `name`; at most 200 MiB; permission `repos.manage`) creates an `artifact` target. See [Scan targets](scan-targets.md). On a scan, the worker downloads the file (SHA-256 checked); zip and tar archives are validated and extracted with the same extractor as source uploads (no links, no path traversal, file count, size and compression ratio limits); Java archives (`.jar`, `.war`, `.ear`, …) and other files are scanned whole. Trivy reports vulnerable components. Nothing in the artifact is run.

## Pull request checks

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/repositories/{id}/pr-settings` | `scans.read` | `{ enabled, gate_severity, source_type }` |
| `PUT` | `/api/v1/repositories/{id}/pr-settings` | `repos.manage` | `{ enabled, gate_severity }`; `gate_severity` is `critical`, `high` (default), `medium`, `low` or `none`. Audited (`repository.pr_checks`). `400` for uploaded repositories |
| `GET` | `/api/v1/pr-checks?repository_id=&status=` | `scans.read` | Latest 200 checks in scope |
| `GET` | `/api/v1/pr-checks/{id}` | `scans.read` | `{ check, findings }`; findings sorted new first, then by severity |
| `POST` | `/api/v1/pr-checks/{id}/repost` | `scans.run` | Post the check's commit status again |

**Flow.** A `pull_request` webhook event (opened, updated, reopened) for a repository with checks enabled queues a scan (`trigger: pull_request`, priority 55) of the PR head branch at the head commit with the repository's scan profile, records a check with status `pending` and posts a pending commit status. A newer push while the scan is queued moves the queued scan to the new head. PR scans never coalesce with scan-branch scans.

**Isolation.** A PR scan's results are stored as `pr_findings`, never as findings: they do not create, update, fix or re-open the repository's findings, and do not change its SBOM inventory or code inventory.

**New or known.** A PR finding is new unless the repository has a finding with the same fingerprint that is not `fixed` (open, in progress, accepted risk or false positive); known findings link to it (`existing_finding_id`).

**Result.** `failed` when a new finding is at or above `gate_severity`; `error` when the scan failed, or was partial without a blocking finding (incomplete results cannot vouch for the PR); otherwise `passed`. The summary lists new findings by severity.

**Commit status.** Context `PATHOS / security`, linking to `/pull-requests?check=<id>`. GitHub (statuses API), GitLab (commit status), Bitbucket Cloud (build status) and Azure DevOps (Git status). The connection's credential needs permission to write statuses. `status_posted` records `pending`, `final`, `failed` (see `status_error`) or `not_supported`. Make the status a required check in branch protection to block merges.

Pull requests from forks are not supported: the head branch must be in the repository.
