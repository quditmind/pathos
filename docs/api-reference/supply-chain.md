---
title: Supply chain and pull request checks
section: api-reference
order: 26
version: "1.0"
updated: 2026-11-19
summary: SBOM inventory search and export (CycloneDX and SPDX), licence policies, package health from deps.dev, malicious packages, build artifact targets and pull request checks with commit statuses.
---
# Supply chain and pull request checks

## SBOM inventory

Each repository has a component inventory, built from the latest scan's SBOM (Syft) or from an [imported SBOM](result-imports.md#importing-sboms).

`GET /api/v1/sbom/components` (`sbom.read` at any scope) searches the inventories in the caller's scope. Components are grouped by name and version across repositories; at most 500, sorted by name.

| Parameter | Description |
|---|---|
| `q` | Case-insensitive search in name and purl |
| `repository_id` | One repository |
| `license` | `deny` or `review` (components whose licence has that policy decision) or `violations` (either) |

Each item: `name`, `version`, `purl`, `type`, `licenses`, `license_policy` (`deny`, `review` or `""`; `deny` wins), `repositories` (full names) and `open_vulnerabilities` (open SCA findings for this package and version in those repositories).

## Licence policies

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/license-policies` | `sbom.read` at any scope | `{ "items": [{ "spdx_id", "decision" }] }` |
| `PUT` | `/api/v1/license-policies` | `settings.manage` (organization-wide) | `{ "items": [{ "spdx_id", "decision" }] }` replaces the whole list (at most 500 entries; `decision` is `deny` or `review`; SPDX ID at most 100 characters) → `204`. Audited (`license_policy.update`) |

New organizations start with `deny` for AGPL-3.0, SSPL-1.0 and CC-BY-NC-4.0 and `review` for GPL-2.0, GPL-3.0, LGPL-3.0 and BUSL-1.1 (the `-only` and `-or-later` SPDX IDs).

## SBOM export

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/repositories/{id}/sbom` | `sbom.read` | The latest scan's CycloneDX SBOM (Syft). Without one (for example an imported SBOM), CycloneDX 1.5 generated from the inventory |
| `GET` | `/api/v1/repositories/{id}/sbom?format=spdx` | `sbom.read` | SPDX 2.3 JSON generated from the inventory: one package per component (purl as an external reference, SPDX licence expression or `NOASSERTION`), `DESCRIBES` for the roots and `DEPENDS_ON` for every dependency edge |
| `GET` | `/api/v1/repositories/{id}/sbom?format=cyclonedx` | `sbom.read` | Same as without `format` |

`404 no_sbom` when the repository has no inventory; `400` for any other `format`. Files are sent as attachments (`*.spdx.json`, `*.cdx.json`).

Component graphs, dependency paths and blast radius are in [Posture](posture.md#endpoints).

## Package health

Package health comes from the `depsdev` intelligence feed ([feeds](risk-intelligence.md#feeds)). The feed is **off by default**: it sends the names of the packages in the inventories (npm, PyPI, Go, Cargo, NuGet, Maven) to `api.deps.dev`, and private package names are sent too. Turn it on with `PUT /api/v1/intel/feeds/depsdev {"enabled": true}` or run it once with `POST /api/v1/intel/feeds/depsdev/run`. Each run refreshes up to 500 packages not refreshed in the last 7 days. There is no file import.

`GET /api/v1/repositories/{id}/dependencies` then returns per component:

| Field | Meaning |
|---|---|
| `latest_version` | The registry's default (latest) version |
| `outdated` | The component's version is lower than `latest_version` (numeric comparison; unparseable versions are never outdated) |
| `deprecated` | The registry marks this version deprecated |
| `scorecard` | OpenSSF Scorecard (0–10) of the source repository (direct dependencies) |
| `provenance` | `verified` (SLSA provenance verified by deps.dev), `unverified`, `none` (checked, no attestation) or absent (not checked; only direct dependencies are) |
| `provenance_source` | The source repository named by the provenance |
| `eol_status`, `eol_cycle`, `eol_date` | [End of life](#end-of-life) of the package's release cycle (`eol`, `approaching`, `supported`), when it is a tracked framework; from the `endoflife` feed |

`stats` adds `outdated` and `deprecated` counts. A root component whose version is newer than the public package of the same name gets no health data (the public package is someone else's).

## End of life

Release cycles and end-of-life dates come from the opt-in `endoflife` [intelligence feed](risk-intelligence.md#feeds). PATHOS matches them to the repository's SBOM components (by package URL), the runtimes and base images declared in its files (reported by the worker, see [worker protocol](worker-protocol.md#runtimes-and-introducing-commits)) and its container image targets. Statuses are recomputed after each repository or image scan, after each feed update and daily.

`GET /api/v1/repositories/{id}/eol` — permission `sbom.read` on the repository.

```json
{
  "feed_loaded": true,
  "feed_as_of": "2026-11-18",
  "eol": 2, "approaching": 1, "supported": 5,
  "computed_at": "2026-11-19T08:00:00Z",
  "items": [
    { "source": "runtime", "component": "node", "version": "16.20.0", "path": ".nvmrc", "product": "nodejs", "product_label": "Node.js",
      "cycle": "16", "eol_date": "2023-09-11T00:00:00Z", "status": "eol", "latest_in_cycle": "16.20.2" },
    { "source": "image", "component": "python:3.8-slim", "version": "3.8", "scan_target_id": "0193…", "product": "python",
      "product_label": "Python", "cycle": "3.8", "eol_date": "2024-10-07T00:00:00Z", "status": "eol", "latest_in_cycle": "3.8.20" }
  ]
}
```

`source` is `sbom`, `runtime` (declared in a file; base images in Dockerfiles have the image reference as `component`) or `image` (an image target). `status` is `eol`, `approaching` (support ends within 180 days) or `supported`. The [dependency graph](posture.md) components carry `eol_status`, `eol_cycle` and `eol_date` as well.

Each product cycle past its end of life is one finding per repository (and image target): category `eol`, scanner `endoflife`, rule `eol/<product>/<cycle>`, `package_name` = product, `package_version` = cycle, severity `medium` (`high` once support ended more than a year ago), confidence `high`. It is resolved automatically when nothing in the repository uses that cycle any more and reopened if it comes back.

## Malicious packages

Findings from OSV `MAL-*` advisories (or titled as malicious code or malware) have `malicious: true`. Their risk uses the KEV likelihood weight and treats them as reachable: a malicious package runs when it is installed. Filter with `GET /api/v1/findings?malicious=true` ([list findings](findings.md#list-findings)).

## Signature verification

Image and artifact targets can be verified with Sigstore cosign on every scan (key-based or keyless), optionally with an in-toto attestation, and a signature can be required: see [signature verification](scan-targets.md#signature-verification).

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
