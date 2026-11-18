---
title: Scan targets
section: api-reference
order: 24
version: "1.0"
updated: 2026-11-19
summary: Container images, web applications (DAST), APIs (OpenAPI), build artifacts and SBOMs as scan targets; authorization statements, credentials, scanning and filters.
---
# Scan targets

A scan target is something PATHOS scans besides a repository's source code. Each target belongs to a repository, so its findings get that repository's application, owners, criticality and access scope.

| Kind | Reference | Scanner | What it finds |
|---|---|---|---|
| `image` | Image reference, e.g. `ghcr.io/acme/api:1.4.2` or `…@sha256:<digest>` | Trivy (image) | Vulnerable OS and language packages in the image |
| `url` | Base URL of a running application | Nuclei | Misconfigurations, exposures, known vulnerabilities (non-intrusive templates) |
| `api` | Base URL plus an OpenAPI 3 / Swagger 2 document | Nuclei DAST templates | Injection and other flaws in each operation |
| `sbom` | Uploaded CycloneDX or SPDX JSON | Grype | Known vulnerabilities in the SBOM's components |
| `artifact` | Uploaded build artifact: zip or tar archive, Java archive, binary | Trivy (filesystem) | Vulnerable components inside the artifact ([details](supply-chain.md#build-artifact-targets)) |

## Permissions

| Action | Permission (on the target's repository) |
|---|---|
| List and read | `scans.read` |
| Create, update, delete | `repos.manage` |
| Scan | `scans.run` |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/scan-targets?repository_id=&kind=` | Targets in the caller's scope, with open findings and the last scan |
| `GET` | `/api/v1/scan-targets/{id}` | One target (includes `api_spec` for API targets) |
| `POST` | `/api/v1/scan-targets` | Create an `image`, `url` or `api` target (JSON) |
| `POST` | `/api/v1/scan-targets/sbom` | Create an SBOM target (`multipart/form-data`: `file`, `repository_id`, optional `name`) |
| `POST` | `/api/v1/scan-targets/artifact` | Create a build artifact target (`multipart/form-data`: `file` up to 200 MiB, `repository_id`, optional `name`) |
| `PUT` | `/api/v1/scan-targets/{id}` | Update (any field below; the kind cannot change) |
| `DELETE` | `/api/v1/scan-targets/{id}` | Delete. `409` while it has findings (disable it instead) or a scan is queued or running |
| `POST` | `/api/v1/scan-targets/{id}/scan` | Queue a scan → `202 { job_id, coalesced }`. `409` if disabled or not authorized |

### Create and update fields

| Field | Description |
|---|---|
| `repository_id`, `kind` | Create only |
| `name` | 1–200 characters |
| `reference` | Image reference or base URL (`http`/`https`, no credentials or fragment) |
| `api_spec` | OpenAPI document (YAML or JSON, ≤ 2 MiB). Every `servers[].url` (or Swagger `host`) must be an absolute URL on the base URL's host |
| `auth_type` | `none`, `basic` (registry or HTTP username and password/token) or `header` (web and API targets: any header, e.g. `Authorization`, `X-API-Key`, `Cookie`) |
| `auth_username`, `auth_header_name` | For `basic` and `header` |
| `auth_secret` | Password, token or header value. Encrypted at rest and never returned (`has_secret` shows that one is stored). On update, omit to keep it, `""` to remove it |
| `authorized`, `authorization_note` | Web and API targets: `authorized: true` records that you are authorized to test the application (your user and the time are stored as `authorized_by` / `authorized_at`). Required on create and whenever the address changes |
| `config` | `{ rate_limit: 1–100 (requests/s, default 20), min_severity: low|medium|high|critical }` for web and API targets |
| `enabled` | Disabled targets are kept with their findings but cannot be scanned |

`egress_host` in the response is the host the worker must reach through the egress proxy (see the installation guide).

## How a target scan runs

- The scan uses the repository's scan profile for timeout, severity threshold and exclusions. The scanners follow from the kind; target scanners cannot be added to repository profiles (`400`).
- The execution appears under **Scans** with `asset_type` = the kind and `target_id`, `target_name`, `target_reference`. Its configuration snapshot records the target and scanners.
- Before a web or API scan, the worker checks that the egress proxy lets it reach the target; otherwise the scan fails with an explanation and no findings change.
- Findings record `scan_target_id`, `scan_target_kind` and `scan_target_name`. A target's findings are separate from the repository's (the same CVE in the image and in the manifests are two findings), and only a successful scan of the same target marks them fixed.
- Retrying a failed target scan queues a new scan of the target.

## Filters

- Findings of targets: `scan_target_id` and `target_kind` on [list findings](findings.md#list-findings).
- Target scans: `asset_type` and `target_id` on [list executions](scans.md#list-executions).
