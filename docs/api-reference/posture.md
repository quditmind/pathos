---
title: Posture
section: api-reference
order: 30
version: "1.0"
updated: 2026-11-19
summary: Application posture and risk rollup, aggregation, benchmarking, coverage, unmanaged and shadow repositories, SCM inventory, dependency graphs and paths, blast radius, the context graph and attack paths.
---
# Posture

All results are computed live and limited to the caller's repository scope.

## Endpoints

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/posture/applications?days=90` | `findings.read` | One row per application (plus "No application"), ordered by risk |
| `GET` | `/api/v1/posture/aggregate?by=&days=90` | `findings.read` | The same figures by `application`, `business_unit`, `team`, `owner` (application, technical or business owner) or `region` |
| `GET` | `/api/v1/posture/benchmark?by=&days=90` | `findings.read` | Groups with normalised metrics, a rank and the metric list (`metrics[].lower_is_better`) |
| `GET` | `/api/v1/posture/coverage?days=30&application_id=&q=` | `repos.read` | Repositories × categories (`sast`, `secrets`, `sca`, `iac`, `cicd`, `container`, `dast`), at most 1,000 repositories |
| `GET` | `/api/v1/posture/unmanaged?stale_days=30&active_days=90` | `repos.read` | Governance gaps; shadow repositories and inventory status for callers with organization-wide `repos.read` |
| `POST` | `/api/v1/scm-connections/{id}/inventory` | `repos.manage` above repository scope | Refresh a connection's repository inventory now (`502 inventory_failed` with the run on provider errors) |
| `GET` | `/api/v1/repositories/{id}/dependencies` | `sbom.read` | Components (with `depth`, open vulnerabilities), edges and counts. At most 5,000 components |
| `GET` | `/api/v1/repositories/{id}/dependencies/paths?ref=` | `sbom.read` | Up to five shortest paths from a root to the component |
| `GET` | `/api/v1/findings/{id}/dependency-paths` | `findings.read` | For a dependency finding: the matching components, `relation` and paths, or a `reason` |
| `GET` | `/api/v1/posture/blast-radius?cve=` or `?package=&version=` | `findings.read` | Affected repositories with ownership, exposure, relation, packages, open findings, risk and KEV |
| `GET` | `/api/v1/posture/context-graph?node=application:<id>` or `repository:<id>` | `findings.read` | Nodes and edges around the application or repository |
| `GET` | `/api/v1/posture/attack-paths?min_risk=50&limit=100&application_id=` | `findings.read` | Paths from internet-facing entry points to risky findings ([details](#attack-paths)) |

## Group fields

| Field | Description |
|---|---|
| `open` | Open findings by severity; `open_total`, `kev_open`, `sla_breached`, `high_risk_open` (risk ≥ 50) |
| `max_risk`, `avg_risk` | Over open findings |
| `risk_score`, `risk_band`, `risk_basis` | Rollup: `max_risk` + min(15, other findings with risk ≥ 50), capped at 100; `risk_basis` gives `max_finding_risk`, `other_high_risk_findings` and `uplift` |
| `fixed`, `mttr_days`, `sla_compliance` | Findings fixed in the `days` window, mean days from first seen to fixed, % fixed by their SLA date |
| `coverage` | % of the group's repositories with a successful SAST, SCA and secrets scan in the last 30 days (each category a third) |
| `last_scan_at` | Last successful or partial scan |

Applications also return `application_key`, `criticality`, `lifecycle`, `environment`, `business_unit`, `owner` and `scan_targets`. Benchmarks add `open_per_repository`, `critical_high_per_repository` and `rank`.

## Coverage cells

`status`:
- `covered`: a success within `days`
- `stale`: only older successes
- `never`
- `not_configured`: container or DAST with no enabled target

Each cell also gives `last_at` and the `scanners` that succeeded. Target scans count while the target exists and is enabled.

## Unmanaged

`repositories[].issues` contains:
- `no_application`
- `no_owner`: no owner and no responsible team
- `never_scanned`
- `stale_scan`
- `scanning_disabled`
- `sync_failing`: SCM synchronization failed, missing or without permission
- `archived_in_scm`

`counts` gives the number per issue, plus `shadow`.

`shadow[]` lists repositories an SCM connection sees that are not archived, that were pushed to within `active_days` (or have no push date), and that are not in PATHOS. The inventory refreshes daily per connection (at most 20,000 repositories per connection). A truncated listing never removes entries.

## Dependency data

Components have:
- `depth`: 0 for a root (typically the project itself), 1 for a direct dependency, 2 or more for transitive ones, `null` without graph data
- `relation`: the same as words (`root`, `direct`, `transitive`, `unknown`)

Edges come from CycloneDX `dependencies`, or from SPDX `DEPENDS_ON` and `*DEPENDENCY_OF` relationships (`CONTAINS` is not a dependency).

## Blast radius

`relation` is the closest relation of the package in the repository's latest SBOM, or `none` when the package is not in it (for example, found only in a container image). `targets` names the scan targets with matching findings. `summary` counts repositories, applications, business units and internet-exposed repositories.

## Context graph

Node `type` is one of:
- `application`, `repository`
- `owner`, `team`, `business_unit`
- `target`, `component`, `finding`

Nodes carry `label`, `sub`, `risk`, `severity` and `link` (a PATHOS page). Edge `kind` is one of `owns`, `contains`, `scans`, `depends_on` or `affects`.

The graph includes up to 50 repositories, 100 targets, and the 8 riskiest open findings per repository.

## Attack paths

A path leads from the internet through a tested web application or API (DAST target), or through an internet-exposed repository (and its container image), to a finding. Dependency findings count only when they are reachable. Paths are ranked by the finding's risk.

`min_risk` is 0–100 (default 50), `limit` 1–500 (default 100), `application_id` (optional, PATHOS 3.0) narrows the paths to one application's repositories. The response has `min_risk`, `items`, `counts` (paths per entry) and `truncated`.

Items contain:

- `finding_id`, `risk`, `severity`, `kev`, `exploit_available`
- `entry` (`dast_target` or `exposed_repository`)
- `steps[]{type,label,sub,link}`, where type is `internet`, `target`, `application`, `repository`, `component`, `image` or `finding`
- `reasons[]`
- `title`, `category`, `cve`, `cwe[]`, `repository_id`, `application_id`, `file_path`, `line` (the finding; added in PATHOS 3.0 for threat modelling, which turns each path into a threat)
