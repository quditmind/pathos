---
title: Scans
section: api-reference
order: 21
version: "1.0"
updated: 2026-11-19
summary: Start, list, monitor, retry, cancel and compare scan executions, with their stages, logs, findings, raw scanner output and history.
---
# Scans

A scan execution runs one existing [scan profile](scan-configuration.md#scan-profiles) against one repository (or one of its [scan targets](scan-targets.md)). Every execution has a permanent **Scan ID** (`scan_key`, e.g. `QD-SCAN-000042`), a read-only snapshot of the configuration it used, engine jobs per scanner, stage events and an execution log.

All endpoints are under `/api/v1`, need a browser session, and mutations need `X-CSRF-Token` (see [API reference overview](index.md)). Errors use the common `{"error": {"code", "message"}}` body.

## The execution object

```json
{
  "id": "0193a1c2-5b6e-7c3d-9e10-1f2a3b4c5d6e",
  "scan_key": "QD-SCAN-000042",
  "name": "Nightly secrets",
  "asset_type": "repository",
  "target_id": null,
  "target_name": null,
  "target_reference": null,
  "repository_id": "0193a1c2-0000-7000-8000-000000000101",
  "repository_name": "acme/payments-api",
  "repository_key": "QD-REPO-000042",
  "profile_id": "0193a1c2-0000-7000-8000-000000000201",
  "profile_name": "Secrets and dependencies",
  "profile_version": 3,
  "trigger": "manual",
  "priority": 70,
  "status": "running",
  "progress": 55,
  "stage": "scanning:osv-scanner",
  "ref": "main",
  "commit_sha": "",
  "attempts": 1,
  "worker_name": "worker-core-1",
  "requested_by": "Dana Owner",
  "error": "",
  "findings_new": 0,
  "findings_fixed": 0,
  "findings_total": 0,
  "severity": { "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0 },
  "gate_failed": false,
  "retry_of": null,
  "retry_count": 0,
  "schedule_id": null,
  "schedule_run_id": null,
  "snapshot_id": null,
  "queued_at": "2026-11-17T09:00:00Z",
  "started_at": "2026-11-17T09:00:04Z",
  "finished_at": null,
  "duration_ms": 41250
}
```

| Field | Meaning |
|---|---|
| `status` | `queued`, `running`, `succeeded`, `partial` (some engines failed), `failed`, `cancelled` |
| `progress`, `stage` | Derived from recorded stages: lease 5 %, source checkout 15 %, each finished engine job up to 95 %, finalization 100 %. `stage`: `queued`, `starting`, `fetching_source`, `scanning[:<scanner>]`, `finalizing`, `finished` |
| `severity`, `findings_total` | Distinct findings observed by this execution |
| `findings_new`, `findings_fixed` | Findings first seen in, and resolved by, this execution |
| `retry_of`, `retry_count` | Set on retries, which are always new executions |
| `asset_type`, `target_id`, `target_name`, `target_reference` | `repository` for source-code scans; otherwise the [scan target](scan-targets.md) kind and the target |
| `trigger`, `priority` | `manual`, `schedule`, `push`, `merge`, `pull_request`, `onboarding`, `emergency` or `import`; the queue priority follows the trigger (emergency 100 … schedule 30) |
| `gate_failed` | The profile's `fail_on_critical` gate or a blocking [security policy](governance.md#security-policies) failed |
| `config_snapshot` | Only on `GET /scans/{id}`: profile id, name, version, change note, scanners and their configuration, exclusions, severity threshold, timeout, SBOM, fail on critical, retention, capture time. Immutable |

Database entities: `scan_jobs`, `scan_results` (engine jobs), `scan_job_events`, `scan_job_logs`, `finding_occurrences`, `scan_profile_versions`.

## Start and manage executions

### Start scans

`POST /api/v1/scans` — queues one execution per repository.

Permission: `scans.run` on each repository (others are reported per item). Scope: the repository's business unit, region or organization.

| Body field | Type | Required | Description |
|---|---|---|---|
| `repository_ids` | uuid[] | yes | 1–1000 repositories |
| `profile_id` | uuid | no | An existing, non-archived scan profile. Omit to use each repository's own (or the default) profile |
| `name` | string | no | Up to 200 characters; default "repository · profile" |
| `trigger` | string | no | `manual` (default), `emergency` or `onboarding` |

```json
{ "repository_ids": ["0193a1c2-0000-7000-8000-000000000101"], "profile_id": "0193a1c2-0000-7000-8000-000000000201", "name": "Release check" }
```

Response `202`:

```json
{ "items": [ { "repository_id": "0193a1c2-0000-7000-8000-000000000101", "job_id": "0193a1c2-5b6e-7c3d-9e10-1f2a3b4c5d6e", "coalesced": false } ] }
```

`coalesced: true` means an execution of the same repository and profile version was already queued; it was updated instead of duplicated. Per-item `error` values: `not scannable or not permitted`, `repository is archived or scanning is disabled`, `cannot scan yet: …` (no profile, no snapshot, no branch).

Status codes: `202`, `400 invalid_request` (empty list, unknown or archived profile, name too long), `401`, `403`.

### Start a scan of one repository

`POST /api/v1/repositories/{id}/scan` — the repository's own profile; see [Repositories](repositories.md).

### List executions

`GET /api/v1/scans` — newest first, 50 per page. Permission: `scans.read` (repositories outside the caller's scope are not listed).

| Parameter | Description |
|---|---|
| `q` | Matches Scan ID, execution name, repository name or Repository ID |
| `scan_key`, `repository_key` | Exact, case-insensitive |
| `repository_id`, `profile_id`, `schedule_id` | UUIDs |
| `status` | One status or `active` (queued and running) |
| `trigger` | `manual`, `schedule`, `push`, `merge`, `pull_request`, `onboarding`, `emergency` |
| `scanner` | Executions with an engine job of this scanner |
| `asset_type` | `repository`, `image`, `url`, `api` or `sbom` |
| `target_id` | Executions of one scan target |
| `from`, `to` | `YYYY-MM-DD` (inclusive) or RFC 3339 |
| `cursor` | `next_cursor` of the previous page |

Response `200`: `{ "items": [execution…], "next_cursor": "2026-11-17T09:00:00Z|0193a1c2-…" }`.

### Get an execution

`GET /api/v1/scans/{id}` — the execution with `results` (engine jobs: `scanner_key`, `scanner_version`, `status`, `duration_ms`, `findings_count`, `error`, `has_artifact`) and `config_snapshot`. Permission `scans.read`. `404` when it does not exist or is out of scope.

### Cancel an execution

`POST /api/v1/scans/{id}/cancel` — queued or running only. Permission `scans.run`. `409 conflict` otherwise. Audited (`scan.cancel`).

### Retry an execution

`POST /api/v1/scans/{id}/retry` — creates a **new** execution of the same repository and profile (current version), linked by `retry_of`. Only `failed`, `partial` or `cancelled` executions. Permission `scans.run`.

Response `202`: the new execution. Errors: `409 conflict` (wrong status, repository not scannable or missing prerequisites). Audited (`scan.retry`).

## Execution details

### Stages

`GET /api/v1/scans/{id}/stages` → `{ "stages": [...], "events": [...] }`. Permission `scans.read`.

```json
{
  "stages": [
    { "key": "queued", "label": "Queued", "status": "succeeded", "started_at": "2026-11-17T09:00:00Z", "finished_at": "2026-11-17T09:00:04Z", "duration_ms": 4000 },
    { "key": "source", "label": "Source checkout", "status": "succeeded", "started_at": "2026-11-17T09:00:04Z", "finished_at": "2026-11-17T09:00:09Z", "duration_ms": 5000 },
    { "key": "scanner:gitleaks", "label": "gitleaks", "scanner": "gitleaks", "scanner_version": "8.30.1", "status": "succeeded", "findings": 2, "duration_ms": 3100 },
    { "key": "finalize", "label": "Findings and results", "status": "pending" }
  ],
  "events": [ { "stage": "leased", "scanner": "", "status": "info", "message": "picked up by worker worker-core-1", "at": "2026-11-17T09:00:04Z" } ]
}
```

Stage status: `pending`, `running`, `succeeded`, `failed`, `skipped`, `timed_out`, `cancelled`.

### Execution log

`GET /api/v1/scans/{id}/logs` → `{ "items": [{ "id", "at", "level", "source", "message" }], "sources": ["gitleaks", "worker"], "next_after_id": null }`. Permission `scans.read`.

| Parameter | Description |
|---|---|
| `source` | `worker`, `platform` or a scanner key |
| `level` | Minimum level: `debug`, `info`, `warn`, `error` |
| `after_id` | Only lines after this id (live tail) |

At most 1,000 lines per response; at most 5,000 lines are kept per execution. Secrets are redacted when stored.

### Raw scanner output

`GET /api/v1/scans/{id}/results/{scanner}/artifact` — downloads what the scanner produced in this execution (its raw report, or the SBOM for Syft), decompressed, as an attachment named `<scanner>-<execution id>.json`. Permission `scans.read`. Engine jobs with output have `has_artifact: true`. `404` when the execution or the output does not exist.

### Findings of an execution

`GET /api/v1/scans/{id}/findings?severity=&scanner=` → `{ "items": [...] }`. Permission `findings.read` on the repository. Each item is a finding plus `scanner`, `evidence` (`file:line` or `package@version`), `occurrence_commit_sha` and `is_new` (first seen in this execution). At most 1,000, most severe first.

### History of the asset

`GET /api/v1/scans/{id}/history` → `{ "items": [execution…] }` — executions of the same repository in the last 360 days (at most 200).

## Overview

`GET /api/v1/scans/overview?days=30` — `days` 1–360. Permission `scans.read`; finding totals need `findings.read`.

```json
{
  "days": 30,
  "scans": { "total": 128, "running": 2, "queued": 5, "completed": 110, "failed": 9, "cancelled": 2 },
  "open_findings": { "critical": 3, "high": 17, "medium": 42, "low": 60, "info": 8 },
  "open_findings_total": 130,
  "critical_high": 20,
  "recent": [],
  "trend": [ { "day": "2026-11-17", "completed": 4, "failed": 1, "cancelled": 0, "new_findings": 6 } ],
  "upcoming": [ { "schedule_id": "0193a1c2-0000-7000-8000-000000000301", "name": "Nightly EMEA", "next_run_at": "2026-11-18T02:00:00Z", "kind": "cron" } ]
}
```

## Comparison

`GET /api/v1/scans/compare?ids=<id>,<id>[,…]` — 2–10 executions, ordered chronologically; each is compared with the previous one. Permission `scans.compare` on every repository involved.

Per execution (`scans[]`): the execution fields plus `scanners`, `succeeded_scanners`, `complete`, `new`, `fixed`, `recurring`, `unchanged`, `not_covered`, `profile_changed`, `engine_changes` (for example `"osv-scanner 2.2.0 → 2.3.1"`, `"trivy-fs added"`) and `duration_delta_ms`.

Per finding (`findings[]`, at most 2,000): `id`, `title`, `severity`, `scanners` and `states` (execution id → `present` (first execution), `new`, `recurring`, `unchanged`, `fixed`, `not_covered`, `absent`).

> A finding is only **fixed** when the later execution completed and a scanner that reports it succeeded. When the execution failed, was cancelled, or its covering scanner did not succeed, the finding is **not covered** instead.

Errors: `400 invalid_request` (fewer than 2 or more than 10 ids, invalid id), `403`, `404`.

## Worker API (internal)

Workers report stages and log lines with `POST /internal/worker/v1/jobs/{id}/events`; see [Worker protocol: events and logs](worker-protocol.md#events-and-logs).
