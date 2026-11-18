---
title: Scan schedules
section: api-reference
order: 22
version: "1.0"
updated: 2026-11-19
summary: Create one-time, recurring and interval scan schedules with execution plans, scan windows, retries, concurrency limits and run history.
---
# Scan schedules

A schedule runs an **execution plan** — rows of asset scope × existing [scan profile](scan-configuration.md#scan-profiles) — at its activations. Each activation creates one execution per distinct repository × profile pair, each with its own Scan ID and the schedule and activation ids. See [Scans](scans.md).

All endpoints are under `/api/v1`, need a session, and mutations need `X-CSRF-Token`.

## The schedule object

```json
{
  "id": "0193a1c2-0000-7000-8000-000000000301",
  "name": "Nightly EMEA",
  "enabled": true,
  "kind": "cron",
  "cron": "0 2 * * 1-5",
  "run_at": null,
  "interval_minutes": null,
  "timezone": "Europe/Berlin",
  "window_start": "01:00",
  "window_end": "05:00",
  "window_days": [1, 2, 3, 4, 5],
  "retry_max": 2,
  "retry_delay_minutes": 30,
  "max_concurrent": 10,
  "notify_on": ["failed"],
  "priority": 30,
  "plan": [
    { "id": "0193a1c2-0000-7000-8000-000000000401", "target_type": "business_unit", "target_id": "0193a1c2-0000-7000-8000-000000000501",
      "target_name": "Payments", "profile_id": "0193a1c2-0000-7000-8000-000000000201", "profile_name": "Secrets and dependencies" },
    { "id": "0193a1c2-0000-7000-8000-000000000402", "target_type": "repository", "target_id": "0193a1c2-0000-7000-8000-000000000101",
      "target_name": "acme/payments-api (QD-REPO-000042)", "profile_id": null, "profile_name": "" }
  ],
  "target_type": "business_unit",
  "target_id": "0193a1c2-0000-7000-8000-000000000501",
  "target_name": "Payments",
  "next_run_at": "2026-11-18T01:00:00Z",
  "last_run_at": "2026-11-17T01:00:00Z",
  "last_status": "queued 12",
  "last_queued": 12,
  "missed_runs": 0,
  "created_at": "2026-11-01T08:00:00Z",
  "can_manage": true
}
```

`enabled: false` means paused. `target_*` repeat the first plan row for older clients. Database entities: `scan_schedules`, `scan_schedule_targets`, `scan_schedule_runs`, `scan_jobs.schedule_id` / `schedule_run_id`.

## Request body

`POST /api/v1/schedules`, `PUT /api/v1/schedules/{id}` and `POST /api/v1/schedules/preview` take:

| Field | Type | Required | Rules |
|---|---|---|---|
| `name` | string | yes | 1–120 characters |
| `kind` | string | no | `cron` (default), `once`, `interval` |
| `cron` | string | for `cron` | 5-field expression; at most one activation per hour |
| `run_at` | RFC 3339 | for `once` | In the future. For `interval`: optional first run |
| `interval_minutes` | int | for `interval` | 60–525600 |
| `timezone` | string | no | IANA zone, default `UTC` |
| `window_start`, `window_end` | `HH:MM` | no | Both or neither; different; start after end spans midnight |
| `window_days` | int[] | no | 0 = Sunday … 6 = Saturday; empty = every day; needs a window |
| `retry_max` | int | no | 0–5 (default 0) |
| `retry_delay_minutes` | int | no | 5–1440 (default 30) |
| `max_concurrent` | int | no | 0–1000, 0 = unlimited (queued + running executions of this schedule) |
| `notify_on` | string[] | no | `completed`, `failed` |
| `priority` | int | no | 0–90 (default 30) |
| `enabled` | bool | no | default `true` |
| `plan` | object[] | yes* | 1–50 rows: `target_type` (`organization`, `region`, `business_unit`, `repository`), `target_id` (null for organization), `profile_id` (existing non-archived profile, or null for each repository's own profile). *Older clients may send `target_type`/`target_id` instead (one row) |

Permission: `schedules.manage` on the scope of **every** plan row.

Daily, weekly and monthly schedules are `cron` schedules (for example `0 2 * * *`, `0 2 * * 1`, `0 2 1 * *`).

## Endpoints

### List schedules

`GET /api/v1/schedules` → `{ "items": [schedule…] }`. Permission `scans.read` on at least one plan row; `can_manage` reflects `schedules.manage` on all rows.

### Get a schedule

`GET /api/v1/schedules/{id}` → schedule. `404` when not visible.

### Preview

`POST /api/v1/schedules/preview` → `{ "next_runs": [5 times], "repositories": 14, "executions": 15, "window": "01:00–05:00 Mon,Tue,Wed,Thu,Fri" }`. Permission `scans.read`; counts only include repositories the caller can see. `400` for invalid input (same rules as create).

### Create a schedule

`POST /api/v1/schedules` → `201` schedule. Audited (`schedule.create`, with the plan).

```json
{
  "name": "Weekly full scan",
  "kind": "cron",
  "cron": "0 3 * * 6",
  "timezone": "Europe/Berlin",
  "window_start": "01:00",
  "window_end": "07:00",
  "retry_max": 1,
  "max_concurrent": 5,
  "notify_on": ["failed"],
  "plan": [
    { "target_type": "organization", "target_id": null, "profile_id": "0193a1c2-0000-7000-8000-000000000201" },
    { "target_type": "repository", "target_id": "0193a1c2-0000-7000-8000-000000000101", "profile_id": "0193a1c2-0000-7000-8000-000000000202" }
  ]
}
```

Errors: `400 invalid_request` (for example `the cron expression never fires`, `run_at must be a time in the future`, `plan entry 2: scan profile not found or archived`), `403`.

### Update a schedule

`PUT /api/v1/schedules/{id}` — full replacement (same body); the plan is replaced. `200` schedule. Audited (`schedule.update`).

### Pause and resume

`POST /api/v1/schedules/{id}/pause`, `POST /api/v1/schedules/{id}/resume` → schedule. Resuming does not replay activations missed while paused. Audited.

### Run now

`POST /api/v1/schedules/{id}/run` → `{ "queued": 3, "coalesced": 0, "skipped": 0, "failed": 0, "deferred": 2 }`. Creates a `manual` activation now, ignoring the scan window; `deferred` executions wait for the concurrency limit. Audited (`schedule.run`).

### Delete a schedule

`DELETE /api/v1/schedules/{id}` → `204`. Executions it created stay in the scan history. Audited.

### Activation history

`GET /api/v1/schedules/{id}/runs` → `{ "items": [...] }` (latest 100):

```json
{ "id": "0193a1c2-0000-7000-8000-000000000601", "due_at": "2026-11-17T01:00:00Z", "trigger": "schedule", "status": "partial",
  "queued": 15, "skipped": 0, "failed": 0, "pending": 0, "message": "14 succeeded, 1 failed",
  "started_at": "2026-11-17T01:00:02Z", "finished_at": "2026-11-17T01:41:10Z", "jobs": { "succeeded": 14, "failed": 1, "cancelled": 0 } }
```

| `status` | Meaning |
|---|---|
| `running` | Executions queued or running, or retries due |
| `waiting` | Entries waiting for the scan window or for capacity |
| `completed` | Every execution succeeded (or nothing was scannable) |
| `partial` | Some executions failed after retries |
| `failed` | Every execution failed after retries |

`trigger`: `schedule`, `manual` or `catch_up` (missed activations caught up once). An activation is unique per schedule and due time, so a retried or recovered scheduler pass never runs it twice.

### Scheduler status

`GET /api/v1/scheduler/status` (`scans.read` or `scanners.read` at any scope) — leader, heartbeat, workers online/offline, queued and running executions, oldest queued, schedules, missed runs.
