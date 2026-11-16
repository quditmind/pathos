# Scanning module

The Scanning module runs, monitors, schedules and compares scan executions.
It **consumes** scan profiles and the scanner engine registry; it never
creates, edits or deletes them. Those live in the **Configurations** section
(Scan profiles, Scanners & workers).

Navigation: **Scanning → Scan Overview · Scans · Scan Schedules · Scan Comparison**.

## Executions

A scan execution (`scan_jobs`) is one run of one profile version against one
asset (today: a repository). It has:

| Field | Notes |
|---|---|
| `scan_key` | Permanent Scan ID `QD-SCAN-000001`, assigned by a database trigger from `scan_key_seq`, unique, never reused, immutable |
| `name` | Given when started; defaults to "asset · profile" (schedule name for scheduled runs) |
| `config_snapshot` | The effective configuration captured at enqueue time: profile id/name/version, change note, scanners with their configuration, exclusions, severity threshold, timeout, SBOM, fail-on-critical, retention. Immutable (trigger) |
| `progress`, `stage` | Derived only from recorded facts: lease (5 %), source checkout (15 %), each finished engine job (up to 95 %), finalization (100 %). Never estimated |
| `retry_of`, `retry_count` | A retry is a new execution linked to the failed one; history is never overwritten |
| `schedule_id`, `schedule_run_id` | Origin schedule and activation |

Each execution has child **engine jobs** (`scan_results`, one per scanner,
with version, status, duration and findings count), **stage events**
(`scan_job_events`: queued, leased, source, scanner, finalize, cancel, retry)
and an **execution log** (`scan_job_logs`, at most 5,000 lines per execution,
secrets redacted on ingestion). Workers report source and scanner stage
events and log lines through `POST /internal/worker/v1/jobs/{id}/events`;
the platform records lease, results, finalization and cancellation itself.

Queued executions coalesce per repository **and profile version**, so one
repository can be queued for several profiles; at most one execution per
repository runs at a time.

## Scan history and comparison

Executions are never deleted. Findings observed by an execution are known
through `finding_occurrences → scan_results → scan_jobs`. The comparison
(`GET /api/v1/scans/compare`, 2–10 executions, `scans.compare`) orders them
chronologically and classifies every finding against the previous execution:

| State | Meaning |
|---|---|
| new | observed now, never observed before the previous execution |
| recurring | observed now, absent in the previous execution, observed earlier |
| unchanged | observed in both |
| fixed | observed before, absent now, and this execution completed with a scanner that covers the finding succeeding |
| not covered | absent now, but this execution failed or was cancelled, or every scanner covering the finding failed — **never counted as fixed** |

The comparison also reports duration differences, profile (version) changes
and scanner engine changes (added, removed, version changed). Search and
comparison cover 360 days; execution logs and stage events are kept for
`PATHOS_SCAN_LOG_RETENTION_DAYS` (default 400, minimum 360).

## Schedules

| Feature | Implementation |
|---|---|
| Kinds | `cron` (daily, weekly, monthly presets and custom expressions, at most hourly), `once` (`run_at`), `interval` (`interval_minutes` ≥ 60, optional first run) |
| Time zone | IANA zone per schedule |
| Approved scan window | `window_start`/`window_end` (HH:MM, may span midnight) and optional weekdays; activations are moved into the next window, and activations waiting for a window are held as `waiting` |
| Execution plan | `scan_schedule_targets`: rows of asset scope (organization, region, business unit, repository) × an existing profile (or each repository's own profile). Each activation creates one execution per distinct repository × profile pair |
| Concurrency | `max_concurrent` caps queued + running executions of the schedule; the rest stay pending on the activation and are queued as capacity frees |
| Retries | `retry_max` (0–5) and `retry_delay_minutes`; failed executions of an activation are retried as new executions |
| Missed runs | Activations missed while the scheduler was down are caught up once (`catch_up`) and raise `schedule.missed` |
| Duplicate prevention | `scan_schedule_runs (schedule_id, due_at)` is unique, and one activation creates at most one execution per repository × profile version (`scan_jobs_run_dedupe_uq`), so retried or recovered scheduler passes never double-run |
| Pause / resume | `enabled`; resuming does not replay activations missed while paused |
| History | `GET /api/v1/schedules/{id}/runs`: each activation with status, queued, skipped, failed, pending and execution status counts |
| Notifications | `notify_on`: `schedule.completed` and/or `schedule.failed` to the schedule's creator (configurable rules) |

## Permissions

`scans.read` (view), `scans.run` (start, retry, cancel), `scans.compare`
(new; history and comparison, part of every read-only role),
`schedules.manage` (per plan entry scope), `findings.read` (findings of an
execution).

## API

See `docs/api-reference/scans.md` and `docs/api-reference/schedules.md`
(also in the in-app Help Center).
