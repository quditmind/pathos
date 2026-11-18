# Scanning module: design notes

Engineering notes on how scan executions, schedules and comparisons are built. This page does not describe how to use them:

- How to use the Scanning pages: [user guide: Scanning](user-guide/scanning.md) (also in the in-app Help Center).
- Endpoints and fields: [API reference: Scans](api-reference/scans.md), [Scan schedules](api-reference/schedules.md) and [Scan targets](api-reference/scan-targets.md).
- Isolation of the workers and the scanner lifecycle: [ARCHITECTURE.md §5](ARCHITECTURE.md#5-scanner-execution-and-isolation). Scanners and their licences: [SCANNER_CATALOG.md](SCANNER_CATALOG.md).
- Tables: [DATABASE.md](DATABASE.md#scanning-module-migration-00011).

Code: `backend/internal/scans` (executions, ingestion, targets, PR checks), `backend/internal/schedule` (schedules and the scheduler role), `backend/internal/worker` (the worker agent), migration `00011_scanning_module.sql`.

## Boundaries

The Scanning module runs, monitors, schedules and compares scan executions. It **consumes** scan profiles and the scanner catalog; it never creates, edits or deletes them. Those belong to the Configurations section (scan profiles, scanners and workers, custom rules).

## Executions

An execution (`scan_jobs`) is one run of one immutable profile version against one asset: a repository, a scan target (`target_id`, `target_kind`) or a pull request (`pull_request`).

- **Identity.** `scan_key` (`QD-SCAN-000001`) is assigned by a trigger from `scan_key_seq`: unique, never reused, and immutable.
- **Configuration snapshot.** `config_snapshot` captures the effective configuration at enqueue time (profile id, name and version, change note, scanners and their configuration, exclusions, severity threshold, timeout, SBOM, fail on critical, retention). A trigger rejects changes to it, so an execution always shows what it actually ran with.
- **Progress** is derived only from recorded facts, never estimated: lease 5 %, source checkout 15 %, each finished engine job up to 95 %, finalization 100 %.
- **Children.** One engine job per scanner (`scan_results`: version, status, duration, findings count), stage events (`scan_job_events`: queued, leased, source, scanner, finalize, cancel, retry) and an execution log (`scan_job_logs`: at most 5,000 lines per execution, secrets redacted on ingestion).
- **Who records what.** Workers report source and scanner stages and log lines through `POST /internal/worker/v1/jobs/{id}/events`. The platform records lease, results, finalization and cancellation itself.
- **Retries** create a new execution linked by `retry_of`; history is never overwritten.

### Queueing and concurrency

- A partial unique index allows **one queued execution per repository, profile version, target and pull request**. New triggers for the same combination are absorbed by the queued execution. A repository can therefore be queued for several profiles at once.
- Leasing (`FOR UPDATE SKIP LOCKED`) never starts a second execution of a repository while one is running.
- An expired lease is requeued by the scheduler leader (or failed after the maximum attempts).

## Comparison

Executions are never deleted. The findings an execution observed are known through `finding_occurrences → scan_results → scan_jobs`, so any two executions can be compared after the fact.

The classification (new, recurring, unchanged, fixed, not covered) is described in the [user guide](user-guide/scanning.md#scan-comparison) and the [API reference](api-reference/scans.md#comparison). The design rule behind it: a finding is only counted as **fixed** when the later execution completed and a scanner that covers the finding succeeded. A failed or cancelled execution, or a failed covering scanner, gives **not covered**, never fixed. Automatic resolution of findings after a scan follows the same rule.

Search and comparison cover 360 days. Execution logs and stage events are kept for `PATHOS_SCAN_LOG_RETENTION_DAYS` (default 400, minimum 360; read by the `jobs` role).

## Schedules

| Concern | Implementation |
|---|---|
| Kinds | `cron` (at most hourly), `once` (`run_at`) and `interval` (`interval_minutes` ≥ 60) |
| Execution plan | `scan_schedule_targets`: rows of asset scope (organization, region, business unit, repository) × profile (or each repository's own). Each activation creates one execution per distinct repository × profile pair |
| Scan window | `window_start`/`window_end` (may span midnight) and optional weekdays. Activations outside the window are held as `waiting` and queued when it opens |
| Concurrency | `max_concurrent` caps the schedule's queued plus running executions. The rest stay pending on the activation and are queued as capacity frees |
| Retries | `retry_max` (0–5) and `retry_delay_minutes`. Failed executions of an activation are retried as new executions |
| Missed runs | Activations missed while the scheduler was down are caught up once and raise `schedule.missed` |
| No double runs | `scan_schedule_runs (schedule_id, due_at)` is unique, and one activation creates at most one execution per repository × profile version (`scan_jobs_run_dedupe_uq`). Retried or recovered scheduler passes therefore never run a schedule twice |
| Pause and resume | `enabled`. Resuming does not replay activations missed while paused |
| Notifications | `notify_on`: `completed` and/or `failed` raise `schedule.completed` / `schedule.failed`, routed by the notification rules |

The scheduler itself (leader election, the 15-second tick) is described in [ARCHITECTURE.md](ARCHITECTURE.md#11-scheduling-and-notifications).

## Permissions

`scans.read` (view), `scans.run` (start, retry, cancel), `scans.compare` (history and comparison; part of every read-only role), `schedules.manage` (checked for every plan entry's scope) and `findings.read` (findings of an execution). The full matrix is in [RBAC_MATRIX.md](RBAC_MATRIX.md).
