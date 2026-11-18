---
title: Worker protocol (internal)
section: api-reference
order: 53
version: "1.0"
updated: 2026-11-19
summary: The internal /internal/worker/v1 API that scan workers use to register, lease jobs, send heartbeats, events and results, and complete jobs. Not for API clients.
---

# Worker protocol (internal)

> **Internal API.** These endpoints are used only by the PATHOS scan worker agent (`pathos-worker`). They are not part of the public API, are not reachable through the edge proxy, and do not accept sessions or REST API tokens. They are described here for operators and for people building or debugging workers. To manage workers, use [`/api/v1/workers`](administration.md#scan-workers).

## Where it runs

The API serves the worker API on a separate listener, `PATHOS_WORKER_API_ADDR` (default `:8081`), on the internal `worker-api` network. Worker containers reach only this listener and the egress proxy (see `docs/SECURITY.md` and `docs/ARCHITECTURE.md`). The worker finds it through `PATHOS_API_URL` (for example `http://api:8081`).

The listener is started only when `PATHOS_WORKER_BOOTSTRAP_TOKEN` is set (at least 32 characters). Without it the worker API is disabled and scans stay queued.

## Authentication

1. **Registration.** The worker calls `POST /internal/worker/v1/register` with `Authorization: Bearer <PATHOS_WORKER_BOOTSTRAP_TOKEN>`, a secret shared between the API and the workers. The worker removes the variable from its environment so scanner processes never see it.
2. **Per-worker token.** Registration returns a random worker token. Every other call sends `Authorization: Bearer <worker token>`. PATHOS stores only its SHA-256 hash and updates the worker's `last_seen_at` on each call.
3. A missing, unknown or revoked token returns `401 unauthenticated`. The worker agent then registers again. Registering again with the same name issues a new token and invalidates the old one.

A worker [revoked by an administrator](administration.md#scan-workers) gets `403 worker_revoked` on registration and stops; it can register again only after its record is deleted.

## Endpoints

Bodies are JSON unless stated otherwise. Errors use the [common error format](index.md#errors).

| Method | Path | Description |
|---|---|---|
| `POST` | `/internal/worker/v1/register` | [Register](#register) (bootstrap token) |
| `POST` | `/internal/worker/v1/lease` | [Lease the next job](#lease-a-job) |
| `POST` | `/internal/worker/v1/jobs/{id}/heartbeat` | [Extend the lease, learn about cancellation](#heartbeat) |
| `GET` | `/internal/worker/v1/jobs/{id}/source` | [Download the source snapshot](#download-the-source-or-target-file) of an uploaded repository |
| `GET` | `/internal/worker/v1/jobs/{id}/target-file` | [Download the uploaded SBOM or artifact](#download-the-source-or-target-file) of a scan target job |
| `POST` | `/internal/worker/v1/jobs/{id}/events` | [Report stage events and log lines](#events-and-logs) |
| `POST` | `/internal/worker/v1/jobs/{id}/imports` | [Upload the code inventory](#code-inventory) used for reachability |
| `POST` | `/internal/worker/v1/jobs/{id}/runtimes` | [Upload the declared runtimes and base images](#runtimes-and-introducing-commits) (end of life) |
| `POST` | `/internal/worker/v1/jobs/{id}/blame` | [Upload the introducing commits](#runtimes-and-introducing-commits) of code findings |
| `POST` | `/internal/worker/v1/jobs/{id}/results` | [Upload one scanner's output](#results) |
| `POST` | `/internal/worker/v1/jobs/{id}/complete` | [Finish the job](#complete) |

Every `/internal/worker/v1/jobs/{id}/…` call must come from the worker that holds the job's lease: another worker gets `409 lease_lost`, an unknown job `404`. Except for the heartbeat, the job must still be `running` (`409 conflict` "job is …" otherwise).

### Register

```json
{
  "name": "worker-core-1",
  "family": "core",
  "version": "1.4.0",
  "scanners": { "opengrep": "1.10.0", "gitleaks": "8.21.2" },
  "plugins": { "plugin-example": { "name": "Example scanner", "homepage": "https://scanner.example.com" } }
}
```

`name` is 1–100 characters of letters, digits, `.`, `_` and `-` (defaults to the host name in the agent, `PATHOS_WORKER_NAME`); `family` 1–40 characters (`PATHOS_WORKER_FAMILY`, default `core`); at most 100 scanners. Unknown scanner keys are dropped unless they are declarative plugin adapters described in `plugins`; those become selectable in scan profiles. Response `200`: `{ "worker_id": "<uuid>", "token": "<worker token>" }`. Jobs still leased by a previous run of the same worker are returned to the queue. Audited as `worker.register`.

### Lease a job

`POST /internal/worker/v1/lease` (empty JSON object). Before leasing, expired leases are returned to the queue (or failed when the job has used all its attempts). Returns `204` when nothing is queued; the agent polls every 5 seconds. Otherwise `200` with the job, which is now `running` with a 5-minute lease:

| Field | Description |
|---|---|
| `job_id`, `repository_id`, `full_name` | The job and its repository. |
| `clone_url`, `ref`, `commit_sha`, `full_history` | What to clone (empty `clone_url` for uploaded repositories). |
| `credential` | Clone credential of the repository's SCM connection, if any. |
| `public` | The repository is public; the worker may clone anonymously if the credential fails. |
| `source` | For uploaded repositories: `{ type: "snapshot", sha256, size }`; download it from `/internal/worker/v1/jobs/{id}/source`. |
| `target` | For scan-target jobs (image, web application, API, artifact, SBOM, declared endpoints): kind, reference and any decrypted target credential. Endpoints jobs carry `endpoints[]` (`kind`, `value`, `authorized`: only authorized endpoints may be contacted) and `rate_limit`; image and artifact jobs with a verification policy carry `signature` (the [policy](scan-targets.md#signature-verification)) and, for artifacts, `signature_material`. |
| `timeout_seconds`, `exclusions`, `scanners[]` | From the pinned scan profile version: `{ key, config }` per scanner. Opengrep's config includes the organization's custom rules. |

If no clone credential can be obtained, the job fails and `204` is returned.

### Heartbeat

`POST /internal/worker/v1/jobs/{id}/heartbeat` extends the lease by 5 minutes and returns `{ "cancel": false }`. When a user cancelled the job it returns `{ "cancel": true }` and the worker stops. The agent sends a heartbeat every 30 seconds.

### Download the source or target file

`GET /internal/worker/v1/jobs/{id}/source` streams the decrypted snapshot (`application/gzip`, with `Content-Length`); the worker verifies its SHA-256 and size before scanning. `404 no_snapshot` if the job has none.

`GET /internal/worker/v1/jobs/{id}/target-file` returns the uploaded SBOM or build artifact of a scan-target job, decompressed (`application/json`). `404 no_target_file` if the job has none.

### Events and logs

`POST /internal/worker/v1/jobs/{id}/events` with `{ events: [], logs: [] }` (at most 200 events and 1,000 log lines per call) → `204`.

- Event: `stage` (`queued`, `leased`, `source`, `scanner`, `ingest`, `finalize`, `cancel`, `retry`), `scanner`, `status` (`started`, `succeeded`, `failed`, `skipped`, `timed_out`, `info`), `message`, `at`.
- Log line: `at`, `level` (`debug`, `info`, `warn`, `error`), `source` (`worker` or a scanner key), `message`.

Messages are redacted and cut to 2,000 characters; timestamps far in the future or before the job started are replaced by the server time. A job keeps at most 5,000 log lines. These feed the execution [stages and logs](scans.md).

### Code inventory

`POST /internal/worker/v1/jobs/{id}/imports` with `{ version: 1, files_scanned, imports: { … }, strings: { … } }` (at most 8 MiB) stores the repository's import inventory and recomputes the reachability of its dependency findings (see [Reachability](vulnerability-intelligence.md#reachability)). Returns `{ "findings_updated": n }`. Ignored (`0`) for pull request scans; `400` for scan-target jobs.

### Runtimes and introducing commits

After the scanners of a repository job (not for scan targets; ignored for pull request scans):

- `POST /internal/worker/v1/jobs/{id}/runtimes` with `{ version: 1, runtimes: [{ kind: "runtime" | "image", name, version, path }] }` (at most 1,000 entries, 1 MiB) replaces the repository's declared runtimes (`node`, `python`, `ruby`, `go`, `java`, `dotnet`, `php`) and Dockerfile base images (`name` is the image reference). Invalid entries are dropped. Response `{ "stored": n }`. They are matched to end-of-life data when the job completes.
- `POST /internal/worker/v1/jobs/{id}/blame` with `{ version: 1, mode: "full" | "shallow", entries: [{ file, line, commit, author, time }], missing: [{ file, line }] }` (at most 5,000 each, 4 MiB). For each code finding (`sast`, `secrets`, `iac`) of this job at `file:line`, `full` records the introducing commit (full SHA), the author's **name** and the commit time, unless one is already known; `missing` lines are not in the scanned commit; `shallow` marks the job's code findings `shallow_clone` (unknown). The worker sends `full` only for repositories with full history, and never sends author e-mail addresses. Response `{ "findings_updated": n }`.

### Results

`POST /internal/worker/v1/jobs/{id}/results`, once per scanner (body at most 96 MiB):

| Field | Description |
|---|---|
| `scanner` | Scanner key (built-in or plugin). |
| `version` | Scanner version. |
| `status` | `succeeded`, `failed`, `skipped` or `timed_out`. |
| `duration_ms`, `error` | Run time and error message. |
| `content_type` | Format of the raw output. |
| `output_gzip` | The raw tool output, gzip-compressed and base64-encoded. |

The output is parsed into findings at once. Response `{ "findings": n }`. A decompressed output over the size limit returns `413 too_large`.

### Complete

`POST /internal/worker/v1/jobs/{id}/complete` with `{ status: "succeeded" | "failed", error, commit_sha }`. `commit_sha` (the commit actually scanned) is stored when it is a full SHA. PATHOS finalizes the job (new and fixed findings, security gate, policies), then posts pull request statuses or starts follow-up work (AI review, Human Eye queue). Response `{ "status": "<final job status>" }`.
