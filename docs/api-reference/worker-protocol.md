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

**Organizations (multi-tenancy).** A worker belongs to exactly one organization: the one named by `organization` at registration (`PATHOS_WORKER_ORGANIZATION`), or the default organization (`PATHOS_ORG_SLUG`) when it is empty. Every call with its token is scoped to that organization: it leases only that organization's jobs, and another organization's job ids answer `404`. A worker of a suspended organization gets `403 organization_suspended`. Workers are never shared between organizations.

## Endpoints

Bodies are JSON unless stated otherwise. Errors use the [common error format](index.md#errors).

| Method | Path | Description |
|---|---|---|
| `POST` | `/internal/worker/v1/register` | [Register](#register) (bootstrap token) |
| `POST` | `/internal/worker/v1/lease` | [Lease the next job](#lease-a-job) |
| `POST` | `/internal/worker/v1/jobs/{id}/heartbeat` | [Extend the lease, learn about cancellation](#heartbeat) |
| `GET` | `/internal/worker/v1/jobs/{id}/source` | [Download the source snapshot](#download-the-source-or-target-file) of an uploaded repository |
| `GET` | `/internal/worker/v1/jobs/{id}/target-file` | [Download the uploaded SBOM, artifact or mobile app](#download-the-source-or-target-file) of a scan target job |
| `POST` | `/internal/worker/v1/jobs/{id}/events` | [Report stage events and log lines](#events-and-logs) |
| `POST` | `/internal/worker/v1/jobs/{id}/imports` | [Upload the code inventory](#code-inventory) used for reachability |
| `POST` | `/internal/worker/v1/jobs/{id}/changes` | [Upload the material change report](#material-changes) |
| `POST` | `/internal/worker/v1/jobs/{id}/runtimes` | [Upload the declared runtimes and base images](#runtimes-and-introducing-commits) (end of life) |
| `POST` | `/internal/worker/v1/jobs/{id}/blame` | [Upload the introducing commits](#runtimes-and-introducing-commits) of code findings |
| `POST` | `/internal/worker/v1/jobs/{id}/secret-validation` | [Upload live secret validation verdicts](#secret-validation) |
| `POST` | `/internal/worker/v1/jobs/{id}/results` | [Upload one scanner's output](#results) |
| `POST` | `/internal/worker/v1/jobs/{id}/complete` | [Finish the job](#complete) |
| `POST` | `/internal/worker/v1/fix-lease` | [Lease a fix job](#fix-jobs) (when no scan is waiting) |
| `POST` | `/internal/worker/v1/fix-jobs/{id}/result` | [Report the edited files of a fix job](#fix-jobs) |

Every `/internal/worker/v1/jobs/{id}/…` call must come from the worker that holds the job's lease: another worker gets `409 lease_lost`, an unknown job `404`. Except for the heartbeat, the job must still be `running` (`409 conflict` "job is …" otherwise).

### Register

```json
{
  "name": "worker-core-1",
  "family": "core",
  "version": "1.4.0",
  "scanners": { "opengrep": "1.10.0", "gitleaks": "8.21.2", "bandit": "1.9.4", "plugin-sast-example": "2.0" },
  "plugins": { "plugin-sast-example": { "name": "Example scanner", "homepage": "https://scanner.example.com" } },
  "tools": {
    "bandit": { "name": "Bandit", "category": "sast", "scan_types": ["sast"], "license_spdx": "Apache-2.0", "family": "sast",
                "targets": ["repository"], "network": "none", "intrusive": false, "parser": "import:bandit", "first_party": true },
    "plugin-sast-example": { "name": "Example scanner", "category": "sast", "scan_types": ["sast"], "license_spdx": "MIT",
                "targets": ["repository"], "network": "none", "parser": "sarif", "first_party": false }
  }
}
```

`organization` (optional) is the slug of the organization the worker serves; an unknown or suspended organization returns `400`. The agent sends it only when `PATHOS_WORKER_ORGANIZATION` is set. `name` is 1–100 characters of letters, digits, `.`, `_` and `-` (defaults to the host name in the agent, `PATHOS_WORKER_NAME`), unique within the organization; `family` 1–40 characters (`PATHOS_WORKER_FAMILY`, default `core`); at most 700 scanners. `tools` describes the [tool manifests](scan-types-and-tools.md#tool-manifests) among `scanners` (metadata only, never commands): first-party manifests of family images (catalog keys that are not built into the core image) and operator plugins (`plugin-<category>-<name>`). Invalid entries (a first-party claim for a core tool or a plugin key, a category that does not match the key, an unknown scan type or target) are dropped. `plugins` is the PATHOS 1.x form (name and homepage of SARIF plugins) and is still accepted. Unknown scanner keys are dropped. Plugins become selectable in scan profiles or on scan targets, with the declared scan types, targets, network and intrusive flags. Response `200`: `{ "worker_id": "<uuid>", "token": "<worker token>" }`. Jobs still leased by a previous run of the same worker are returned to the queue. Audited as `worker.register`.

### Lease a job

`POST /internal/worker/v1/lease` (empty JSON object). Before leasing, expired leases are returned to the queue (or failed when the job has used all its attempts). Jobs that use manifest tools are routed: a worker leases such a job only when it advertises every manifest tool of the job, unless no online worker advertises all of them (then any worker leases it and reports the tools it lacks as `skipped`). Returns `204` when nothing is queued; the agent polls every 5 seconds. Otherwise `200` with the job, which is now `running` with a 5-minute lease:

| Field | Description |
|---|---|
| `job_id`, `repository_id`, `full_name` | The job and its repository. |
| `clone_url`, `ref`, `commit_sha`, `full_history` | What to clone (empty `clone_url` for uploaded repositories). |
| `credential` | Clone credential of the repository's SCM connection, if any. |
| `public` | The repository is public; the worker may clone anonymously if the credential fails. |
| `source` | For uploaded repositories: `{ type: "snapshot", sha256, size }`; download it from `/internal/worker/v1/jobs/{id}/source`. |
| `target` | For scan-target jobs (image, web application, API, artifact, mobile app, LLM endpoint, SBOM, declared endpoints): kind, reference and any decrypted target credential; LLM endpoint jobs also carry `model`. Endpoints jobs carry `endpoints[]` (`kind`, `value`, `authorized`: only authorized endpoints may be contacted) and `rate_limit`; image and artifact jobs with a verification policy carry `signature` (the [policy](scan-targets.md#signature-verification)) and, for artifacts, `signature_material`. `intrusive_authorized: true` when intrusive testing of the target is authorized; the agent skips intrusive tools otherwise. |
| `timeout_seconds`, `exclusions`, `scanners[]` | From the pinned scan profile version: `{ key, config }` per scanner. Opengrep's config includes the organization's custom rules. |
| `previous_commit_sha` | Commit of the repository's previous successful scan of the same ref (Git branch scans only; omitted for the first scan, pull requests, uploads and targets). The worker compares it with the scanned commit. |
| `collect_authors` | `true` only while the organization has developer attribution on: the worker then lists the commit author names between the two commits. |
| `secret_validation` | Only when an administrator enabled [live secret validation](../user-guide/secret-validation.md) providers, for repository branch scans (never pull requests, scan targets or offline installations): `{ providers: [...], rate_per_second, max_checks }`. Absent means off. |

If no clone credential can be obtained, the job fails and `204` is returned.

### Heartbeat

`POST /internal/worker/v1/jobs/{id}/heartbeat` extends the lease by 5 minutes and returns `{ "cancel": false }`. When a user cancelled the job it returns `{ "cancel": true }` and the worker stops. The agent sends a heartbeat every 30 seconds.

### Download the source or target file

`GET /internal/worker/v1/jobs/{id}/source` streams the decrypted snapshot (`application/gzip`, with `Content-Length`); the worker verifies its SHA-256 and size before scanning. `404 no_snapshot` if the job has none.

`GET /internal/worker/v1/jobs/{id}/target-file` returns the uploaded SBOM, build artifact or mobile app of a scan-target job, decompressed (`application/json`). `404 no_target_file` if the job has none.

### Events and logs

`POST /internal/worker/v1/jobs/{id}/events` with `{ events: [], logs: [] }` (at most 200 events and 1,000 log lines per call) → `204`.

- Event: `stage` (`queued`, `leased`, `source`, `scanner`, `ingest`, `finalize`, `cancel`, `retry`), `scanner`, `status` (`started`, `succeeded`, `failed`, `skipped`, `timed_out`, `info`), `message`, `at`.
- Log line: `at`, `level` (`debug`, `info`, `warn`, `error`), `source` (`worker` or a scanner key), `message`.

Messages are redacted and cut to 2,000 characters; timestamps far in the future or before the job started are replaced by the server time. A job keeps at most 5,000 log lines. These feed the execution [stages and logs](scans.md).

### Code inventory

`POST /internal/worker/v1/jobs/{id}/imports` with `{ version: 1, files_scanned, imports: { … }, strings: { … } }` (at most 8 MiB) stores the repository's import inventory and recomputes the reachability of its dependency findings (see [Reachability](vulnerability-intelligence.md#reachability)). Returns `{ "findings_updated": n }`. Ignored (`0`) for pull request scans; `400` for scan-target jobs.

### Material changes

`POST /internal/worker/v1/jobs/{id}/changes` (at most 16 MiB), sent after the scanners and before `complete`:

```json
{
  "version": 1, "status": "computed", "reason": "", "base_sha": "<sha>", "head_sha": "<sha>",
  "files_changed": 12, "truncated": false,
  "changes": [{ "category": "auth", "rule_id": "auth.spring-security", "file_path": "src/SecurityConfig.java", "change_type": "modified",
                "side": "added", "start_line": 20, "end_line": 21, "match_count": 2, "snippet": "…", "explanation": "…" }],
  "commits": [{ "sha": "<sha>", "author_name": "Ada Lovelace", "authored_at": "2026-11-18T10:00:00Z", "files": ["src/SecurityConfig.java"] }],
  "commits_complete": true
}
```

`status` is `computed`, `baseline`, `unchanged` or `unavailable` (with `reason`). Changes with unknown rules, and dependency changes (the API computes those from the SBOMs), are dropped; snippets are redacted. `commits` are ignored and never stored unless the organization has attribution on; the worker sends author names only, never e-mail addresses. A retried job replaces the earlier report. Ignored for pull request and scan-target jobs. Returns `{ "material_changes": n }` and queues the `change.material` notification event when `n > 0`; `400` for an invalid report.

The worker fetches only the two commits (shallow, `--depth 1`, or `--depth 100` of the scanned commit when authors are collected) into a private bare repository with the job's clone credential, computes `git diff -U0` without external diff or textconv drivers and runs the rules on the changed lines; nothing in the repository is executed.

### Runtimes and introducing commits

After the scanners of a repository job (not for scan targets; ignored for pull request scans):

- `POST /internal/worker/v1/jobs/{id}/runtimes` with `{ version: 1, runtimes: [{ kind: "runtime" | "image", name, version, path }] }` (at most 1,000 entries, 1 MiB) replaces the repository's declared runtimes (`node`, `python`, `ruby`, `go`, `java`, `dotnet`, `php`) and Dockerfile base images (`name` is the image reference). Invalid entries are dropped. Response `{ "stored": n }`. They are matched to end-of-life data when the job completes.
- `POST /internal/worker/v1/jobs/{id}/blame` with `{ version: 1, mode: "full" | "shallow", entries: [{ file, line, commit, author, time }], missing: [{ file, line }] }` (at most 5,000 each, 4 MiB). For each code finding (`sast`, `secrets`, `iac`) of this job at `file:line`, `full` records the introducing commit (full SHA), the author's **name** and the commit time, unless one is already known; `missing` lines are not in the scanned commit; `shallow` marks the job's code findings `shallow_clone` (unknown). The worker sends `full` only for repositories with full history, and never sends author e-mail addresses. Response `{ "findings_updated": n }`.

### Secret validation

Only for jobs whose lease carried `secret_validation`. After the scanners, the agent parses its own secret findings (secret scanners and the secret rules of SAST tools), reads each finding's line from the checkout, recognizes the credential and asks the provider's read-only endpoint, through the egress proxy only, at the leased rate and up to `max_checks`. Then:

`POST /internal/worker/v1/jobs/{id}/secret-validation` with (at most 1,000 results, 2 MiB):

```json
{
  "version": 1,
  "providers": ["github"],
  "results": [
    { "fingerprints": ["…"], "file": "config/.env", "line": 2, "provider": "github", "status": "active",
      "identity": "user octo-test", "endpoint": "GET https://api.github.com/user", "http_status": 200,
      "detail": "the provider accepted the credential (HTTP 200)", "checked_at": "2026-11-19T10:00:00Z" }
  ]
}
```

`fingerprints` are those of the job's findings at that location (the API matches `secrets` findings of this job by fingerprint). `status` is `active`, `inactive`, `error` or `not_checked`. The report never contains a secret. The API drops invalid results, turns verdicts for providers that are not enabled (now) into `not_checked`, keeps `identity` only for `active`, never lets `error` or `not_checked` replace an earlier `active` or `inactive` verdict, raises active findings to `critical` and restores the severity on `inactive`. Ignored for pull request and scan target jobs. Response `{ "findings_updated": n, "dropped": n }`. Every upload is audited as `secret_validation.batch` (counts only).

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
| `parser` | Manifest tools whose output is not SARIF: `{ "kind": "import", "format": "bandit" }` or `{ "kind": "jsonmap", "jsonmap": { … } }` ([jsonmap](scan-types-and-tools.md#jsonmap)). Refused (`400`) for built-in tools and for invalid parsers. |

A `failed` or `timed_out` result may carry `output_gzip` too (2.2.2): the findings of such a partial report are stored, the result keeps its status, the execution is `partial`, and nothing the tool covers is auto-resolved. A `skipped` result whose `error` starts with `scanner not available in this worker image` makes the execution `partial` (`failed` when nothing ran) with `PTH-SCAN-1101`.

The output is parsed into findings at once; the tool's original output is stored with its parser, so findings can be located in it later. Response `{ "findings": n }`. A decompressed output over the size limit returns `413 too_large`.

### Complete

`POST /internal/worker/v1/jobs/{id}/complete` with `{ status: "succeeded" | "failed", error, commit_sha }`. `commit_sha` (the commit actually scanned) is stored when it is a full SHA. PATHOS finalizes the job (new and fixed findings, security gate, policies), then posts pull request statuses or starts follow-up work (AI review, Human Eye queue). Response `{ "status": "<final job status>" }`.

### Release (2.2.2)

`POST /internal/worker/v1/jobs/{id}/release` with `{ "reason": "worker w1 stopped (SIGTERM) before the scan finished" }`. A worker that is stopping (SIGTERM during an upgrade or restart) hands its running job back instead of reporting partial results: the job returns to the queue (`status` `queued`, for any worker), or is failed when it has used its attempts or the same scan is queued again. An execution event records the reason. Response `{ "status": "queued" | "failed" }`; `409` when the job is no longer leased by this worker. The worker makes the call with its own short timeout, not with the cancelled job context; against an API without this endpoint it reports the job as failed.

### Fix jobs

Fix jobs produce the file edits for [fix pull requests](findings.md#fix-pull-requests). The agent asks for one only when `lease` returned `204` (scans come first).

`POST /internal/worker/v1/fix-lease` (empty JSON object) returns `204` when nothing is queued, otherwise `200` with `{ fix_id, full_name, clone_url, ref, credential, public, ecosystem, package_name, current_version, target_version, manifest_hint, timeout_seconds }`. The job is leased for 10 minutes; an expired lease returns it to the queue, at most 3 attempts. `ref` is the repository's scan branch.

The worker clones `ref` (shallow, with the same hardening as scans: no hooks, filters, submodules or symbolic links), edits the manifests as text and never runs a package manager, build tool or repository code. It then calls `POST /internal/worker/v1/fix-jobs/{id}/result` with one of:

- `{ "status": "ok", "base_commit": "<full SHA cloned>", "files": [{ "path": "requirements.txt", "content_base64": "…" }], "notes": [] }`: 1–20 files, each at most 5 MiB (20 MiB in total), relative paths without `..`. The API then creates the branch, commit and pull request itself; the worker never pushes.
- `{ "status": "not_supported", "error": "…" }` or `{ "status": "failed", "error": "…" }`.

Response `204`. Another worker gets `409 lease_lost`.

### AI fix verification jobs

These verify [AI-proposed fixes](ai-and-mcp.md#ai-proposed-fixes). The agent asks for one after `lease` and `fix-lease` returned `204`.

`POST /internal/worker/v1/ai-fix-lease` (empty JSON object) returns `204` or `200` with `{ fix_id, phase, full_name, clone_url, ref, commit_sha, credential, public, scanner_key, scanner_config, rule_id, file_path, start_line, diff, test_runner, timeout_seconds }`. Phase `verify` goes to a worker that registered `scanner_key`; phase `test` only to a worker of family `fuzz`. The lease lasts 20 minutes; an expired lease returns the job to its queue, at most 3 attempts.

- **verify:** clone `ref` at `commit_sha` (hardened as for scans), check the diff against the policy, apply it, run the scanner on the changed files before and after, compare. Result: `{ "phase": "verify", "status": "passed"|"failed", "failure_reason", "base_commit", "steps": [{ "key": "apply"|"scan", "status", "detail" }], "scan_evidence", "before_report_gzip", "after_report_gzip", "files": [{ "path", "content_base64" }] }`. `files` are the fixed files; the API accepts only paths the diff changes.
- **test:** clone `commit_sha` (the verified commit), apply the diff and run `pathos-fixtest <runner>` through the sandbox runner without and with the fix. Result: `{ "phase": "test", "status", "failure_reason", "steps": [{ "key": "tests", … }], "test_log" }` (the API keeps at most 256 KiB of the log, redacted).

`POST /internal/worker/v1/ai-fix-jobs/{id}/result` → `204`. A result for the wrong phase is `400`; another worker gets `409 lease_lost`. The worker never pushes.
