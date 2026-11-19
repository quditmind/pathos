---
title: Troubleshooting: Workers
section: troubleshooting
order: 111
version: "1.0"
updated: 2026-11-20
summary: Scan workers: registration, leases, sandbox and result uploads (6 codes, PTH-WORK-*)
---

# Troubleshooting: Workers

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Scan workers: registration, leases, sandbox and result uploads.

| Code | Title | Severity |
|---|---|---|
| [PTH-WORK-1001](#PTH-WORK-1001) | Worker revoked | warning |
| [PTH-WORK-1002](#PTH-WORK-1002) | Worker lost the job lease | warning |
| [PTH-WORK-1003](#PTH-WORK-1003) | Worker registration refused | error |
| [PTH-WORK-1004](#PTH-WORK-1004) | Worker sandbox unavailable | warning |
| [PTH-WORK-1005](#PTH-WORK-1005) | Worker could not upload a result | error |
| [PTH-WORK-1006](#PTH-WORK-1006) | Worker offline | warning |

<a id="PTH-WORK-1001"></a>

## PTH-WORK-1001: Worker revoked

| | |
|---|---|
| Severity | warning |
| Category | authorization |
| HTTP status | 403 |
| AI help | not offered |
| Short codes | `worker_revoked` |
| Raised in | internal/scans/worker_api.go |

**What it means.** An administrator revoked the worker; its token no longer works.

**Confirmed cause.** The worker's registration was revoked. Confirmed automatically when this code is raised.

**Probable causes**

1. The worker was revoked on purpose
2. A replaced host still runs the old worker

**Impact.** The worker takes no more scans.

**How to fix**

1. Stop the old worker.
2. To bring it back, delete its state and register it again with the bootstrap token.

**Verify**

1. The worker shows online in Configurations → Scanners & workers.


<a id="PTH-WORK-1002"></a>

## PTH-WORK-1002: Worker lost the job lease

| | |
|---|---|
| Severity | warning |
| Category | conflict |
| HTTP status | 409 |
| AI help | offered |
| Short codes | `lease_lost` |
| Raised in | internal/scans/worker_api.go, internal/scans/fixprs.go, internal/scans/aifixes.go |

**What it means.** The worker reported on a job that is no longer leased to it (the lease expired and the job was requeued or reassigned).

**Confirmed cause.** The job is not leased by this worker. Confirmed automatically when this code is raised.

**Probable causes**

1. The worker paused longer than the lease (heartbeats missed)
2. An administrator revoked the worker

**Impact.** The worker's result for this job is discarded; the job runs again elsewhere.

**How to fix**

1. Check the worker's CPU and memory; long pauses mean an overloaded host.

**Verify**

1. The job completes on the next attempt.


<a id="PTH-WORK-1003"></a>

## PTH-WORK-1003: Worker registration refused

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | 401 |
| AI help | offered |
| Raised in | internal/scans/worker_api.go (register) |

**What it means.** Registration needs the bootstrap token (PATHOS_WORKER_BOOTSTRAP_TOKEN) and an active organization.

**Confirmed cause.** The bootstrap token or the organization in the registration is not valid. Confirmed automatically when this code is raised.

**Probable causes**

1. The worker uses another bootstrap token than the API
2. PATHOS_WORKER_ORGANIZATION names an unknown or suspended organization

**Impact.** The worker cannot take scans.

**How to fix**

1. Set the same PATHOS_WORKER_BOOTSTRAP_TOKEN on the API and the worker.
2. Check the worker's organization slug.

**Verify**

1. The worker log shows "registered" and it appears online.


<a id="PTH-WORK-1004"></a>

## PTH-WORK-1004: Worker sandbox unavailable

| | |
|---|---|
| Severity | warning |
| Category | configuration |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/worker/agent.go |

**What it means.** The worker could not open the shared sandbox directory (PATHOS_SANDBOX_DIR) of its sandbox runner container (`pathos-worker sandbox-runner`), so tools that run repository code (fuzzing harnesses) are skipped.

**Confirmed cause.** The worker's sandbox could not be opened. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The sandbox runner service (for example worker-fuzz-sandbox) is not running
2. The shared sandbox volume is not mounted in both containers
3. Another worker already uses the same sandbox directory

**Impact.** Scans run, but sandboxed tools are skipped (scans may be partial).

**How to fix**

1. Start the sandbox runner service with the worker (docs/OPERATIONS.md, "Fuzzing worker").
2. Check the worker log line "sandbox unavailable" for the reason.

**Verify**

1. The worker log no longer reports the sandbox as unavailable.


<a id="PTH-WORK-1005"></a>

## PTH-WORK-1005: Worker could not upload a result

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/worker/agent.go, internal/worker/fixpr.go, internal/worker/aifix.go |

**What it means.** Uploading a tool result or completing the job to the internal worker API failed.

**Confirmed cause.** The upload to the worker API failed (see the worker log). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The API is restarting
2. The result exceeds the upload limit
3. A network problem between worker and API

**Impact.** Results of the tool are lost for this attempt; the job is retried or ends partial.

**How to fix**

1. Check connectivity from the worker to PATHOS_API_URL.
2. Check the API log at the same time.

**Verify**

1. A new scan uploads all results.


<a id="PTH-WORK-1006"></a>

## PTH-WORK-1006: Worker offline

| | |
|---|---|
| Severity | warning |
| Category | availability |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/scans/worker_api.go (online window), internal/notify |

**What it means.** A registered worker has not sent a heartbeat within the online window; an administrator notification is sent once.

**Confirmed cause.** The worker stopped polling the API. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The worker container stopped
2. The worker host lost network access

**Impact.** Scans that need this worker's tools wait in the queue.

**How to fix**

1. Start the worker (`docker compose up -d worker-core` or its family).
2. Check its log for the last error.

**Verify**

1. The worker shows online again.

