---
title: Troubleshooting: Discovery
section: troubleshooting
order: 106
version: "1.0"
updated: 2026-11-20
summary: Code discovery (CodeGraph worker) (7 codes, PTH-DISC-*)
---

# Troubleshooting: Discovery

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Code discovery (CodeGraph worker).

| Code | Title | Severity |
|---|---|---|
| [PTH-DISC-1001](#PTH-DISC-1001) | No CodeGraph worker is online | warning |
| [PTH-DISC-1002](#PTH-DISC-1002) | The discovery tool did not succeed | error |
| [PTH-DISC-1003](#PTH-DISC-1003) | The discovery execution ended without a graph | error |
| [PTH-DISC-1004](#PTH-DISC-1004) | The discovery output was refused | error |
| [PTH-DISC-1005](#PTH-DISC-1005) | The application has no repository to build | warning |
| [PTH-DISC-1006](#PTH-DISC-1006) | The repository cannot be built | warning |
| [PTH-DISC-1007](#PTH-DISC-1007) | The graph is incomplete (size limits) | warning |

<a id="PTH-DISC-1001"></a>

## PTH-DISC-1001: No CodeGraph worker is online

| | |
|---|---|
| Severity | warning |
| Category | availability |
| HTTP status | 409 |
| AI help | offered |
| Short codes | `no_graph_worker` |
| Raised in | internal/codegraph/service.go (build) |

**What it means.** A CodeGraph build was requested, but no worker that provides the discovery tool (pathos-graph, worker-graph family image) has been seen in the last two minutes.

**Confirmed cause.** No online worker advertises the pathos-graph tool. Confirmed automatically when this code is raised.

**Probable causes**

1. The worker-graph service is not started (Compose profile graph)
2. The worker-graph container exits at start (see its log)
3. The worker serves another organization (PATHOS_WORKER_ORGANIZATION)

**Impact.** Nothing was queued; no snapshot was created.

**How to fix**

1. Start the worker: `COMPOSE_PROFILES=graph docker compose up -d worker-graph`.
2. Check Configurations → Scanners & workers: the worker lists the pathos-graph tool.
3. Build again.

**Verify**

1. The build answers 202 and the snapshot reaches "building".


<a id="PTH-DISC-1002"></a>

## PTH-DISC-1002: The discovery tool did not succeed

| | |
|---|---|
| Severity | error |
| Category | execution |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/codegraph/ingest.go (OnGraphResult) |

**What it means.** The discovery execution ran, but the pathos-graph tool failed, timed out or was skipped, so the snapshot has no graph.

**Confirmed cause.** The tool reported failure, a timeout or a skip (the snapshot error gives its message). Confirmed automatically when this code is raised.

**Probable causes**

1. The execution ran on a worker without the tool (no worker-graph online when it was leased)
2. The repository is larger than the worker's memory or time limits
3. A parser crashed on an unusual file

**Impact.** The snapshot is failed; earlier snapshots are unchanged.

**How to fix**

1. Open the execution (scan_job_id) and read the pathos-graph log.
2. If skipped: start worker-graph and build again.
3. If out of memory or time: raise PATHOS_WORKER_MEMORY or exclude generated directories, then build again.

**Verify**

1. A new build ends with status ready.


<a id="PTH-DISC-1003"></a>

## PTH-DISC-1003: The discovery execution ended without a graph

| | |
|---|---|
| Severity | error |
| Category | execution |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/codegraph/build.go (Reconcile) |

**What it means.** The scan execution that builds the snapshot finished, failed, was cancelled or expired before the discovery tool uploaded a graph.

**Confirmed cause.** The execution reached a final state and no graph arrived (the snapshot error names the state). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The clone failed (credential or network)
2. The execution was cancelled
3. The worker lease expired repeatedly (worker restarts)

**Impact.** The snapshot is failed; earlier snapshots are unchanged.

**How to fix**

1. Open the execution and read its source and worker events.
2. Fix the cause (see PTH-SCAN and PTH-WORK codes) and build again.

**Verify**

1. A new build ends with status ready.


<a id="PTH-DISC-1004"></a>

## PTH-DISC-1004: The discovery output was refused

| | |
|---|---|
| Severity | error |
| Category | validation |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/codegraph/model.go (Validate) |

**What it means.** The graph document the worker uploaded does not satisfy the contract (schema pathos.codegraph/v1): unknown types, a missing node, a containment cycle, or an edge without static evidence.

**Confirmed cause.** Validation of the uploaded graph failed (the snapshot error names the first problem). Confirmed automatically when this code is raised.

**Probable causes**

1. The worker-graph image and the API are different PATHOS versions
2. A discovery engine bug

**Impact.** Nothing of the graph was stored; the snapshot is failed.

**How to fix**

1. Run worker images of the same version as the API.
2. Download the execution's pathos-graph artifact and report the problem with it.

**Verify**

1. A new build ends with status ready.


<a id="PTH-DISC-1005"></a>

## PTH-DISC-1005: The application has no repository to build

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `no_repositories` |
| Raised in | internal/codegraph/service.go (build) |

**What it means.** A CodeGraph build needs at least one active repository of the application, and repository_id, when given, must be one of them.

**Confirmed cause.** No active repository of the application matched the request. Confirmed automatically when this code is raised.

**Probable causes**

1. No repository is assigned to the application
2. The repository belongs to another application or is archived

**Impact.** Nothing was queued.

**How to fix**

1. Assign the repository to the application (Assets → Repositories).
2. Build again.

**Verify**

1. The build answers 202.


<a id="PTH-DISC-1006"></a>

## PTH-DISC-1006: The repository cannot be built

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `not_buildable` |
| Raised in | internal/codegraph/build.go (buildError) |

**What it means.** The repository cannot be scanned: it is archived, scanning is disabled for automatic builds, it has no branch to scan, or an uploaded repository has no source snapshot.

**Confirmed cause.** The scan queue refused the repository (the message gives the reason). Confirmed automatically when this code is raised.

**Probable causes**

1. Scanning is disabled for the repository
2. The repository has no default branch
3. An uploaded repository has no snapshot yet

**Impact.** Nothing was queued for this repository.

**How to fix**

1. Fix the repository settings named in the message.
2. Build again.

**Verify**

1. The build answers 202.


<a id="PTH-DISC-1007"></a>

## PTH-DISC-1007: The graph is incomplete (size limits)

| | |
|---|---|
| Severity | warning |
| Category | limits |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/codegraph/ingest.go (Load) |

**What it means.** Discovery stopped at its file, node or edge limits, so the snapshot holds part of the repository (status partial). The snapshot statistics list what was skipped.

**Confirmed cause.** The discovery document reports truncated: true. Confirmed automatically when this code is raised.

**Probable causes**

1. A very large repository or monorepo
2. Generated or vendored code that is not excluded

**Impact.** Views and paths miss the skipped parts.

**How to fix**

1. Check the snapshot's stats.skipped.
2. Remove generated code from the repository or split it, then build again.

**Verify**

1. A new build ends with status ready.

