---
title: Troubleshooting: CodeGraph
section: troubleshooting
order: 107
version: "1.0"
updated: 2026-11-20
summary: The code graph store and views (5 codes, PTH-GRAPH-*)
---

# Troubleshooting: CodeGraph

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

The code graph store and views.

| Code | Title | Severity |
|---|---|---|
| [PTH-GRAPH-1001](#PTH-GRAPH-1001) | The snapshot is not ready | info |
| [PTH-GRAPH-1002](#PTH-GRAPH-1002) | The graph could not be stored | error |
| [PTH-GRAPH-1003](#PTH-GRAPH-1003) | Invalid graph query | warning |
| [PTH-GRAPH-1004](#PTH-GRAPH-1004) | Snapshots of different repositories cannot be compared | warning |
| [PTH-GRAPH-1005](#PTH-GRAPH-1005) | The snapshot is archived | info |

<a id="PTH-GRAPH-1001"></a>

## PTH-GRAPH-1001: The snapshot is not ready

| | |
|---|---|
| Severity | info |
| Category | state |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `snapshot_not_ready` |
| Raised in | internal/codegraph/service.go (ready) |

**What it means.** Views, nodes, paths, diffs and exports need a snapshot with status ready or partial.

**Confirmed cause.** The snapshot is queued, building or failed. Confirmed automatically when this code is raised.

**Probable causes**

1. The build is still running
2. The build failed (see the snapshot's error code)

**Impact.** The request was not answered; nothing changed.

**How to fix**

1. Wait for the build to finish, or open the failed snapshot's error code.
2. Pick a ready snapshot.

**Verify**

1. The snapshot list shows status ready.


<a id="PTH-GRAPH-1002"></a>

## PTH-GRAPH-1002: The graph could not be stored

| | |
|---|---|
| Severity | error |
| Category | internal |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/codegraph/ingest.go (Load) |

**What it means.** A valid discovery document could not be written to the graph store.

**Confirmed cause.** The database refused or failed the snapshot transaction (see the API log for the snapshot). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A database error or timeout
2. A constraint violation (an edge without evidence of its type)

**Impact.** The snapshot is failed; nothing of it was stored.

**How to fix**

1. Check the API log with the snapshot id.
2. Build again; report the problem with the request ID if it repeats.

**Verify**

1. A new build ends with status ready.


<a id="PTH-GRAPH-1003"></a>

## PTH-GRAPH-1003: Invalid graph query

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 400 |
| AI help | not offered |
| Raised in | internal/codegraph/service.go (parseViewParams, paths) |

**What it means.** A view, focus, depth, layer, filter, limit or path parameter is not valid.

**Confirmed cause.** A query parameter is outside its allowed values (the message names it). Confirmed automatically when this code is raised.

**Probable causes**

1. An unknown view name
2. A limit above 2,000 or a depth above 3
3. A filter that is not key:value

**Impact.** Nothing was returned.

**How to fix**

1. Use GET /api/v1/codegraph/views for the valid views, types and layers.
2. Correct the parameter.

**Verify**

1. The request answers 200.


<a id="PTH-GRAPH-1004"></a>

## PTH-GRAPH-1004: Snapshots of different repositories cannot be compared

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `different_repositories` |
| Raised in | internal/codegraph/service.go (diff, changeBase) |

**What it means.** A diff or change-impact view compares two snapshots of the same repository.

**Confirmed cause.** The two snapshots belong to different repositories. Confirmed automatically when this code is raised.

**Probable causes**

1. The application has several repositories and two of them were picked

**Impact.** Nothing was compared.

**How to fix**

1. Pick two snapshots of the same repository.

**Verify**

1. The diff answers 200.


<a id="PTH-GRAPH-1005"></a>

## PTH-GRAPH-1005: The snapshot is archived

| | |
|---|---|
| Severity | info |
| Category | state |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `snapshot_archived` |
| Raised in | internal/codegraph/export.go (Retain), service.go (ready) |

**What it means.** Snapshots beyond the retention setting (keep_snapshots) are archived: their nodes and edges leave the database; with object storage the JSON export remains downloadable.

**Confirmed cause.** The snapshot's status is archived. Confirmed automatically when this code is raised.

**Probable causes**

1. More than keep_snapshots newer snapshots exist for the repository

**Impact.** Views, nodes and paths are not available for this snapshot.

**How to fix**

1. Use the export (when object storage is configured).
2. Raise keep_snapshots in the CodeGraph settings to keep more snapshots in the database.
3. Build the commit again if its graph is needed.

**Verify**

1. A newer snapshot opens.

