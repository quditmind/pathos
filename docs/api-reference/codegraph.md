---
title: CodeGraph
section: api-reference
order: 8
version: "3.0"
updated: 2026-11-20
summary: Build code graphs of an application's repositories, list snapshots, read the 15 views with server-side aggregation and lazy expansion, inspect nodes, trace paths, compare snapshots and export JSON. Behind the codegraph feature flag.
---
# CodeGraph

CodeGraph stores a graph of an application's code, APIs, data stores, deployment and dependencies, one **snapshot** per repository and commit. The [user guide](../user-guide/codegraph.md) explains builds, views and evidence; the design is in [PATHOS_CODEGRAPH_ARCHITECTURE.md](../aspm/PATHOS_CODEGRAPH_ARCHITECTURE.md).

Every endpoint answers `404` with `PTH-PLAT-1007` (`feature_disabled`) while the organization's `codegraph` feature flag is off (Administration → Feature flags).

## Permissions

| Operation | Permission |
|---|---|
| List snapshots, read a snapshot, views, nodes, paths, diffs | `findings.read` on the snapshot's repository. The snapshot list shows only snapshots of repositories in the caller's scope |
| Export (`GET …/export`) | `findings.read` and `findings.export` on the snapshot's repository |
| Build (`POST …/build`) | `scans.run` on each repository built (repositories without it are left out) |
| Read settings | `findings.read` or `settings.manage` anywhere in the organization |
| Change settings | `settings.manage` organization-wide |

## Objects

### Node

```json
{ "id": "0196…", "key": "fn:go:backend/internal/x.Run", "type": "function", "label": "Run", "layer": "code",
  "parent": "0196…", "group": "agg:dir:backend/internal/x",
  "attrs": { "language": "Go", "file": "backend/internal/x/run.go", "line": 12, "end_line": 40, "technology": "", "framework": "" },
  "finding_counts": { "high": 1 } }
```

| Field | Meaning |
|---|---|
| `type` | `repository`, `module`, `file`, `function`, `class`, `route`, `api_operation`, `datastore`, `queue`, `external_service`, `container`, `iac_resource`, `component` (SBOM), `secret_ref`, `trust_boundary`, `application` |
| `layer` | `code`, `api`, `data`, `deploy`, `dependency`, `ownership` |
| `key` | Stable across snapshots (type and qualified name, never a line number); diffs compare keys |
| `parent` | The containing node (repository › module › file › class › function) |
| `group` | The aggregate this node belongs to (its directory, or its type for nodes without a file) |
| `attrs` | Small scalar attributes: `language`, `framework`, `file`, `line`, `end_line`, `technology`, `exposure`, `method`, `path`, `purl`, `version`, … Secret references carry names and locations only, never values |
| `finding_counts` | Open findings located in this node (the innermost function or class containing the finding's line, else the file; dependency findings on the matching component), by severity, counted when the snapshot was stored |

### Edge

```json
{ "id": "0196…", "source": "0196…", "target": "0196…", "type": "calls", "evidence": "verified", "count": 1,
  "evidence_refs": [ { "kind": "file_line", "ref": "backend/internal/x/run.go:18", "detail": "call store.Load" } ] }
```

| Field | Meaning |
|---|---|
| `type` | `calls`, `imports`, `defines`, `exposes`, `reads`, `writes`, `publishes`, `consumes`, `depends_on`, `deployed_as`, `crosses_boundary`, `owns` |
| `evidence` | `verified` (static: a file and line, an SBOM record, a rule match, an inventory record), `observed` (runtime context) or `ai_inferred` (an AI evidence record). The strongest evidence the edge holds |
| `evidence_refs` | At least one, always. `kind`: `file_line` (`<path>:<line>`), `sbom` (bom-ref or purl), `scan` (rule or scan reference), `registry` (a PATHOS inventory record: ownership), `runtime` (an observed workload), `ai_record` |
| `count` | 1 for a stored edge. Greater than 1 for a **lifted** or **aggregated** edge (several stored edges between the members of two shown nodes or aggregates); its `id` then starts with `e:` and its `evidence_refs` are samples of the stored edges |

An edge without evidence cannot exist: the database refuses it (deferred constraint trigger), and the API never returns one.

### Snapshot

```json
{ "id": "0196…", "application_id": "…", "repository_id": "…", "repository_name": "acme/shop", "scan_job_id": "…",
  "ref": "main", "commit_sha": "…", "trigger": "manual", "status": "ready", "storage": "rows",
  "node_count": 18234, "edge_count": 40211, "engines": { "pathos-graph": "…", "tree-sitter": "…" },
  "stats": { "files_scanned": 2104, "duration_ms": 41000, "languages": { "Go": 1120 } },
  "error_code": "", "error": "", "created_at": "…", "started_at": "…", "finished_at": "…", "archived_at": null }
```

`status`: `queued` → `building` → `ready`, `partial` (discovery hit its size limits, `PTH-DISC-1007`) or `failed` (`error_code` says why); `archived` beyond the retention setting. `trigger`: `manual` (API) or `scan` (rediscovery). `storage`: `rows`, `object` (archived; only the export remains in object storage) or `none` (archived without object storage; summary only). `engines` records each discovery engine's version.

## Build

`POST /api/v1/codegraph/applications/{id}/build`

```json
{ "repository_id": "…", "ref": "main" }
```

Both fields are optional: without `repository_id` every active repository of the application is built (up to 50); without `ref` the repository's scan branch. Each repository gets a discovery execution (a scan execution with trigger `codegraph` that runs only the `pathos-graph` tool on a `worker-graph` worker) and a snapshot.

Response `202`:

```json
{ "snapshots": [ { "snapshot_id": "…", "repository_id": "…", "scan_job_id": "…", "status": "queued", "coalesced": false } ],
  "errors": [ { "repository_id": "…", "code": "PTH-DISC-1006", "message": "…" } ] }
```

A build of a repository whose discovery is already queued joins it (`coalesced: true`, same snapshot).

| Status | Code | When |
|---|---|---|
| `409` | `PTH-DISC-1001` (`no_graph_worker`) | No worker that provides `pathos-graph` was seen in the last two minutes |
| `422` | `PTH-DISC-1005` (`no_repositories`) | The application has no active repository, or `repository_id` is not one of them |
| `409` | `PTH-DISC-1006` (`not_buildable`) | The repository cannot be scanned (archived, scanning disabled, no branch, upload without snapshot) |
| `403` | — | The caller lacks `scans.run` on every repository |

## Snapshots

`GET /api/v1/codegraph/applications/{id}/snapshots?repository_id=&status=&limit=` (newest first, `limit` 1–200, default 50) → `{ "snapshots": [Snapshot] }`.

`GET /api/v1/codegraph/applications/{id}/snapshots/{sid}` → the snapshot and, when it is readable, counts:

```json
{ "snapshot": { … }, "views": [ … ], "node_types": { "function": 9120 }, "layers": { "code": 15000 },
  "edge_types": { "calls": 30111 }, "evidence_types": { "verified": 40190, "observed": 21 }, "open_findings": { "high": 4 } }
```

Snapshot reads first settle builds whose execution ended without a graph (`failed`, `PTH-DISC-1003`).

## Views

`GET /api/v1/codegraph/views` lists the 15 views with their node and edge types, plus the node types, edge types, layers, evidence types and evidence reference kinds.

`GET /api/v1/codegraph/applications/{id}/snapshots/{sid}/graph?view=&focus=&depth=&layers=&filters=&limit=&compare=`

| Parameter | Meaning |
|---|---|
| `view` | `architecture` (default), `call_graph`, `data_flow`, `api`, `dependencies`, `deployment`, `ownership`, `trust_boundaries`, `internet_exposure`, `findings_overlay`, `sbom`, `datastores`, `external_services`, `secrets_and_config`, `change_impact` |
| `focus` | A node id: the node, its children (lazy expansion) and its neighbours up to `depth` hops. An aggregate id (`agg:…`): its members, one directory level deeper, and their direct neighbours |
| `depth` | 1–3 (default 1) |
| `layers` | Comma-separated layers to keep |
| `filters` | Comma-separated `key:value`: `type:<node type>`, `language:<name>`, `technology:<text>` (or `framework:`), `severity:<critical…info>` (nodes with open findings of that severity, with their ancestors), `evidence:<verified\|observed\|ai_inferred>` (edges), `q:<text>` (label or key) |
| `limit` | 1–2,000 (default 500): the most nodes plus aggregates returned |
| `compare` | `change_impact` only: the base snapshot (default: the previous ready snapshot of the same repository) |

Response:

```json
{ "snapshot_id": "…", "view": "call_graph", "focus": "", "depth": 1, "limit": 500,
  "nodes": [Node], "edges": [Edge],
  "aggregated": [ { "id": "agg:dir:backend/internal", "label": "backend/internal", "count": 812,
                    "child_types": { "function": 790, "class": 22 }, "finding_counts": { "high": 3 } } ],
  "truncated": false, "base_snapshot_id": null }
```

**Aggregation.** When a view has more nodes than `limit`, the server groups them by directory, one path level at a time from the deepest, until the result fits; groups of one stay nodes. Edges between groups are merged (`count`, strongest `evidence`, sample `evidence_refs`). Request `focus=<aggregate id>` to expand a group. `truncated` is true when even the coarsest grouping, or the edge cap (5 × `limit`), cut the result.

**Lifting.** Some views (architecture, dependencies, findings overlay) show containers only (modules, for example); a call between two functions is shown as an edge between their modules.

`change_impact` marks nodes with `attrs.change`: `added`, `changed` or `removed` (removed nodes come from the base snapshot and carry its ids).

| Status | Code | When |
|---|---|---|
| `400` | `PTH-GRAPH-1003` | Unknown view, layer, filter, or a value out of range |
| `409` | `PTH-GRAPH-1001` (`snapshot_not_ready`) | The snapshot is queued, building or failed |
| `409` | `PTH-GRAPH-1005` (`snapshot_archived`) | The snapshot is archived |
| `422` | `PTH-GRAPH-1004` (`different_repositories`) | `compare` is a snapshot of another repository |

## Node inspector

`GET /api/v1/codegraph/applications/{id}/snapshots/{sid}/nodes/{nid}`

```json
{ "node": Node, "ancestors": [ { "id": "…", "type": "module", "label": "x" } ],
  "children": { "count": 12, "types": { "function": 12 } },
  "edges_out": [ Edge + { "other": { "id": "…", "type": "function", "label": "Load" } } ], "edges_in": [ … ],
  "edges_out_total": 3, "edges_in_total": 1,
  "finding_counts": { "high": 1 }, "rollup_finding_counts": { "high": 2 },
  "findings": [ { "id": "…", "title": "…", "severity": "high", "status": "open", "rule_id": "…", "file_path": "…", "start_line": 18 } ],
  "source_links": [ { "file": "backend/internal/x/run.go", "line": 12, "url": "https://github.com/acme/shop/blob/<commit>/backend/internal/x/run.go#L12" } ] }
```

Up to 200 edges each way, each with up to five evidence references; up to 100 open findings located in the node (its line range, its file, its directory for a module, its package for a component). Source links point to GitHub and Azure DevOps at the snapshot's commit; other sources get the file and line without a URL.

## Paths

`GET /api/v1/codegraph/applications/{id}/snapshots/{sid}/paths?from=&to=&direction=&max=&limit=&types=`

A bounded breadth-first search from `from` along edges `out` (default: source → target) or `in`, up to `max` hops (1–8, default 6), over the edge `types` given (comma-separated; default all). With `to`: up to `limit` (1–50, default 20) shortest paths to it. Without: one shortest path to each node the search ended at (farthest first).

```json
{ "from": "…", "direction": "out", "max": 6, "paths": [ [ "edge id", "edge id" ] ], "nodes": [Node], "edges": [Edge],
  "truncated": false, "budget_exceeded": false }
```

`truncated` means more paths or nodes lie beyond `limit` or `max`; `budget_exceeded` means the search visited its budget of 200,000 nodes. Errors: `400` `PTH-GRAPH-1003`, `404` (unknown node), `409` as for views.

## Diff

`GET /api/v1/codegraph/applications/{id}/diff?from=<snapshot>&to=<snapshot>`

Compares two snapshots of the same repository by stable keys. A node is **changed** when its label, type, layer, file, language, technology, parent or open finding count differs; an edge when its evidence type differs.

```json
{ "from": "…", "to": "…", "repository_id": "…",
  "summary": { "added_nodes": 3, "removed_nodes": 1, "changed_nodes": 2, "added_edges": 5, "removed_edges": 2, "changed_edges": 0 },
  "added":   { "nodes": [ { "id": "…", "key": "…", "type": "route", "label": "POST /orders", "layer": "api", "file": "…" } ],
               "edges": [ { "id": "…", "key": "…", "source_key": "…", "target_key": "…", "type": "calls", "evidence": "verified" } ] },
  "removed": { "nodes": [ … ], "edges": [ … ] },
  "changed": { "nodes": [ … ], "edges": [ { …, "previous_evidence": "observed" } ] },
  "truncated": false }
```

At most 2,000 items per list. Errors: `400` (`from`/`to` not ids), `404`, `409` (`PTH-GRAPH-1001`, `PTH-GRAPH-1005`), `422` `PTH-GRAPH-1004`.

## Export

`GET /api/v1/codegraph/applications/{id}/snapshots/{sid}/export?format=json`

Downloads the whole snapshot (`application/json`, attachment): `{ "schema": "pathos.codegraph.export/v1", "pathos_version", "exported_at", "snapshot", "nodes": [Node], "edges": [Edge with every evidence reference and its "key"] }`. PNG and SVG exports are rendered in the browser. Archived snapshots are served from object storage when they were archived there; otherwise `409` `PTH-GRAPH-1005`.

## Settings

`GET /api/v1/codegraph/settings`, `PUT /api/v1/codegraph/settings`

```json
{ "auto_rebuild": true, "min_interval_minutes": 60, "keep_snapshots": 10, "updated_at": null }
```

| Field | Default | Meaning |
|---|---|---|
| `auto_rebuild` | `true` | After a successful repository branch scan (a pushed commit, a schedule, a manual scan) of a repository that belongs to an application, rebuild its graph — when the flag is on and a graph worker is online |
| `min_interval_minutes` | 60 | Rate limit: no rediscovery while the repository's newest snapshot is younger (0–10,080) |
| `keep_snapshots` | 10 | Snapshots kept per repository; older ones are archived by the jobs service (1–1,000) |

Rediscovery is also skipped while a build is queued or running and when the newest ready snapshot has the scanned commit. Changes are audited (`codegraph.settings.update`); builds are audited as `codegraph.build`.

## Troubleshooting

| Code | Meaning | Fix |
|---|---|---|
| `PTH-DISC-1001` | No CodeGraph worker online | Start `worker-graph` (`COMPOSE_PROFILES=graph`) |
| `PTH-DISC-1002` | The discovery tool failed, timed out or was skipped | Read the execution's `pathos-graph` log; start `worker-graph`; raise memory or time |
| `PTH-DISC-1003` | The execution ended without a graph | Read the execution's events (clone, cancellation, lease) |
| `PTH-DISC-1004` | The discovery output was refused | Run worker images of the API's version |
| `PTH-DISC-1005` | No repository to build | Assign repositories to the application |
| `PTH-DISC-1006` | The repository cannot be built | Fix the repository settings named in the message |
| `PTH-DISC-1007` | The graph is incomplete (limits) | See `stats.skipped`; exclude generated code |
| `PTH-GRAPH-1001` | Snapshot not ready | Wait, or open a ready snapshot |
| `PTH-GRAPH-1002` | The graph could not be stored | Check the API log; build again |
| `PTH-GRAPH-1003` | Invalid graph query | Use `GET /api/v1/codegraph/views` for valid values |
| `PTH-GRAPH-1004` | Snapshots of different repositories | Compare snapshots of one repository |
| `PTH-GRAPH-1005` | Snapshot archived | Use the export, or raise `keep_snapshots` |

Full entries: [Discovery](../troubleshooting/disc.md), [CodeGraph](../troubleshooting/graph.md).
