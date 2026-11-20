Quditmind PATHOS · applies to v2.2.0 · status: Prototype

# PATHOS CodeGraph architecture

## Purpose

CodeGraph is the code-level graph of an application: modules, files, classes and functions with their calls and imports, routes and API operations, data stores, queues, external services, secret references, containers and infrastructure, SBOM components, trust boundaries and ownership. It is the base for the threat models of M5 and for placing findings in their code context. This page describes what milestone M4 builds: the discovery worker, the graph store, the graph service and API, and the rediscovery loop. The user view is in the [user guide](../user-guide/codegraph.md); the endpoints in the [API reference](../api-reference/codegraph.md).

## Scope

In scope (M4 engine): the `worker-graph` discovery family image and its engine `pathos-graph`; snapshots per application, repository and commit in PostgreSQL; the 15 views with server-side aggregation, lifting and lazy expansion; the node inspector; bounded path tracing; snapshot diffs; JSON export; build jobs through the existing scan job and lease system; rediscovery after scans; retention.

Out of scope: the graph UI (M4 UI builder, against the contract below); AI-inferred edges (rule 5 allows them, but discovery is static only; the AI evidence record table of ADR-008 is deferred to the first AI producer, M5/M7); data-flow (taint) analysis with Joern (ADR-006 tier 2, not included, see [Decisions](#decisions)); graphs that span several repositories of an application (each snapshot covers one repository).

## Architecture

```
 user / UI ──▶ API (internal/codegraph) ──▶ PostgreSQL: codegraph_* tables
                 │  POST …/build                ▲
                 ▼                              │ load (validate, enrich, insert)
          scan_jobs (trigger codegraph,         │
          system profile: pathos-graph) ──lease──▶ worker-graph ── clone ──▶ pathos-graph discover (no network)
                                                     │ upload pathos.codegraph/v1 JSON as the tool result
                                                     ▼
                                     scans.Ingest → OnGraphResult hook
 scan finished (push, schedule, manual) ── OnScanFinished hook ──▶ rediscovery (flag, settings, rate limit)
 jobs runner (every 6 h) ──▶ Reconcile + Retain (archive beyond keep_snapshots)
```

The graph store is relational ([ADR-004](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-004-graph-store-postgresql-versus-a-graph-database)). Graph queries do not run as recursive SQL: the service loads a ready snapshot's nodes and edges once into a compact in-memory **skeleton** (ids, keys, types, parents, groups; no attributes or evidence), cached per snapshot (snapshots never change once ready), and reads attributes and evidence from the database only for what a response returns.

## Components

| Component | Where | Role |
|---|---|---|
| `pathos-graph` | `workers/graph/discover` (own Go module, cgo; installed at `/opt/pathos/graph/bin`) | Discovery engine: reads a checkout, writes a `pathos.codegraph/v1` document |
| Graph rules | `workers/graph/rules`, fixtures `workers/graph/rules-tests` | PATHOS Opengrep rules for routes, database/ORM access and queues (separate from `workers/rules`, which produce findings) |
| Tool manifest | `workers/graph/tools.d/pathos-graph.yaml` | Runs the engine in the worker (`network: none`, `sandbox: false`, output file) |
| `worker-graph` image | `workers/graph/Dockerfile` | Family image on `worker-core` (Compose profile `graph`) |
| Catalogue entry | `backend/internal/scanners/catalog_graph.go` | `pathos-graph`, family `graph`; manifest-routed, so only workers that advertise it lease graph executions; refused in scan profiles |
| Store | migrations `00049`–`00051` | `codegraph_snapshots`, `codegraph_nodes`, `codegraph_edges`, `codegraph_evidence`, `codegraph_settings`; `scan_jobs.trigger` `codegraph` |
| Service and API | `backend/internal/codegraph` | Build, ingest (`OnGraphResult`), views, inspector, paths, diff, export, settings, rediscovery (`OnScanFinished`), `Reconcile`, `Retain` |
| Scan hooks | `backend/internal/scans` | `EnqueueOpts.ProfileVersionID` (system profile), lease `kind: codegraph` (only the graph tool runs, no change detection or inventories), `Ingest` routes `pathos-graph` output to `OnGraphResult`, `Finalize` short path |
| Error codes | `backend/internal/platform/diag/catalogue_disc_graph.go` | `PTH-DISC-1001`…`1007`, `PTH-GRAPH-1001`…`1005` |

## Data flow

1. **Build.** `POST /api/v1/codegraph/applications/{id}/build` (or rediscovery) checks that a worker advertising `pathos-graph` is online, ensures the organization's system profile "CodeGraph discovery (system)" (stored archived, so it never appears in profile choices; it lists the mandatory scanners as every profile version must, and the lease drops them), queues a scan execution with trigger `codegraph` through `scans.EnqueueWith` (coalescing with a queued one) and creates the snapshot (`queued`).
2. **Lease.** The routing condition of the existing lease sends the execution to a worker that advertises `pathos-graph`. The lease carries `kind: codegraph`; the agent clones as for any scan, skips material change detection, and runs only `pathos-graph`; it uploads no import, runtime, blame or change inventories.
3. **Discovery** (inside the worker, no network): file walk with limits and exclusions, language detection (go-enry), Go via `go/parser`, Java/Python/JS/TS/C#/PHP/Ruby via tree-sitter, Opengrep with the graph rules (routes, DB, queues), OpenAPI documents (kin-openapi), Dockerfiles/Compose/Kubernetes/Terraform, secret references, Syft SBOM. Calls and imports are kept only when resolved inside the repository; unresolved ones are dropped, never guessed.
4. **Upload.** The document is the tool's result (gzip, base64), stored as a raw JSON artifact of the execution. `scans.Ingest` does not parse it into findings; after the result row commits it calls `OnGraphResult`.
5. **Load.** `Validate` checks the contract (schema, types, layers, unique keys, parents, no containment cycle, every edge with static evidence; `observed`, `ai_inferred` and `owns` are refused from discovery) and merges duplicate edges. `enrich` adds the application node and its `owns` edge (evidence `registry`), observed runtime workloads linked to the repository (`deployed_as`, and `crosses_boundary` to the internet boundary for exposed workloads; evidence `runtime`), parents, depth, aggregation groups (`dir:<directory>` or `type:<type>`) and the repository's open findings (attached to the innermost function or class containing the line, else the file; dependency findings to the matching component). One transaction writes nodes (parents first), edges and evidence in multi-row `INSERT` batches (`COPY` is refused under row-level security); deferred constraint triggers verify at commit that every edge has evidence of its type. The snapshot becomes `ready` (or `partial` when discovery reports truncation).
6. **Completion.** The execution completes through the normal path; `Finalize` takes a short path for `codegraph` (no auto-resolve, end-of-life, policies or gate). `Reconcile` fills the commit and fails snapshots whose execution ended without a graph (`PTH-DISC-1003`).
7. **Rediscovery.** After every successful repository branch scan, `OnScanFinished` queues a rebuild when the flag is on, `auto_rebuild` is on, the repository belongs to an application, a graph worker is online, no build is queued or running, the newest snapshot is older than `min_interval_minutes` and the scanned commit differs from the newest ready snapshot's.
8. **Read.** Views, inspector, paths and diffs run on the cached skeleton; responses read attributes and evidence for their nodes and edges.

### The 15 views

Each view is a named filter (node types, edge types) with optional **lifting** (an edge whose end is not shown attaches to the nearest shown containment ancestor: module-level dependencies from function calls), **pruning** (dropping nodes of some types that no shown edge touches), a **seed** set (internet exposure: within three hops of the `internet` and `http-ingress` boundaries), a **findings** filter (nodes with open findings and their ancestors) or a **change** filter (nodes changed since a base snapshot and their neighbours). Definitions: `Views` in `backend/internal/codegraph/views.go`, served by `GET /api/v1/codegraph/views`.

### Aggregation and lazy expansion

A view returns at most `limit` units (nodes plus aggregates; default 500, at most 2,000). Over the limit, the server groups nodes by directory, deepest level first, collapsing the largest groups until the result fits, so as many real nodes as possible stay visible; if collapsing every group of a level is not enough, it goes one directory level up. Edges between units are merged with a count, the strongest evidence type and sample evidence references. `focus=<node id>` adds the node's children and neighbours up to `depth`; `focus=agg:<group>` returns the group's members one directory level deeper with their direct neighbours.

### Paths and diffs

Path tracing is a breadth-first search on the skeleton, out or in, up to 8 hops and a 200,000-node visit budget, keeping every shortest-path predecessor; up to 50 paths are enumerated over that DAG. Diffs compare stable node keys (type and qualified name, never a line) and edge keys (`source|type|target`).

## Dependencies

| Dependency | Licence | Use |
|---|---|---|
| PostgreSQL 18 (existing) | PostgreSQL | Store |
| Discovery engine dependencies | see [Discovery engines](#discovery-engines) | `worker-graph` image only; the API adds no dependency |

## APIs

All under `/api/v1/codegraph`, behind the `codegraph` flag: `GET views`; `GET`/`PUT settings`; `POST applications/{id}/build`; `GET applications/{id}/snapshots`; `GET applications/{id}/snapshots/{sid}`; `GET …/graph`; `GET …/nodes/{nid}`; `GET …/paths`; `GET …/export?format=json`; `GET applications/{id}/diff?from=&to=`. Details: [API reference](../api-reference/codegraph.md).

### Engine ↔ UI contract

- Node: `{id, key, type, label, layer, parent, group, attrs{language, framework, file, line, end_line, technology, exposure, …}, finding_counts{severity: n}}` — `key`, `parent` and `group` are additions to the agreed contract.
- Edge: `{id, source, target, type, evidence, count, evidence_refs:[{kind, ref, detail}]}` — `count` is an addition (lifted and aggregated edges); `kind` adds `registry` (ownership from the PATHOS inventory) to `file_line|sbom|scan|runtime|ai_record`.
- Graph response: `{nodes, edges, aggregated:[{id, label, count, child_types, finding_counts}], truncated}` plus `snapshot_id`, `view`, `focus`, `depth`, `limit`, `base_snapshot_id`.
- Changes against the contract in the M4 brief: `nodes/{nid}`, `paths`, `export` and `graph` are under `snapshots/{sid}`; export needs `findings.export`; the extra endpoints `views` and `settings`.

### Discovery document (`pathos.codegraph/v1`)

`{schema, generator, engines{engine: version}, stats{files_scanned, duration_ms, languages, skipped[], truncated, node_count, edge_count}, nodes[{key, type, label, parent, layer, attrs}], edges[{source, target, type, evidence: "verified", evidence_refs[]}]}`. Exactly one `repository` node (key `repository`); keys are stable across commits.

## Protocols

The worker talks only to the internal worker API (lease, heartbeat, results, complete), unchanged. Discovery processes run without proxy settings (`network: none`); the worker-graph container is on the `scan` (egress proxy, used only by the clone) and `worker-api` networks like every family worker.

## Authentication

Users: session or API token, then `findings.read` on the snapshot's repository (resolved through `authz` like findings), `findings.export` for export, `scans.run` for builds, `settings.manage` for settings. Snapshot lists are filtered to the caller's repository scope. Workers: their worker token.

## Security requirements

- Discovery never builds or runs repository code; it parses files with limits (file size, file count, node and edge caps) and runs every engine as a separate process without proxy settings.
- Secret references carry names and locations, never values; a credential-looking literal is recorded as "literal value present (not stored)".
- Rule 5: every stored edge has at least one evidence row of its type (deferred constraint trigger; integration test); discovery cannot produce `observed` or `ai_inferred` edges.
- Tenant isolation: `organization_id` on every table, composite foreign keys, row-level security from `pathos_apply_app_grants()`; the skeleton cache is used only after the snapshot passed the organization and repository checks; the isolation suite probes every CodeGraph route.
- Feature flag `codegraph`, off by default.

## Error handling

| Code | Raised |
|---|---|
| `PTH-DISC-1001` | Build with no graph worker online (`409`) |
| `PTH-DISC-1002` | The tool failed, timed out or was skipped (snapshot failed) |
| `PTH-DISC-1003` | The execution ended without a graph (snapshot failed) |
| `PTH-DISC-1004` | The document failed validation (snapshot failed) |
| `PTH-DISC-1005` | No repository to build (`422`) |
| `PTH-DISC-1006` | The repository cannot be scanned (`409`) |
| `PTH-DISC-1007` | Discovery truncated (snapshot partial) |
| `PTH-GRAPH-1001` | Snapshot not ready (`409`) |
| `PTH-GRAPH-1002` | The graph could not be stored (snapshot failed) |
| `PTH-GRAPH-1003` | Invalid graph query (`400`) |
| `PTH-GRAPH-1004` | Diff of different repositories (`422`) |
| `PTH-GRAPH-1005` | Snapshot archived (`409`) |

Generated pages: [disc](../troubleshooting/disc.md), [graph](../troubleshooting/graph.md).

## Operations

- Start the worker: `COMPOSE_PROFILES=graph docker compose up -d worker-graph` (one or more replicas; memory `PATHOS_WORKER_MEMORY`, default 4 GB).
- Settings per organization (`PUT /api/v1/codegraph/settings`): `auto_rebuild` (true), `min_interval_minutes` (60), `keep_snapshots` (10).
- Retention: the jobs runner archives snapshots beyond `keep_snapshots` every 6 hours (object storage: `graphs/<org>/<snapshot>.json.gz`; otherwise summary only) and settles builds that ended without a graph.
- The API's skeleton cache holds at most 1.5 million nodes plus edges (least recently used snapshots are dropped).

### Measurements

Measured on 2026-11-20 on the development host (20 cores, 30 GB RAM, of which about 10 GB free; PostgreSQL 18.7 in a container).

**Discovery on the PATHOS repository** (worker-graph image, `--network none --memory 4g --read-only --cap-drop ALL`, three runs): 9.1–9.3 s wall time, peak memory 872–1,003 MiB (Opengrep and Syft included), exit 0. 1,074 files (Go 725, TSX 217, TS 81, Python 26, Java 10, JS 9, C# 3, Ruby 2, PHP 1), not truncated; output 11.4 MB JSON (748 KB gzip).

| | Total | By type |
|---|---|---|
| Nodes | 10,750 | function 6,043 · component 1,362 · class 1,323 · file 1,109 · route 458 · module 183 · api_operation 138 · container 58 · secret_ref 36 · iac_resource 19 · datastore 7 · queue 7 · external_service 3 · trust_boundary 3 · repository 1 |
| Edges | 27,173 | calls 12,923 · defines 8,037 · imports 2,448 · depends_on 2,279 · reads 529 · crosses_boundary 467 · writes 302 · exposes 138 · deployed_as 41 · publishes 6 · consumes 3 |
| Evidence | 33,163 refs | file_line 30,910 · sbom 2,253; every edge verified; none without evidence (also checked after storing) |

**Store and API** (integration tests through the worker API and the HTTP handlers, the suite's PostgreSQL with row-level security on):

| Measurement | Result |
|---|---|
| Ingest of the PATHOS graph (validate, enrich, insert 10,750 nodes, 27,173 edges, 33,163 evidence rows, commit-time evidence checks) | 21.4 s |
| Ingest of a synthetic graph (test data: 20,000 functions in 200 directories, 40,000 calls) | 5.9–6.4 s |
| 2,000-node view, synthetic graph (`call_graph`, `limit=2000`: 1,800 nodes + 182 aggregates, 4,003 edges, 1.5 MB) | cold (skeleton load) 93–147 ms; warm median 30–64 ms, p95 44–80 ms (10 runs) |
| PATHOS graph, `limit=2000`, warm median (first request) | architecture 22 ms (54 ms), 260 units · call_graph 45 ms (52 ms), 1,963 units · api 16 ms (16 ms), 1,028 units · dependencies 33 ms (58 ms), 1,546 units · internet_exposure 58 ms (61 ms), 1,893 units |
| Path search out of a route, 8 hops, 50 paths | 3–4 ms |

ADR-004's revisit trigger (path search above 2 s p95 at 8 hops) is not reached; ADR-005's 2 s budget is for the browser render and is measured by the UI milestone.

## Implementation status

Built in M4 (engine): everything in [Scope](#scope). Proposed elsewhere and not built: `codegraph_group_edges` (precomputed aggregate edges; measurement showed query-time aggregation on the skeleton is fast enough), `codegraph_diffs` (diffs are computed on request), saved graph views (`graph-views`, UI milestone), `ai_evidence_records` (first AI producer).

## Known limitations

- One snapshot covers one repository; an application with several repositories has several graphs.
- Calls are resolved by name within the repository (same file, module or imported symbol); dynamic dispatch, reflection, dependency injection and calls into libraries are not edges.
- Routes come from the rules' framework patterns; custom routers and configuration-driven routes are missed.
- Runtime edges exist only for workloads whose running image is linked to the repository (digest, tag or OCI source label).
- `finding_counts` are counted when the snapshot is stored; the inspector lists current findings.
- Path search budgets: 8 hops, 200,000 visited nodes, 50 paths.
- Discovery gaps: Spring path prefixes only from a class-level `@RequestMapping`; Rails `resources` routes are not expanded; calls through an interface resolve to the interface method, not its implementations.
- Ingest of a large graph runs inside the worker's result upload (21 s for the PATHOS graph).

## Future improvements

- Data-flow edges (Joern or language-specific taint engines) for large-memory workers.
- AI-inferred edges with evidence records (dynamic dispatch, configuration-driven routing), labelled `ai_inferred`.
- Cross-repository application graphs (service-to-service calls through declared APIs).
- Precomputed layouts per snapshot and level for the UI.

## Decisions

- **Graph store: PostgreSQL** (ADR-004, as proposed). Query-time aggregation and lifting over a cached in-memory skeleton instead of the proposed precomputed `codegraph_group_edges`: views answer in tens of milliseconds on the measured graphs, and any view, filter or focus aggregates the same way.
- **Build jobs are scan executions** (trigger `codegraph`, archived system profile) rather than a new queue: they reuse lease routing to the family worker, clone credentials, uploaded-source snapshots, heartbeats, cancellation, timeouts and the executions log.
- **Snapshots per repository** under an application (the brief's "per application per commit"): a repository belongs to one application, so an application's graphs are its repositories' snapshots.
- **Static evidence only in discovery**; `observed` edges come from the runtime context at ingest; no `ai_inferred` edges in M4.
- **Joern: not included in M4.** Discovery without it runs in under 1 GiB and about 9 s on PATHOS inside the 4 GB worker. Joern needs a JVM with a heap of about 3 GB (ADR-006), which leaves no headroom next to Opengrep, and would add a large JVM layer and its vulnerability surface to the image (the Joern image itself was not measured). The static read, write, publish and consume rules cover the contract's data-flow edges. Revisit in M5 as an opt-in tier-2 engine with `JAVA_OPTS` heap limits and a repository size limit.
- **Terraform without HCL** (MPL-2.0): a brace-aware line scanner reads resources.
- **Network: none** follows the existing manifest convention (no proxy settings for the tool; the worker's networks reach only the egress proxy and the worker API). The sandbox runner (`network_mode: none` container) is not used, because discovery runs no repository code.

## Discovery engines

| Engine | Version | Licence | Gives | Evidence |
|---|---|---|---|---|
| Go `go/parser` (toolchain) | go1.27.4 | BSD-3-Clause | Go packages, files, types, functions, methods, imports, calls | file_line |
| tree-sitter (`github.com/tree-sitter/go-tree-sitter`) | 0.25.0 | MIT | Parser runtime (cgo) | — |
| Grammars: Java 0.23.5, Python 0.25.0, JavaScript 0.25.0, TypeScript/TSX 0.23.2, C# 0.24.0, PHP 0.25.2, Ruby 0.23.1 | as listed | MIT | Classes, functions, imports, calls | file_line |
| go-enry | 2.9.6 | Apache-2.0 | Languages, vendored and generated files | — |
| kin-openapi | 0.153.0 | MIT | OpenAPI and Swagger operations | file_line |
| Opengrep (worker-core) with `workers/graph/rules` | 2.0.0 | LGPL-2.1 (engine), PATHOS rules | Routes, database/ORM access, queues, outbound HTTP | file_line |
| Syft (worker-core) | worker-core version | Apache-2.0 | SBOM components and dependencies | sbom |
| Dockerfile, Compose, Kubernetes, Terraform readers (PATHOS) | — | Apache-2.0 | Containers, IaC resources, exposure, secret references | file_line |

Each run records the versions in `codegraph_snapshots.engines`. Image `pathos-worker-graph`: 1.82 GB (about 50 MB over worker-core's 1.77 GB). Trivy gate (2026-11-20): 0 fixable of 119 HIGH/CRITICAL findings, the same 119 unfixed Debian 13.7 packages as worker-core. Discovery limits: 50,000 files, 1 MiB per file, 300,000 nodes, 300,000 edges; skipped directories include `.git`, `node_modules`, `vendor`, `third_party`, `dist`, `build`, `target`, `.venv`. Test and fixture files carry `attrs.role = "test"`.
