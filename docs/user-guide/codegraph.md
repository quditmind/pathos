---
title: CodeGraph
section: user-guide
group: discover
order: 30
version: "3.0"
updated: 2026-11-20
summary: Discover how an application is built — modules, functions, calls, routes, APIs, data stores, queues, external services, containers, infrastructure and dependencies — as a graph in which every connection shows its evidence.
---
# CodeGraph

CodeGraph turns an application's repositories into a graph: what the code contains (modules, files, classes, functions), how it is connected (calls and imports), what it exposes (routes and API operations), what it touches (databases, queues, secrets, external services), how it is deployed (containers, Kubernetes and Terraform resources) and what it depends on (SBOM components). The graph is the base for threat modelling and for seeing which code a finding sits in and what can reach it.

CodeGraph is a new module. An administrator turns it on with the **codegraph** feature flag (Administration → Feature flags); until then its pages and API answer "feature disabled" (`PTH-PLAT-1007`).

## Every connection has evidence

Each edge in the graph says how PATHOS knows it:

| Label | Meaning | Example evidence |
|---|---|---|
| **Verified** | Found statically in the source, the SBOM or the PATHOS inventory | `api/orders.go:42` (the call site), `pkg:npm/express@4.21.2` (the SBOM), the application record |
| **Observed** | Seen at runtime | A Kubernetes workload running an image built from the repository |
| **AI-inferred** | Proposed by an AI model, with its evidence record | Not produced by discovery: CodeGraph discovery uses static evidence only |

An edge without evidence cannot be stored. When discovery cannot prove a connection (dynamic dispatch, a URL built at run time), the connection is left out rather than guessed.

## Building a graph

A graph is built per repository and commit, as a **snapshot**. Open the application, then CodeGraph, and choose **Build** (or call [`POST /api/v1/codegraph/applications/{id}/build`](../api-reference/codegraph.md#build)). Every active repository of the application is built, or the one you choose.

The build runs on a **graph worker** (`worker-graph`), like a scan: it clones the repository and reads the source. It never builds or runs repository code and has no network access during discovery. The build appears under Scans as an execution named "CodeGraph discovery" (trigger `codegraph`), with its log.

Snapshot states: **queued**, **building**, **ready**, **partial** (the repository was larger than the discovery limits; the snapshot lists what was skipped) and **failed** (with an error code, see Troubleshooting). Older snapshots become **archived** (see Retention).

### What discovery finds

| Area | How |
|---|---|
| Modules, files, classes, functions, calls and imports | Go: the Go parser. Java, Python, JavaScript/TypeScript, C#, PHP and Ruby: tree-sitter grammars. Calls are kept only when the called function is found in the repository |
| Routes | PATHOS rules for net/http, chi, gin, Spring, Flask, Django, FastAPI, Express, NestJS, ASP.NET, Laravel and Rails |
| API operations | OpenAPI and Swagger files, matched to the routes that implement them |
| Data stores, queues, external services | Database, ORM and queue access rules in code (an edge only where a code site exists), and service definitions in Compose files and configuration |
| Containers and infrastructure | Dockerfiles, Docker Compose, Kubernetes manifests, Terraform |
| Secrets and configuration | References to credentials (environment variable names, Kubernetes secret references, Terraform secret resources) — names and locations only, never values |
| Components | The SBOM of the repository (Syft) |
| Languages | Language detection per file |
| Ownership | The application that owns the repository (from the inventory). The full ownership picture (business unit, owners, teams) stays in the [context graph](posture.md) |
| Runtime | Workloads in connected Kubernetes clusters that run an image linked to the repository, and whether they are internet-exposed ([Runtime context](runtime.md)) |
| Findings | Open findings of the repository, attached to the function, class or file that contains them |

### Rediscovery after new commits

With **automatic rediscovery** on (the default), each successful scan of a repository's branch — after a push, a schedule or a manual scan — rebuilds its graph when:

- the repository belongs to an application, the flag is on and a graph worker is online;
- no build of the repository is queued or running;
- the newest snapshot is older than the **minimum interval** (default 60 minutes);
- the scanned commit differs from the newest ready snapshot's commit.

Administrators change these settings (and retention) with [`PUT /api/v1/codegraph/settings`](../api-reference/codegraph.md#settings).

## Views

Each snapshot can be read in 15 views. The graph component offers zoom, pan, search, filters by type, technology and security, layer toggles, expand and collapse, the node inspector, path tracing and PNG, SVG or JSON export.

| View | Shows |
|---|---|
| Architecture | Modules, containers, data stores, queues, external services; calls and imports between modules |
| Call graph | Functions and calls |
| Data flow | Routes, handlers, data stores, queues, secrets, external services |
| API | Routes, API operations, handlers, the boundaries they cross |
| Dependencies | Modules and the modules and components they import or depend on |
| Deployment | Containers, infrastructure resources, what they are built from and expose |
| Ownership | Application and repository |
| Trust boundaries | Boundaries and what crosses them |
| Internet exposure | Everything within three hops of the internet and HTTP ingress |
| Findings overlay | Units with open findings, in context |
| SBOM | Components and their dependency tree |
| Data stores | Databases and caches and the code that uses them |
| External services | Third-party services and queues |
| Secrets and configuration | Secret references (never values) |
| Change impact | What changed since an earlier snapshot, with direct neighbours |

**Large graphs.** A view returns at most 2,000 nodes (500 by default). When there are more, PATHOS groups nodes by directory and shows each group as one node with its size; expand a group to see the level below. Edges between groups show how many connections they stand for.

**Path tracing.** From any node, trace outgoing paths (what it reaches) or incoming paths (what reaches it), up to eight hops. A search that hits its limits says so.

**Compare.** Pick two snapshots of the same repository to see added, removed and changed nodes and edges.

## Retention

PATHOS keeps the 10 newest snapshots of each repository (setting `keep_snapshots`). The jobs service archives older ones: with object storage configured, the snapshot's JSON export is kept there and can still be downloaded; without it, only the snapshot's summary remains. Failed snapshots beyond the limit are deleted.

## Permissions

Viewing a graph needs **findings.read** on the repository; exporting needs **findings.export** too; building needs **scans.run**; changing settings needs **settings.manage**.

## Troubleshooting

| Code | What you see | What to do |
|---|---|---|
| [PTH-DISC-1001](../troubleshooting/disc.md#PTH-DISC-1001) | Build refused: no CodeGraph worker is online | Start the graph worker (`COMPOSE_PROFILES=graph docker compose up -d worker-graph`) and check Configurations → Scanners & workers |
| [PTH-DISC-1002](../troubleshooting/disc.md#PTH-DISC-1002) | Snapshot failed: the discovery tool did not succeed | Open the execution's log; if the tool was skipped, start the graph worker; if it ran out of memory or time, raise the worker limits |
| [PTH-DISC-1003](../troubleshooting/disc.md#PTH-DISC-1003) | Snapshot failed: the execution ended without a graph | Open the execution: clone errors, cancellation or worker restarts |
| [PTH-DISC-1004](../troubleshooting/disc.md#PTH-DISC-1004) | Snapshot failed: the discovery output was refused | Run worker images of the same PATHOS version as the server |
| [PTH-DISC-1005](../troubleshooting/disc.md#PTH-DISC-1005) | Build refused: no repository to build | Assign repositories to the application |
| [PTH-DISC-1006](../troubleshooting/disc.md#PTH-DISC-1006) | Build refused: the repository cannot be built | Enable scanning, set a branch, or upload a snapshot |
| [PTH-DISC-1007](../troubleshooting/disc.md#PTH-DISC-1007) | Snapshot partial | The repository exceeded the discovery limits; see the skipped list |
| [PTH-GRAPH-1001](../troubleshooting/graph.md#PTH-GRAPH-1001) | Snapshot not ready | Wait for the build, or open a ready snapshot |
| [PTH-GRAPH-1002](../troubleshooting/graph.md#PTH-GRAPH-1002) | Snapshot failed: the graph could not be stored | Build again; report the request ID if it repeats |
| [PTH-GRAPH-1003](../troubleshooting/graph.md#PTH-GRAPH-1003) | Invalid graph query | Correct the view, filter or limit |
| [PTH-GRAPH-1004](../troubleshooting/graph.md#PTH-GRAPH-1004) | Cannot compare | Compare two snapshots of the same repository |
| [PTH-GRAPH-1005](../troubleshooting/graph.md#PTH-GRAPH-1005) | Snapshot archived | Download its export, or keep more snapshots |
| PTH-PLAT-1007 | CodeGraph not available | Ask an administrator to turn on the codegraph feature flag |
