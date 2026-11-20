---
title: CodeGraph
section: user-guide
group: discover, inventory
order: 16
version: "3.0"
updated: 2026-11-20
summary: The CodeGraph of an application — modules, functions, calls, routes, APIs, data stores, queues, external services, containers, infrastructure and dependencies as one graph with evidence on every edge — how it is built, its 15 views, filters, layers, inspector, path tracing, snapshots, compare and export.
---
# CodeGraph

The **CodeGraph** shows an application as one graph: what its repositories contain (modules, files, classes, functions), how they are connected (calls and imports), what they expose (routes and API operations), what they touch (data stores, queues, secrets, external services), how they are deployed (containers, Kubernetes and Terraform resources), what they depend on (SBOM components) and the trust boundaries around them. Every edge says **how PATHOS knows it**. The graph is the base for threat modelling and for seeing which code a finding sits in and what can reach it.

The CodeGraph is behind the feature flag `codegraph` (off by default). An administrator turns it on under **Administration › Feature flags**. Until then the sidebar items **CodeGraph** and **API & endpoints** are shown disabled with an **Off** badge ("not enabled"), the application profile's CodeGraph tab says the module is not enabled, and the API answers "feature disabled" (`PTH-PLAT-1007`).

Open it from **3 · Discover › CodeGraph** and choose an application, or go to `/codegraph/<application id>`. The same screen is the **CodeGraph** tab of the application profile.

## Every connection has evidence

Each edge carries an evidence label and at least one evidence reference you can open in the inspector:

| Line | Evidence | Meaning | Example evidence |
|---|---|---|---|
| Solid green | **Verified** | Found statically in the source, the SBOM, a scan or the PATHOS inventory | `api/orders.go:42` (the call site), `pkg:npm/express@4.21.2` (the SBOM), the application record (registry) |
| Dashed blue | **Observed** | Seen at runtime | A Kubernetes workload running an image built from the repository |
| Dotted purple | **AI-inferred** | Proposed by an AI model from an evidence record. It needs confirmation and is never shown as verified | Not produced by discovery: CodeGraph discovery uses static evidence only |

An edge without evidence cannot be stored. When discovery cannot prove a connection (dynamic dispatch, a URL built at run time), the connection is left out rather than guessed.

**Trust boundaries** are dashed red containers around the nodes they hold. The legend under the graph repeats these styles.

## Building a graph

A graph is built per repository and commit, as a **snapshot**. The first time, select **Build CodeGraph**; afterwards **Rebuild** builds a new snapshot of the current commit (or call [`POST /api/v1/codegraph/applications/{id}/build`](../api-reference/codegraph.md#build)). Every active repository of the application is built, or the one you choose. Building needs the **scans.run** permission; without it the buttons are not shown.

The build runs on a **graph worker** (`worker-graph`), like a scan: it clones the repository and reads the source. It never builds or runs repository code and has no network access during discovery. The build appears under Scans as an execution named "CodeGraph discovery" (trigger `codegraph`), with its log. While a build is queued or running the page says so and refreshes on its own.

The header shows the branch and commit the snapshot was built from, when it was built, and how many nodes and edges it has.

Snapshot states: **queued**, **building**, **ready**, **partial** (the repository was larger than the discovery limits; the snapshot lists what was skipped and the graph shows what was found) and **failed** (with an error code, see [Troubleshooting](#troubleshooting)). Older snapshots become **archived** (see [Retention](#retention)).

### What discovery finds

| Area | How |
|---|---|
| Modules, files, classes, functions, calls and imports | Go: the Go parser. Java, Python, JavaScript/TypeScript, C#, PHP and Ruby: tree-sitter grammars. Calls are kept only when the called function is found in the repository |
| Routes | PATHOS rules for net/http, chi, gin, Spring, Flask, Django, FastAPI, Express, NestJS, ASP.NET, Laravel and Rails |
| API operations | OpenAPI and Swagger files, matched to the routes that implement them |
| Data stores, queues, external services | Database, ORM and queue access rules in code (an edge only where a code site exists), and service definitions in Compose files and configuration |
| Containers and infrastructure | Dockerfiles, Docker Compose, Kubernetes manifests, Terraform |
| Secrets and configuration | References to credentials (environment variable names, Kubernetes secret references, Terraform secret resources) — names and locations only, never values |
| Components | The SBOM of the repository |
| Languages | Language detection per file |
| Ownership | The application that owns the repository (from the inventory). The full ownership picture (business unit, owners, teams) stays in the [context graph](posture.md#context-graph) |
| Runtime | Workloads in connected Kubernetes clusters that run an image linked to the repository, and whether they are internet-exposed ([Runtime context](runtime.md)) |
| Findings | Open findings of the repository, attached to the function, class or file that contains them |

### Rediscovery after new commits

With **automatic rediscovery** on (the default), each successful scan of a repository's branch — after a push, a schedule or a manual scan — rebuilds its graph when:

- the repository belongs to an application, the flag is on and a graph worker is online;
- no build of the repository is queued or running;
- the newest snapshot is older than the **minimum interval** (default 60 minutes);
- the scanned commit differs from the newest ready snapshot's commit.

Administrators (`settings.manage`) change these settings and retention under **CodeGraph settings** at the bottom of **3 · Discover › CodeGraph**, or with [`PUT /api/v1/codegraph/settings`](../api-reference/codegraph.md#settings).

## Views

The view switcher has 15 views. Each asks the server for the part of the graph it needs:

| View | Shows |
|---|---|
| Architecture | Modules, containers, data stores, queues and external services, and the calls and imports between modules |
| Call graph | Functions and the calls between them |
| Data flow | Routes, handlers, data stores, queues, secrets and external services: where data is read, written, published and consumed |
| API & endpoints | Routes and API operations, their handlers, exposure and the boundaries they cross |
| Dependencies | Imports between modules and the third-party components they use |
| Deployment | Containers and infrastructure resources, what they are built from and what they expose |
| Ownership | Application and repositories (the [context graph](posture.md#context-graph) as a layer) |
| Trust boundaries | Trust boundaries and the edges that cross them |
| Internet exposure | Everything within three hops of the internet and HTTP ingress |
| Findings overlay | Nodes with open findings and their severity, in context |
| SBOM | Components from the SBOM and their dependency tree |
| Data stores | Databases, caches and queues and the code that uses them |
| External services | Third-party services and queues the application calls |
| Secrets & configuration | Where secrets and configuration are referenced. Secret **values** are never stored or shown |
| Change impact | What changed since an earlier snapshot, with direct neighbours (see [Snapshots and compare](#snapshots-and-compare)) |

**Large graphs.** A view returns at most 2,000 nodes (500 by default). When there are more, the server groups nodes by directory: a group node (double border) stands for many nodes, with their count, types and open findings. Edges between groups show how many connections they stand for. Select **Expand** on a group (or focus it and press Enter) to load the level below; **Back to the full view** returns. When the view still hits the limit, the page says the server truncated it.

## Search, filters and layers

- **Search** highlights matching nodes by name, file or technology; press Enter for the next match and Shift+Enter for the previous one.
- **Filters**: node type, technology, security status (has open findings, minimum severity, internet-exposed) and evidence type. The button shows how many filters are active; **Clear filters** resets them.
- **Layers** switch whole layers on and off: Code, API, Data, Deployment, Dependencies, Ownership.

A line under the toolbar says how many nodes the filters and layers hide.

## Node inspector

Select a node to open the inspector on the right: its type and layer, attributes, the file and line it is defined at, open findings by severity (with links to the findings), source links, and every incoming and outgoing edge with its evidence label and references (file and line, SBOM reference, scan, inventory record, runtime fact or AI evidence record). Secret references show where a secret is used, never its value.

## Path tracing

In the inspector, **Trace in** highlights everything that leads to the node and **Trace out** everything the node reaches; the rest of the graph is dimmed. The banner above the graph names the trace and its size; Escape or the × clears it. Paths are computed on the server over the whole snapshot, up to eight hops; a trace that hits its limits says so.

## Snapshots and compare

Every build is a saved **snapshot**. Choose another snapshot in the **Snapshot** list to see an older graph. Choose a snapshot of the same repository in **Compare with…** to see the differences: added elements in green, removed ones in red (dashed), changed ones in amber, with counts in the legend. The **Change impact** view compares with the previous snapshot unless you choose one.

## Export

**Export** offers a PNG or SVG image of the whole graph (drawn in your browser) and the snapshot as JSON (from the server, stamped with the PATHOS version). File names carry the PATHOS version and the time. JSON export needs the **findings.export** permission.

## Keyboard and accessibility

- Tab moves into the graph; the arrow keys move to the nearest node in that direction; Enter inspects a node (or expands a group); Escape clears the trace or the selection.
- Every node and edge has an accessible name (for example "exampleCharge() calls Example PSP, evidence Observed").
- **List** shows the same nodes and relationships as tables, with the same filters, for screen readers and for copying.
- With *reduce motion* set in your system, zooming and centring do not animate.

## API & endpoints

**3 · Discover › API & endpoints** opens the CodeGraph in the **API & endpoints** view for an application: routes and API operations found in the code (and in OpenAPI files), the handlers behind them, and which are reachable from the internet. Filter by **Internet-exposed** or **Has open findings** to see the riskiest entry points first.

## Retention

PATHOS keeps the 10 newest snapshots of each repository (setting `keep_snapshots`). The jobs service archives older ones: with object storage configured, the snapshot's JSON export is kept there and can still be downloaded; without it, only the snapshot's summary remains. Failed snapshots beyond the limit are deleted.

## Permissions

Viewing a graph needs **findings.read** on the repository; exporting JSON needs **findings.export** too; building and rebuilding need **scans.run**; changing settings needs **settings.manage**.

## Troubleshooting

| Code or symptom | What you see | What to do |
|---|---|---|
| PTH-PLAT-1007 / "CodeGraph is not enabled" | The `codegraph` feature flag is off for the organization | An administrator with `settings.manage` turns it on under Administration › Feature flags |
| "No CodeGraph yet" | No build has run for the application | Select **Build CodeGraph** (needs `scans.run`). The application needs at least one repository |
| No **Build** or **Rebuild** button | You do not have the `scans.run` permission | Ask someone who can run scans to build the graph |
| The build stays queued | No graph worker is online | Check **Configurations › Scanners & workers**; start the graph worker (`COMPOSE_PROFILES=graph docker compose up -d worker-graph`) |
| [PTH-DISC-1001](../troubleshooting/disc.md#PTH-DISC-1001) | Build refused: no CodeGraph worker is online | Start the graph worker and check Configurations › Scanners & workers |
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
| "Nothing in the … view" | The snapshot has no elements of that kind (for example no deployment files) | Try another view, or add the repositories that hold them and rebuild |
| Group nodes instead of single nodes | The view is larger than the server's limit | Expand a group, narrow the view or use filters |
| "The server truncated this view" | The view hit the server's node limit | Expand groups or choose a narrower view |
| "Nothing to compare yet" in Change impact | Only one finished snapshot exists | Rebuild after the next commit, then compare |
| Export fails | The browser blocked the download, the graph is empty, or (JSON) you lack `findings.export` | Allow downloads for PATHOS; for very large graphs export JSON instead of an image |
| An edge is dotted purple | It is AI-inferred and needs confirmation | Open it in the inspector to see the AI evidence record; it turns green only with static or runtime evidence |
