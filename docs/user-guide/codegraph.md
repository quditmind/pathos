---
title: CodeGraph
section: user-guide
group: discover, inventory
order: 16
version: "3.0"
updated: 2026-11-20
summary: The CodeGraph of an application — code, APIs, data stores, deployment and dependencies as one graph with evidence on every edge — its 15 views, filters, layers, inspector, path tracing, snapshots, compare and export.
---
# CodeGraph

The **CodeGraph** shows an application as one graph: its repositories, modules, files, functions and classes; its routes and API operations; the data stores, queues and external services it uses; the containers and infrastructure it is deployed as; the third-party components from its SBOM; and the trust boundaries around them. Every edge says **how PATHOS knows it**.

The CodeGraph is behind the feature flag `codegraph` (off by default). An administrator turns it on under **Administration › Feature flags**. Until then the sidebar items **CodeGraph** and **API & endpoints** show "arrives in roadmap phase 4".

Open it from **3 · Discover › CodeGraph** and choose an application, or go to `/codegraph/<application id>`. The same screen is the **CodeGraph** tab of the application profile.

## Building the graph

The graph is built per application by the graph worker from the application's repositories. The first time, select **Build CodeGraph**; afterwards **Rebuild** builds a new snapshot of the current commit. A build also runs after scans. While a build is queued or running the page says so and refreshes on its own.

The header shows the branch and commit the snapshot was built from, when it was built, and how many nodes and edges it has. A **partial** build means some discovery engines did not finish; the graph shows what the others found.

## Evidence on every edge

Each edge carries an evidence label (and at least one evidence reference you can open in the inspector):

| Line | Evidence | Meaning |
|---|---|---|
| Solid green | **Verified** | Static: found in the code, the SBOM or a scan (file and line, SBOM reference or scan). |
| Dashed blue | **Observed** | Dynamic: seen at runtime (for example a running workload). |
| Dotted purple | **AI-inferred** | Proposed by the AI from an evidence record. It needs confirmation and is never shown as verified. |

**Trust boundaries** are dashed red containers around the nodes they hold. The legend under the graph repeats these styles.

## Views

The view switcher has 15 views. Each asks the server for the part of the graph it needs:

| View | Shows |
|---|---|
| Architecture | Services, modules, data stores and external services, and how they connect |
| Call graph | Functions and the calls between them |
| Data flow | Where data is read, written, published and consumed |
| API & endpoints | Routes and API operations, their handlers and exposure |
| Dependencies | Imports between modules and the third-party components they use |
| Deployment | Containers and infrastructure resources |
| Ownership | Applications, repositories and owners (the [context graph](posture.md#context-graph) as a layer) |
| Trust boundaries | Trust boundaries and the edges that cross them |
| Internet exposure | Internet-exposed entry points and what they reach |
| Findings overlay | Nodes with open findings and their severity |
| SBOM | Components from the SBOM and the code that depends on them |
| Data stores | Databases, caches and queues and the code that uses them |
| External services | Third-party services the application calls |
| Secrets & configuration | Where secrets and configuration are referenced. Secret **values** are never stored or shown |
| Change impact | What changed between two snapshots (see [Snapshots and compare](#snapshots-and-compare)) |

Large views are **aggregated by the server**: a group node (double border) stands for many nodes, with their count and types. Select **Expand** on it (or focus it and press Enter) to load its contents; **Back to the full view** returns.

## Search, filters and layers

- **Search** highlights matching nodes by name, file or technology; press Enter for the next match and Shift+Enter for the previous one.
- **Filters**: node type, technology, security status (has open findings, minimum severity, internet-exposed) and evidence type. The button shows how many filters are active; **Clear filters** resets them.
- **Layers** switch whole layers on and off: Code, API, Data, Deployment, Dependencies, Ownership.

A line under the toolbar says how many nodes the filters and layers hide.

## Node inspector

Select a node to open the inspector on the right: its type and layer, attributes, the file and line it is defined at, open findings by severity (with links to the findings), source links, and every incoming and outgoing edge with its evidence label and references (file and line, SBOM reference, scan, runtime fact or AI evidence record). Secret references show where a secret is used, never its value.

## Path tracing

In the inspector, **Trace in** highlights everything that leads to the node and **Trace out** everything the node reaches; the rest of the graph is dimmed. The banner above the graph names the trace and its size; Escape or the × clears it. Paths are computed on the server over the whole snapshot (up to eight hops).

## Snapshots and compare

Every build is a saved **snapshot**. Choose another snapshot in the **Snapshot** list to see an older graph. Choose a snapshot in **Compare with…** to see the differences: added elements in green, removed ones in red (dashed), changed ones in amber, with counts in the legend. The **Change impact** view compares with the previous snapshot unless you choose one.

## Export

**Export** offers a PNG or SVG image of the whole graph (drawn in your browser) and the snapshot as JSON (from the server, stamped with the PATHOS version). File names carry the PATHOS version and the time.

## Keyboard and accessibility

- Tab moves into the graph; the arrow keys move to the nearest node in that direction; Enter inspects a node (or expands a group); Escape clears the trace or the selection.
- Every node and edge has an accessible name (for example "exampleCharge() calls Example PSP, evidence Observed").
- **List** shows the same nodes and relationships as tables, with the same filters, for screen readers and for copying.
- With *reduce motion* set in your system, zooming and centring do not animate.

## API and endpoints

**3 · Discover › API & endpoints** opens the CodeGraph in the **API & endpoints** view for an application: routes and API operations found in the code, the handlers behind them, and which are reachable from the internet. Filter by **Internet-exposed** or **Has open findings** to see the riskiest entry points first.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| "CodeGraph is not enabled" | The `codegraph` feature flag is off for the organization | An administrator with `settings.manage` turns it on under Administration › Feature flags |
| "No CodeGraph yet" | No build has run for the application | Select **Build CodeGraph**. The application needs at least one repository |
| The build stays queued | No graph worker is online | Check **Configurations › Scanners & workers**; start a worker of the graph family |
| "The last CodeGraph build failed" with a code | A discovery engine failed (the code says which step) | Open the code in the Troubleshooting centre, fix the cause and select **Rebuild** |
| "Nothing in the … view" | The snapshot has no elements of that kind (for example no deployment files) | Try another view, or add the repositories that hold them and rebuild |
| Group nodes instead of single nodes | The view is larger than the server's limit | Expand a group, narrow the view or use filters |
| "The server truncated this view" | The view hit the server's node limit | Expand groups or choose a narrower view |
| "Nothing to compare yet" in Change impact | Only one finished snapshot exists | Rebuild after the next commit, then compare |
| Export fails | The browser blocked the download or the graph is empty | Allow downloads for PATHOS; for very large graphs export JSON instead of an image |
| An edge is dotted purple | It is AI-inferred and needs confirmation | Open it in the inspector to see the AI evidence record; it turns green only with static or runtime evidence |
