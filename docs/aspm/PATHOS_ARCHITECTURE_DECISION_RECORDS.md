Quditmind PATHOS · applies to v2.2.0 · status: Proposed

# PATHOS architecture decision records: lifecycle release

## Purpose

This file records the architecture decisions for the lifecycle release (the work described in the owner's build prompt, milestones M1 to M11). Each record states the context, the options, the proposed decision, the consequences and the status. All records were written in M0 and none is accepted yet: a record becomes **Accepted** only when the owner approves it at the M0 gate or at the gate of its milestone.

## Scope

In scope: version metadata, diagnostics, feature flags, the graph store and graph UI, discovery engines, threat modelling, AI evidence, reverse-engineering isolation, gates, tool-name display, the help system and release naming. Out of scope: decisions already taken and built before 2.2.0 (they are recorded in [ARCHITECTURE.md](../ARCHITECTURE.md), [MULTI_TENANCY.md](../MULTI_TENANCY.md) and [PATHOS_IMPLEMENTATION_ROADMAP.md](PATHOS_IMPLEMENTATION_ROADMAP.md#3-decisions-needed-from-the-product-owner)).

## Architecture

The lifecycle release extends the existing stack (Go API and jobs, PostgreSQL 18, Redis, hardened worker pools per tool family, React 19 frontend served by Caddy, Keycloak). It adds no new runtime service in M1 to M9. M4 adds a discovery worker family and M10 a reverse-engineering worker family, both following the existing worker contract ([ARCHITECTURE.md §5](../ARCHITECTURE.md)). Records are numbered ADR-001 to ADR-013 below.

| ADR | Title | Milestone | Status |
|---|---|---|---|
| [001](#adr-001-version-and-build-metadata) | Version and build metadata | M1 | Proposed, needs owner approval |
| [002](#adr-002-error-catalogue-and-diagnostic-engine) | Error catalogue and diagnostic engine | M1 | Proposed, needs owner approval |
| [003](#adr-003-feature-flag-framework) | Feature-flag framework | M1 | Proposed, needs owner approval |
| [004](#adr-004-graph-store-postgresql-versus-a-graph-database) | Graph store: PostgreSQL versus a graph database | M4 | Proposed, needs owner approval |
| [005](#adr-005-graph-ui-library-react-flow-with-elk-versus-cytoscape) | Graph UI library | M4 | Proposed, decision after measurement |
| [006](#adr-006-codegraph-discovery-engines) | CodeGraph discovery engines | M4 | Proposed, needs owner approval |
| [007](#adr-007-threat-model-engine-and-framework-mappings) | Threat-model engine and framework mappings | M5 | Proposed, needs owner approval |
| [008](#adr-008-ai-evidence-record-and-reproducibility) | AI evidence record and reproducibility | M4, M7 | Proposed, needs owner approval |
| [009](#adr-009-reverse-engineering-isolation) | Reverse-engineering isolation | M10, M11 | Proposed, needs owner approval |
| [010](#adr-010-gates-never-block-without-a-policy) | Gates never block without a policy | M8 | Proposed, needs owner decision on legacy thresholds |
| [011](#adr-011-hide-tool-names-in-the-ui-keep-them-in-the-api) | Hide tool names in the UI, keep them in the API | M1, M6 | Proposed, needs owner decision on help and exports |
| [012](#adr-012-help-system-offline-content-and-route-to-article-mapping) | Help system | M1 | Proposed, needs owner approval |
| [013](#adr-013-naming-and-versioning-of-the-lifecycle-release) | Naming and versioning of the lifecycle release | all | Open: owner decides |

---

### ADR-001: Version and build metadata

**Context (verified in code).**

- The API binary gets its version from `-ldflags "-X pathos/internal/server.Version=${VERSION}"` (`backend/Dockerfile:10`, `ARG VERSION=dev`). `server.Version` defaults to `dev` (`backend/internal/server/server.go:52`) and is returned by `GET /healthz` (`server.go:105`).
- `pathosctl` is built in the same Dockerfile without any version (`backend/Dockerfile:11`) and has no version command (`backend/cmd/pathosctl/main.go`).
- The worker agent: `-X main.version=${VERSION}` (`workers/core/Dockerfile:17`); it reports the version at registration (`backend/internal/worker/agent.go:178`) into `workers.version` (`00003_scanning.sql:98`).
- The CLI: `-X main.version=${version}` in the release job (`.github/workflows/release.yml:223`); `pathos --version` prints it (`backend/cmd/pathos-cli/main.go:131`).
- Two helper binaries in the SCA family image have a hard-coded version: `-X main.version=1.0.0` for `pathos-depcheck` and `pathos-reach` (`workers/sca/Dockerfile:65`, `:67`). They report 1.0.0 in a 2.2.0 image.
- The release workflow builds `pathos`, `pathos-proxy` and `pathos-worker-core` with `build-args: VERSION=<tag>` (`release.yml:83`), then the eight family images with `VERSION` and `CORE_IMAGE` (`release.yml:166-168`). Images carry OCI labels `version` and `revision=${{ github.sha }}` (`release.yml:87-90`), SBOM and provenance attestations, and cosign signatures.
- Docker Compose passes `VERSION: "${PATHOS_VERSION:-dev}"` for local builds (`docker-compose.yml:128`, `:380`).
- The frontend is built inside `deploy/caddy/Dockerfile` (`npm run build`); `frontend/package.json` holds `"version": "2.2.0"`; `vite.config.ts` has no `define`.

**Options.**

1. Add `Commit` and `BuildDate` beside `Version` in the existing ldflags, fed by new `ARG COMMIT` and `ARG BUILD_DATE` in the same Dockerfiles, and by `build-args` in `release.yml` (`COMMIT=${{ github.sha }}`, `BUILD_DATE` from the tag commit time, which keeps builds reproducible). Local builds default to `COMMIT=unknown` and an empty date.
2. Read build information at run time from Go's `debug.ReadBuildInfo()` (`vcs.revision`, `vcs.time`). It is empty in these builds: the Dockerfiles copy sources without `.git`, and `-trimpath` builds inside Docker have no VCS stamping.
3. A new release tool (goreleaser or similar). Rejected: the prompt says to extend the existing process, and the existing one already signs, attests and publishes.

**Decision (proposed).** Option 1.

- One small package (for example `backend/internal/platform/buildinfo`) holds `Version`, `Commit`, `BuildDate`. `server.Version` stays as a variable for compatibility with the existing ldflags path, or the ldflags path moves and the Dockerfiles change in the same PR; both are acceptable, the first is smaller.
- Apply the same three ldflags to `pathos`, `pathosctl`, `pathos-worker`, `pathos-cli`, `pathos-depcheck` and `pathos-reach`. Remove the hard-coded `1.0.0` in `workers/sca/Dockerfile`.
- Add `pathosctl version`.
- Workers report `commit` with `version` at registration (additive field); `/api/v1/meta` returns worker and pack versions from there.
- Frontend: `define: { __PATHOS_BUNDLE_VERSION__: JSON.stringify(process.env.PATHOS_VERSION ?? pkg.version) }` in `vite.config.ts`, with `ARG VERSION` passed to `deploy/caddy/Dockerfile` (the proxy image already receives `VERSION` in `release.yml:83`, unused today). The shell compares it with `/api/v1/meta.version` and shows the reload banner on mismatch.
- Pre-release: the version string is the tag without `v` (for example `2.3.0-rc.1`); the UI marks any version with a `-` suffix or `dev` as pre-release.

**Consequences.** No new release job. Every image and binary can answer "which commit". Local builds show `dev` and `unknown`, which the UI labels as a development build. The `package.json` version becomes a fallback only; it must still be bumped in release PRs (as today).

**Status.** Proposed, needs owner approval.

---

### ADR-002: Error catalogue and diagnostic engine

**Context.** Errors today are `httpx.Error{Status, Code, Message, Details, Fields}` (`backend/internal/platform/httpx/httpx.go`), with 56 distinct snake_case codes passed to `httpx.E` and `invalid_request` at about 615 call sites. There is no catalogue, no confirmed-versus-probable cause, no generated troubleshooting docs. Some stored records have free-text errors (`repository_import_items.error_code`, `runtime_clusters.last_error`, `scm_connections.status`).

**Options.**

1. A Go catalogue package (`backend/internal/platform/diag`) as the single source of truth; docs generated from it; the API envelope filled from it.
2. A YAML or JSON catalogue file read by Go and the docs generator. Equivalent at run time, but loses compile-time references (`diag.ConnUntrustedCertificate`) and needs a loader test.
3. A database table. Rejected ([database design](PATHOS_DATABASE_DESIGN.md#error-catalogue-m1-code-not-a-table)): it can drift from the binary and is not needed per organization.

**Decision (proposed).** Option 1.

- Entry fields: code `PTH-<AREA>-<NNNN>`, area, category, severity, title, technical description, confirmed-cause text, probable causes (ordered), impact, corrective actions (numbered, each with an optional route), verification steps (and an optional machine check for Verify), docs slug, `ai_help` (bool).
- Areas as in the prompt: `PLAT`, `AUTH`, `CONN`, `SYNC`, `ONB`, `DISC`, `GRAPH`, `TM`, `REA`, `SCAN`, `WORK`, `AI`, `GATE`, `REM`, `REP`, `MON`. Numbers are never reused; a removed code stays in the catalogue as deprecated.
- Number blocks per area (proposed): `0xxx` generic and HTTP-level mappings, `1xxx` configuration and validation, `2xxx` external system or dependency, `3xxx` internal processing, `9xxx` reserved. The prompt's example `PTH-CONN-1004` fits.
- `make docs-errors` runs a small Go program (`scripts/` or `cmd/pathosctl docs-errors`, in the Go container like the other targets) that writes `docs/troubleshooting/<area>.md` with front matter (so the Help Center can bundle them) and an index.
- Tests: (a) every catalogue entry has a generated doc section and every doc anchor has an entry (the generator runs in CI with `git diff --exit-code`); (b) every `httpx.E` code literal in the source has a default mapping (AST scan, like `backend/internal/server/tenancy_gaps_test.go`); (c) every entry has at least one action and one verification step; (d) no entry text contains a secret-looking value or an internal hostname (reuse the redaction patterns).
- The envelope keeps `error.code` and adds `error_code` and the catalogue fields ([API design](PATHOS_API_DESIGN.md#error-envelope-today-and-proposed)).
- Logs: `request_id` exists on the access log today (`httpx.go`, `Middleware`); `error_code` is added there and in `WriteError`.

**Consequences.** Every API error gets a catalogue code in M1 through the default mapping; specific codes are added area by area as modules are touched. The prompt's literal envelope (`code` = catalogue code) is not followed; that needs owner approval. The generated docs add about 16 files to `docs/troubleshooting/`.

**Status.** Proposed, needs owner approval (especially the `error_code` field name).

---

### ADR-003: Feature-flag framework

**Context.** No feature-flag framework exists (no match for feature flags in `backend/` or `frontend/src`). Opt-in behaviour today is per setting: for example `repositories.pr_checks_enabled`, `secret_validation_settings`, `developer_insight_settings`, the `phase` field of `NavItem` that shows a disabled menu item (`frontend/src/components/layout/AppShell.tsx:72`), and installation-wide environment variables. Rule 9: every new module behind a flag, off by default until its milestone is approved.

**Options.**

1. Server-side flags per organization: definitions in Go, state in `organization_feature_flags`, read by the API (gating routes and jobs) and exposed to the UI through `/api/v1/meta`.
2. Environment variables per installation. Simple, but cannot differ between organizations in a multi-tenant install and needs a restart.
3. A third-party flag service (Unleash, OpenFeature provider, LaunchDarkly). Adds a service or an external dependency; conflicts with air-gapped installs.

**Decision (proposed).** Option 1, plus an installation-wide "force off" environment variable for operators.

- Definitions: key, milestone, description, `depends_on`, default off. Enabling a flag whose dependency is off is refused (`409`).
- API: a middleware or per-service check answers `404 not_found` for routes of a disabled module, so a disabled module behaves like an absent one. Jobs and workers skip disabled modules per organization.
- UI: the shell reads `feature_flags` from `/api/v1/meta` once per session (and after a flag change). A disabled module's menu items stay visible with the existing `phase` treatment where the prompt wants "arrives in roadmap phase N", or the "feature disabled" state that names the flag and the `flags.manage` permission.
- Who can change flags: `flags.manage` (organization-only). Every change is audited.
- Tests: a unit test fails when a new route group has no flag in the catalogue; e2e runs with flags on and off for each new page.

**Consequences.** Small, testable, works offline. Flags are not a security boundary on their own: permissions still apply. Removing a flag after general availability needs a cleanup PR per module.

**Status.** Proposed, needs owner approval.

---

### ADR-004: Graph store: PostgreSQL versus a graph database

**Context.** The existing intelligence layer is relational by decision ([roadmap §1](PATHOS_IMPLEMENTATION_ROADMAP.md#1-target-architecture)): graph questions are answered in SQL by `internal/posture` (context graph capped at 5,000 component nodes, `backend/internal/posture/graph.go:55`). The install is Docker Compose with PostgreSQL 18 (`docker-compose.yml:257`), must work air-gapped ([AIRGAP.md](../AIRGAP.md)), and supports optional multi-tenancy enforced by PostgreSQL row-level security ([MULTI_TENANCY.md](../MULTI_TENANCY.md)). CodeGraph needs: store per snapshot, aggregation by containment level, neighbourhood expansion, bounded path search, diffs between snapshots.

**Options.**

| | PostgreSQL tables (recursive CTEs) | Apache AGE (PostgreSQL extension, openCypher) | Neo4j (separate server) |
|---|---|---|---|
| Licence | PostgreSQL licence (in use) | Apache-2.0 | Community Edition GPLv3; clustering and several operations features need the commercial Enterprise Edition |
| PostgreSQL 18 | Yes | The project lists support for PostgreSQL 11 to 18 (github.com/apache/age, release badge v1.8.0, checked 2026-11-20). Must be verified on the exact minor version before use | n/a |
| Air-gapped install | Nothing new | The official `postgres` image does not include it: a custom PostgreSQL image must be built, pinned and signed | One more image and volume, its own backup |
| Tenant isolation | Existing RLS policies and composite keys apply unchanged | Graph data lives in AGE's own schemas and label tables; the existing RLS design (`pathos_enable_tenant_rls`) and the isolation test do not cover them without extra work | Separate system: tenant isolation must be re-implemented in every query |
| Backup and restore | Existing `pg_dump` path | Same database, but the extension must exist at restore time | Separate procedure |
| Operations cost | None new | Custom image upkeep for every PostgreSQL patch release | A JVM service, memory tuning, upgrades, monitoring |
| Query fit | Good for bounded traversals (depth ≤ 8, budgets), aggregation by precomputed groups; weak for unbounded path queries | Cypher path queries | Best for deep, ad-hoc traversals |

**Decision (proposed).** PostgreSQL tables, as designed in [PATHOS_DATABASE_DESIGN.md](PATHOS_DATABASE_DESIGN.md#codegraph-m4): nodes with a containment tree, edges with evidence, precomputed group edges per level, bounded recursive path search, diffs by stable node and edge keys, old snapshots archived to object storage.

**Consequences.** No new service and no change to backup, isolation or air-gapped installation. Deep or unbounded path queries are limited by hop and row budgets, and the UI says when a search was cut. Revisit if measurement in M4 shows path search on the largest test repository above 2 s p95 at 8 hops; AGE would then be the first alternative, because it keeps the data in PostgreSQL.

**Status.** Proposed, needs owner approval.

---

### ADR-005: Graph UI library: React Flow with ELK versus Cytoscape

**Context.** No graph library is in the frontend today (`frontend/package.json` has React 19, TanStack, Radix, Recharts); the context graph page draws its own columns (`frontend/src/features/posture/ContextGraphPage.tsx`). The prompt asks for one shared graph component (zoom, pan, search, filters, layers, expand and collapse, inspector, path tracing, PNG/SVG/JSON export, snapshots, compare, keyboard access with ARIA on nodes) and a budget of first render under 2 s for 2,000 nodes. It names React Flow with ELK unless measurement shows a need for Cytoscape.

**Options.**

| | React Flow (`@xyflow/react`) + ELK (`elkjs`) | Cytoscape.js |
|---|---|---|
| Licence | React Flow: MIT. elkjs: Eclipse Public License 2.0 (to verify in its `LICENSE.md` before adoption; EPL-2.0 is weak copyleft and file-scoped, so bundling the unmodified library in an Apache-2.0 product is normally fine, but it must be listed in `NOTICE`) | MIT |
| Rendering | DOM/SVG per node: React components, Tailwind tokens, focusable nodes, ARIA is natural | Canvas (and an optional WebGL renderer in recent versions): fast at high node counts, but nodes are not DOM elements, so keyboard and screen-reader access must be built beside the canvas |
| Layout | ELK layered and other algorithms, run in a web worker | Built-in and extension layouts (including ELK through an adapter) |
| Bundle size | React Flow moderate; elkjs large (several hundred KB minified). Lazy-loaded with the graph routes | Moderate |
| Fit with design tokens and themes | Direct (React + CSS variables) | Through Cytoscape's own style sheet; tokens must be mapped |

**Decision (proposed).** React Flow with ELK in a web worker, lazy-loaded, behind one shared component, with server-side aggregation keeping the default view at 500 nodes or fewer ([API: M4](PATHOS_API_DESIGN.md#m4-codegraph)). Confirm by measurement before M4 UI work starts; switch to Cytoscape only if the plan below fails after the listed mitigations.

**Measurement plan.**

1. Fixture: a seeded generator of synthetic graphs labelled as test data (rule 4), with 500, 1,000, 2,000 and 5,000 nodes, edge ratios 1.5 and 3, and a containment depth of 4. Plus the real CodeGraph of the PATHOS repository once M4 discovery runs.
2. Harness: a test route available only in development builds, driven by Playwright (`e2e/`, run with `scripts/e2e.sh`) in Chromium.
3. Metrics, each over 10 runs, reporting median and p95: time from data received to layout done (ELK in the worker); time to first rendered frame with all nodes placed (`PerformanceObserver` and a `requestAnimationFrame` marker); interaction frame rate while panning and zooming for 5 s; JS heap after render.
4. Environments: (a) the reference client, which the owner must define (proposed: 4 CPU cores, 8 GB RAM, current Chrome, 1440×900); (b) the same with Chrome DevTools CPU throttling ×4 as a pessimistic case.
5. Pass: 2,000 nodes, data received to interactive, p95 under 2 s on (a). Results go in the M4 PR and in this ADR.
6. Mitigations before switching library, in order: React Flow's visible-element-only rendering; simplified node components at low zoom; cached server-side layout positions per snapshot and level; layout of only the changed part after expand.
7. If React Flow still fails, run the same harness with Cytoscape (canvas, then WebGL renderer) and add a keyboard-accessible node list beside the canvas.

**Consequences.** Two new dependencies (or one, if Cytoscape wins), pinned like the rest. One graph component for CodeGraph, threat models, reverse engineering and later the context graph. The 2 s budget is not proven until the measurement runs.

**Status.** Proposed; the decision is final only after measurement.

**Measurement (M4 UI, 2026-11-20).** Run with the plan above (`scripts/graph-bench.sh`, details and numbers in [PERFORMANCE.md](../PERFORMANCE.md#graph-rendering)). React Flow rendering meets the budget; **ELK layered does not**: 4.5 s for 500 nodes and 28.6 s for 1,000 (Node, cold, trust boundaries as containers), and it did not finish 2,000 nodes within 120 s in Chromium. Applied mitigation, beyond the four listed: the worker uses ELK only up to 250 nodes and 500 edges and a linear-time layered layout above (`frontend/src/components/graph/fastLayout.ts`). Result for 2,000 nodes and 2,998 edges: p95 774 ms from data received to placed and fitted (p95 3.3 s with CPU throttling ×4). Cytoscape was not needed for rendering. Licences verified: `@xyflow/react` 12.12.1 MIT; `elkjs` 0.12.1 is **EPL-2.0 OR GPL-3.0-or-later** (package `LICENSE.md` and SPDX headers; used under EPL-2.0 and listed in `NOTICE`; 0.13.0 is deprecated on npm). Open for the owner: the reference client, and whether server-side cached positions (mitigation 3) should replace the client fallback layout for large views.

---

### ADR-006: CodeGraph discovery engines

**Context (verified).** Existing building blocks: `pathos-reach` (call sites of external-module members for JavaScript/TypeScript, Python and Java, from source only, no network; shipped in `worker-sca`, `backend/cmd/pathos-reach/main.go:1-14`); Syft SBOMs and dependency edges (`sbom_dependencies`); Opengrep with PATHOS rules, including route and material-change rules (`workers/rules`, `material_changes` categories `api_endpoint`, `auth`, `crypto`); Python `tree-sitter==0.26.1` is already pinned with hashes in `workers/sast/requirements.txt:176` and `workers/mobile/requirements.txt:227` (as a dependency of other tools); `worker-sast` already builds a cgo tree-sitter consumer (Bearer, `workers/sast/Dockerfile:83-97`). Joern is not present. Workers run read-only, non-root, all capabilities dropped, 4 GB memory by default (`docker-compose.yml:28-46`).

**Options and evidence.**

| Engine | What it gives | Licence | Runtime and memory | Evidence type |
|---|---|---|---|---|
| tree-sitter + grammars | Files, modules, classes, functions, imports, declared routes (with queries) for many languages; fast, incremental | MIT (core; most grammars MIT, each to be checked) | Native, low memory | verified |
| `pathos-reach` (existing) | Calls into external modules with caller chains | PATHOS (Apache-2.0) | Go, low memory | verified |
| Opengrep with PATHOS rules (existing engine) | Routes, DB access, auth and crypto calls, framework configuration | LGPL-2.1 engine, PATHOS rules | Existing in worker-core | verified |
| Syft (existing) | Components and dependency edges | Apache-2.0 | Existing | verified |
| Joern | Code property graph: data flow and taint paths, deeper call graphs | Apache-2.0 | JVM. The heap must be set explicitly (`-J-Xmx`); the Joern docs' kernel-scale example used tens of GB (docs.joern.io/installation). Needs per-repository size limits | verified |
| go-enry, scc | Language detection, size metrics | MIT | Low | verified (metadata) |
| dependency-cruiser | JS/TS module graph | MIT | Node.js | verified |
| kin-openapi | OpenAPI documents to operations | MIT | Go library | verified |
| Universal Ctags | Symbol index | GPL-2.0 | Native; separate process only (same rule as the AGPL tools in the catalogue) | verified |
| Microsoft Application Inspector | Feature tags (crypto, auth, PII) | MIT | .NET runtime, large image | verified (tags) |
| Runtime (existing runtime context, `00035`) | Deployed workloads, ingress, images | — | Existing | observed |
| AI (M4/M7) | Edges the static engines cannot prove (dynamic dispatch, configuration-driven routing) | — | Provider per task | ai_inferred, with an evidence record |

**Decision (proposed).**

- Tier 1 (M4, required): tree-sitter for structure, PATHOS Opengrep rules for routes and DB access, `pathos-reach` output for calls, Syft for components, kin-openapi for declared APIs, runtime context for observed edges. All run in a new **`worker-graph`** family image built on worker-core (same pattern as the eight family images, `release.yml:112-127`), so the core image does not grow.
- Tier 2 (M4 stretch or M5): Joern for data-flow edges, in the same family image, with `JAVA_OPTS` heap limits tied to the worker memory limit (proposed default 3 GB heap in a 4 GB worker, configurable), a repository size limit, and a clear "skipped: too large" result. Never run on worker-core.
- Every engine runs as a separate process, pinned by version and digest, with no network (the graph build needs none) and with the existing per-job tmpfs.
- Each engine version is recorded in `codegraph_snapshots.engines`.
- Licence and maintenance of each engine are re-verified in the M4 PR (prompt §7).

**Consequences.** One new worker family image and one more Compose profile. Memory: tier 1 fits the default 4 GB worker; Joern needs an operator choice for large repositories. Not measured yet: build time and graph size for the PATHOS repository.

**Status.** Proposed, needs owner approval.

---

### ADR-007: Threat-model engine and framework mappings

**Context.** Existing: attack paths and blast radius (`backend/internal/posture/attack.go`), CWE on findings, compliance catalogue in code (`backend/internal/compliance`). Nothing models threats today. Rule 5 requires an evidence label on every threat.

**Options.** (1) A PATHOS rule engine over CodeGraph (STRIDE per element kind and edge kind, LINDDUN for flows that carry personal data), plus attack-path integration, plus optional AI suggestions recorded as `ai_inferred`. (2) Run OWASP pytm or Threagile as the engine. Both expect their own model input (Python code or YAML) rather than a discovered graph, so they fit better as import and export formats. (3) AI-only generation. Rejected by rule 4 and rule 5: it cannot be the only source.

**Decision (proposed).** Option 1. pytm, Threagile and OWASP Threat Dragon are supported as **formats** (import and export), not as engines. Mappings: STRIDE category → CAPEC and ATT&CK through rule tables; CWE from linked findings; D3FEND countermeasures suggested for mitigations; LINDDUN categories from data-flow rules. Every generated threat carries its rule id or attack path as evidence.

**Licence terms of the reference data** (checked 2026-11-20; re-check in the M5 PR):

| Data | Terms | What PATHOS must do |
|---|---|---|
| MITRE ATT&CK | Non-exclusive, royalty-free licence for research, development and commercial use, provided MITRE's copyright designation and the licence are reproduced in any copy (attack.mitre.org, Terms of Use). Required notice: "© <year> The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." | Ship the notice in `NOTICE`, the About dialog and exports that include ATT&CK text |
| MITRE CWE | Same form: non-exclusive, royalty-free licence for research, development and commercial purposes, on condition that MITRE's copyright designation and the licence are reproduced (cwe.mitre.org, Terms of Use). CWE is a MITRE trademark | Same |
| MITRE CAPEC | Published under MITRE terms of the same form as CWE (to verify on capec.mitre.org before shipping) | Same |
| MITRE D3FEND | The D3FEND ontology repository states the MIT licence (github.com/d3fend/d3fend-ontology) | Keep the MIT notice |
| LINDDUN | The LINDDUN site states "Copyright DistriNet, KU Leuven" and names no licence for its threat trees or cards (linddun.org, checked 2026-11-20) | Use only the seven category names and PATHOS's own descriptions; do not ship LINDDUN text or cards until the licence is confirmed. **Open question for the owner** |

Data ships with the build and in the offline bundle; no online fetch is needed ([database design](PATHOS_DATABASE_DESIGN.md#threat-modelling-m5)).

**Consequences.** Threat quality depends on CodeGraph coverage; elements the graph does not show produce no threats, and the UI must say so. The engine is explainable: each threat names its rule.

**Status.** Proposed, needs owner approval.

---

### ADR-008: AI evidence record and reproducibility

**Context (verified).** AI reviews and AI fixes store provider, model, configuration version, tokens and the SHA-256 of the transmitted request (`ai_reviews.transmitted_sha256`, `00004_ai_mcp.sql:81`; `ai_fix_proposals.transmitted_sha256`, `00033_verified_ai_fixes.sql:37`), not the request or response. One default AI configuration per organization (`00004_ai_mcp.sql:37`). Providers: Anthropic, OpenAI, xAI and OpenAI-compatible local servers such as Ollama ([ARCHITECTURE.md §6](../ARCHITECTURE.md#6-ai-review-architecture)). Guardrails exist: redaction, nonce-fenced untrusted evidence, strict JSON schema validation, no AI closure of critical findings, AI never overrides a human.

**Options.** (1) Keep hashes only. Proves what was sent, but cannot replay or show it. (2) Store the redacted prompt and response in the encrypted store, with model digest, template version and parameters, so a decision can be shown and replayed. (3) Store everything in database rows. Large and harder to expire.

**Decision (proposed).** Option 2 with the `ai_evidence_records` table ([database design](PATHOS_DATABASE_DESIGN.md#ai-evidence-records-m4-table-m7-full-use)).

- "Reproducible" means: the record holds every input reference, the exact redacted prompt, the template version, model name and digest (for local models), parameters (temperature 0 and a seed where the provider supports them), and the response. A replay re-sends the stored prompt to the same model version and compares conclusions. Hosted models can change behind the same name; the replay result is recorded, not assumed equal.
- Model per task (`ai_task_assignments`). Proposed defaults: the local provider for every task that sends code (`finding_validation`, `graph_inference`, `threat_suggestion`, `fix_proposal`, `troubleshooting`) when a local provider is configured; otherwise the organization default, as today. The owner's local setup (Ollama) fits this default.
- Every AI output used in the product is labelled `ai_inferred` and links to its record. No silent suppression: an AI conclusion can propose a status change but never apply it without the existing approval policy.
- Secrets are never sent (existing redaction) and never stored.

**Consequences.** More storage for prompts (redacted code fragments). Retention needs an owner decision (see the open question in the database design). Replay costs tokens and must be rate-limited.

**Status.** Proposed, needs owner approval.

---

### ADR-009: Reverse-engineering isolation

**Context (verified).** Prior art: code from scanned repositories runs only through `Sandbox.RunUntrusted` (`backend/internal/worker/sandbox.go`) in a sibling **sandbox runner** container with `network_mode: none`, its own UID, PID and IPC namespaces, read-only root filesystem, no capabilities and resource limits ([ARCHITECTURE.md, "Running repository code"](../ARCHITECTURE.md#running-repository-code)). Ordinary workers are read-only, non-root, `cap_drop: [ALL]`, `no-new-privileges`, on the `scan`, `worker-api` and `malware` networks (`docker-compose.yml:28-46`). A worker needs the `worker-api` network to lease jobs and upload results. The binary family image runs CVE Binary Tool, capa and YARA-X on artifacts (`workers/binary/Dockerfile`).

**Options.**

1. Static tier in a new `workers/rea` family: the agent container stays on `worker-api` only (no `scan` network, so no egress at all), and every analysis tool (radare2, Ghidra headless, Jadx, ILSpy, binwalk, LIEF, angr) runs as a separate process inside a sandbox runner with `network_mode: none`, using the `RunUntrusted` contract. Parsing untrusted binaries can trigger parser bugs, so the parsers get the same isolation as untrusted code.
2. Run the tools directly in the agent container without the runner. Simpler, but a parser exploit would reach the worker token.
3. Dynamic analysis (sandbox tier: Frida, Tracee, Qiling) in the release. Rejected for this release: prompt §6 puts it after the release, on a throwaway VM, never on the PATHOS host.

**Decision (proposed).** Option 1 for M10. M11 (sandbox tier) is not designed here and needs its own approval.

- "No network" in the prompt applies to the analysis processes (none). The agent keeps only the internal `worker-api` network, which it needs to receive jobs; it has no route to the internet or the scan egress proxy.
- Read-only root filesystem, non-root, all capabilities dropped, `no-new-privileges`, memory and PID limits, per-job tmpfs; no Docker socket (existing rules).
- Default input: artifacts proven to come from the organization's own builds (signature or provenance verification already recorded in `signature_verifications`); third-party artifacts only when an administrator enables it per organization.
- Tool licences to verify in the M10 PR: radare2 (LGPL-3.0), Ghidra (Apache-2.0, JVM, large image), Jadx (Apache-2.0), ILSpy (MIT, .NET), binwalk (MIT), LIEF (Apache-2.0), angr (BSD-2-Clause, Python, high memory).

**Consequences.** A new family image with a JVM (Ghidra) and .NET (ILSpy) runtime is large; the image size must be measured and documented. Analyses are slower than in-process runs because inputs are copied into the runner.

**Status.** Proposed, needs owner approval.

---

### ADR-010: Gates never block without a policy

**Context (verified).** Policies with a `block` action fail the scan gate and pull request checks (`backend/internal/policy/policy.go:47-50`). Other blocking paths exist without a policy object: profile `fail_on_critical` (default off), signature-required targets, repository `pr_gate_severity` (default `high`, active only when PR checks are enabled), and the CI caller's `fail_on` threshold on `GET /api/v1/scans/{id}/gate` (`backend/internal/scans/gate.go:45`, default `none`).

**Options.** (a) Count those opt-in settings as policies and document it; (b) migrate them into generated policy rows with identical behaviour; (c) keep them and record them as legacy reasons.

**Decision (proposed).** New gates (`security_gates`) always reference a policy; the database refuses a blocking `gate_decisions` row without a policy ([database design](PATHOS_DATABASE_DESIGN.md#remediation-items-and-gate-decisions-m8)). With no gate configured, `POST /api/v1/gates/evaluate` returns `pass`. For the existing thresholds, option (b) is recommended for M8, behind the M8 flag, with a parity test. The CI `fail_on` parameter is the caller's own decision and is documented as such.

**Consequences.** The "no gate blocks without a policy" test becomes exact. Migrating legacy thresholds touches profile and repository settings pages; their old fields stay readable.

**Status.** Proposed, needs owner decision on the legacy thresholds.

---

### ADR-011: Hide tool names in the UI, keep them in the API

**Context.** Rule 3: tool names only on Configurations › Scan profiles (`/configurations/scan-profiles`) and Scanners & workers (`/configurations/scanners`); elsewhere the kind of check and "confirmed by N engines". Today tool names appear in many places (finding details, scan pages, imports, rule ids such as `gitleaks:…`). The data exists: `findings.scanner_keys` (`00003_scanning.sql:181`) and the scan-type registry (`backend/internal/scanners/scantypes.go`).

**Decision (proposed).**

- API responses keep tool fields for audit (prompt rule 3).
- Frontend: one helper maps a scanner key to its check label; one `<EngineCount>` component shows "confirmed by N engines". A `<ToolName>` component is the only way to render a tool name, and a lint rule (or unit test over the source) allows it only under the two configuration routes.
- Rule ids that start with a tool name are shown without the prefix outside the two pages.
- Test: an e2e crawl of every non-configuration route, in both themes, fails if visible text contains a catalogue tool name (word-boundary match on `scanner_catalog.name`; ambiguous common words such as "Infer", "Clair", "dive" or "witness" are checked through `data-tool` attributes instead of text).

**Conflicts (need owner decisions).**

1. The in-app Help Center bundles `docs/user-guide/*.md`, which names tools in many articles. Is help part of "the UI" for rule 3? Proposed: help articles are exempt (they document the configuration pages).
2. Exports: SARIF requires `tool.driver.name`; CSV exports include scanner columns today. Proposed: exports keep tool names (they are audit artefacts), or SARIF uses driver `PATHOS` with the original tool in `properties`. Owner to choose.
3. Import pages (`/scans/imports`) select a format by tool name (232 formats). Proposed: exempt, or add it as a third configuration-like page.

**Status.** Proposed, needs owner decision on the three conflicts.

---

### ADR-012: Help system: offline content and route-to-article mapping

**Context (verified).** Help content is already offline: `frontend/src/features/help/content.ts:37` bundles `docs/user-guide/*.md` and `docs/api-reference/*.md` at build time with `import.meta.glob` (front matter: title, section, order, version, updated, summary), plus images. Routes `/help` and `/help/$section/$slug` exist. There is no route-to-article mapping and no drawer. The router defines 74 routes (`frontend/src/app/router.tsx`).

**Decision (proposed).**

- Keep build-time bundling; add `docs/troubleshooting/*.md` (generated, ADR-002) as a third section. No runtime fetch.
- A typed map `routeHelp: Record<RoutePath, {section, slug, anchor?}>` next to the router. The help drawer (F1 or `?`) opens the mapped article for the current route.
- Test (Vitest): enumerate every route from the router tree; fail when a route has no entry, when an entry points at a missing article or anchor, or when an entry names a route that no longer exists.
- "What's new in v{version}" renders the version's section of `CHANGELOG.md`, bundled the same way.
- User-guide pages get a Troubleshooting section listing their error codes; a test checks each listed code exists in the catalogue.

**Consequences.** The bundle grows with the troubleshooting docs (text only). Every new route must ship with its help mapping, enforced in CI.

**Status.** Proposed, needs owner approval.

---

### ADR-013: Naming and versioning of the lifecycle release

**Context.** The build prompt is titled "PATHOS 2.0" and assumes the code is at 1.1.1. The repository is at **2.2.0**: `2.0.0` was released (CHANGELOG `## [2.0.0] — 2026-11-19`, commit `2e3f2cc`), followed by `2.1.0` and `2.2.0`. Prompt rule 2 forbids inventing versions; prompt §8 says the CHANGELOG gets "Unreleased" entries and no version is assigned without the owner. Releases are made by pushing a tag `vX.Y.Z` (`release.yml:20-22`), and the version flows from the tag into every image and binary (ADR-001). Prompt §6 M11 says "after 2.0".

**Options.**

| Option | Description | Effect |
|---|---|---|
| A | Ship each approved milestone in the next minor release (2.3.0, 2.4.0, …) with its modules behind flags. "Lifecycle release" stays a programme name | Matches semantic versioning: everything is additive |
| B | Collect all milestones into one major release (3.0.0) | A major number signals breaking changes, but the plan is additive; long-lived branch or many flags until then |
| C | Keep the name "PATHOS 2.0" as a product or marketing name | Clashes with the released 2.0.0 tag, CHANGELOG entry and images; users cannot tell them apart |
| D | A product edition name independent of the version number (for example "PATHOS Lifecycle") | Name and version decoupled; the version still comes from the tag |

**Decision.** None. The owner decides. Until then, documents say "the lifecycle release", CHANGELOG entries go under `## [Unreleased]`, and the prompt's "after 2.0" (M11) is read as "after the lifecycle release".

**Consequences.** None until the owner decides.

**Status.** Open: owner decides.

---

## Components

New components proposed by these records: `internal/platform/buildinfo` (ADR-001), `internal/platform/diag` and `make docs-errors` (ADR-002), `internal/platform/flags` (ADR-003), the CodeGraph store and service (ADR-004), the shared graph component (ADR-005), the `worker-graph` family (ADR-006), the threat-model engine (ADR-007), AI evidence records (ADR-008), the `workers/rea` family (ADR-009), gates (ADR-010), `<ToolName>` and `<EngineCount>` (ADR-011), the help drawer and route map (ADR-012).

## Data flow

Discovery worker → CodeGraph snapshot → threat-model engine and attack paths → findings correlation and AI evidence → remediation items and gate decisions → monitoring events and reports. Each arrow carries evidence labels (rule 5). Details per milestone are in the [roadmap](PATHOS_IMPLEMENTATION_ROADMAP.md#17-lifecycle-release-plan-m0m11-proposed).

## Dependencies

Proposed new third-party dependencies, all to be pinned and licence-checked in their milestone PR: `@xyflow/react` and `elkjs` (or Cytoscape.js), tree-sitter grammars, Joern, kin-openapi, dependency-cruiser, go-enry, scc, Universal Ctags (separate process), MITRE ATT&CK, CAPEC, CWE and D3FEND data, and the reverse-engineering tools listed in ADR-009.

## APIs

See [PATHOS_API_DESIGN.md](PATHOS_API_DESIGN.md#lifecycle-release-endpoints-m0-proposed).

## Protocols

No new external protocol in M1. Connector protocols are specified in [PATHOS_INTEGRATION_TECHNICAL_SPEC.md](PATHOS_INTEGRATION_TECHNICAL_SPEC.md). Workers keep the existing internal worker API ([worker protocol](../api-reference/worker-protocol.md)).

## Authentication

Unchanged: Keycloak sessions with CSRF, REST API tokens, worker tokens. `/api/v1/meta` is the only new route with an unauthenticated form (ADR-001, [API design](PATHOS_API_DESIGN.md#m1-shell-metadata-diagnostics-flags)).

## Security requirements

Rules 3 to 7 and 9 of the prompt map to ADR-011, ADR-008, ADR-005/006 (evidence labels), ADR-008 (secrets never sent), ADR-010 and ADR-003. Tenant isolation follows [MULTI_TENANCY.md](../MULTI_TENANCY.md) for every new table and route.

## Error handling

All new modules raise catalogue codes (ADR-002). First code ranges per area are listed in the [API design](PATHOS_API_DESIGN.md#lifecycle-release-endpoints-m0-proposed).

## Operations

New Compose profiles for `worker-graph` and `worker-rea`; release workflow matrix entries for both families; new ldflags (ADR-001). Offline bundle gains the MITRE data (ADR-007).

## Implementation status

Nothing in this file is implemented. Every "Context" paragraph describes existing code as verified on `main` at 2.2.0 (commit `f3c5efd`).

## Known limitations

- The CodeGraph volume (ADR-004, ADR-006) is not measured; the 2 s graph budget was measured in M4 (ADR-005).
- Licence statements for CAPEC and LINDDUN still need verification (ADR-007); elkjs was verified in M4 (ADR-005).
- ADR-011 and ADR-013 cannot be completed without owner decisions.

## Future improvements

- The prompt's literal error envelope as an opt-in content type (ADR-002, option C).
- Apache AGE if bounded SQL traversal proves too slow (ADR-004).
- The reverse-engineering sandbox tier (M11), on a separate VM, with its own ADR.
