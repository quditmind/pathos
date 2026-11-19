Quditmind PATHOS · applies to v2.2.0 · status: Existing

# PATHOS architecture assessment (phase 0 baseline)

> §1 to §7 below are a **historical snapshot**; §8 ([Lifecycle release audit (M0)](#8-lifecycle-release-audit-m0)) is current and was checked against the code of PATHOS 2.2.0 (commit `f3c5efd`).
>
> **Status of §1 to §7: historical snapshot.** Written in phase 0 of the ASPM programme (2026-11-17) and not updated since. It describes PATHOS as it was before the ASPM phases, as the baseline for [PATHOS_FEATURE_GAP_ANALYSIS.md](PATHOS_FEATURE_GAP_ANALYSIS.md). The gaps listed under "does not yet have" below were addressed in ASPM phases 1 to 10 (see [PATHOS_IMPLEMENTATION_ROADMAP.md](PATHOS_IMPLEMENTATION_ROADMAP.md)); what is still open is listed in the register. For the current architecture read [ARCHITECTURE.md](../ARCHITECTURE.md); for the current schema, [DATABASE.md](../DATABASE.md).

It was based on the code on `main`, plus the Human Review module in PR #29, which was complete with CI green but not yet merged.

## 1. Summary

PATHOS is already a working, self-hosted ASPM foundation:

- multi-provider repository onboarding
- a sandboxed, distributed scanning pipeline that runs 7 engines and normalises their output
- a de-duplicated finding store with lifecycle and SLA tracking
- AI review that can use a local model (Ollama)
- manual review with four-eyes approval
- scheduling, notifications, scoped RBAC, MFA, audit logging, backup and restore, and observability

What it does **not** yet have:

- **External intelligence**: EPSS, CISA KEV, CVE details.
- **Contextual risk**: application-level scoring, reachability, a dependency or context graph.
- **More engines**: DAST, API, container image, IaC breadth. Most of the ~50 catalogued scanners have no adapter.
- **Ingestion from outside**: SARIF and JSON import, SBOM import.
- **Developer-workflow integration**: pull-request checks, outbound webhooks, Jira, ServiceNow.
- **Governance**: a general policy engine, compliance control mapping, executive and custom reporting.

The architecture can absorb all of these without a rewrite. None of the 100 capabilities needs a framework change.

## 2. Technology

| Layer | Technology | Notes |
|---|---|---|
| Backend | Go 1.27, `net/http` ServeMux, pgx v5, goose migrations | One binary with roles `api`, `jobs`, `scheduler`. 21 internal packages (22 with `review`) |
| Database | PostgreSQL 18 | 67 tables on `main` (+9 in PR #29), 11 migrations (+1). Least-privilege app role; append-only audit and history tables enforced by grants |
| Queue / cache | Valkey | Rate limiting, leader election. Job queues are in PostgreSQL (`SKIP LOCKED`) |
| Frontend | React 19, TypeScript 6, Vite 8, TanStack Router and Query, Tailwind 4, Radix, Recharts | Feature folders under `src/features`, a shared design system, dark and light themes |
| Identity | Keycloak (OIDC with PKCE) | Local accounts, TOTP MFA, password policy, enforced MFA, admin API limited to private networks |
| Scan workers | `worker-core` image (Go agent and pinned tools) | Non-root, read-only filesystem, `cap_drop: ALL`, tmpfs, no Docker socket, egress through an allow-listing Squid proxy |
| AI | Provider abstraction: Anthropic, OpenAI, xAI, self-hosted OpenAI-compatible (Ollama, vLLM) | Strict JSON schema, redaction, fenced untrusted evidence, approval policy |
| Storage | PostgreSQL inline or S3-compatible (SeaweedFS profile) for scan artifacts; encrypted file store for source snapshots and evidence | AES-256-GCM with per-object keys |
| Proxy | Caddy | TLS, security headers, `/internal` blocked |
| Observability | slog JSON, OpenTelemetry traces and metrics, optional Grafana LGTM | |
| Deployment | Docker Compose (single host), production override, backup, restore and upgrade scripts | |

Full detail: [ARCHITECTURE.md](../ARCHITECTURE.md), [DATABASE.md](../DATABASE.md), [SECURITY.md](../SECURITY.md), [OPERATIONS.md](../OPERATIONS.md).

## 3. Modules (backend packages and UI)

| Area | Package(s) | UI | State |
|---|---|---|---|
| Identity, sessions, users, teams, roles | `auth`, `identity`, `authz`, `org` | Users, Organization | Scoped RBAC (organization, region, business unit, repository), 10 system roles (+ Independent Reviewer), custom roles, no privilege escalation |
| Assets | `repos`, `scm` | Repositories, Imports, Applications, Asset settings, Tags, SCM connections | GitHub, GitLab, Bitbucket, Azure DevOps (PAT, OAuth, App, service principal), uploads, discovery, sync, webhooks, Repository IDs, ownership and exposure metadata |
| Scanning | `scans`, `scanners`, `schedule`, `worker` | Scan Overview, Scans, Schedules, Comparison, Scan profiles, Scanners and workers | Versioned profiles, leases, retries, stages and logs, config snapshots, schedules with windows and plans |
| Findings | `scans` (ingest, findings), `vuln` | Findings, Risk acceptances, SBOM, Policies | Fingerprinting, cross-tool SCA de-duplication, lifecycle trigger and history, SLA, risk acceptance with expiry, SBOM inventory, licence policy |
| AI and MCP | `ai`, `mcp` | AI reviews, AI settings, MCP registry, API tokens | Automated review queue, approval, local models, MCP server with personal tokens |
| Human Review (PR #29) | `review` | 6 pages and the assessment workspace | Queue, 8-tab workspace, decisions, independent review, evidence, AI assistance, reports |
| Notifications | `notify` | Notifications admin, inbox | Outbox, rules, templates, SMTP, in-app |
| Dashboard and search | `dashboard`, `search` | Dashboard, Ctrl-K | KPIs from live data, trends |
| Platform | `platform/*`, `audit`, `secrets` | Audit log | Rate limits, telemetry, object storage, encryption keyring |

About 180 REST endpoints on `main` (about 215 with PR #29), all under `/api/v1`, plus an internal worker API on `:8081` and MCP at `/mcp`.

## 4. Scanning architecture

```
scheduler/webhook/manual ─▶ scan_jobs (queued) ─lease─▶ worker (sandbox)
   clone/snapshot ─▶ tools ─▶ SARIF/JSON ─▶ POST results ─▶ ingest (normalise, fingerprint, de-duplicate) ─▶ findings
                                                                 └▶ raw artifacts (retention) ─▶ AI review queue ─▶ Human Review queue
```

- Engines with adapters (`worker-core`): **Gitleaks** (mandatory), **Opengrep** (12 PATHOS baseline rules plus mounted rule packs), **Trivy fs**, **Syft** (CycloneDX SBOM), **Grype**, **OSV-Scanner**, **Checkov**.
- Catalogued with a licence decision but **no adapter** (about 45): TruffleHog, Semgrep CE, CodeQL, Bandit, Gosec, …, ZAP, Nuclei, Schemathesis, Trivy image, KICS, Kubescape, Scorecard, ScanCode, …
- Adding an engine means four things:
  - a catalogue entry in `scanners/catalog.go`
  - an invocation in `worker/tools.go`
  - a parser (SARIF, so usually none)
  - adding the tool to a worker image

  This is a workable plugin seam, but it is compiled in.
- **Targets are repositories only.** DAST, API and image scanning need new target types (URL, API spec, image reference).
- Not present: incremental scanning, PR-diff scanning, and external SARIF/JSON or SBOM import.

## 5. Data model highlights

- `findings`:
  - one row per (repository, fingerprint), with `scanner_keys[]` as provenance and `finding_occurrences` holding commit, file and line per sighting
  - category, rule, CWE[], CVE, CVSS (score only), package coordinates, location, snippet
  - status, SLA, assignee, recurrence, AI status
  - `human_*` columns (PR #29)
- Status values: `open`, `in_progress`, `needs_review`, `fixed`, `false_positive`, `accepted_risk`. Every change is recorded by a trigger in `finding_status_history`.
- `applications` (name, description, business unit, owner, security owner, criticality) ↔ `repositories` (many to one), which carry most of the context: environment, criticality, exposure, data classification, lifecycle, owners, compliance scopes.
- `sbom_components` is a **flat** list per repository (name, version, purl, type, licences). It has no dependency edges and no direct/transitive flag.
- Multi-tenancy is ready in the schema: `organization_id` is on every table, with composite foreign keys. At runtime there is one organization per deployment (`PATHOS_ORG_SLUG`).

## 6. Security posture of the platform

These strengths must be kept:

- the worker sandbox and egress allow-list
- secret redaction in reports, AI prompts and logs
- encryption at rest for secrets, source and evidence
- append-only audit, enforced by database grants
- CSRF and same-site sessions
- rate limiting
- gosec, govulncheck, Trivy and ZAP gates in CI
- MFA enforcement
- the Keycloak admin surface limited to private networks

Every new feature must preserve them: no external calls without configuration, no code execution on the API host, redaction before AI.

## 7. Must not break

- the `/api/v1` contracts used by the UI, MCP tools and webhooks
- the finding status values (stored in history and used by triggers, SLA and AI policy)
- fingerprints (changing them would re-open every finding)
- the worker API protocol
- Repository and Scan IDs
- the RBAC permission keys
- the backup format
- the least-privilege grant function `pathos_apply_app_grants`, which every migration must keep updating

## 8. Lifecycle release audit (M0)

This section is the existing-project audit for the **lifecycle release** (the nine-phase Application Security Lifecycle described in the owner's build prompt). It was made on 2026-11-20 against the code of PATHOS **2.2.0** (`main`, commit `f3c5efd`). Every number below was counted from the code, not from older documents. The capability-by-capability comparison is in [PATHOS_FEATURE_GAP_ANALYSIS.md › Lifecycle release capability matrix (M0)](PATHOS_FEATURE_GAP_ANALYSIS.md#lifecycle-release-capability-matrix-m0); the phase model is in [PATHOS_APPLICATION_SECURITY_LIFECYCLE.md](PATHOS_APPLICATION_SECURITY_LIFECYCLE.md).

The build prompt calls the new work "PATHOS 2.0" and assumes version 1.1.1. Version 2.0.0 is already released, and the code is 2.2.0. This audit calls the new work "the lifecycle release" and assigns no version.

### 8.1 Inventory

#### Backend packages

43 packages under `backend/internal/` (plus 10 under `backend/internal/platform/`):

`ai`, `aifix`, `analyst`, `audit`, `auth`, `authz`, `bench`, `compliance`, `dashboard`, `depcheck`, `depfix`, `eol`, `identity`, `ingest`, `insights`, `intel`, `material`, `mcp`, `notify`, `org`, `platform`, `policy`, `posture`, `pushprotect`, `reach`, `reachscan`, `releases`, `reporting`, `repos`, `review`, `risk`, `runtimectx`, `scanners`, `scans`, `schedule`, `scm`, `search`, `secrets`, `server`, `tenancy`, `tickets`, `vuln`, `worker`.

`platform/`: `config`, `crypto`, `db`, `httpx`, `logging`, `objstore`, `ratelimit`, `sourcestore`, `telemetry`, `tenant`.

Binaries in `backend/cmd/`: `pathos` (API, jobs, scheduler roles), `pathos-worker`, `pathos-cli`, `pathosctl`, `pathos-depcheck`, `pathos-reach`, `pathos-bench`, `pathos-loadgen`.

None of these packages implements a code graph, threat modelling, reverse engineering, a diagnostic catalogue or feature flags.

#### Migrations

38 goose migrations in `backend/migrations/`. The highest number is **00042** (`00042_same_org_references.sql`). Numbers 00030, 00036, 00037 and 00039 are not present; the next free number is 00043. Migrations are additive, and every one keeps `pathos_apply_app_grants` up to date (§7).

#### API routes

Counted from every `mux.HandleFunc` / `mux.Handle` call with a method pattern in non-test Go files under `backend/internal/` (415 registrations):

| Surface | Routes | Where |
|---|---|---|
| Public REST API `/api/v1/*` | **388** | 27 packages; the largest are `scans` (73), `repos` (65), `review` (37), `notify` (23), `runtimectx` (20), `releases` (18), `vuln` (17), `identity` (16) |
| Internal worker API `/internal/worker/v1/*` (port 8081) | 17 (+1 `GET /healthz`) | `scans/worker_api.go` |
| SCM webhooks `/api/webhooks/{provider}/{id}` | 4 | `repos` |
| Sign-in `/api/auth/*` | 3 | `server/server.go:106-107,158`, `auth` |
| Health | `GET /healthz`, `GET /readyz` | `server/server.go:104-106` |
| MCP | `/mcp` (JSON-RPC, one handler) | `server/server.go:155` |

By method: 197 GET, 146 POST, 33 PUT, 30 DELETE, 9 PATCH. There is no `/api/v1/meta` and no endpoint that returns feature flags, worker versions and scanner pack versions together.

#### Worker images

Nine worker images, each with its own Dockerfile and pinned base-image digests:

- `workers/core` (the Go agent and the core tools)
- eight family images built on the pushed worker-core image by digest: `sast`, `iac`, `sca`, `dast`, `mobile`, `binary`, `ai`, `fuzz`.

`workers/rules`, `rules-extra` and `rules-tests` are rule packs, not images. The release workflow (`.github/workflows/release.yml`) builds `pathos`, `pathos-proxy`, `pathos-worker-core` and the eight family images, signs each digest with cosign keyless and attaches SBOM and provenance attestations.

Scanner catalogue (verified in code):

- 98 catalogued integrations: the `s(...)` entries in `scanners/catalog.go` and `catalog_<family>.go`.
- 25 scan types (`scanners/scantypes.go`, asserted by `scantypes_test.go:13`).
- `docs/SCANNER_CATALOG.md:168` documents 232 import formats from 207 tools. The source has 198 direct `registerImportFormat` calls, and the remaining formats are registered in loops (for example `import_sarif_tools.go`). The 232 total was not re-counted at run time.

#### Frontend routes and menu

- `frontend/src/app/router.tsx` declares **74 routes**: `/login`, 2 redirects (`/scans/profiles` → `/configurations/scan-profiles`, `/admin/scanners` → `/configurations/scanners`) and 71 pages inside the authenticated shell.
- `frontend/src/components/layout/AppShell.tsx` `groups` has **9 groups and 58 menu items**. A tenth group, *Installation* (1 item, `/installation/organizations`), is added at run time only on multi-tenant installs for installation administrators (`AppShell.tsx:214-220`).

| Group (today) | Items | Routes |
|---|---|---|
| Overview | 4 | `/`, `/executive`, `/reports`, `/insights/developers` |
| Assets | 4 | `/repositories`, `/repositories/imports`, `/applications`, `/runtime` |
| Posture | 8 | `/posture`, `/posture/coverage`, `/posture/unmanaged`, `/posture/benchmark`, `/posture/attack-paths`, `/compliance`, `/posture/blast-radius`, `/posture/graph` |
| Scanning | 7 | `/scans/overview`, `/scans`, `/scans/schedules`, `/scans/compare`, `/scans/targets`, `/pull-requests`, `/scans/imports` |
| Configurations | 4 | `/configurations/scan-profiles`, `/configurations/scanners`, `/configurations/scan-coverage`, `/configurations/custom-rules` |
| Vulnerabilities | 7 | `/findings`, `/risk`, `/suppression-rules`, `/sbom`, `/portfolio`, `/sbom/policies`, `/vex` |
| Human Eye | 6 | `/human-review`, `/human-review/queue`, `/human-review/assessments`, `/human-review/assignments`, `/human-review/reports`, `/human-review/configurations` |
| AI & MCP | 6 | `/ai/analyst`, `/ai`, `/ai/reports`, `/admin/ai`, `/admin/ai-usage`, `/admin/mcp` |
| Administration | 12 | `/admin/users`, `/admin/organization`, `/admin/scm`, `/admin/tags`, `/admin/assets`, `/admin/policies`, `/admin/integrations`, `/admin/risk-intelligence`, `/admin/developer-attribution`, `/admin/secret-validation`, `/admin/notifications`, `/admin/audit` |
| *Installation* (multi-tenant only) | 1 | `/installation/organizations` |

Pages that are not in the menu (13):

- `/help` and `/help/$section/$slug`
- `/settings/security` and `/settings/tokens` (both in the user menu)
- `/scans/$id`, `/vulnerabilities/$id` and `/human-review/reviews/$id`
- `/repositories/import`, `/repositories/import/csv`, `/repositories/import/$source` and `/repositories/imports/$id`
- `/applications/$id/versions`

There is no `/applications/$id` page today. `/applications?app=<id>` opens the edit dialog on the list page (`features/repos/ApplicationsPage.tsx:59-104`).

`NavItem.phase` exists. An item with `phase` and no `to` renders disabled, with the tooltip "arrives in roadmap phase N" and a "Soon" badge (`AppShell.tsx:72, 253-265`). No item uses it today.

#### Shell, help and theme

- **Brand.** `Logo.tsx` has `LogoMark` (an SVG shield using `--primary`) and `Wordmark`, which renders only "PATHOS". The sidebar shows the wordmark when expanded and the mark when collapsed (`AppShell.tsx:230`). The shell, login page and sidebar show no vendor name and no version.
- **Top bar** (`AppShell.tsx:283-340`), from left to right:
  - search button (opens the command palette, `CommandPalette.tsx`, Ctrl/⌘ K)
  - organization switcher (multi-tenant only)
  - notification centre (`NotificationCentre.tsx`)
  - **Help** link to `/help`
  - theme toggle
  - user menu (API tokens, Sign-in security, Sign out)
- **Help system** (`frontend/src/features/help`):
  - `content.ts:37` bundles every Markdown file in `docs/user-guide` (32 articles) and `docs/api-reference` (29 articles) at build time with `import.meta.glob`, with front matter (title, section, order, version, updated, summary), so help works offline.
  - `HelpPages.tsx` renders the home page with search and the article page.
  - There is no route-to-article map, no help drawer, no F1 or `?` shortcut, no "What's new", no keyboard-shortcut dialog and no About page.
  - `docs/user-guide/troubleshooting.md` is a hand-written FAQ (20 headings), not a code catalogue; 6 user-guide pages have a "Troubleshooting" heading.
  - Article front matter carries a doc `version` ("1.0", "1.1" or "2.0"), not the product version.
- **Theme and design tokens.**
  - `frontend/src/index.css` defines the tokens on `:root`: background, surface, surface-muted, foreground, muted-foreground, border, ring, primary(-hover/-foreground), danger(-soft), success(-soft), warning(-soft), five severity colours and five code-viewer colours.
  - `.dark` redefines the same names, except the severity colours, which are shared by both themes.
  - Tailwind 4 maps them with `@theme inline`.
  - The theme is a `.dark` class toggled in `AppShell.tsx:181-200`. The choice is stored in `localStorage["pathos-theme"]`, and the default follows `prefers-color-scheme`.
  - No `prefers-reduced-motion` rule exists in `src`.
- **Primitives**:
  - `components/ui/primitives.tsx`: Input, Select, Label, Card, Badge, Spinner, EmptyState, Alert, Skeleton, PageHeader, Table, Th, Td.
  - `components/ui/`: button, dialog, confirm, combobox, color-picker, progress.
  - `components/data/`: DataTable, FilterBar, KpiCard, Severity, TagChip.
  - There is no ErrorPanel, no breadcrumb, no "permission denied" or "feature disabled" state component, and no graph component.
- **Graph rendering.** `posture/ContextGraphPage.tsx` draws its own SVG. `package.json` has no React Flow, ELK or Cytoscape (its runtime dependencies are Radix, TanStack Query and Router, cmdk, lucide, marked, Recharts).
- **Data tables.** `components/data/DataTable.tsx` has a column chooser (saved per table in `localStorage`) and CSV export **of the loaded rows only**, generated in the browser. It has no density toggle, no saved views (except on the Reports page), no server-side sort or filter, and no sticky-header option. List APIs use cursor pagination (`GET /api/v1/findings` returns `next_cursor`, `scans/findings.go:431-485`).

#### Version plumbing

| Component | How the version is set | Where it is shown |
|---|---|---|
| API (`pathos`) | `-ldflags "-X pathos/internal/server.Version=${VERSION}"` in `backend/Dockerfile:10`; default `"dev"` (`server/server.go:51-52`) | `GET /healthz` → `{"status":"ok","version":…}` (`server.go:104-106`) |
| `pathosctl` | no ldflags (`backend/Dockerfile:11`) | — |
| Worker agent | `-X main.version=${VERSION}` (`workers/core/Dockerfile:17`) | sent at registration (`cmd/pathos-worker/main.go:83`); stored in `workers.version` (`00003_scanning.sql:98`); listed by `GET /api/v1/workers` |
| CLI (`pathos-cli`) | `-X main.version=${version}` in `release.yml:223` | `pathos version`, `pathos --version` / `-v` print `pathos <version>` (`cmd/pathos-cli/main.go:131,143`); User-Agent `pathos-cli/<version>` |
| Frontend | `frontend/package.json` `"version": "2.2.0"`; **not injected** into the bundle (`vite.config.ts` has no `define`) | nowhere |
| Images | `VERSION` build argument; OCI labels `org.opencontainers.image.version` and `.revision` (`release.yml:166-175`) | registry only |

No `Commit` or `BuildDate` variable exists in any Go binary. The git SHA is only in the image label. Tool versions per worker are reported in the `workers.scanners` JSON column.

#### Error responses

`backend/internal/platform/httpx/httpx.go:22-70`:

- `httpx.Error{Status, Code, Message, Details?, Fields?}` is written as `{"error": {"code", "message", "details"?, "fields"?}, "request_id": "…"}`.
- Codes exist, but they are **snake_case slugs**, not catalogue codes. Predefined: `unauthenticated`, `forbidden`, `not_found`, `csrf_failed`, `invalid_request`, `conflict`, `internal`. 61 distinct codes are passed to `httpx.E(...)` across the packages, for example `validation_failed`, `rate_limited`, `scm_error`, `ai_not_configured`, `lease_lost` and `fix_pr_not_available`.
- `request_id` sits **beside** `error`, not inside it as in the prompt's §3.2 example.
- There are no fields for title, cause, probable causes, impact, actions, verification steps or docs URL, and no `PTH-…` code anywhere in the repository.
- Unknown errors become `500 internal`; their text is logged, never returned (`httpx.go:57-70`).
- The access log line carries `request_id` and `trace_id` (`httpx.go:153-196`). It carries no `error_code`.
- The frontend's `ApiError` keeps `code`, `message` and `requestId` (`frontend/src/api/client.ts:4-52`).

#### Feature flags

**There is no feature-flag framework.** Modules are switched on in four separate ways:

- per-organization settings in the database (for example `developer_insight_settings.attribution_enabled`, default false, `00028_developer_context.sql:71`; secret validation; AI fixes and fix PRs per repository)
- per-repository opt-ins (`pr_checks_enabled`, push protection, endpoint verification)
- Compose profiles for the family worker images
- a database switch for multi-tenancy (`pathosctl multi-tenancy enable`, `platform/config/config.go:92-94`)

No environment variable named `PATHOS_FEATURE_*` exists, and the API exposes no flag list.

#### Exports

| Export | Format | Where | Version-stamped? |
|---|---|---|---|
| Table CSV (every `DataTable`) | CSV of the loaded rows, made in the browser | `components/data/DataTable.tsx:39-136` | No (file name has the date) |
| Report run | JSON or `?format=csv` | `reporting/reports.go:556-580` | No |
| Human Eye reports | CSV | `review/reports.go:454-475` | No |
| Executive overview | browser print (PDF via the print dialog) | `reporting/ExecutivePage.tsx:83` | No |
| SBOM | CycloneDX 1.5 (scan SBOM or generated), SPDX 2.3 | `vuln/sbom.go:294`, `vuln/export.go:146,196` | Tool "PATHOS" without a version; timestamp only |
| VEX | OpenVEX 0.2.0, CycloneDX VEX | `releases/vexapi.go:48`, `releases/vex.go:175,283` | Tool "PATHOS" without a version |
| AI reports | Markdown | `GET /api/v1/ai/reports/{id}/markdown` | No |
| AI fix evidence | before/after reports | `GET /api/v1/ai-fixes/{id}/reports/{which}` | No |

PATHOS does not **export** SARIF (SARIF is an import format only), and there is no server-side PDF generation. No export carries `Quditmind`, a version, a commit or a build stamp.

#### Tests and e2e

- **Make targets.** The Makefile has `test`, `test-go`, `test-web`, `test-integration`, `test-rules`, `security`, `smoke`, `rbac-matrix`, `triage`, `triage-create`, `load-test`, `dast` and **`e2e`** (`Makefile:45-46` runs `scripts/e2e.sh`).
- **How e2e runs.** `scripts/e2e.sh` runs the pinned Playwright image `mcr.microsoft.com/playwright:v1.65.1-noble` with `--network host` against the running stack. It signs in as the bootstrap administrator from `.env` and handles the forced password change.
- **Specs.** `e2e/tests/` has 6 specs with 22 `test(` declarations (help 3, navigation 4, onboarding 2, scanning 4, workflows 6, human-review 3). Four of them loop over page lists, so a run has **68 test cases**: navigation 38 (35 pages), scanning 9, human-review 8, workflows 6, onboarding 4, help 3. Settings are in `e2e/playwright.config.ts` (1440×900, one worker).
- **Tests that pin today's shell.** Three tests assert the current menu and top bar exactly. §2.3 and §5 change both, so these tests will fail:
  - `e2e/tests/help.spec.ts:3-13` expects Help to be a **link** named "Help", placed directly after Notifications, and the text "Documentation version 1.0".
  - `e2e/tests/human-review.spec.ts:23-32` expects a menu section named "Human Eye" and the exact labels "Review Queue", "Review Reports" and "Review Configurations".
  - `e2e/tests/scanning.spec.ts:23-39` expects the exact labels "Scan Overview", "Scan Schedules", "Scan Comparison" and "Import Results", and a "Configurations" section.
- **Screenshots.** `e2e/screenshots.config.ts` captures the Help Center screenshots in **light theme only** (`colorScheme: "light"`).
- **CI.** CI runs `scripts/e2e.sh` (`.github/workflows/ci.yml:214`).

### 8.2 What the prompt (§2 to §5) asks for, compared with the inventory

| Prompt | Asks for | Today (2.2.0) | Gap |
|---|---|---|---|
| §0 facts | ldflags `server.Version`, `/healthz` version, router, tokens, `NavItem.phase`, `Logo.tsx`, palette, notification centre, help routes, `catalog.go`, pinned `workers/core/Dockerfile`, docs folders, make targets including `make e2e` | All confirmed in code | The prompt's base version (1.1.1) is wrong: the code is 2.2.0 |
| §2.1 brand header | `LogoMark` + "Quditmind \| PATHOS" + live version chip, About, update banner, pre-release tag | Wordmark shows "PATHOS" only; no version in the UI | Wordmark text, version chip, About dialog, bundle/backend mismatch banner, pre-release tag; same brand block on login, collapsed sidebar (tooltip), exports, email |
| §2.1 right side | search, notifications, Help (?), theme, user menu | All exist; Help is a plain link to `/help` | Help becomes a menu |
| §2.2 build metadata | `Commit`, `BuildDate` ldflags in API, CLI and workers; `GET /api/v1/meta`; Vite `define`; stamped exports | `Version` only (API, worker agent, CLI); no `/meta`; no frontend version; no stamps | All four are new; extend `backend/Dockerfile`, `workers/core/Dockerfile`, `release.yml`, `docker-compose.yml` build args |
| §2.3 help menu | help drawer per route (F1/`?`) with a unit test, help centre by phase, Troubleshooting centre, shortcuts, What's new, API reference, System status, diagnostic bundle, About; offline | Help centre and API reference exist and are offline; `/readyz` checks PostgreSQL and Valkey; the workers page shows worker health | Route-to-article map and test, drawer, troubleshooting route, shortcuts dialog, changelog rendering, system status page (object storage, worker packs, connectors and AI providers are not aggregated), redacted diagnostic bundle, About |
| §3.1 error catalogue | `PTH-<AREA>-<NNNN>`, Go catalogue, generated `docs/troubleshooting/*.md`, `make docs-errors`, two-way test | 61+ snake_case codes, no catalogue, no `docs/troubleshooting/` | All new. The existing slugs must keep working (backward compatibility) |
| §3.2 envelope | `error.{code,title,message,cause,probable_causes,impact,actions,verify,docs_url,request_id}`; `request_id` and `error_code` on every log line | `error.{code,message,details,fields}` + top-level `request_id`; logs have `request_id`, not `error_code` | Additive fields. **Conflict:** `error.code` is already a slug; replacing it with `PTH-…` would break clients that match slugs (UI, CLI, VS Code and JetBrains plugins, MCP). Proposal: keep `code` and add `diag_code` (or keep `request_id` at both levels); decide in an ADR |
| §3.3 UI states | `<ErrorPanel>`, AI troubleshooting, 7 page states | `EmptyState`, `Skeleton`, `Alert`, `Spinner` exist and are used unevenly | ErrorPanel, permission-denied and feature-disabled states, success toasts (no toast primitive exists), AI troubleshooting |
| §4 UI standards | tokens only, WCAG 2.2 AA, page anatomy, server-side tables with saved views, density and stamped CSV, one shared graph component (React Flow + ELK, ADR), responsive, performance budgets | Tokens and both themes exist; `PageHeader` exists; no breadcrumb; client-side CSV of loaded rows; custom SVG graph; ~450 `aria-` attributes, no audit; no reduced-motion rule | Breadcrumb, server-side CSV, saved views, density, graph component and ADR, reduced-motion, accessibility audit, performance measurements |
| §5 sidebar | 12 groups; 55 existing items kept; 9 new items | 9 groups, 58 items (+1 multi-tenant) | See §8.3: the count is 58, not 55; 4 current items are missing from the table |
| §5 app hub | `/applications/$id` with 10 tabs | List plus edit dialog; versions page at `/applications/$id/versions`; findings and SBOM can be filtered by application (`scans/findings.go:333`) | New route and tabs; most tab data exists |

### 8.3 Menu mapping check (prompt §5 against the code)

Checked every row of the §5 table, and the `I` array of the menu design page, against `router.tsx` and `AppShell.tsx`.

**Every existing route named in the table exists.** All 56 routes named in the table resolve to a page in `router.tsx`: the 55 menu items plus `/repositories/import`. The 9 items marked new have no route: Lifecycle overview, Connectors (`/connectors`), CodeGraph, API & endpoints, Threat models, Binary analysis, Remediation workspace, Continuous monitoring and Reverse engineering tools. Only `/connectors` has a route named in the prompt. The other 8 need a route defined in their milestone.

**Mismatches:**

1. **"55 current menu pages" is wrong for 2.2.0.** The menu has **58** items in 9 groups, and 59 on a multi-tenant install. The 55 matches the 1.1.1 menu that the design page was drawn from.
2. **Four current menu items are missing from the table.** Under rule 1 they would be lost from the menu:
   | Item | Route | Group today | Added in | Proposed place (owner to decide) |
   |---|---|---|---|---|
   | Runtime | `/runtime` | Assets | 2.1 (`a814c71`) | 2 · Inventory (running workloads and images are assets), or 9 · Report & monitor |
   | Scan coverage | `/configurations/scan-coverage` | Configurations | 2.0.0 (`2e3f2cc`) | Configurations (unchanged) |
   | Secret validation | `/admin/secret-validation` | Administration | 2.1 (`a814c71`) | Configurations (it is a module setting), or Administration |
   | Organizations | `/installation/organizations` | Installation (multi-tenant only) | 2.2 (`f3c5efd`) | Keep the separate conditional *Installation* group |
3. **"Add repositories" (`/repositories/import`) is not a current menu item.** The page exists and is reached from a button on Repositories (the design page records this as "(button on Repositories)"). It is a new menu *entry* for an existing page, not a moved one.
4. **There is no `/applications/$id` route.** The application profile hub is a new route. It must not break `/applications/$id/versions` or the `?app=` deep link that `/applications` accepts today.
5. **The non-menu list in §5 is incomplete.** It omits `/repositories/imports/$id` (import job progress) and `/installation/organizations`. `/repositories/import/*` covers `/repositories/import/csv` and `/repositories/import/$source` only.
6. **Labels change, routes do not.** Scan Overview, Scan Schedules, Scan Comparison, Import Results, Review Queue, Review Reports and Review Configurations become sentence case. "Overview" (Human Eye) becomes "Human Eye overview". The "Human Eye" menu section disappears. `e2e/tests/human-review.spec.ts:23-32` and `e2e/tests/scanning.spec.ts:23-39` assert these exact labels and sections, so they will fail. This conflicts with M1's "all existing e2e tests pass unchanged" (C11).
7. **Menu visibility is per item.** The new groups mix permissions. For example, 8 · Remediate & gate holds Policies (`settings.manage`, organization-wide) and Pull request checks (`scans.read`, scoped). A group is hidden only when none of its items are visible (`AppShell.tsx:233-234`), so no new rule is needed. Some groups will show partially for scoped users.
8. **The design page's connector list is also drawn from 1.1.1.** It marks as "new" items that 2.2.0 already has:
   - JetBrains IDEs (`ide/jetbrains`)
   - GitHub Enterprise Server and Azure DevOps Server (`scm/providers.go:53,129`)
   - Kubernetes (read-only cluster inventory, `runtimectx/k8s.go`, `00035_runtime_context.sql`)

   It also gives "25 formats" for scanner result import; the code has 232.

### 8.4 Conflicts between the prompt and the code (the code wins for what exists)

| # | Prompt says | Code says | Recommendation |
|---|---|---|---|
| C1 | Base is PATHOS 1.1.1; new work is "PATHOS 2.0" | 2.2.0 released; 2.0.0 exists | Call it "the lifecycle release"; assign no version (rule 2) |
| C2 | Rule 8: multi-tenant out of scope | 2.2.0 ships optional multi-tenancy (off by default), with an extra menu group and organization switcher | Rule 1 wins: keep it; build nothing new for it; test new pages with it off and on |
| C3 | 55 current menu pages | 58 (+1) | §8.3 |
| C4 | `error.code` becomes `PTH-…` | `error.code` is a snake_case slug that clients match | Additive field; ADR |
| C5 | Tool names hidden outside two configuration pages (rule 3) | Tool names show on Findings ("Detected by"), scan details (engine list, `scans/details/OverviewTab.tsx:146`), Human Eye workspace, related findings and Import results (the import format picker names tools by necessity) | Owner decision for Import results; others become "kind of check · confirmed by N engines" |
| C6 | Rule 7: no gate blocks without a policy | PR checks block on a per-repository severity threshold (`repositories.pr_gate_severity`, default `high`, active only when `pr_checks_enabled`; `00020_supply_chain.sql:49-51`, `scans/prchecks.go:184-205`); the CLI gate blocks on the caller's `--fail-on` (`scans/gate.go:45-52`) | Owner decision: does an explicit repository threshold or CI flag count as a policy? If not, M8 must turn them into policy objects |
| C7 | M11 sandbox "never on the PATHOS host" | The 2.1 sandbox (fuzz harnesses, AI-fix test runs) is a sibling container with `network_mode: none` **on the worker host** (`worker/sandbox.go:25-45`) | Keep for fuzzing and fix verification; M11 binary detonation needs a separate VM host as the prompt says |
| C8 | M6: 20 kinds of check × 10 tools | 25 scan types (different split, for example `crypto`, `database`, `ai`, `runtime`, `manual`) and 98 integrations | Map the 20 prompt kinds onto the 25 scan types; do not replace them |
| C9 | "Quick / Standard / Comprehensive / Custom" profiles | Versioned, named profiles; one seeded "Default" (`scans/profiles.go:374-395`) | Add the three as seeded templates beside "Default" |
| C10 | `docs/troubleshooting/*` generated | `docs/user-guide/troubleshooting.md` exists (hand-written FAQ) | Keep the FAQ; link it from the generated pages |
| C11 | M1 done-when: "all existing e2e tests pass unchanged" | §2.3 turns Help into a menu, and §5 removes the "Human Eye" section and renames labels. Three tests assert today's shell: `help.spec.ts:3-13`, `human-review.spec.ts:23-32`, `scanning.spec.ts:23-39` | Owner decision. Option 1: allow these three navigation assertions to change, while every page-render and workflow test stays unchanged. Option 2: keep the old labels (no sentence-case change) and keep Help as a link with an extra menu button beside it. Option 1 is recommended |

### 8.5 Not verified

- The import-format total (232) was taken from `docs/SCANNER_CATALOG.md` and the 2.0.0 changelog, not counted at run time.
- Accessibility (WCAG 2.2 AA) and the performance budgets in §4 have not been measured; no measurement exists in the repository.
- Whether every page renders the loading, empty and error states was not checked page by page.

### 8.6 Decisions on the conflicts (owner-delegated, 2026-11-20)

The owner delegated these decisions ("do whatever feels best, think like me"). Each is applied from M1 onwards.

| # | Decision |
|---|---|
| C1 | The lifecycle release is **PATHOS 3.0** (semantic-versioning major: new navigation, new phases, new error fields). Version numbers are still changed only in release PRs. |
| C2 | Multi-tenancy stays as shipped in 2.2.0 (opt-in, off by default). Nothing new is built for it; every new tenant table follows `docs/MULTI_TENANCY.md` (RLS policy, classification in the isolation test). |
| C3 | The menu has 58 items (59 with multi-tenancy). The four items missing from the prompt's table are kept: Runtime `/runtime` → **3 · Discover** (after Context graph); Scan coverage `/configurations/scan-coverage` → **Configurations** (after Scanners & workers); Secret validation `/admin/secret-validation` → **Configurations** (after Risk & intelligence); Installation › Organizations → first item of **Administration** on multi-tenant installs. |
| C4 | `error.code` keeps the existing snake_case slug (web app, CLI and JetBrains plugin match it). The catalogue code `PTH-<AREA>-<NNNN>` is a new field, **`error.error_code`** (the same key the logs use). All other envelope fields are added inside `error` as the prompt specifies. |
| C5 | Tool names are hidden everywhere except Scan profiles and Scanners & workers, **plus Import results**, where the user must pick the report format of a named tool (a functional necessity). The API keeps tool fields for audit. |
| C6 | A repository's PR gate threshold and the CLI's `--fail-on` are explicit, user-configured policies. One default is not: PR checks currently block at "high" when enabled without a threshold. In M8, enabling PR checks requires choosing block or warn, and existing repositories are migrated to an explicit policy with their current behaviour, so nothing silently changes. |
| C7 | The 2.1 sandbox is a container runner on the worker host. It remains the runner for fuzzing and fix tests; the reverse-engineering sandbox tier (M11, after 3.0) uses a throwaway VM as the prompt says. |
| C8 | The prompt's 20 kinds of check are mapped onto the existing 25 scan types in M6 (a display grouping); no scan type is removed. |
| C9 | M6 adds the Quick / Standard / Comprehensive profiles beside the existing Default profile (which stays). *Implemented in M6* (flag `scan_profile_tiers`, migration 00048); C5 and C8 also: kinds of check in `scantypes.go`, tool names hidden by the web app and enforced by `frontend/src/test/toolNames.test.tsx`. M6 also treats **Scan coverage** (Configurations, listed with Scanners & workers) as a page that may name tools, and leaves tool names on the configuration surfaces where an administrator selects engines by name (Scan targets › Additional tools, Custom rules, security policy and suppression rule conditions); see the M6 report. |
| C10 | The hand-written `docs/user-guide/troubleshooting.md` FAQ stays; the generated catalogue goes under `docs/troubleshooting/`, and the FAQ links to it. |
| C11 | The three e2e tests that pin the old navigation (help.spec.ts:3-13, human-review.spec.ts:23-32, scanning.spec.ts:23-39) may change their navigation and label assertions only; every page-render and workflow assertion stays unchanged. |
| — | SARIF export does not exist, so it is out of scope for version stamping until an export is added. |
| — | Connector questions (integration spec): Generic Git and Bitbucket Pipelines are in M2; Postman and GraphQL come with API discovery (M4). The eight existing integrations missing from the design are listed in the Connectors hub. The inbound webhook limit is raised to 25 MB in M2. OpenBao is listed as Vault-compatible. Cloud vendor SDKs are used where they help, plain HTTP elsewhere (ADR in M2). |
| — | Roadmap open questions (§17.5): **AI prompt retention**: evidence records keep the redacted prompt and response (no secrets or raw source beyond the cited snippet) for 180 days by default, configurable per organization, deleted with the finding's retention. **LINDDUN**: no licence is stated, so its catalogue text is not bundled; only PATHOS's own privacy-threat categories cite it by name and link. **Performance reference client**: the development machine of the benchmarks (i7-13800H, 20 threads, 32 GB, Chromium) until a customer reference exists. **Sidebar regroup**: ships without a feature flag (navigation only, no data or URL change; old URLs keep working). **First connector kinds in M2**: parity for the existing SCM/ticketing/webhook connectors, then Generic Git, GitHub Enterprise and GitLab self-managed with a per-connection CA, Bitbucket Data Center, Bitbucket Pipelines, Vault/OpenBao; cloud accounts (AWS, Azure, GCP) last. **Security classification fields**: data classification, criticality, internet exposure, compliance scope and authentication model, all optional with an onboarding status. **Imported threats without evidence**: labelled *imported, unverified* until linked to evidence. **Legacy gate thresholds**: handled as decided in C6. |
| — | Version build gaps found by the audit (`workers/sca/Dockerfile` hard-codes 1.0.0 for `pathos-depcheck` and `pathos-reach`; `pathosctl` has no version; the proxy ignores `VERSION`) are fixed in M1 with the Commit and BuildDate ldflags. Tables that default to `gen_random_uuid()` (v4) are left as they are; new tables use application-generated UUIDv7. |
