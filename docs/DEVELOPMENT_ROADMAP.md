# Development Roadmap

Each phase ends with: working features, automated tests passing, `docker compose up -d` validated, docs updated, and a milestone report (implemented / files / tests / open issues / verify commands / next).

| Phase | Status |
|---|---|
| 0 Environment & architecture | **Done (2026-11-15)** |
| 1 Foundation | **Done (2026-11-15)**: see milestone report below |
| 2 Premium UI & dashboard | **Done (2026-11-15)**: see milestone report below |
| 3 Repository & asset management | **Done (2026-11-15)**: see milestone report below |
| 4 Scanning engine | **Done (2026-11-15)**: see milestone report below |
| 5 AI & MCP | Not started |
| 6 Vulnerability management | Not started |
| 7 Scheduling & notifications | Not started |
| 8 Enterprise hardening | Not started |

## Phase 1: Foundation
- Go module skeleton (`cmd/pathos` roles, `pathosctl`), config loading with validation, slog JSON logging with secret redaction, health/readiness endpoints.
- PostgreSQL + goose migrations: organizations, regions/countries/BUs (seeded), users, teams, roles, permissions, role_assignments, secrets, audit_logs.
- Envelope encryption package plus master-key handling.
- Keycloak realm import (`pathos` realm, `pathos-web` confidential client, bootstrap admin with forced password change). BFF OIDC login/logout, Redis-backed sessions, CSRF.
- RBAC engine: 9 seeded roles, permission catalog, scoped assignments, middleware + SQL scope filters. User management API (list, invite/provision, deactivate, assign roles). Audit logging on every mutation.
- React app shell (Vite/TS/Tailwind/shadcn), login redirect, user management screens.
- `docker-compose.yml` with proxy, api, migrate, postgres, valkey, keycloak, seaweedfs, mailpit(dev). Health checks, networks, volumes, `.env.example`, `install.sh`.
- Tests: Go unit tests (authz, crypto, config), integration tests with testcontainers (migrations, RBAC queries), frontend unit tests, compose smoke test script.
- Docs: README, INSTALLATION, SECURITY, RBAC_MATRIX, API_DOCUMENTATION (OpenAPI), CHANGELOG.

## Phase 2: Premium UI & dashboard
Design tokens, light/dark themes, logo/favicon, Keycloak login theme, navigation shell, ⌘K global search, notification centre shell, `DataTable`/`FilterBar`/`KpiCard` components. Dashboard aggregate endpoints (SQL-backed, scope-filtered) with all 24 KPIs and charts. KPIs whose data source lands in a later phase are shown as **"Not yet available"** rather than with fake numbers. Drill-down links.

## Phase 3: Repository & asset management
SCM connections (GitHub App / PAT, GHE base URL, Azure DevOps Services/Server), repo discovery and import, bulk onboarding (selection + CSV), branch selection, metadata and classification, tag categories and mandatory tags, bulk tagging, applications, archive/delete. Webhook receivers (signature-verified) for push, PR and merge.

## Phase 4: Scanning engine
Catalog seeding from SCANNER_CATALOG, Adapter interface, shared SARIF parser, worker agent + lease API, `worker-core` image (Gitleaks, Opengrep, Trivy, Syft, Grype, OSV-Scanner, Checkov), egress proxy, scan profiles with versioning (Gitleaks locked on), result normalization and fingerprinting, raw report storage. Then the remaining worker families.

## Phase 5: AI & MCP
Provider interface and Anthropic / OpenAI / xAI adapters, AI configurations (versioned), redaction, prompt-injection-resistant prompt assembly, JSON-schema-validated output, review pipeline as background jobs, human approval queue, PATHOS MCP server (interactive mode), MCP server registry with approval and tool allow-lists.

## Phase 6: Vulnerability management
Findings UI, lifecycle state machine and history, assignment, SLA policies and deadlines, accepted-risk workflow with expiry, recurrence tracking, SBOM inventory and component search.

## Phase 7: Scheduling & notifications
Leader-elected scheduler, cadence by repo / region / BU / profile, priorities, retries, cancellation, missed-schedule detection, worker health. SMTP settings, templates, rules, delivery history.

## Phase 8: Enterprise hardening
Load tests (k6), security tests (gosec, Trivy on our images, ZAP baseline against PATHOS itself), production compose overrides, backup/restore/upgrade scripts validated, OTel exporters, final documentation.

## Phase 1 milestone report (2026-11-15)

**Implemented:** everything in the Phase 1 scope above, with these deviations:

| Planned | Delivered | Reason / follow-up |
|---|---|---|
| sqlc-generated queries | Hand-written pgx queries in each package's `store.go` | Small surface so far. Revisit when Phase 3 adds many list/filter queries |
| oapi-codegen server types; openapi-typescript client | Hand-written OpenAPI 3.1 spec (`backend/api/openapi.yaml`) plus a typed fetch client | Wire codegen in Phase 2, when the API surface grows |
| testcontainers-go | `scripts/test-integration.sh` (throwaway PostgreSQL container on a private network) | Avoids mounting the Docker socket into the test container |
| SeaweedFS in compose | Not deployed yet | No object storage consumer until Phase 4 (raw reports, SBOMs) |
| User-management "teams" API | Schema only (`teams`, `team_members`) | UI/API for teams lands with Phase 3 ownership features |

**Tests:**
- Go unit tests (config, logging redaction, envelope crypto, RBAC, RBAC doc sync, HTTP helpers, open-redirect guard).
- Go integration tests against PostgreSQL 18: idempotent migrations, `pathos_app` privilege denials, JIT provisioning rules, BU-hierarchy scoping, secret AAD binding and rotation, audit pagination.
- Vitest frontend tests.
- End-to-end smoke test: 35 checks through the real proxy and Keycloak.
- Playwright run of the UI with no runtime errors.

**Verify:**
```bash
make test && make test-integration
docker compose up -d --build --wait && make smoke
```

**Open issues:** see "Known gaps" in [SECURITY.md](SECURITY.md). Keycloak realm changes after first start must be made in the Keycloak admin console (the import is first-start only).

**Next:** Phase 2, the premium UI and dashboard.

## Phase 2 milestone report (2026-11-15)

**Implemented:**
- **Dashboard API** (`GET /api/v1/dashboard`). The 24-KPI catalog plus 6 chart panels are defined once in `backend/internal/dashboard/catalog.go`, each tagged with its data-source phase and required permission. Every item returns one of three states: `ok` with values, `not_yet_available` (no number, shows the phase that delivers it) or `restricted` (no value is sent). Filters: period (7/30/90/365 days), region, country, business unit. KPIs that are not geo-scoped are labelled `org_wide` when a geo filter is set.
- **Live today:** Active users (with trend and sparkline), Pending invitations, Security events (denied/failed actions vs the previous period), Sign-ins per day, Administrative changes.
- **Global search** (`GET /api/v1/search`) across users, business units, regions and countries, permission-aware, 5 results per type.
- **UI:**
  - ⌘K / Ctrl+K command palette (search, navigation, theme, sign out) and a notification centre shell.
  - `KpiCard` (value, polarity-aware delta, sparkline, drill-down), `FilterBar` and `DataTable` (column chooser saved per browser, CSV export with formula-injection protection, load more).
  - Users and Audit pages rebuilt on `DataTable`, with URL-driven filters so drill-downs and search results deep-link. Charts are lazy-loaded (Recharts kept out of the main bundle).
- **Keycloak login theme** `pathos` (`deploy/keycloak/themes/pathos`): PATHOS mark and colours over `keycloak.v2`.

**Upgrading a Phase 1 install:** the realm import runs only on first start. In the Keycloak admin console set *Realm settings → Themes → Login theme* to `pathos`. After any theme change, run `docker compose up -d --force-recreate keycloak`, because Keycloak keeps a gzip cache of theme files inside the container.

**Tests:** dashboard catalog and filter unit tests; integration tests for dashboard values, permission restrictions and search scoping; frontend tests for KpiCard states, delta polarity, CSV escaping and href splitting; smoke test now has 40 checks; Playwright run of login, dashboard, palette, drill-down, notifications and dark mode.

**Deviations:** OpenAPI code generation is still deferred (spec updated by hand). Saved table views are not implemented; column choices persist per browser.

**Next:** Phase 3, repository and asset management.

## Phase 3 milestone report (2026-11-15)

**Implemented:**
- **Schema** (migration 00002): `scm_connections`, `applications`, `repositories`, `tag_categories`, `tags`, `repository_tags`, `webhook_deliveries`. Same-organization integrity uses composite foreign keys throughout.
- **SCM clients** (`internal/scm`):
  - GitHub: github.com and Enterprise Server; PAT or GitHub App, with an RS256 app JWT and a cached installation token; Link-header pagination restricted to the same host.
  - Azure DevOps: Services and Server, PAT.
  - An SSRF-safe HTTP client sits underneath both.
- **Connections:** create (tested immediately), test, rename, change owner, rotate credentials, rotate webhook secret (shown once), delete (credentials destroyed).
- **Repositories:**
  - Discovery with import state; import by selection (with defaults) or CSV (dry run, per-line results); re-import is idempotent.
  - Live branch selection; placement (application, business unit, country), classification (criticality, environment), technologies and scan toggle.
  - Archive/unarchive, delete (archived only), bulk tagging (atomic, up to 500).
- **Scoped access:** repository-scope grants work end to end. Region grants match through the repository's country; BU grants include descendants; moves require permission at the destination.
- **Tags:** categories with *mandatory* and *single-value* rules, enforced on import, edit and bulk tag. Non-compliance is counted when a rule is tightened later.
- **Applications:** create/update/archive with owner and security owner, scoped by business unit.
- **Webhooks:** GitHub (HMAC) and Azure DevOps (basic auth) receivers normalise push / pull request / merge events, de-duplicate deliveries and expose an `OnEvent` hook for Phase 4.
- **Dashboard and search:** the *Repositories*, *Applications* and *Without owner* KPIs plus a *Repositories by criticality* chart are now live, scope- and geo-filtered. Global search covers repositories and applications.
- **UI:** Repositories (filters, bulk actions, drawer editor with branch picker), Import (selection + CSV), Applications, SCM connections, Tags.

**Tests:**
- SCM unit tests against fake GitHub and Azure DevOps servers: pagination, cross-host link refusal, App JWT signature and token caching, auth failure mapping, branches.
- SSRF policy and dial-time blocking; webhook signature and event parsing.
- An integration test of the full lifecycle: taxonomy, connection, discovery, mandatory tags, import/CSV dry run, BU/region/repository scoping, destination checks, bulk-tag rules, applications, webhooks (signature, replay, provider mismatch), archive/delete.
- Smoke test now has 50 checks, including a live call to `api.github.com` that confirms egress and credential-failure handling.
- A Playwright pass over every new screen.

**Deviations:** repository metadata (default branch, archived flag, last push) is captured at import time; periodic re-sync with the SCM moves to the Phase 7 scheduler. Webhook events are recorded but trigger nothing until Phase 4.

**Next:** Phase 4, the scanning engine.

## Phase 4 milestone report (2026-11-15)

**Implemented:**
- **Catalog:** all 52 integrations (plus Syft), synced from `internal/scanners/catalog.go`. The seven `worker-core` tools are runnable today; the rest are marked *planned* with their worker family.
- **Scan profiles:** immutable versions (settings plus scanners, with a version history and change notes). Gitleaks is locked on, enforced by the API and by a deferred database constraint trigger. Also: a default profile, per-repository assignment, severity threshold, glob exclusions, timeout, raw-report retention and a security gate on new critical findings.
- **Jobs:**
  - Manual, bulk and webhook-triggered (push/merge to the scan branch).
  - Each repository has at most one queued job, which absorbs new triggers, and one running job.
  - Priority queue with `SKIP LOCKED` leasing, lease heartbeats, expiry/retry (3 attempts) and cancellation, delivered to the worker through its heartbeat.
- **Worker API** (`:8081`, internal network only, 404 at the proxy):
  - The bootstrap token is exchanged for a per-worker token (hashed, revocable). A revoked worker name cannot re-register.
  - Workers receive a clone credential per job: a ≤1 h installation token for GitHub Apps, otherwise the PAT.
- **`worker-core` image:**
  - Gitleaks 8.30.1, Opengrep 2.0.0, Trivy 0.76.2, Syft 1.57.1, Grype 0.121.3, OSV-Scanner 2.7.1, Checkov 3.4.5. Every binary is pinned by SHA-256.
  - Runs non-root with a read-only root filesystem, `cap_drop: ALL`, a tmpfs workspace, and memory and PID limits. No Docker socket and no platform secrets.
  - Hardened shallow clone: credential via environment only, no hooks, no `file://`/`ext::`, no symlinks, fsck, no redirects, size cap. `.git` is deleted before scanning.
  - Each tool runs in its own process group, so a timeout kills every child.
- **Egress proxy** (Squid): workers can only reach the allowlisted SCM hosts and vulnerability databases. Private ranges and cloud metadata are denied, and access is logged to a volume.
- **Normalization** (server-side): a SARIF parser plus the Grype JSON parser (for CVE aliases, fixes and CVSS); severity mapping; repository-relative paths; and line-independent fingerprints.
  - Cross-tool SCA de-duplication: the same CVE in the same package from Trivy, Grype and OSV is one finding listing all three tools.
  - Findings below the threshold and in excluded paths are dropped.
  - Findings no longer reported are auto-fixed, but only when every scanner that detected them succeeded.
- **Raw reports and SBOMs** stored gzip-compressed and downloadable; a nightly retention prune.
- **PATHOS baseline Opengrep rules** (12 original rules, Apache-2.0). Community rule packs with Commons Clause terms are not bundled (D5); administrators mount their own at `workers/rules-extra`.
- **Dashboard:** open/critical/high findings, risk score, exposed secrets, vulnerable dependencies, scan coverage, scans completed and success rate, plus the severity trend, distribution, riskiest repositories and scans-by-scanner charts are live.
- **UI:** Scans (live polling, per-scanner results, raw downloads, cancel), Findings (read-only, severity summary, filters, sightings), Scan profiles (editor with locked Gitleaks and history), Scanners & workers, and *Scan now* / bulk scan / profile selection on repositories.

**Verified end to end:**
- A live scan of the public `snyk-labs/nodejs-goof` through the egress proxy: all 7 tools succeeded in about 2 minutes on a cold cache.
- 814 raw SCA results were de-duplicated into 336 findings.
- The rescan took 24 s with cached databases, and fingerprints were stable (1 new finding from an updated rule, 0 spuriously fixed).

**Tests:**
- Parser unit tests on real tool output: counts, redaction, Opengrep normalization, cross-tool fingerprint equality, Grype enrichment, exclusions and malformed input.
- The `TestScanPipeline` integration test: profiles, coalescing, RBAC, worker auth and isolation between workers, fixture ingestion, dedup, auto-fix with a failed scanner, cancel, lease expiry, revocation and default-profile protection.
- Smoke test now has 58 checks.

**Deviations:**
- Raw reports and SBOMs are stored in PostgreSQL (`scan_artifacts`, gzip) behind one code path, instead of SeaweedFS/S3. Moving them to object storage is scheduled for Phase 8.
- Pull-request webhooks are recorded but do not trigger scans (findings are tracked per scan branch).
- Only the `core` worker family is built.
- Public repositories fall back to an anonymous clone when the stored credential is rejected; private ones never do.

**Next:** Phase 5, AI review and MCP.
