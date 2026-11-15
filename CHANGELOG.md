# Changelog

## [Unreleased] — Continuous integration (2026-11-15)

### Added
- GitHub Actions CI:
  - Backend: gofmt, vet, race-enabled unit tests, gosec, govulncheck.
  - Integration tests against PostgreSQL 18.
  - Frontend: typecheck, tests, build, npm audit.
  - Full-stack job from a fresh install: smoke test, Playwright, Trivy, ZAP baseline.
- Actions are pinned to commit SHAs. Dependabot updates Go, npm, Docker, Compose and Actions.
- Playwright browser test suite (`e2e/`, `make e2e`): every page renders without page errors or CSP violations, plus the command palette, security headers, schedule lifecycle, notification administration, policies, the finding drawer and the notification centre.

### Fixed
- `backend/internal/secrets` was never committed: the unanchored `secrets/` pattern in `.gitignore` excluded it, so a fresh clone could not build. The pattern is now `/secrets/`. Found by the fresh-install CI dry run.
- Command palette: typing a page name and pressing Enter right away opened the Dashboard, because page matching used the debounced query. It now uses the live input.
- Integration test files were not gofmt-formatted (`go fmt ./...` skips build-tagged files); CI now checks with `gofmt -l`.

## Phase 8: Enterprise hardening (2026-11-15)

### Added
- API rate limiting (GCRA in Valkey) with `429` and `Retry-After`; tuned with `PATHOS_RATE_LIMIT_SCALE`.
- Keycloak admin console restricted to `KEYCLOAK_ADMIN_ALLOW`; optional TOTP enrolment for new users (`PATHOS_REQUIRE_MFA`).
- `docker-compose.prod.yml` production override, plus `backup.sh`, `restore.sh` and `upgrade.sh`, and the `docs/OPERATIONS.md` runbook.
- OpenTelemetry traces and metrics (OTLP/HTTP) with route-level spans and platform gauges; optional Grafana LGTM profile.
- S3-compatible object storage for scan artifacts (SeaweedFS profile) and `pathosctl migrate-artifacts`.
- `make security` (gosec, govulncheck, npm audit, Trivy, ZAP baseline) and `make load-test` (k6 with 100k-finding seed data).

### Fixed
- The worker context reader now resolves symlinked directories (defence in depth).
- Valkey crash-looped after any restart; it now runs unprivileged as its own user.
- 42 fixable HIGH/CRITICAL vulnerabilities in our images: go-jose, plus Caddy and Gitleaks rebuilt with patched dependencies; Debian packages upgraded and pip removed from the worker runtime.
- TLS clients without SNI are served; cross-origin isolation headers were added.
- The dashboard findings trend is 10× faster on large datasets.

## Phase 7: Scheduling & notifications (2026-11-15)

### Added
- `scheduler` role and compose service. A Postgres advisory lock elects the leader, so replicas are hot standbys. It runs cron schedules (with time zones) targeting the organization, a region, a business unit (including children), a repository or a scan profile, with per-schedule priority. It catches up missed runs once and reports them, recovers expired worker leases and reports offline workers.
- Schedules API and UI: create, edit, pause, run now, delete, cadence presets with a live preview of the next runs and repository count, scheduler and queue health, and a "Last run" link to the schedule's scan jobs.
- Notification engine: a trigger-fed outbox, eight built-in rules, custom rules (event, minimum severity, region, business unit or repository scope, role/user/email/dynamic recipients, email and in-app channels), editable templates with a live preview, SMTP settings with a test email, delivery history with retry, and an in-app notification centre with an unread badge.
- Events: new findings, scan failed, SLA breached, finding assigned, risk acceptance requested and decided, schedule missed, worker offline.
- SCM metadata re-sync: nightly in `jobs`, or **Re-sync metadata** per connection.

### Fixed
- The `jobs` service was on the internal `data` network only, so automated AI reviews could not reach the provider. It now also joins `edge` (with `HTTPS_PROXY` support), which notification email also needs.
- Assignments now record the acting user, so self-assignment is not notified.

## Phase 6: Vulnerability management (2026-11-15)

### Added
- Finding lifecycle enforced by a database trigger: append-only status history with actor/source/reason, SLA deadline on detection, recurrence counter when a fixed finding reappears.
- Manual triage API and UI: status changes with required reasons, assignment, atomic bulk status/assign, history timeline, SLA and assignee columns and filters.
- Risk acceptance workflow: time-boxed (≤ 365 days), approved by a different person with `findings.accept_risk`, revocable, findings reopen automatically at expiry (jobs role, every 10 minutes).
- SLA policies per severity (default 7/30/90/180 days) with recomputation; license policy (deny/review by SPDX id).
- SBOM inventory: Syft CycloneDX components stored per scan, component search across repositories with license-policy matches and open vulnerability counts, CycloneDX download per repository.
- UI pages: Risk acceptances, SBOM inventory, Policies. All 24 dashboard KPIs are now live.

### Fixed
- Client disconnects are no longer logged as internal errors.
- `openapi.yaml` is valid YAML again (an unquoted description broke parsing).

## Phase 5: AI review & MCP (2026-11-15)

### Added
- AI providers: Anthropic (official Go SDK, default `claude-opus-5-5`, structured output, prompt caching, refusal fallbacks), OpenAI and xAI. Keys are encrypted and tested.
- Versioned AI configurations, a review queue in the jobs role, auto-review after scans, and per-review transmitted-payload hashes.
- Redaction, nonce-fenced untrusted evidence, strict output validation, code context captured by workers.
- Approval queue with a critical-finding guardrail and four-eyes for interactive reviews.
- PATHOS MCP server (`/mcp`) with personal API tokens; MCP server registry with tool allow-lists.

## Phase 4: Scanning engine (2026-11-15)

### Added
- Scanner catalog (52 integrations), versioned scan profiles with mandatory Gitleaks, scan jobs with priority leasing, retries, cancellation and webhook triggers.
- `worker-core` image (Gitleaks, Opengrep, Trivy, Syft, Grype, OSV-Scanner, Checkov; checksum-pinned) and the `pathos-worker` agent with a hardened clone. Internal worker API with per-worker revocable tokens.
- Squid egress proxy with an allowlist and denial of private and metadata destinations.
- Server-side normalization: SARIF and Grype JSON parsing, cross-tool de-duplication, line-independent fingerprints, auto-resolution and a security gate. Raw report/SBOM storage with retention.
- PATHOS baseline Opengrep rules (Apache-2.0).
- UI: Scans, Findings (read-only), Scan profiles, Scanners & workers, Scan now / bulk scan; live scanning KPIs and charts.

## Phase 3: Repository & asset management (2026-11-15)

### Added
- SCM connections: GitHub (PAT or GitHub App), GitHub Enterprise Server, Azure DevOps Services and Server. Credentials are encrypted and write-only; outbound calls are SSRF-protected.
- Repository discovery and import (selection with defaults, CSV bulk onboarding with dry run), live branch selection, placement and classification, archive/delete, and bulk tagging.
- Tag categories with mandatory and single-value rules; applications with owners.
- Signature-verified GitHub and Azure DevOps webhook receivers with replay protection.
- Repository-scoped RBAC through the BU → region → organization hierarchy.
- Dashboard KPIs Repositories, Applications and Without owner, plus a criticality chart; repositories and applications in global search.

## Phase 2: Premium UI & dashboard (2026-11-15)

### Added
- Dashboard API with the 24-KPI catalog and chart panels. KPIs that have no data source yet are reported as "not yet available", never with placeholder numbers. Values are permission-aware, with period and geography filters.
- Global search API and the ⌘K command palette.
- UI components: KpiCard, FilterBar and DataTable (column chooser, CSV export). Also a notification centre shell, a dashboard page with lazy-loaded charts, and deep-linkable filters on the Users and Audit pages.
- Keycloak login theme `pathos`.
- Audit log `outcome` filter.

## Phase 1: Foundation (2026-11-15)

### Added
- Go backend (`pathos` with `api` and `jobs` roles, `pathosctl`): validated configuration (with `_FILE` secret support), slog JSON logging with secret redaction, and `/healthz` and `/readyz`.
- PostgreSQL schema and goose migrations: organizations, regions, countries, business units, users, teams, roles, permissions, role assignments, encrypted secrets, and an append-only audit log partitioned by month. Runtime role `pathos_app` with least privilege.
- RBAC: 29-permission catalog, 9 system roles, and scoped assignments (organization, region, business unit with descendants, repository). Includes privilege-escalation and last-super-admin protections, and SQL scope filters.
- AES-256-GCM envelope encryption for secrets, with versioned master keys and `pathosctl rotate-master-key`.
- Keycloak `pathos` realm import, BFF OIDC login (PKCE), Valkey sessions, CSRF protection, logout through Keycloak, JIT provisioning and bootstrap super admin.
- User management API: list and search, invite with Keycloak account creation and set-password email, deactivate/reactivate with immediate session revocation, and role grant/revoke. Also organization structure and audit log endpoints. OpenAPI spec in `backend/api/openapi.yaml`.
- React app shell (Vite, TypeScript, Tailwind 4, TanStack Query/Router): login, navigation, light/dark theme, and Users, Organization and Audit log screens.
- `docker-compose.yml` (proxy, migrate, api, jobs, postgres, valkey, keycloak, mailpit[dev]) with health checks, internal networks, hardened containers and digest-pinned images. Also `.env.example` and `deploy/scripts/install.sh`.
- Tests: Go unit tests, Go integration tests against PostgreSQL, Vitest frontend tests, and an end-to-end smoke test (`scripts/smoke-test.py`).
