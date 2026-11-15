# Development Roadmap

Each phase ends with: working features, automated tests passing, `docker compose up -d` validated, docs updated, and a milestone report (implemented / files / tests / open issues / verify commands / next).

| Phase | Status |
|---|---|
| 0 Environment & architecture | **Done (2026-11-15)** |
| 1 Foundation | **Done (2026-11-15)**: see milestone report below |
| 2 Premium UI & dashboard | Not started |
| 3 Repository & asset management | Not started |
| 4 Scanning engine | Not started |
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
