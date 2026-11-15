# Changelog

## [Unreleased] — Phase 2: Premium UI & dashboard (2026-11-15)

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
