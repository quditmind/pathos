# Multi-tenancy

One PATHOS installation can host several isolated **organizations** (tenants), for example for a managed security service provider or a hosted offering. No data of one organization is visible to, or changeable by, another. This note records the audit made before the change, the design, what is enforced where, how identities map to organizations, how to enable it, and what is not covered.

A single-organization install is unchanged: multi-tenancy is off until an operator runs `pathosctl multi-tenancy enable`, and the existing organization becomes the first organization when it is enabled.

## 1. Audit (before the change)

PATHOS was designed for one organization per deployment (decision D3 of the ASPM roadmap), but the schema already carried `organization_id` on almost every table, and handlers already took the organization from the authenticated principal. The audit below was made against the 2.1 branch (migrations up to 00035), with every migration applied to an empty PostgreSQL 18 database.

### 1.1 Tables

| Kind | Count | Tables | Scoping |
|---|---|---|---|
| Tenant tables with `organization_id NOT NULL` | 124 (plus the audit log partitions) | repositories, findings, scan_jobs, users, secrets, audit_logs, … (every table not listed below) | The column; most child tables reference their parents with composite `(organization_id, id)` foreign keys |
| Tenant table with nullable `organization_id` | 1 | `roles` | `NULL` = the 11 system roles (global, read-only for the application); otherwise an organization's custom role |
| Child tables without `organization_id` | 7 | `application_version_repositories`, `custom_rule_versions`, `fix_pull_request_findings`, `pr_findings`, `profile_scanners`, `source_upload_parts`, `role_permissions` | Through their parent rows |
| Global reference data | 12 | `eol_cycles`, `eol_products`, `intel_epss`, `intel_feed_runs`, `intel_feeds`, `intel_kev`, `intel_vulns`, `package_health`, `permissions`, `scanner_catalog`, `scheduler_state`, `goose_db_version` | Shared by design: public vulnerability and end-of-life data, the permission catalog, the scanner catalog, scheduler leader state, migration bookkeeping |
| `organizations` | 1 | | The tenant itself |
| Audit log partitions | 5 at the time | `audit_logs_YYYY_MM`, `audit_logs_default` | Through the parent table |

Single-column foreign keys between two tenant tables: **87** (for example `scm_connections.secret_id → secrets.id`, `scan_jobs.leased_by → workers.id`, `notifications.user_id → users.id`). Foreign key checks do not apply row-level security, so the database itself did not prevent a row of one organization from pointing at another organization's row.

### 1.2 Query paths

| Path | How the organization was chosen | Finding |
|---|---|---|
| REST API handlers (387 routes in 56 files) | From the authenticated principal (`p.OrganizationID`), never from client input: no request body, path or query parameter carries an organization | Good. But a principal with an organization-wide grant was authorized for *any* resource id without the resource being looked up, so several handlers answered `200` with an empty result for another organization's id instead of `404` (no data, but existence semantics differed) |
| Authorization hierarchy (`org.Hierarchy`) | A **single process-wide** organization id (`PATHOS_ORG_SLUG`) | Gap: wrong for any second organization |
| Sessions | Redis; the session already stored the organization | Good |
| API tokens, MCP tokens | Looked up by hash; carry their organization | Good |
| Worker API | Workers registered into the single process-wide organization; leases already filtered by the worker's organization | Gap: no way to register a worker for another organization |
| Inbound SCM webhooks | Connection id in the URL, signature checked with that connection's secret | Good |
| Scheduler, jobs (AI review queue, notifications, imports, feeds, risk recompute, runtime sync, ticket sync, retention, fix PR tracking, EOL) | Iterate over all rows; each row carries its organization | Good at the application level; no database backstop |
| Repository import worker | Authorized placements against the single process-wide hierarchy | Gap |
| Exports, search, reports | Through the API handlers above | Good |
| Bulk inserts (SBOM components and dependencies, licences, code imports, EOL, material changes, scan commits) | `COPY` | Incompatible with row-level security (PostgreSQL rejects `COPY FROM` into such tables) |
| Object storage | Keys `artifacts/<org>/…`, `snapshots/<org>/…`, `uploads/<org>/…`, `evidence/<org>/…` | Good |

### 1.3 Global settings and caches

- Environment settings are installation-wide: database, Redis, master keys, OIDC client, offline mode, SCM network policy, rate limits, object storage, ClamAV, the worker bootstrap token, retention. They stay installation-wide.
- `PATHOS_ORG_SLUG` named *the* organization. It now names the **default** organization: the first one, the one that cannot be suspended or deleted, and where workers without an explicit organization register.
- In-process caches: the SCM machine-token cache is keyed by a hash of the credential (identical credentials share a token, different credentials never do). The rate limiter is keyed by user id (users are per organization). No other process-wide cache holds tenant data.
- The scanner catalog is global: workers (run by the operator) register plugin and manifest tools into it, and every organization sees them.

### 1.4 Unique constraints

| Constraint | Decision |
|---|---|
| `users.keycloak_subject` unique installation-wide | **Changed** to unique per organization: one person has one users row per organization they belong to |
| `organizations.slug` | Stays global (it identifies the organization) |
| Readable keys (`repositories.repository_key`, `applications.application_key`, `scan_jobs.scan_key`, `human_reviews.review_key`, `human_review_evidence.evidence_key`) | Stay globally unique: they come from global sequences, so they cannot collide. Residual: an organization can infer roughly how many such objects the installation created (see §6) |
| Hash and child-id keys (`workers.token_sha256`, `api_tokens.token_sha256`, `scan_results(scan_job_id, scanner_key)`, …) | Global by nature (UUIDs or hashes); no change |

## 2. Design

Defence in depth with two independent layers, plus database constraints.

### 2.1 Application layer

- **The organization comes from the authenticated identity only.** The authentication middleware puts the principal's organization into the request context (`tenant.WithOrg`): a browser session's active organization, an API token's organization, an MCP token's organization, a worker's organization, or an inbound webhook connection's organization. Handlers keep using `p.OrganizationID` in every query, as before.
- **Authorization proves the target belongs to the organization.** `authz.Authorizer.Can` resolves the ancestors of every non-organization target (repository, business unit, region) inside the request's organization, also for organization-wide grants, and an organization-scope target must be the principal's own organization. Another organization's resource is therefore answered like a missing one (`404`, or `403` where a handler maps authorization failures so).
- The hierarchy takes the organization from the request context; the default organization is only a fallback for single-organization installs.
- Handlers that list a sub-resource now check the parent exists in the organization (worker job routes, webhook deliveries, custom rule versions, runtime cluster and registry runs and images, notification retry, runtime sync).

### 2.2 Database layer: row-level security

Migration 00041 defines a policy on every tenant table:

```sql
USING      (organization_id = ANY ((SELECT pathos_visible_orgs())::uuid[]))
WITH CHECK (organization_id = ANY ((SELECT pathos_visible_orgs())::uuid[]) OR (SELECT pathos_rls_bypass()))
```

- `pathos_visible_orgs()` returns the organization in `app.organization_id`; with `app.rls_bypass = 'on'` (and no organization) all organizations; otherwise **none**. The scalar subquery is evaluated once per statement and keeps `organization_id` indexes usable.
- The connection pool (`internal/platform/db`) sets both variables with `set_config` on **every connection checkout**, from the context of the query that checks the connection out, overwriting whatever the connection carried before. This gives the guarantee of a per-transaction `SET LOCAL` (a connection never keeps a previous request's scope) and also covers queries outside explicit transactions. A connection whose scope cannot be set is destroyed, never handed out.
- Child tables without `organization_id` follow their parents (`EXISTS` on the parent, whose own policy applies); where a child links two tenant tables both parents must be visible. Organizations see only their own `organizations` row. System roles stay readable; custom roles are per organization.
- **Fail closed:** a context with neither an organization nor system scope sees no tenant rows at all.
- **New tables are isolated by default:** `pathos_apply_app_grants()`, which every migration calls, creates the standard policy on any new table with an `organization_id` column, and turns row-level security on when multi-tenancy is enabled. An integration test fails if a table without `organization_id` and without a policy is added and not classified as global reference data.
- **Roles:** `pathos_owner` owns the tables and runs migrations and `pathosctl`; table owners are not subject to row-level security (no `FORCE`). `pathos_app` (API, jobs, scheduler) is. PostgreSQL superusers bypass it as always.
- **Audit log partitions:** the application has no privileges on them any more (it uses the parent table, whose policy applies; inserts route to partitions without partition privileges).
- **Enforcement follows the mode:** the policies exist on every install, but row-level security is enabled only by `pathosctl multi-tenancy enable` (`installation_settings.multi_tenant`). Single-organization installs keep it off: with one organization it could hide nothing, and PostgreSQL plans some queries more conservatively under row-level security (§6).
- `COPY FROM` is not supported with row-level security; with multi-tenancy enabled the seven bulk inserts send multi-row `INSERT` statements instead, which the policies check.

### 2.3 System scope

Some code legitimately works across organizations. It runs in **system scope** (`tenant.WithSystem`, `app.rls_bypass = 'on'`): the scheduler and the jobs service (each row carries its organization), the lookups that authenticate a request before its organization is known (API token, MCP token and worker token hashes, the webhook connection id) — immediately narrowed to the found organization — and installation administration behind an explicit installation-administrator check. A narrower scope always wins (`tenant.WithOrg` inside system scope switches the bypass off); the repository import worker narrows each item to its organization. Every function that may widen the scope is listed in `systemScopeAllowed` in `backend/internal/server/tenancy_gaps_test.go`; adding one fails the test until it is reviewed.

### 2.4 Database constraints

Migration 00042 adds a composite `(organization_id, <column>) → (organization_id, id)` foreign key next to each of the 86 single-column references between two tenant tables (all except role assignments), and a trigger that lets a role assignment use only a system role or a custom role of the same organization. The database itself now rejects a reference from one organization to another, for every role including the owner. The keys are `NO ACTION` (checked after the original key's `CASCADE`/`SET NULL`), so deletes behave as before.

## 3. Organizations and administrators

| | Who | What |
|---|---|---|
| **Installation administrator** | People listed in `installation_admins` (by identity-provider subject) | Create, list, suspend, resume and delete organizations; read the installation audit log. Nothing else: an installation administrator sees an organization's data only through an ordinary membership with ordinary roles in it |
| Organization roles (`super_admin`, `platform_admin`, …) | Per organization, as before | Everything inside one organization |

The brief called the new role "platform administrator". PATHOS already has an organization role named **Platform Administrator** (`platform_admin`, operates one organization's settings), so the new installation-level role is called **installation administrator** everywhere (UI, API, configuration, CLI) to keep the two apart.

- Bootstrap: `PATHOS_INSTALLATION_ADMIN_EMAIL` becomes an installation administrator at its first sign-in with a verified email. Afterwards: `pathosctl installation-admin grant|revoke <email>` and `pathosctl installation-admin list` (the person must have signed in once).
- Signing in needs a membership. `PATHOS_INSTALLATION_ADMIN_EMAIL` joins the default organization (without roles) at the first verified sign-in; other installation administrators need a membership somewhere.
- **Create** (`POST /api/v1/installation/organizations`): the organization with the default regions, scan profile, SLA and licence policies, notification rules, MCP registry entry and asset classifications; optionally an invited **super administrator** by email (linked at their first sign-in with a verified email).
- **Suspend**: members cannot sign in to it (a session in it can only switch organization or sign out), its API tokens, MCP tokens and workers are refused (`403 organization_suspended`), and the scheduler starts no scheduled scans for it. Work already queued (notifications, AI review queue items, intelligence recompute) is still processed by the jobs service. The default organization cannot be suspended.
- **Delete**: only a suspended organization, confirmed by its slug. Stored objects (scan artifacts, source snapshots, upload parts, review evidence) are deleted first; then `pathos_delete_organization` (a `SECURITY DEFINER` function owned by the migration owner) deletes every row of the organization, including its audit log, and the organization. The installation audit log keeps the lifecycle record. The default organization cannot be deleted. Large organizations are deleted in one transaction.
- Every action is in the **installation audit log** (`installation_audit_logs`, append-only for the application); creation is also recorded in the new organization's own audit log.

## 4. Identity: users, memberships and the switcher

- A person is identified by the identity-provider (OIDC) **subject**. Membership of an organization is a users row in that organization; one subject has at most one row per organization. Roles stay per organization.
- **Login** (multi-tenant mode) collects the person's organizations from:
  1. organizations where the subject already has a users row (not deactivated);
  2. organizations with a pending **invitation** for the email, only when the identity provider asserts the email is verified;
  3. active organizations named in the **organization claim** of the ID token (just-in-time membership without roles, like a first sign-in in a single-organization install).
  4. the default organization, for the verified `PATHOS_BOOTSTRAP_ADMIN_EMAIL` and `PATHOS_INSTALLATION_ADMIN_EMAIL` (so a fresh multi-tenant install can be administered).
  Suspended organizations and deactivated memberships are skipped. A person with none is refused (`no_organization`). The session starts in the default organization when the person belongs to it, else in the first one. `PATHOS_BOOTSTRAP_ADMIN_EMAIL` applies to the default organization only.
- **Keycloak:** the shipped realm adds a *Group Membership* mapper to the `pathos-web` client (claim `groups`, full group path, ID token). Create a group `/pathos/<slug>` per organization and add people to it. `deploy/keycloak/setup.sh` adds the mapper to existing realms. Settings: `PATHOS_OIDC_ORGANIZATION_CLAIM` (default `groups`), `PATHOS_OIDC_ORGANIZATION_PREFIX` (default `/pathos/`; `-` takes every claim value as a slug, for an IdP that emits a plain list of slugs).
- **Other OIDC providers:** emit a claim listing the person's organization slugs (or group paths) and set the two settings accordingly.
- **SAML:** PATHOS signs people in through Keycloak, which brokers SAML identity providers. Map the SAML attribute that lists the person's groups to Keycloak group membership with an identity-provider mapper (*Advanced Attribute to Group* or *SAML Attribute to Group*); the groups claim above then carries it. This path was not tested end to end in this change.
- **Removing someone from an organization:** removing the group in the identity provider does **not** remove an existing PATHOS membership. Deactivate the user in that organization (Administration → Users), which also ends their sessions.
- An organization administrator can invite any email address; if a Keycloak account exists for it, the invitation links to it. That adds the person to the inviting organization only; it gives the inviter no access to the person's other organizations.
- One person has **one identity-provider account** for all their organizations. Deactivating them in one organization disables that account only when they belong to no other organization (otherwise only the membership is deactivated). User administrators of any of their organizations can see whether the account has MFA and can require MFA or recovery codes on it, which applies to every organization the person signs in to.
- **Switcher:** people in several organizations get an organization switcher in the header. `GET /api/v1/me/organizations` lists their active memberships; `POST /api/v1/me/organization` checks the target against the caller's own memberships, starts a new session (new cookie and CSRF token) and ends the old one; the page reloads, so no data of the previous organization stays in the browser. API tokens and MCP tokens belong to one organization and cannot switch.

## 5. Workers

**Each worker belongs to exactly one organization.** It registers with the operator's bootstrap token and `PATHOS_WORKER_ORGANIZATION=<slug>` (empty: the default organization). Its token is bound to that organization; every worker API request is scoped to it, a lease only returns that organization's jobs, and another organization's job ids answer `404`. Workers of a suspended organization are refused.

**Shared workers are not implemented.** A worker shared by several organizations would hold, for the duration of each job, one organization's source code, scan credentials (clone tokens, target credentials) and results on a host that also runs other organizations' jobs; a compromised scanner in one job could reach the next organization's data on that host, and the worker API would need per-job scope switching. Dedicated workers cost more capacity (at least one worker per organization and family) but keep each organization's code and credentials on its own workers. Run one set of workers per organization; workers are cheap containers and idle workers only poll.

The bootstrap token is an installation secret: whoever holds it can register a worker for any organization. Tenants do not get it.

## 6. Limits and residual risks

- **Query plans under row-level security:** PostgreSQL may not use an index for a condition with a function that is not `LEAKPROOF` (for example `lower(name) = $1`) when row-level security applies, because such conditions are evaluated after the policy. Most PATHOS queries filter by uuid, text equality and timestamps (leakproof). Lookups by `lower(...)` (names, clone URLs, SBOM component names) can become sequential scans within the policy's rows. This is why single-organization installs keep row-level security off. Not measured at scale in this change.
- Readable keys come from installation-wide sequences, so an organization can estimate how many repositories, applications, scans or reviews the whole installation created.
- Organization slugs are installation-wide: a create request for a taken slug answers `409`.
- The scanner catalog, vulnerability intelligence (EPSS, KEV, OSV), end-of-life data and feed settings are shared by every organization (public data; feeds are configured by the operator). Organization-level settings (SLAs, licence policy, risk model, AI providers and configurations, integrations, notifications, secrets, Human Eye settings, developer attribution, secret validation, MCP registry, audit log) are per organization.
- Jobs and the scheduler run in system scope; their isolation rests on the application layer (every row carries its organization) and on the composite foreign keys, not on row-level security.
- The organization claim adds memberships but never removes them (§4).
- Valid-body write probes cover 130 of the 131 write routes that address a B resource; the remaining one is the GitHub webhook route, which is unauthenticated and stops at B's signature check. Of the 15 creates that take a parent in the body, 11 have a valid control; the other 4 (repository import from an SCM, the two repository import job routes, SCM OAuth start) are probed with B's parents only, because their control would contact an SCM or needs an uploaded archive.
- The organization switcher handler is covered by type checks, the frontend test and the membership tests, not by an integration test with a real session store (the integration suite has no Redis).

## 7. Tests

| Test | What it proves |
|---|---|
| `backend/test/integration/zz_tenant_isolation_test.go` | Organization B is the suite's main organization, holding data of every resource type the other integration tests create (the file runs last), plus seeded rows for up to 17 types they leave empty. Organization A gets users of all 11 system roles, each with a REST token and an MCP token, and data of its own. Every route found in the source by an AST scan of `HandleFunc`/`Handle` registrations (**435** routes, **551** probes: each id parameter replaced by a B resource id of the matching table; list, search and export routes also with B's ids as filters) is called through the real server and authentication middleware as each of the 11 users, **twice**: with row-level security enforced and with it switched off (application layer alone). Each pass is **6,076** requests. Pass criteria: no response contains an id of any B row or a B user's email, other than ids the requests themselves sent (A's own audit log records the targets of A's requests); every route that addresses a B resource answers `403` or `404` (writes may answer `400`/`422` when the empty body is rejected before the lookup, and `409 attribution_disabled` reflects A's own setting); no `500`; B's rows in every tenant table and every child table, including its audit log, are byte-for-byte unchanged afterwards. Also: forged webhook deliveries to B's connections (rejected with a 4xx status, recorded in B's own audit log), 33 MCP tool calls with B's ids, a worker of A that tries to lease and act on a queued B job and on a queued B fix verification (remediation), row-level security directly (no session variable → every tenant table empty; A's scope → no B row in any of the 126 tables with `organization_id`, inserts into B rejected, updates and deletes of B rows affect nothing, moving a row to B rejected, no direct partition access, system scope sees both), cross-organization foreign keys rejected for the owner too, and that organization roles (including `platform_admin`) cannot use the installation API |
| Valid-body write probes (same file, `zz_tenant_bodies_test.go`) | Every write route (POST, PUT, PATCH, DELETE) that addresses a B resource in its path also gets a **valid body**: generated from the handler's request struct (found by an AST scan of the `httpx.DecodeJSON` target) and completed by a per-route fixture table for enumerations and formats, with every reference in the body pointing at A's own resources. As each of the 11 users, in both passes: **131** write routes, **1,444** requests per pass, statuses 401 ×11 (forged GitHub webhook), 403 ×553, 404 ×877 and nothing else; **130** routes reached the organization check (not 400/422, not stopped by the webhook signature or the session-only token rule) and answered 403 or 404. `DELETE /api/v1/me/tokens/{id}` is session-only, so it is called with A's session principal directly (404). The test fails if fewer than 130 routes reach the check, or if any of 62 named routes (findings status, assignment, risk acceptance, suppression, tickets, AI fixes, secret validation recheck; repository update, sync, delete, scan; scan target update with authorization and intrusive authorization, delete, scan; scan profiles, schedules, security and component policies; users, role assignments, MFA, tokens; SCM, ticket and webhook integrations; runtime clusters and registries; Human Eye comments, decisions, assessments) does not |
| Parent-in-body creates (same file) | Every POST route without a path id whose body references a tenant resource (repository, application, finding, review, user, business unit, scan profile, tag, …) is called with **B's** ids in the body: all **15** are rejected (400, 404 or 409, never 2xx, no leak, B unchanged). The same body with **A's** ids is accepted for **11** of them (the control that shows the body is valid and only the parent's organization made the difference); the test fails if fewer than 11 controls succeed |
| `TestTenantScopeNeverCarriesOver` (`zz_tenant_lifecycle_test.go`) | With a pool of one connection: an organization's scope, system scope, a rolled-back transaction and a transaction that widened its own scope never carry over to the next unscoped query (it sees no organization) |
| `backend/test/integration/zz_tenant_lifecycle_test.go` | Create (seeding, invited super administrator), duplicate and invalid slugs, login mapping (invitation with verified email, organization claim without roles, refusal without membership, unverified email does not link), two memberships of one person, suspension (sign-in and API tokens refused), the default organization cannot be suspended, delete (suspension and slug required, stored objects deleted, no row left in any tenant table, other organizations untouched), installation audit log |
| `backend/internal/server/tenancy_gaps_test.go` | Static checks of the source: every use of system scope is reviewed (allowlist), request code never starts from `context.Background()`, no request field or path/query parameter carries an organization, every route pattern is a literal (so the isolation suite sees it), and only reviewed routes are served without authentication |
| `backend/internal/platform/tenant`, `backend/internal/tenancy` unit tests | Scope resolution (organization narrows system scope, fail closed without scope) and claim mapping |
| Whole integration suite | Runs with multi-tenancy enabled (row-level security on every tenant table) and still passes; the migration rollback test rolls back through 00042–00040 and re-applies them |

Run: `scripts/test-integration.sh` (Docker only). Measured on 2026-11-19 on a 20-core machine with 30 GB of memory: the whole suite, including both isolation passes, took between 18.9 s and 30.5 s of `go test` time across runs with the valid-body probes (63 top-level tests). Not measured: request latency or database load with row-level security under production data volumes.

## 8. Enabling multi-tenancy and upgrading

See [OPERATIONS.md](OPERATIONS.md#multi-tenancy). In short: upgrade as usual (migrations 00040–00042 change nothing for a single-organization install), then `pathosctl multi-tenancy enable`, restart `api`, `jobs` and `scheduler`, sign in as `PATHOS_INSTALLATION_ADMIN_EMAIL`, create organizations, and start one set of workers per organization.
