# Development roadmap: platform phases P1 to P8

**Status: complete.** This is the plan and the milestone reports of the original platform build, delivered in eight phases on 2026-11-15. To keep them apart from the later ASPM programme, they are called **platform phases P1 to P8** here.

The ASPM programme that followed has its own phases 1 to 10, all done, with completion reports in [aspm/PATHOS_IMPLEMENTATION_ROADMAP.md](aspm/PATHOS_IMPLEMENTATION_ROADMAP.md). The two numberings are unrelated: platform phase P7 (scheduling and notifications) is not ASPM phase 7 (supply chain). New work is planned against the ASPM register ([aspm/PATHOS_FEATURE_GAP_ANALYSIS.md](aspm/PATHOS_FEATURE_GAP_ANALYSIS.md)), not here.

Each phase ended with working features, automated tests passing, `docker compose up -d` validated, docs updated, and a milestone report (implemented / files / tests / open issues / verify commands / next). The reports are kept as written: what they call open, deferred or "not verified" describes the state at that milestone, and much of it was delivered later (see the CHANGELOG).

| Phase | Status |
|---|---|
| P0 Environment and architecture | Done (2026-11-15) |
| P1 Foundation | Done (2026-11-15) |
| P2 Premium UI and dashboard | Done (2026-11-15) |
| P3 Repository and asset management | Done (2026-11-15) |
| P4 Scanning engine | Done (2026-11-15) |
| P5 AI and MCP | Done (2026-11-15) |
| P6 Vulnerability management | Done (2026-11-15) |
| P7 Scheduling and notifications | Done (2026-11-15) |
| P8 Enterprise hardening | Done (2026-11-15) |

## P1: Foundation
- Go module skeleton (`cmd/pathos` roles, `pathosctl`), config loading with validation, slog JSON logging with secret redaction, health/readiness endpoints.
- PostgreSQL + goose migrations: organizations, regions/countries/BUs (seeded), users, teams, roles, permissions, role_assignments, secrets, audit_logs.
- Envelope encryption package plus master-key handling.
- Keycloak realm import (`pathos` realm, `pathos-web` confidential client, bootstrap admin with forced password change). BFF OIDC login/logout, Redis-backed sessions, CSRF.
- RBAC engine: 9 seeded roles, permission catalog, scoped assignments, middleware + SQL scope filters. User management API (list, invite/provision, deactivate, assign roles). Audit logging on every mutation.
- React app shell (Vite/TS/Tailwind/shadcn), login redirect, user management screens.
- `docker-compose.yml` with proxy, api, migrate, postgres, valkey, keycloak, seaweedfs, mailpit(dev). Health checks, networks, volumes, `.env.example`, `install.sh`.
- Tests: Go unit tests (authz, crypto, config), integration tests with testcontainers (migrations, RBAC queries), frontend unit tests, compose smoke test script.
- Docs: README, INSTALLATION, SECURITY, RBAC_MATRIX, API_DOCUMENTATION (OpenAPI), CHANGELOG.

## P2: Premium UI & dashboard
Design tokens, light/dark themes, logo/favicon, Keycloak login theme, navigation shell, ⌘K global search, notification centre shell, `DataTable`/`FilterBar`/`KpiCard` components. Dashboard aggregate endpoints (SQL-backed, scope-filtered) with all 24 KPIs and charts. KPIs whose data source lands in a later phase are shown as **"Not yet available"** rather than with fake numbers. Drill-down links.

## P3: Repository & asset management
SCM connections (GitHub App / PAT, GHE base URL, Azure DevOps Services/Server), repo discovery and import, bulk onboarding (selection + CSV), branch selection, metadata and classification, tag categories and mandatory tags, bulk tagging, applications, archive/delete. Webhook receivers (signature-verified) for push, PR and merge.

## P4: Scanning engine
Catalog seeding from SCANNER_CATALOG, Adapter interface, shared SARIF parser, worker agent + lease API, `worker-core` image (Gitleaks, Opengrep, Trivy, Syft, Grype, OSV-Scanner, Checkov), egress proxy, scan profiles with versioning (Gitleaks locked on), result normalization and fingerprinting, raw report storage. Then the remaining worker families.

## P5: AI & MCP
Provider interface and Anthropic / OpenAI / xAI adapters, AI configurations (versioned), redaction, prompt-injection-resistant prompt assembly, JSON-schema-validated output, review pipeline as background jobs, human approval queue, PATHOS MCP server (interactive mode), MCP server registry with approval and tool allow-lists.

## P6: Vulnerability management
Findings UI, lifecycle state machine and history, assignment, SLA policies and deadlines, accepted-risk workflow with expiry, recurrence tracking, SBOM inventory and component search.

## P7: Scheduling & notifications
Leader-elected scheduler, cadence by repo / region / BU / profile, priorities, retries, cancellation, missed-schedule detection, worker health. SMTP settings, templates, rules, delivery history.

## P8: Enterprise hardening
Load tests (k6), security tests (gosec, Trivy on our images, ZAP baseline against PATHOS itself), production compose overrides, backup/restore/upgrade scripts validated, OTel exporters, final documentation.

## P1 milestone report (2026-11-15)

**Implemented:** everything in the phase P1 scope above, with these deviations:

| Planned | Delivered | Reason / follow-up |
|---|---|---|
| sqlc-generated queries | Hand-written pgx queries in each package's `store.go` | Small surface so far. Revisit when phase P3 adds many list/filter queries |
| oapi-codegen server types; openapi-typescript client | Hand-written OpenAPI 3.1 spec (`backend/api/openapi.yaml`) plus a typed fetch client | Wire codegen in phase P2, when the API surface grows |
| testcontainers-go | `scripts/test-integration.sh` (throwaway PostgreSQL container on a private network) | Avoids mounting the Docker socket into the test container |
| SeaweedFS in compose | Not deployed yet | No object storage consumer until phase P4 (raw reports, SBOMs) |
| User-management "teams" API | Schema only (`teams`, `team_members`) | UI/API for teams lands with phase P3 ownership features |

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

**Open issues:** see [Known gaps in SECURITY.md](SECURITY.md#known-gaps). Keycloak realm changes after first start must be made in the Keycloak admin console (the import is first-start only).

**Next:** Phase P2, the premium UI and dashboard.

## P2 milestone report (2026-11-15)

**Implemented:**
- **Dashboard API** (`GET /api/v1/dashboard`). The 24-KPI catalog plus 6 chart panels are defined once in `backend/internal/dashboard/catalog.go`, each tagged with its data-source phase and required permission. Every item returns one of three states: `ok` with values, `not_yet_available` (no number, shows the phase that delivers it) or `restricted` (no value is sent). Filters: period (7/30/90/365 days), region, country, business unit. KPIs that are not geo-scoped are labelled `org_wide` when a geo filter is set.
- **Live today:** Active users (with trend and sparkline), Pending invitations, Security events (denied/failed actions vs the previous period), Sign-ins per day, Administrative changes.
- **Global search** (`GET /api/v1/search`) across users, business units, regions and countries, permission-aware, 5 results per type.
- **UI:**
  - ⌘K / Ctrl+K command palette (search, navigation, theme, sign out) and a notification centre shell.
  - `KpiCard` (value, polarity-aware delta, sparkline, drill-down), `FilterBar` and `DataTable` (column chooser saved per browser, CSV export with formula-injection protection, load more).
  - Users and Audit pages rebuilt on `DataTable`, with URL-driven filters so drill-downs and search results deep-link. Charts are lazy-loaded (Recharts kept out of the main bundle).
- **Keycloak login theme** `pathos` (`deploy/keycloak/themes/pathos`): PATHOS mark and colours over `keycloak.v2`.

**Upgrading a phase P1 install:** the realm import runs only on first start. In the Keycloak admin console set *Realm settings → Themes → Login theme* to `pathos`. After any theme change, run `docker compose up -d --force-recreate keycloak`, because Keycloak keeps a gzip cache of theme files inside the container.

**Tests:** dashboard catalog and filter unit tests; integration tests for dashboard values, permission restrictions and search scoping; frontend tests for KpiCard states, delta polarity, CSV escaping and href splitting; smoke test now has 40 checks; Playwright run of login, dashboard, palette, drill-down, notifications and dark mode.

**Deviations:** OpenAPI code generation is still deferred (spec updated by hand). Saved table views are not implemented; column choices persist per browser.

**Next:** Phase P3, repository and asset management.

## P3 milestone report (2026-11-15)

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
- **Webhooks:** GitHub (HMAC) and Azure DevOps (basic auth) receivers normalise push / pull request / merge events, de-duplicate deliveries and expose an `OnEvent` hook for phase P4.
- **Dashboard and search:** the *Repositories*, *Applications* and *Without owner* KPIs plus a *Repositories by criticality* chart are now live, scope- and geo-filtered. Global search covers repositories and applications.
- **UI:** Repositories (filters, bulk actions, drawer editor with branch picker), Import (selection + CSV), Applications, SCM connections, Tags.

**Tests:**
- SCM unit tests against fake GitHub and Azure DevOps servers: pagination, cross-host link refusal, App JWT signature and token caching, auth failure mapping, branches.
- SSRF policy and dial-time blocking; webhook signature and event parsing.
- An integration test of the full lifecycle: taxonomy, connection, discovery, mandatory tags, import/CSV dry run, BU/region/repository scoping, destination checks, bulk-tag rules, applications, webhooks (signature, replay, provider mismatch), archive/delete.
- Smoke test now has 50 checks, including a live call to `api.github.com` that confirms egress and credential-failure handling.
- A Playwright pass over every new screen.

**Deviations:** repository metadata (default branch, archived flag, last push) is captured at import time; periodic re-sync with the SCM moves to the phase P7 scheduler. Webhook events are recorded but trigger nothing until phase P4.

**Next:** Phase P4, the scanning engine.

## P4 milestone report (2026-11-15)

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
- Raw reports and SBOMs are stored in PostgreSQL (`scan_artifacts`, gzip) behind one code path, instead of SeaweedFS/S3. Moving them to object storage is scheduled for phase P8.
- Pull-request webhooks are recorded but do not trigger scans (findings are tracked per scan branch).
- Only the `core` worker family is built.
- Public repositories fall back to an anonymous clone when the stored credential is rejected; private ones never do.

**Next:** Phase P5, AI review and MCP.

## P5 milestone report (2026-11-15)

**Implemented:**
- **Providers** behind one `ai.Provider` interface:
  - **Anthropic** through the official Go SDK (`anthropic-sdk-go/v2`), default model `claude-opus-5-5`, with JSON-schema structured output (`output_config.format`), an effort setting, a cached static system prompt, refusal and truncation handling, and server-side refusal fallbacks (`fallbacks: "default"`) on supported models.
  - **OpenAI and xAI** through the Chat Completions API with strict JSON-schema responses. The model is configured explicitly; no default is guessed.
  - Keys are envelope-encrypted (`ai` kind) and tested on save. Errors never echo request bodies or keys.
- **Versioned AI configuration:** provider, model, effort, trusted organization instructions, auto-review, categories, minimum severity, approval policy (`always` / `false_positives` / `never`), daily limit, code-context toggle and extra redaction patterns.
- **Pipeline:** new findings from a scan (within the filters and daily limit), or manual requests, enter a queue that the `jobs` role processes with `SKIP LOCKED`, lease expiry and rate-limit backoff. Each review records the model, the configuration version, token counts and the SHA-256 of exactly what was transmitted.
- **Prompt-injection resistance:**
  - The evidence is redacted (secrets, keys, long tokens, organization patterns), JSON-encoded and fenced in `<untrusted_evidence id=NONCE>`, with a random per-request nonce.
  - The system prompt forbids following instructions found in the evidence.
  - The output is validated strictly (unknown fields rejected, enums and ranges checked).
  - Code is never sent for secret findings.
- **Code context:** workers capture ±5 lines around each SAST/IaC result, reading only inside the checkout. The API redacts it again before storing it.
- **Human approval:** reviews apply automatically only when policy allows. **Critical findings are never closed by AI**: a false-positive verdict goes to a human, and approving it requires a written justification. Interactive reviews need a second person to approve (four-eyes). AI never overrides a human status.
- **PATHOS MCP server** (`POST /mcp`, JSON-RPC 2.0 over Streamable HTTP):
  - Tools `list_pending_findings`, `get_finding_evidence` (same redaction and fencing) and `submit_review`.
  - Authenticated with personal API tokens (`pathos_pat_…`, hashed, 1–90 days, revocable, at most 10 per user). Tokens act with the owner's current permissions and die immediately on deactivation.
  - Reviews are attributed to the human with `source=interactive_mcp`.
- **MCP registry:** request/approve/reject/disable servers and allow-list individual tools (requested tools start disallowed). The built-in PATHOS server is seeded and governed the same way.
- **UI:** AI reviews (approval queue), AI settings, MCP registry, API tokens (with the `claude mcp add` command), and an AI section in the finding drawer. The three AI KPIs are live.

**Tests:**
- Unit: redaction, nonce fencing against fake delimiters, strict validation, the decision/guardrail matrix.
- Integration (`TestAIReviewAndMCP`), with a fake provider capturing the exact transmitted request:
  - configuration requirement, permissions, the redacted/fenced prompt and model default, approval, the critical guardrail with a justification;
  - invalid output becomes a failed review, and auto-review respects severity filters;
  - full MCP protocol, token revocation and deactivation, four-eyes, and registry tool/server controls.
- Smoke test now has 67 checks, including a live SDK call to the Anthropic API that correctly reports an invalid key.

**Not verified:** a real review against a live provider, because no API key is available in this environment. Everything up to the HTTP call is covered with the fake provider, and the SDK path is verified up to authentication.

**Next:** Phase P6, vulnerability management.

## P6 milestone report (2026-11-15)

**Implemented:**
- **Lifecycle in the database:** the `pathos_finding_lifecycle` trigger records every status change in an append-only history, with actor, source (`user` / `scanner` / `ai` / `expiry` / `system`) and reason. It sets SLA deadlines at detection, counts recurrences (fixed → open) and maintains `resolved_at` / `accepted_until`. Scanner auto-fix, AI decisions and manual triage all pass through it.
- **Triage:** a manual transition map (accepted risk only via the workflow), reasons required for false positive and fixed, Critical false positives require `findings.accept_risk`, assignment, and atomic bulk status/assign of up to 1000 findings within scope.
- **Risk acceptance:** request with justification and an expiry of at most 365 days, then approval or rejection by a different person (service check plus DB CHECK constraint), revocation, withdrawal, and automatic expiry that reopens the finding.
- **Policies:** SLA days per severity (7/30/90/180/none by default, with deadline recomputation) and a license policy (deny AGPL/SSPL/CC-BY-NC, review GPL/LGPL-3/BUSL by default).
- **SBOM:** Syft CycloneDX components are stored per scan. A cross-repository component search shows license-policy matches and open vulnerability counts, and each repository has a CycloneDX download.
- **UI:**
  - The findings page gained SLA and assignee columns, status/assignee/SLA filters and a bulk action bar.
  - The finding drawer has a lifecycle panel (status, assignee, risk acceptance, history timeline) and a code snippet with the matched line highlighted.
  - New pages: Risk acceptances, SBOM inventory and Policies.
- All 24 dashboard KPIs are now live.

**Tests:**
- Integration (`TestVulnerabilityManagement`): trigger history and sources, SLA on insert and recomputation, recurrence, transition and reason rules, Critical FP guard, bulk atomicity, permission denial (viewer, analyst without accept_risk), self-approval refused, the approve → expire → reopen cycle, append-only history for the app role, CycloneDX parsing and storage, and license filters.
- Frontend unit tests for SLA state and transition rules.
- The smoke test now has 76 checks, adding the policy seeds, SBOM API, filters, the reason/workflow guards, assignment and history.
- Live end to end: a rescan of `snyk-labs/nodejs-goof` stored 572 SBOM components (251 with licenses) and ranked vulnerable components (handlebars 4.0.11: 21 open). SLA deadlines were backfilled for all 337 existing findings.

**Next:** Phase P7, scheduling and notifications.

## P7 milestone report (2026-11-15)

**Implemented:**
- **Scheduler role:**
  - Leader election through `pg_try_advisory_lock` on a dedicated connection; standbys poll and take over when the leader's connection drops. Verified live: stopping the leader container moved leadership within one interval.
  - Every 15 seconds it runs due schedules (row locks with `SKIP LOCKED`), detects missed runs (catch-up once plus a `schedule.missed` event), requeues expired leases (previously only on the next lease call) and emits `worker.offline` once per outage. A heartbeat goes to `scheduler_state`.
- **Schedules:**
  - A dependency-free five-field cron parser with names, steps and macros, standard day-of-month/day-of-week OR semantics and DST handling (a time skipped at spring-forward runs right after the jump).
  - Schedules use IANA time zones (tzdata embedded) and can target the organization, a region, a business unit (with descendants), a repository or a scan profile.
  - Priority is 0–90, and at most one run per hour is allowed.
  - Scheduled jobs coalesce with queued ones and record `schedule_id`.
  - Authorization is scope-aware for create, edit, run, delete and list.
- **Notifications:**
  - Triggers on `scan_jobs`, `risk_acceptances` and `findings.assignee_id` write a `notification_events` outbox; the SLA detector feeds it too.
  - The dispatcher in `jobs` matches rules by event, severity and scope (repository, business-unit ancestry, region) and resolves recipients: roles at a covering scope, users, external addresses, and dynamic assignee, requester, eligible approvers (excluding the requester) and application owners. It renders templates (organization override, falling back to the default if broken) and writes deduplicated in-app and email deliveries.
  - The sender claims emails with a lease, sends one recipient per message and retries with backoff. STARTTLS is strict, and credentials are never sent without TLS.
  - SMTP is seeded from the same `PATHOS_SMTP_*` variables as Keycloak.
- **SCM metadata re-sync:** names, URLs, default branch, visibility, description, upstream archive state and last push are refreshed nightly or on demand. Placement and classification are never touched.
- **UI:**
  - New pages: Scan schedules (with scheduler, worker and queue health) and Administration → Notifications (rules, SMTP with test email, templates with live preview, delivery history with retry and message view).
  - The notification centre is live (unread badge, deep links, mark read), and SCM connections have **Re-sync metadata**.
- **Fixes found on the way:**
  - `jobs` had no route to AI providers (internal network only), so automated reviews could not have worked in compose.
  - Assignment did not record the actor, so self-assignment generated a notification.
  - The rule list returned `null` recipient lists, which crashed the page. This was found by the Playwright pass and is now covered by an integration assertion.

**Tests:**
- Unit:
  - Cron: fields, macros, DOM/DOW OR, steps, leap day, never-firing expressions, time zones, DST both ways, minimum interval.
  - Templates: every default renders without missing fields; broken and oversized templates are rejected.
  - Header-injection-proof message building, SMTP host policy, and config per role.
- Integration:
  - `TestSchedulesAndScheduler`: validation, scope authorization and visibility, BU descendants, tick execution with priority and `schedule_id`, no double run, missed-run catch-up without stacking, run now, lease recovery, one offline event per outage, and advisory-lock exclusivity and release.
  - `TestNotifications`, against an in-test SMTP server:
    - built-in rules, SMTP validation and the write-only password, the STARTTLS downgrade refusal, and delivery;
    - a scan failure reaching role recipients in-app and by email, repository-scoped rules and custom templates, and header injection from scanner error text;
    - approvers excluding the requester and out-of-scope managers, decision notices, and self-assignment suppression through the real API;
    - one SLA breach event per breach, the inbox and read state, history and retry, append-only history, and suppression when email is disabled.
- The smoke test now has 87 checks, including leader health, schedule CRUD and preview, the seeded rules and SMTP, and a real test email delivered by `jobs` to Mailpit and verified through Mailpit's API.

**Next:** Phase P8, enterprise hardening.

## P8 milestone report (2026-11-15)

**Implemented:**
- **Rate limiting:**
  - GCRA buckets in Valkey (an atomic Lua script on server time, shared by replicas), with an in-memory fallback.
  - Classes: login per IP, anonymous per IP, reads and writes per user, webhooks per connection, MCP per token.
  - Throttled requests get `429` with `Retry-After`. The limiter fails open if Valkey is down, and `PATHOS_RATE_LIMIT_SCALE` tunes all limits.
- **Identity hardening:**
  - The Keycloak admin console, admin REST API and master realm are reachable only from `KEYCLOAK_ADMIN_ALLOW` (private networks by default; required in production mode).
  - `PATHOS_REQUIRE_MFA` makes new users enrol TOTP.
- **Production override** (`docker-compose.prod.yml`): resource limits, log rotation, PostgreSQL tuning, a hot-standby scheduler, and an explicit admin allow-list.
- **Operations scripts:** `backup.sh` (online dumps, certificates, object storage, manifest with checksums, retention), `restore.sh` (verify → stop → recreate → restore → migrate → start) and `upgrade.sh` (validate → backup → build or pull → migrate → health → rollback hint), with `docs/OPERATIONS.md` as the runbook.
- **OpenTelemetry:**
  - OTLP/HTTP traces and metrics with route-named spans and `http.route` metric labels (bounded cardinality) plus Go runtime metrics.
  - Leader-only platform gauges (queue depth, workers, notification backlog, open findings, leadership); `trace_id` in access logs.
  - An opt-in Grafana LGTM profile.
- **Object storage:**
  - Scan artifacts can live in S3-compatible storage (aws-sdk-go-v2, path-style, checksums only when required), with SeaweedFS 4.51 as an opt-in profile.
  - A DB constraint guarantees exactly one location per artifact.
  - Objects written by a failed ingest are deleted; retention deletes the row first, then the object.
  - `pathosctl migrate-artifacts` moves existing blobs and can be resumed.
- **Security self-tests** (`make security`): gosec, govulncheck, npm audit, Trivy on our three images and an OWASP ZAP baseline, with a gate.

**Found and fixed by this phase's testing:**
- **Worker context reader:** it trusted `Lstat` on the final path, so a symlinked *directory* in a scanned repository could have pulled files from outside the checkout. The clone already disables symlinks, so this was not exploitable; the reader now resolves every path component as well. Covered by a regression test.
- **Valkey:** it crash-looped on any restart (root without DAC_OVERRIDE could not traverse its own `appendonlydir`). It never surfaced because the container had not restarted. It now runs as its own user with no capabilities.
- **Image vulnerabilities, 42 fixable HIGH/CRITICAL in total:**
  - Our own image: go-jose 4.1.6.
  - Caddy: rebuilt with xcaddy and x/net 0.62.0.
  - Gitleaks: rebuilt from its checksum-verified module with Go 1.27 and patched x/crypto, x/text and compress. This removes 39 issues, including a CRITICAL in the Go standard library.
  - Worker image: Debian packages upgraded, and pip removed from the runtime (it carried vulnerable vendored urllib3 and msgpack).
- **Proxy:** `default_sni` is set, so TLS clients that omit SNI (found by ZAP's Java client) get a certificate instead of an alert. COOP, COEP, CORP and `object-src 'none'` headers were added.
- **Dashboard:** the open-findings trend ran 120 correlated counts. It is now a single-pass running sum, 10× faster at 100k findings. An integration test checks equivalence with the definition, and the two queries matched on all 120 cells with 25k resolved findings.

**Measured:**
- **Load (k6, 100,000 findings across 300 repositories, single API replica):** 0 errors in all runs.

  | Rate | Requests | Detail p95 | List p95 | Dashboard p95 |
  |---|---|---|---|---|
  | 20 req/s | 1,203 | 7 ms | 66 ms | 352 ms (1.25 s before the query rewrite) |
  | 80 req/s | 4,802 | 4.4 ms | 117 ms | 493 ms |

- **Security gate:**
  - gosec: 0 issues (15 reviewed `#nosec`, each with a reason); govulncheck: none; npm audit: 0.
  - Trivy: 0 fixable HIGH/CRITICAL in all three images. What remains has no upstream fix: 118 Debian packages in the worker base, the ecdsa timing issue the maintainers won't fix, and go-jose v3 inside Caddy.
  - ZAP baseline: 0 FAIL, 64 PASS, 4 accepted warnings (documented).
- **Backup, restore and upgrade:**
  - A backup took 2 s.
  - A restore took 40 s and removed a marker row written after the backup; the smoke test passed afterwards and the app role's least-privilege grants were intact.
  - The upgrade ran in production mode and all services survived a full restart.
- **OpenTelemetry:** route-labelled HTTP metrics and scheduler gauges reached Prometheus, and route-named traces reached Tempo (Grafana LGTM).
- **Object storage:** a live S3 round trip against SeaweedFS (bucket, 1 MiB put and get, batch delete, not-found, invalid credentials).
- **Smoke test:** 88 checks, adding rate limiting.

**Not verified:**
- Automated reviews against a live AI provider (no key in this environment).
- An authenticated active DAST scan. Only the passive baseline ran, so as not to mutate the shared development data; run ZAP's API scan against a disposable environment.
- Multi-host deployment (Compose is single-host by design).
