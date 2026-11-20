Quditmind PATHOS · applies to v2.2.0 · status: Proposed

# PATHOS ASPM API design (historical) and lifecycle release endpoints

The first part of this page is the historical ASPM plan (status: Existing, as built). The last section, [Lifecycle release endpoints (M0, proposed)](#lifecycle-release-endpoints-m0-proposed), proposes the endpoints of milestones M1 to M10. None of them exists yet.

> **Status: historical design, written in phase 0 (2026-11-17).** All ten ASPM phases are now built, and several endpoints were built under different paths than planned. This page keeps the plan and maps every planned endpoint to what exists today. For the current API, use the [API reference](../api-reference/index.md). It is the canonical description of paths, permissions, request and response bodies.

The plan kept the existing conventions, and the as-built API follows them:

- everything under `/api/v1`, with a browser session plus CSRF token, or a personal API token (see below)
- JSON errors `{error: {code, message, fields}}`
- server-side filtering
- scoped RBAC enforced in SQL
- an audit entry for every change
- **no existing endpoint changes its contract**; new response fields are additive

## Planned endpoints and what was built

### Phase 1: unified data model

| Planned | As built |
|---|---|
| `GET /findings` with new filters and fields | Built. Filters `lifecycle` (the planned `presentation_status`), `kev`, `epss_min`, `risk_min`, `confidence`, `reachability`, `application_id`; sort by risk. See [Risk intelligence](../api-reference/risk-intelligence.md) |
| `GET /findings/{id}/risk` | Built as planned |
| `GET`, `PUT /risk-model` | Built, plus `GET /risk-model/history` |
| `GET /intel/cves/{id}` | Built (OSV record with EPSS and KEV). See [Vulnerability intelligence](../api-reference/vulnerability-intelligence.md) |
| `GET`, `POST /intel/feeds` | `GET /intel/feeds`, `PUT /intel/feeds/{feed}` (enable, URL, interval), `POST /intel/feeds/{feed}/run` (online), `POST /intel/feeds/{feed}/import` (file) |
| `GET`, `PATCH /applications/{id}` | `PATCH /applications/{id}` with the new fields; read through `GET /applications` and `GET /posture/applications`. See [Applications](../api-reference/applications.md) |

### Phase 2: ingestion and engines

| Planned | As built |
|---|---|
| `POST /imports/results` | Built as planned. See [Result imports](../api-reference/result-imports.md) |
| `POST /imports/sbom` | Built as planned |
| `GET /imports/results/{id}` | Not built. Each import is a scan execution (`GET /scans/{id}`); the list is `GET /imports/history` |
| `/scan-targets` (`GET`, `POST`, `PATCH`, `DELETE`) | `GET`, `POST /scan-targets`, `GET`, `PUT`, `DELETE /scan-targets/{id}`, `POST /scan-targets/{id}/scan`, `POST /scan-targets/sbom`, `POST /scan-targets/artifact`. See [Scan targets](../api-reference/scan-targets.md) |
| `/custom-rules` (`GET`, `POST`, `PUT`) | `GET`, `POST /custom-rules`, `GET`, `PUT`, `DELETE /custom-rules/{id}`, `GET /custom-rules/{id}/versions`, `POST /custom-rules/validate` |

### Phase 3: ASPM inventory

The planned `/aspm/*` prefix became `/posture/*`. See [Posture](../api-reference/posture.md).

| Planned | As built |
|---|---|
| `GET /aspm/applications/{id}/posture` | `GET /posture/applications` (every application with its rollup) and `GET /posture/aggregate` |
| `GET /aspm/coverage` | `GET /posture/coverage` |
| `GET /aspm/unmanaged` | `GET /posture/unmanaged` |
| `GET /aspm/graph` | `GET /posture/context-graph` |
| `GET /aspm/benchmarks` | `GET /posture/benchmark` |
| (not planned) | `GET /posture/blast-radius`, `GET /repositories/{id}/dependencies`, `GET /repositories/{id}/dependencies/paths`, `GET /findings/{id}/dependency-paths` |

### Phase 4: vulnerability intelligence

| Planned | As built |
|---|---|
| `GET`, `POST /findings/{id}/correlations` | `GET /findings/{id}/related`. Correlation is computed on request; there is no confirm or reject |
| `GET`, `POST`, `DELETE /suppression-rules` | `GET`, `POST /suppression-rules`, `POST /suppression-rules/preview`, `POST /suppression-rules/{id}/{action}` (approve, reject, revoke). Rules are revoked, not deleted |
| `GET /findings/{id}/attack-paths` | `GET /posture/attack-paths` |

### Phases 6 to 9: AI, governance, reporting, integrations

| Planned | As built |
|---|---|
| `POST /ai/analyst/sessions` | `/ai/analyst/conversations`: `GET`, `POST`, `GET`, `DELETE /{id}`, `POST /{id}/messages`. See [AI analyst](../api-reference/ai-analyst.md) |
| `GET /ai/usage` | Built as planned |
| `POST /ai/reports` | Built, plus `GET /ai/reports`, `GET /ai/reports/{id}`, `GET /ai/reports/{id}/markdown`. Reports are marked AI-generated; there is no approval step before others can read them |
| `/policies` with `POST /policies/{id}/simulate` | `/security-policies`: `GET`, `POST`, `GET`, `PUT`, `DELETE /{id}`, `GET /{id}/violations`, `POST /security-policies/preview` (dry run), `POST /security-policies/evaluate`; `GET /findings/{id}/policies`. See [Governance](../api-reference/governance.md) |
| `GET /compliance/frameworks/{id}/status` | `GET /compliance/frameworks` and `GET /compliance/frameworks/{key}` |
| `/reports/definitions` with `POST /{id}/run` | `/reports`: `GET`, `POST`, `GET`, `PUT`, `DELETE /{id}`, `GET /reports/{id}/run`, `POST /reports/preview`; executive overview `GET /executive`. See [Integrations and reporting](../api-reference/integrations-reporting.md) |
| `/connectors` with `POST /{id}/test` | Split by kind: outbound webhooks under `/notifications/webhooks` (with `/{id}/test` and `/{id}/deliveries`), Jira and ServiceNow under `/ticket-connections` (with `/{id}/test`) |
| `POST /findings/{id}/tickets` | Built as planned, plus `GET /findings/{id}/tickets` |
| `POST /scm/pull-requests/{id}/checks` (internal) | No endpoint. PATHOS posts the commit status to the provider itself. Results are read with `GET /pr-checks` and `GET /pr-checks/{id}`, re-posted with `POST /pr-checks/{id}/repost`, and configured per repository with `GET`, `PUT /repositories/{id}/pr-settings` |

## Outbound webhook contract

As built (see [Integrations and reporting](../api-reference/integrations-reporting.md) for the payload):

- Headers (generic JSON format; Slack and Teams receive their own payload without them): `X-PATHOS-Event`, `X-PATHOS-Delivery` (delivery UUID), `X-PATHOS-Timestamp`, and, when a signing secret is set, `X-PATHOS-Signature: sha256=<hex>`. The signature is HMAC-SHA256 over `<timestamp>.<body>`, so the timestamp is covered as well as the body. The plan signed the body only.
- Formats: generic JSON, Slack and Microsoft Teams (Adaptive Card).
- Events: any notification event, chosen per endpoint. The plan had a fixed list of seven.
- Retries: 1 minute, 5 minutes, 30 minutes, 2 hours and 6 hours after the first attempt (six attempts, about 9 hours in total). A 4xx response other than 408 or 429 is not retried. The plan said "at most 24 hours".

## Authentication for automation

As built: personal API tokens (`api_tokens`) carry the scopes `mcp`, `api:read` or `api:write`. A token with an `api:*` scope is accepted as `Authorization: Bearer` on every `/api/` endpoint except token management, sign-in, recovery codes and MFA, not only on the few endpoints the plan marked as automation-capable. It acts with the owner's current permissions. `api:read` allows safe methods only. Tokens do not use CSRF. See [API reference: authentication](../api-reference/index.md#authentication) and [SECURITY.md](../SECURITY.md#api-tokens-and-mcp).

## Lifecycle release endpoints (M0, proposed)

**Status: Proposed.** No endpoint in this section exists. Each needs owner approval at its milestone gate ([roadmap §17](PATHOS_IMPLEMENTATION_ROADMAP.md#17-lifecycle-release-plan-m0m11-proposed)). The data model behind it is in [PATHOS_DATABASE_DESIGN.md](PATHOS_DATABASE_DESIGN.md#lifecycle-release-data-model-m0-proposed); the decisions in [PATHOS_ARCHITECTURE_DECISION_RECORDS.md](PATHOS_ARCHITECTURE_DECISION_RECORDS.md).

### Conventions kept (Existing, verified in code)

- Everything under `/api/v1`. Authentication by browser session plus `X-CSRF-Token` on writes, or a REST API token (`api:read` for safe methods, `api:write` for writes) ([API reference: authentication](../api-reference/index.md#authentication)).
- Routes are registered as literal `METHOD /path` patterns with `http.ServeMux` (`backend/internal/server/server.go`; each service's `Register`). The tenant isolation suite finds them by AST scan, so every new route is probed with another organization's ids automatically (`backend/test/integration/zz_tenant_isolation_test.go`).
- The organization always comes from the authenticated principal, never from the request (`backend/internal/server/tenancy_gaps_test.go:189`).
- Unauthenticated routes are allow-listed in `publicRoutes` (`tenancy_gaps_test.go:236`). Adding one needs a review entry there.
- Bodies are strict JSON, at most 1 MiB, unknown fields refused (`httpx.DecodeJSON`, `backend/internal/platform/httpx/httpx.go`).
- Pagination: keyset (`limit`, `cursor`, `next_cursor`) for new lists, as for repositories and users ([pagination](../api-reference/index.md#pagination)).
- Rate limit classes as today ([rate limits](../api-reference/index.md#rate-limits)): authenticated reads 25/s, writes 5/s, unauthenticated 5/s per client IP.
- Every change writes an `audit_logs` entry. Feature-gated endpoints answer `404 not_found` while their flag is off for the organization, so a disabled module looks absent (same as an unknown path), and the UI shows the "feature disabled" state from `/api/v1/meta`.
- Tool names: API responses keep scanner and engine keys (`scanner_key`, `scanner_keys`, `engine`) for audit. The UI hides them outside the two configuration pages ([ADR-011](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-011-hide-tool-names-in-the-ui-keep-them-in-the-api)).

### New permissions (proposed)

Added to `backend/internal/authz/catalog.go` and synced at start-up (`backend/internal/org/bootstrap.go:53`). System-role mappings are part of each milestone's design note; `make rbac-matrix` regenerates [RBAC_MATRIX.md](../RBAC_MATRIX.md).

| Permission | Category | Milestone | Org-only |
|---|---|---|---|
| `flags.manage` | Administration | M1 | yes |
| `ai.troubleshoot` | AI & MCP | M1 | no |
| `connectors.read`, `connectors.manage` | Connectors | M2 | `manage` yes |
| `graph.read` | Discover | M4 | no (repository scope, like `findings.read`) |
| `threatmodels.read`, `threatmodels.edit`, `threatmodels.approve` | Threat model | M5 | no |
| `ai.evidence.read` (built as `ai.evidence_read`) | AI & MCP | M7 | no |
| `remediation.read`, `remediation.manage` | Remediate | M8 | no |
| `gates.manage`, `gates.approve_exception` | Remediate | M8 | `manage` yes |
| `monitoring.read` | Report & monitor | M9 | no |
| `rea.read`, `rea.run` | Reverse engineering | M10 | no |

Existing endpoints keep their existing permissions. New pages that wrap existing endpoints (for example SCM connections inside Connectors) keep calling them with the old permissions until parity is reached.

### Error envelope: today and proposed

**Today (Existing).** `httpx.WriteError` (`backend/internal/platform/httpx/httpx.go`) writes:

```json
{
  "error": { "code": "scm_error", "message": "…", "details": { }, "fields": { } },
  "request_id": "kqzjwhbxutcyrmfpdnaovegs"
}
```

`code` is a stable snake_case string. 56 distinct codes are passed to `httpx.E` in the backend, plus `invalid_request` (`httpx.BadRequest`, about 615 call sites) and `conflict`. Unknown errors become `500 internal` with the text logged, never sent. `request_id` sits beside `error`, equals the `X-Request-Id` header, and is logged on the access line. The historical note at the top of this page lists only `{code, message, fields}`; `details` and `request_id` also exist.

Clients that read `error.code` today:

| Client | Where | Codes it checks |
|---|---|---|
| Web UI | `frontend/src/api/client.ts` (`ApiError.code`); `frontend/src/app/router.tsx:94` | `organization_suspended` and the generic path |
| `pathos` CLI | `backend/cmd/pathos-cli/client.go:44-58` | `token_read_only`, `invalid_token`, prints `code: message` |
| JetBrains plugin | `ide/jetbrains/.../api/PathosClient.kt:311-313` | reads `error.code` and `error.message` |
| VS Code extension | `ide/vscode/src/details.ts` | reads the error body |
| CI templates and customer automation | `integrations/*` and unknown external scripts | unknown |

**Prompt §3.2 asks** for `error.code` to hold `PTH-CONN-1004`. Replacing the value of `code` would break every client above. Options:

| Option | Effect | Recommendation |
|---|---|---|
| A. Replace `code` with the catalogue code | Breaks the web UI, CLI, both IDE plugins and external automation. Violates "no existing endpoint changes its contract" | Rejected |
| B. Keep `code`; add the catalogue fields beside it, with the catalogue code in **`error_code`** (the same name §3.2 uses for log lines) | Fully backward-compatible; old clients ignore unknown members | **Recommended** |
| C. B by default, plus the prompt's exact shape (`code` = catalogue code, old value in `legacy_code`) when the client sends `Accept: application/json; pathos-errors=2` | Lets new clients use the literal §3.2 shape; two shapes to test | Possible later; not in M1 |

Proposed envelope (option B). Members marked *new* are additive:

```json
{
  "error": {
    "code": "scm_error",
    "message": "x509: certificate signed by unknown authority",
    "details": {},
    "error_code": "PTH-CONN-1004",
    "title": "Connection uses an untrusted certificate",
    "severity": "error",
    "cause": { "confirmed": true, "text": "The server certificate is signed by a certificate authority that PATHOS does not trust." },
    "probable_causes": [],
    "impact": "Repositories from this connection are not synchronised and cannot be scanned.",
    "actions": ["Add the issuing CA certificate to the connection.", "Run Verify."],
    "action_links": [{ "index": 0, "route": "/connectors/0193…?tab=configuration" }],
    "verify": ["Health tab shows TLS: pass."],
    "verify_check": { "kind": "connector", "id": "0193…", "check": "tls" },
    "docs_url": "/help/troubleshooting/conn#PTH-CONN-1004",
    "ai_help": true,
    "request_id": "kqzjwhbxutcyrmfpdnaovegs"
  },
  "request_id": "kqzjwhbxutcyrmfpdnaovegs"
}
```

- `actions` stays an array of strings as in §3.2. The screen link for each fix is the additive `action_links` (by index), so a client that expects strings still works.
- `cause.confirmed` is true only when the server proved the cause (for example the TLS handshake error); otherwise `cause` is omitted and `probable_causes` is ordered.
- `message` keeps today's meaning. For `500` it stays `internal server error`; the cause is never sent to the client.
- `request_id` is repeated inside `error` (§3.2) and kept at the top level (today).
- Catalogue text never adds information the legacy response hides. A `404` stays indistinguishable for "missing" and "other organization's" (existence is not disclosed, [MULTI_TENANCY.md §2.1](../MULTI_TENANCY.md#21-application-layer)).
- Mapping: the catalogue has a default entry per legacy code (for example `not_found` → `PTH-PLAT-0404`, `scm_error` → `PTH-CONN-2000`). A call site can attach a specific entry (`httpx.E(...).With(diag.ConnUntrustedCertificate)`). A unit test scans the source for every `httpx.E` code literal and fails when one has no default entry (same AST approach as `tenancy_gaps_test.go`).
- Logging: `WriteError` and the access log line add `error_code` beside the existing `request_id` (`httpx.go`, `Middleware`). Worker and jobs logs add `error_code` where they record a failure.
- Response size grows by roughly 0.5–2 KB per error. Not measured.

### M1: shell, metadata, diagnostics, flags

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `GET /api/v1/meta` | None (public) or any authenticated user | — | See below | `429 rate_limited` |
| `GET /api/v1/feature-flags` | Authenticated | — | `{items: [{key, milestone, description, enabled, depends_on, changed_at, changed_by}]}` for the caller's organization | `401` |
| `PUT /api/v1/feature-flags/{key}` | `flags.manage` | `{enabled: bool, note?: string}` | The flag | `404 not_found` (unknown key, `PTH-PLAT-1101`); `409 conflict` (a dependency is off, `PTH-PLAT-1102`; forced off by the installation, `PTH-PLAT-1103`) |
| `GET /api/v1/diagnostics/codes` | Authenticated | `?area=CONN&q=` | `{items: [catalogue entry]}` (same fields as the envelope) | `400 invalid_request` |
| `GET /api/v1/diagnostics/codes/{code}` | Authenticated | — | Catalogue entry | `404 not_found` |
| `POST /api/v1/diagnostics/verify` | The permission of the checked subject (for example `connectors.manage`, `scans.run`) | `{error_code, subject: {kind, id}, check?}` | `{passed: bool, checks: [{check, status, error_code}], checked_at}` | `400` (code has no verify step, `PTH-PLAT-1201`); `404`; `403` |
| `POST /api/v1/diagnostics/troubleshoot` | `ai.troubleshoot` and read access to the subject | `{error_code, request_id?, route?, subject?: {kind, id}}` | See below | `400`; `404` (subject); `429` |
| `GET /api/v1/system/status` | Authenticated (details per permission) | — | `{checked_at, components: [{name, kind: api\|database\|queue\|object_storage\|worker_pack\|connector\|ai_provider, status, last_check_at, error_code}]}`. Connector and AI provider names only with `connectors.read` or `ai.configure`; otherwise counts | `401` |

**`GET /api/v1/meta`** (prompt §2.2), on the public mux with its own optional authentication (the pattern of `HandleMyOrganizations`, `server.go:113`), added to `publicRoutes`:

Unauthenticated, exactly:

```json
{ "product": "PATHOS", "vendor": "Quditmind", "version": "2.2.0" }
```

Authenticated (valid session or API token):

```json
{
  "product": "PATHOS",
  "vendor": "Quditmind",
  "version": "2.2.0",
  "commit": "f3c5efd…",
  "build_date": "2026-11-19T12:00:00Z",
  "api_version": "v1",
  "feature_flags": ["shell.v2", "diagnostics"],
  "workers": [{ "family": "core", "version": "2.2.0", "online": 2 }],
  "scanner_packs": [{ "family": "sast", "version": "2.2.0", "tools": 31 }]
}
```

- `version` is `server.Version` (`backend/internal/server/server.go:52`), already public through `GET /healthz` (`server.go:105`). The unauthenticated form discloses nothing new.
- An invalid or expired credential gets the unauthenticated form, not `401`, so the login page can always show the version.
- `feature_flags` lists the enabled keys of the caller's organization only.
- `workers` and `scanner_packs` come from registered workers (`workers.family`, `workers.version`, `workers.tools`; `00003`, `00029`). Tool names and per-tool versions stay in the existing `GET /api/v1/workers` for users with `scanners.read`.
- Rate limit: the unauthenticated class (5/s per IP).

**`POST /api/v1/diagnostics/troubleshoot`** (prompt §3.3):

- The server builds the context itself: the catalogue entry, the redacted stored failure records of the subject (connector health checks, scan job events, sync runs) and non-secret configuration metadata. It does not accept log lines or free text from the client (only `route`), so a user cannot paste a secret into it (rule 6).
- Redaction uses the existing AI redaction pipeline ([ARCHITECTURE.md §6](../ARCHITECTURE.md#6-ai-review-architecture)).
- The model comes from the `troubleshooting` task assignment (M7), else the organization default; the proposed default is the local provider ([ADR-008](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-008-ai-evidence-record-and-reproducibility)).
- Response, always `200` when the code exists, also when AI is off:

```json
{
  "catalogue": { "error_code": "PTH-CONN-1004", "title": "…", "cause": {}, "probable_causes": [], "actions": [], "verify": [] },
  "ai": {
    "status": "answered",
    "evidence_record_id": "0193…",
    "evidence_type": "ai_inferred",
    "confirmed_cause": null,
    "probable_causes": ["…"],
    "steps": ["…"],
    "verify": ["…"]
  }
}
```

`ai.status` is `answered`, `disabled` (no provider or flag off), `unavailable` (provider error, with `error_code` `PTH-AI-…`) or `invalid_output`. The catalogue part is always present, so troubleshooting never depends on AI. An AI answer never sets `confirmed_cause` unless the server's own check proved it.

Exports (M1): no new endpoints. Existing exports (CSV, JSON, SARIF, SBOM, report PDFs and printable pages) add the stamp `Quditmind PATHOS v{version} · build {commit} · generated {UTC timestamp}` in a format-appropriate place (CSV comment line or trailing row, JSON `metadata`, SARIF `run.properties`, CycloneDX `metadata.tools` and properties, SPDX `creationInfo.creators`). Whether a leading CSV comment line breaks customer imports must be checked; the safe default is a response header `X-PATHOS-Generated-By` plus a final row.

The "Report a problem" bundle is built in the browser from `GET /api/v1/meta` and a client-side ring buffer of the last 50 request IDs and error codes. No endpoint receives it.

### M2: connectors and health

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `GET /api/v1/connectors/catalogue` | `connectors.read` | — | `{items: [{kind, category, name, auth_methods, status: available\|planned, docs_slug}]}` from the code catalogue | — |
| `GET /api/v1/connectors` | `connectors.read` | `?category=&kind=&health=&q=&limit=&cursor=` | `{items: [{id, kind, category, name, enabled, health, last_checked_at, last_ok_at, last_error_code, credential_expires_at, legacy: {kind, id, path}}], next_cursor}` | `400` |
| `POST /api/v1/connectors` | `connectors.manage` | `{kind, name, config, credential}`; `credential` is write-only | The connector (`201`) | `400`/`422 validation_failed` (`PTH-CONN-1100`…); `409` (duplicate) |
| `GET /api/v1/connectors/{id}` | `connectors.read` | — | Connector with non-secret `config` and `credential: {set: bool, updated_at, expires_at}` | `404` |
| `PATCH /api/v1/connectors/{id}` | `connectors.manage` | Partial `{name, config, enabled}` | Connector | `404`; `422` |
| `PUT /api/v1/connectors/{id}/credential` | `connectors.manage` | `{credential}` | `204` | `404`; `422` |
| `DELETE /api/v1/connectors/{id}` | `connectors.manage` | — | `204` | `404`; `409` (in use by repositories) |
| `POST /api/v1/connectors/{id}/check` | `connectors.manage` | `{checks?: [check_kind]}` | `{health, checks: [{check_kind, status, error_code, detail, observed, duration_ms}], checked_at}`; synchronous, at most 30 s | `404`. A connector that fails its checks is a `200` with failed checks (for example `PTH-CONN-1001`), not an HTTP error |
| `GET /api/v1/connectors/{id}/health` | `connectors.read` | `?limit=&cursor=` | Health check history | `404` |
| `GET /api/v1/connectors/health/summary` | `connectors.read` | — | `{by_category: {scm_ide: {healthy, degraded, failing, unknown}}, failing: [{id, name, last_error_code}]}` | — |

- For a legacy kind, `POST`, `PATCH` and `DELETE` call the existing service (for example the SCM connection service behind `POST /api/v1/scm-connections`) so both pages stay consistent. The legacy endpoints (`/scm-connections`, `/ticket-connections`, `/notifications/webhooks`, `/runtime/clusters`, `/runtime/registries`, `/ai/providers`) are unchanged.
- Connector checks run in the jobs service or a worker, never in the API process, where the existing design already does so (runtime syncs: "the API server never calls the cluster", `00035_runtime_context.sql:27`). For kinds the API tests directly today (`POST /scm-connections/{id}/test`), the behaviour stays.
- Proposed `PTH-CONN` codes (first set): `1001` unreachable or timeout, `1002` DNS failure, `1003` TLS handshake failure, `1004` untrusted certificate, `1005` authentication refused, `1006` missing scope or permission, `1007` provider rate limit, `1008` webhook not registered or failing, `1009` credential expired or expiring, `1010` blocked by the egress or SSRF policy, `1011` unsupported API version. `PTH-SYNC` covers source sync.

### M3: onboarding, inventory, tags, application hub

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `GET /api/v1/assets/lookup` | `repos.read` | `?url=` or `?name=`, `kind?` | `{matches: [{kind, id, name, key, match: clone_url\|key\|name, score}]}` | `400` |
| `POST /api/v1/asset-drafts` | `repos.manage` | `{kind, form, connector_id?}` | Draft with `missing_fields` (`201`) | `422` |
| `GET /api/v1/asset-drafts` | `repos.read` | `?status=&kind=&mine=&cursor=` | List | — |
| `GET`, `PATCH`, `DELETE /api/v1/asset-drafts/{id}` | `repos.read` / `repos.manage` | `PATCH {form}` | Draft | `404`; `409` (already registered) |
| `POST /api/v1/asset-drafts/{id}/register` | `repos.manage` | `{allow_incomplete: bool, allow_duplicate: bool}` | `{kind, id, registration_status}` (`201`) | `409 conflict` with `details.duplicates` (`PTH-ONB-1001`); `422 validation_failed` with `fields` (`PTH-ONB-1002`) when required fields are missing and `allow_incomplete` is false |
| `GET /api/v1/applications/{id}/profile` | `repos.read` | — | Overview, repositories, classification, tags, versions count, lifecycle strip `[{phase, status: done\|partial\|not_started\|disabled, link}]`; one call for the hub header | `404` |
| `PUT /api/v1/applications/{id}/tags` | `repos.manage` | `{tag_ids: []}` | Tags | `422 mandatory_tags_missing` (existing code) |
| `GET /api/v1/tags/history` | `repos.read` | `?subject_kind=&subject_id=&cursor=` | History rows | `400` |
| `PATCH /api/v1/tag-categories/{id}` | `tags.manage` | Adds `applies_to` | Category | Existing |

There is no `GET /api/v1/applications/{id}` today (applications are read through `GET /api/v1/applications` and `GET /api/v1/posture/applications`). The profile endpoint fills that gap without changing the list.

**As built in M3 (2026-11-20; the code is authoritative, see [applications.md](../api-reference/applications.md#onboarding)).** The design above was adjusted while building:

| Proposed | Built | Why |
|---|---|---|
| `GET /api/v1/assets/lookup` | `POST /api/v1/onboarding/match` | Matches a batch of discovered repositories at once and returns application candidates with reasons; body instead of query because a batch holds up to 50 sources |
| `asset-drafts` (separate draft objects) | Drafts are applications with `onboarding_status = draft`, plus `asset_onboardings` rows per repository | A draft is visible in the inventory and the profile like any application (the M3 "done when"); no second object to reconcile |
| `POST /asset-drafts/{id}/register` | `POST /api/v1/applications/{id}/onboarding/complete`; repositories still go through `POST /api/v1/repository-imports` | Reuses the import pipeline instead of a second registration path |
| `GET /api/v1/applications/{id}/profile` | `GET /api/v1/applications/{id}` and `GET /api/v1/applications/{id}/lifecycle` | The missing single read is the plain resource; the strip has its own call |
| `PUT /api/v1/applications/{id}/tags` | `tag_ids` in `PATCH /api/v1/applications/{id}/classification`; `POST /api/v1/tag-assignments/bulk` | One save for the classification form |
| `GET /api/v1/tags/history` | `GET /api/v1/tag-history` | `/tags/{id}` is an existing route family |
| `tag_categories.applies_to` | `tag_categories.mandatory_asset_types` (application types) and `color` | The prompt asks for mandatory categories per asset type |
| Duplicate codes `PTH-ONB-1001`/`1002` | `PTH-ONB-1008`–`1012` (1012: no silent move of a repository from another application) | 1001–1007 were already taken by import errors in M1 |

### M4: CodeGraph

> **As built in M4:** the endpoints follow the engine ↔ UI contract of the M4 brief (application-scoped paths under `/api/v1/codegraph/applications/{id}`, permission `findings.read`, `graph` instead of `view`, `focus` on aggregate ids instead of `/expand`, synchronous `GET …/diff`); see [api-reference/codegraph.md](../api-reference/codegraph.md). Saved graph views, search and stored diffs below are not built.

All graph reads are limited by repository scope (`graph.read`, resolved like `findings.read` through `authz`).

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `POST /api/v1/repositories/{id}/codegraph` | `scans.run` | `{commit_sha?}` | `{snapshot_id, status: building}` (`202`) | `404`; `409` (a build is running, `PTH-DISC-1001`) |
| `GET /api/v1/codegraph/snapshots` | `graph.read` | `?repository_id=&application_id=&status=&cursor=` | Snapshots with counts and engine versions | — |
| `GET /api/v1/codegraph/snapshots/{id}` | `graph.read` | — | Snapshot | `404` |
| `GET /api/v1/codegraph/snapshots/{id}/view` | `graph.read` | `?view=&level=service\|module\|package\|file\|function&focus=&depth=1..3&kind=&technology=&security=&evidence=verified,observed,ai_inferred&max_nodes=` (default 500, at most 2,000) | `{nodes: [{id, kind, label, group: bool, child_count, open_findings, security_tags}], edges: [{id, from, to, kind, count, evidence_types}], level, truncated, aggregated}` | `409` (snapshot not ready, `PTH-GRAPH-1001`); `400` (unknown view) |
| `GET /api/v1/codegraph/snapshots/{id}/nodes/{node_id}/expand` | `graph.read` | `?direction=children\|in\|out&kind=&limit=` (at most 500) | Nodes and edges to add; `truncated` | `404` |
| `GET /api/v1/codegraph/snapshots/{id}/nodes/{node_id}` | `graph.read` | — | Inspector: attributes, evidence per edge (`evidence_type`, file and line link, runtime reference, AI evidence record), linked findings and threats | `404` |
| `GET /api/v1/codegraph/snapshots/{id}/paths` | `graph.read` | `?from=&to=&direction=out\|in&max_hops=1..8&limit=1..50` | `{paths: [[edge_id…]], truncated}` (recursive CTE with a hop and row budget) | `400`; `422` (search budget exceeded, `PTH-GRAPH-1003`) |
| `GET /api/v1/codegraph/snapshots/{id}/search` | `graph.read` | `?q=&kind=&limit=` | Matching nodes with their group path | `400` |
| `GET /api/v1/codegraph/snapshots/{id}/export` | `graph.read` and `findings.export` | `?format=json` | Version-stamped JSON (`application/json`); PNG and SVG are rendered in the browser | `404` |
| `POST /api/v1/codegraph/diffs` | `graph.read` | `{base_snapshot_id, head_snapshot_id}` | `{id, status}` (`202` or `200` when it exists) | `422` (different repositories) |
| `GET /api/v1/codegraph/diffs/{id}` | `graph.read` | `?kind=` | Summary and changed nodes and edges | `404` |
| `GET`, `POST`, `DELETE /api/v1/graph-views` | Authenticated (own views); shared views need the graph's read permission | `{graph, name, snapshot_id?, state, shared}` | Saved views | `404`; `422` |

**Aggregation and lazy expansion.** The `view` call never returns more than `max_nodes` nodes. When the requested level has more, the server answers with group nodes (one level up, from `codegraph_group_edges`) and `aggregated: true`. The client expands a group with `/expand`. The 15 views of M4 are named filters over kinds, levels and edge kinds, defined in code; their list is part of the M4 design note.

### M5: threat models

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `GET /api/v1/threat-models` | `threatmodels.read` | `?application_id=&status=&cursor=` | List | — |
| `POST /api/v1/threat-models` | `threatmodels.edit` | `{application_id, repository_id?, title, method, codegraph_snapshot_id?}` | Model, status `draft` (`201`) | `422`; `409` (a draft exists) |
| `GET`, `PATCH /api/v1/threat-models/{id}` | read / edit | `PATCH {title, summary}` (draft only) | Model with elements and threat counts | `404`; `409` (not a draft, `PTH-TM-1001`) |
| `POST /api/v1/threat-models/{id}/generate` | `threatmodels.edit` | `{engines: [stride, linddun, attack_paths], use_ai: bool}` | `{status: running}` (`202`) | `409` (no ready CodeGraph snapshot, `PTH-TM-1002`) |
| `GET`, `POST /api/v1/threat-models/{id}/threats` | read / edit | Threat fields; `evidence` is required, `evidence_type` is set by the server for generated threats and `manual` threats are `verified` only with a CodeGraph or finding reference | Threats | `422` (missing evidence, `PTH-TM-1003`) |
| `PATCH`, `DELETE /api/v1/threats/{id}` | `threatmodels.edit` | Status, mitigation, owner, mappings | Threat | `404`; `409` |
| `POST /api/v1/threat-models/{id}/submit` | `threatmodels.edit` | — | Model `in_review` | `422` (threat without mitigation, `PTH-TM-1004`) |
| `POST /api/v1/threat-models/{id}/approve`, `/reject` | `threatmodels.approve` | `{note}` | Model and approval row | `409` (author cannot approve, `PTH-TM-1005`) |
| `GET /api/v1/threat-models/{id}/versions` | `threatmodels.read` | — | Versions with approvals | `404` |
| `POST /api/v1/threat-models/import` | `threatmodels.edit` | Multipart file plus `application_id`, `format: threat_dragon\|pytm\|threagile\|pathos` | Model `draft` with imported threats (`evidence_type` of imported threats: `ai_inferred` is never assigned; they are `verified` only if mapped to CodeGraph, else flagged "unverified import") | `415`; `422` (`PTH-TM-1101` parse error with line) |
| `GET /api/v1/threat-models/{id}/export` | `threatmodels.read` | `?format=threat_dragon\|pathos\|markdown` | Version-stamped file | `404` |
| `GET /api/v1/threat-frameworks/{framework}/entries` | Authenticated | `?q=&limit=` | Entries with release and notice | `404` (unknown framework) |
| `GET /api/v1/posture/attack-paths` | `findings.read` (existing) | Additive `application_id` filter | Existing response | Existing |

Imported threats raise an evidence question: the rule 5 labels are *verified*, *observed* and *AI-inferred*, and an imported threat is none of these until it is linked. Proposed: imported threats without a link are stored with `method = 'imported'` and shown as "not yet linked to evidence"; they cannot be approved until linked. **Needs owner confirmation.**

### M6: scan profiles and engines

M6 builds on existing endpoints: `GET /api/v1/scanners`, `GET /api/v1/scan-types`, scan profiles under `/api/v1/scan-profiles`, workers under `/api/v1/workers`. Proposed additive fields only:

- On finding responses: `check_kind` (the scan-type label shown in the UI) and `engines_confirmed` (= `cardinality(findings.scanner_keys)`; the column exists, `00003_scanning.sql:181`).
- On scan profiles: `tier: quick\|standard\|comprehensive\|custom` (presentation of the existing profile settings; the stored profile model is unchanged).

### M7: AI evidence and model per task

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `GET /api/v1/ai/evidence` | `ai.evidence.read` and read access to the subject | `?subject_kind=&subject_id=&task=&cursor=` | Records without prompt or response bodies | `400` |
| `GET /api/v1/ai/evidence/{id}` | Same | `?include=prompt,response` | Record; bodies only with the subject's read permission and only redacted text | `404` |
| `POST /api/v1/ai/evidence/{id}/review` | Task-specific (`ai.review` for findings, `threatmodels.approve` for threats, `graph.read` plus `repos.manage` for graph edges) | `{decision: accepted\|rejected, note}` | Record | `409` (already reviewed) |
| `POST /api/v1/ai/evidence/{id}/replay` | Same as review | — | New record with `replay_of` and a comparison `{same_conclusion: bool, diff}` (`202`) | `409` (model or configuration version no longer available, `PTH-AI-1201`) |
| `GET`, `PUT /api/v1/ai/task-assignments` | `ai.configure` | `PUT {task: configuration_id}` | Assignments | `422` (configuration archived) |
| `GET /api/v1/findings/{id}/correlation` | `findings.read` | — | Related findings (existing logic of `GET /findings/{id}/related`), CodeGraph nodes, threats, runtime facts, each with its evidence label | `404` |

No endpoint suppresses or closes a finding from an AI conclusion alone (existing guardrail: AI never overrides a human decision and never closes a critical, [ARCHITECTURE.md §6](../ARCHITECTURE.md#6-ai-review-architecture)).

**Built in M7 (2026-11-20)**, [API reference](../api-reference/ai-evidence.md). Differences: the permission is `ai.evidence_read`; review permissions are `ai.review` (findings; an AI review awaiting approval also needs `findings.triage`) and `threats.manage` (threat suggestions; the M5 build named the threat permissions `threats.*`); replay answers `201` synchronously; added `PUT /api/v1/ai/evidence-settings`, `POST /api/v1/findings/{id}/correlation/explain` and `POST /api/v1/threat-models/{id}/suggest`; `GET /api/v1/ai/task-assignments` returns every task with its effective configuration, and `PUT` takes `{assignments: {task: configuration_id|null}}`. Since M7 an AI false-positive verdict always waits for a person, whatever the approval policy.

### M8: remediation and gates

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `GET /api/v1/remediation/items` | `remediation.read` | `?application_id=&repository_id=&status=&owner=&cursor=&sort=` | List | — |
| `POST /api/v1/remediation/items` | `remediation.manage` | `{title, kind, application_id?, repository_id?, finding_ids?, threat_ids?, owner_id?, due_at?}` | Item (`201`) | `422` |
| `GET`, `PATCH /api/v1/remediation/items/{id}` | read / manage | Status, owner, due date, links | Item | `404`; `409` (invalid transition, `PTH-REM-1001`) |
| `POST /api/v1/remediation/items/{id}/verify` | `remediation.manage` and `scans.run` | `{scan_job_id?}` (else a new scan is queued) | `{verification_id, status}` (`202`) | `409` (no baseline scan, `PTH-REM-1002`) |
| `GET /api/v1/remediation/items/{id}/verifications` | `remediation.read` | — | Before-and-after evidence | `404` |
| `GET`, `POST /api/v1/gates` | `gates.manage` (list: `remediation.read`) | `{name, stage, policy_id, mode, allow_exceptions, application_id?}` | Gates | `422` (`policy_id` missing or not found, `PTH-GATE-1001`) |
| `GET`, `PUT`, `DELETE /api/v1/gates/{id}` | `gates.manage` | Same fields | Gate | `404` |
| `POST /api/v1/gates/evaluate` | `scans.read` (API token for CI, IDE, pre-commit; session for release and deploy pages) | `{stage, repository_id?, application_version_id?, commit_sha?, pull_request?, scan_id?}` | `{decision_id, outcome: pass\|warn\|block\|approval_required\|exception_applied, gates: [{id, name, mode, policy: {id, name, version}}], reasons: [], exceptions: [], docs_url}` | `404`; `422` |
| `GET /api/v1/gates/decisions` | `remediation.read` | `?repository_id=&stage=&outcome=&cursor=` | Decisions | — |
| `POST /api/v1/gates/decisions/{id}/exceptions` | `remediation.manage` | `{reason, expires_at}` | Exception `requested` (`201`) | `409` (gate does not allow exceptions, `PTH-GATE-1101`) |
| `POST /api/v1/gate-exceptions/{id}/approve`, `/reject` | `gates.approve_exception` | `{note}` | Exception | `409` (requester cannot approve, `PTH-GATE-1102`) |

**Implemented in M8** ([API reference](../api-reference/remediation-and-gates.md)), with these differences: the catalogue codes `PTH-REM-1001`–`1005` and `PTH-GATE-1001`–`1002` already existed (fix pull requests, AI fixes, the scan gate), so M8 uses `PTH-REM-1101`–`1106` and `PTH-GATE-1101`–`1108` (`1101` policy required, `1102` exceptions not allowed, `1103` requester cannot decide, `1104` not pending, `1105` managed by pull request settings, `1106` pull request checks need block or warn, `1107` evidence incomplete, `1108` policy used by gates); verification needs `remediation.manage` and `scans.run`, except for the item's assigned owner (`remediation.read` is enough, owner decision after M8 review); `evaluate` takes `application_id` instead of `application_version_id`; added `GET /api/v1/gates/decisions/{id}`, `GET /api/v1/gate-exceptions`, `POST …/revoke`, `POST /api/v1/remediation/items/bulk` and saved views (`/api/v1/remediation/views`). The existing PR checks now decide through the gates engine (decision C6).

**Rule 7 in the API.** `evaluate` returns `block` or `approval_required` only when an enabled gate whose policy matched says so; with no gate configured the outcome is `pass` and `reasons` says "no gate configured". The database refuses a blocking decision without a policy ([database design](PATHOS_DATABASE_DESIGN.md#remediation-items-and-gate-decisions-m8)). The existing `GET /api/v1/scans/{id}/gate`, PR checks and the CLI `pathos gate` keep working unchanged; how their non-policy thresholds relate to rule 7 is an open owner decision recorded in the database design.

### M9: reporting and monitoring

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `GET /api/v1/monitoring/feed` | `monitoring.read` (rows filtered by repository and application scope) | `?since=&kind=&severity=&application_id=&acknowledged=&cursor=&limit=` | `{items: [{id, occurred_at, kind, severity, summary, subject: {kind, id, link}, evidence_type, acknowledged_at}], next_cursor}` | `400` |
| `POST /api/v1/monitoring/feed/{id}/acknowledge` | `monitoring.read` and the subject's triage permission | — | Event | `404` |
| `GET /api/v1/monitoring/drift` | `graph.read` | `?application_id=&since=` | CodeGraph diffs over the threshold, with summaries | — |

Report upgrades extend the existing `/api/v1/reports` and `/api/v1/executive` responses additively (version stamp, new sections). The feed is polled; server-sent events are a later option.

**Implemented in M9** ([API reference](../api-reference/monitoring.md)), with these differences: the feed is `GET /api/v1/monitoring/events` (plus `types`, `summary`, CSV export) and uses `findings.read` scoped by repository instead of a new `monitoring.read` permission (no RBAC catalogue change); events are not acknowledged (they are an audit-like stream; follow-up work happens in the linked page); drift is `GET /api/v1/monitoring/drift` and `/drift/{id}` with stored drift records per snapshot rather than on-request diffs; `GET/PUT /api/v1/monitoring/settings` turns drift alerts on (off by default). The technical report (`/api/v1/ai/reports`, kind technical) and the compliance framework detail gained lifecycle evidence sections; `GET /api/v1/compliance/frameworks/{key}/export` is new. Every download goes through `httpx.Download` (version stamp headers). Codes `PTH-MON-1101`–`1105`, `PTH-REM-1107`, `PTH-REP-1101`.

### M10: reverse engineering, static tier

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `POST /api/v1/rea/analyses` | `rea.run` | `{scan_target_id, application_version_id?, repository_id?, commit_sha?}` | `{id, status: queued, origin}` (`202`) | `422` (not an artifact target, `PTH-REA-1001`); `409 conflict` (artifact not proven to be an own build and third-party analysis is off, `PTH-REA-1002`) |
| `GET /api/v1/rea/analyses` | `rea.read` | `?scan_target_id=&status=&cursor=` | List | — |
| `GET /api/v1/rea/analyses/{id}` | `rea.read` | — | Analysis, engine versions, summary, links to findings and the binary CodeGraph snapshot | `404` |
| `POST /api/v1/rea/analyses/{id}/cancel` | `rea.run` | — | Analysis | `409` (finished) |
| `GET /api/v1/rea/analyses/{id}/source-diff` | `rea.read` and `repos.read` | — | Source-versus-binary diff summary | `404`; `409` (no source mapped, `PTH-REA-1101`) |

### Documentation duty

Every endpoint above, once built, goes into `docs/api-reference/*.md` with request, response, errors and permission, in the same PR (prompt §8). The planned-versus-built table at the top of this page gets a lifecycle part when the first milestone ships.
