---
title: API reference overview
section: api-reference
order: 1
version: "1.0"
updated: 2026-11-20
summary: How the PATHOS REST API works (base URL, sessions and CSRF, REST API tokens, errors, pagination, rate limits, idempotency, permissions) and a map of every API reference page.
---

# API reference overview

The PATHOS REST API is the same API the web interface uses. Everything in this reference is derived from the implemented server code.

## Pages

**Assets and integrations**

| Page | Contents |
|---|---|
| [Assets](assets.md#what-an-asset-is-in-pathos) | What an asset is, asset settings, classification catalogs, tags, directory lookups |
| [Repositories](repositories.md#the-repository-object) | List, get, update, archive, delete, tag, sync, snapshots, insights, scan, legacy imports |
| [Source provider (SCM) connections](integrations.md#providers-and-authentication-methods) | Providers, connections, discovery, SCM inventory, OAuth applications, webhook receivers |
| [Imports and uploads](imports.md#upload-sessions) | Chunked uploads and asynchronous repository import jobs |
| [Applications](applications.md#the-application-object) | Applications and how repositories link to them |
| [Runtime context](runtime.md#clusters) | Kubernetes clusters and container registries (read-only inventories), workloads, application mappings, where a finding runs |
| [CodeGraph](codegraph.md#views) | Code graph snapshots per application, repository and commit: builds, 15 views with server-side aggregation and lazy expansion, node inspector, path tracing, diffs, JSON export, rediscovery settings (feature flag `codegraph`) |
| [Threat models](threat-models.md) | Threat models of an application: STRIDE generation on CodeGraph and attack paths, threats with evidence, method, severity, confidence and mitigation, ATT&CK / CAPEC / CWE / D3FEND mappings, versions and approval, Threat Dragon and PATHOS import and export (feature flag `threat_models`) |
| [Ticketing and reports](integrations-reporting.md#ticketing-jira-servicenow) | Jira and ServiceNow, executive overview, custom reports |

**Findings and scanning**

| Page | Contents |
|---|---|
| [Findings](findings.md) | List, filter and triage findings; status history, risk acceptances, suppression rules, SLA policies |
| [Scans](scans.md) | Start, list, monitor, retry, cancel and compare scan executions |
| [Scan schedules](schedules.md) | Schedules with execution plans, scan windows, retries and run history |
| [Scanners, scan profiles and custom rules](scan-configuration.md) | Scanner catalog, versioned scan profiles, custom Opengrep rules |
| [Scan types and tool manifests](scan-types-and-tools.md) | The 25 scan types with their tools, import formats and live workers; tool manifest parsers (SARIF, import formats, jsonmap) |
| [Scan targets](scan-targets.md) | Container images, web applications, APIs, build artifacts and SBOMs; tools per target and intrusive testing authorization |
| [Result and SBOM imports](result-imports.md) | Import results in 232 formats (SARIF and named SARIF formats of 31 tools, Semgrep, Snyk, SonarQube, ZAP, Burp, Trivy, Nessus, Fortify, GitLab, KICS, CSV, ...) and CycloneDX or SPDX SBOMs; the `pathos` CLI and CI templates are described in [CI/CD integration](../user-guide/ci-cd-integration.md) |
| [Supply chain and pull request checks](supply-chain.md) | SBOM inventory and export, licence policies, package health, pull request checks |
| [Application versions, VEX and component policies](releases-and-vex.md) | Releases with frozen SBOM and findings, component portfolio, OpenVEX and CycloneDX VEX export and import, component policies |
| [Risk scoring and intelligence feeds](risk-intelligence.md) | Risk scores and model, EPSS, KEV, OSV and deps.dev feeds, CVE lookups |
| [Reachability and related findings](vulnerability-intelligence.md) | Reachability and related findings |
| [Posture](posture.md) | Posture rollups, coverage, unmanaged repositories, dependency graphs, blast radius, attack paths |
| [Material changes and developer insights](developer-context.md) | Security-material changes per scan and repository, developer attribution, identity links |
| [Dashboard and global search](dashboard-and-search.md) | Security dashboard KPIs and charts, top-bar search |
| [Human Eye reviews](human-reviews.md) | Manual review queue, assessments, decisions, evidence and reports |
| [AI providers, finding reviews and MCP](ai-and-mcp.md) | AI providers and configurations, AI reviews, MCP server registry, the PATHOS MCP endpoint |
| [AI Security Analyst, reports and usage](ai-analyst.md) | Analyst conversations, AI-written reports, AI usage |

**Governance and administration**

| Page | Contents |
|---|---|
| [Security policies and compliance](governance.md) | Policies (conditions → actions), violations, compliance framework views |
| [Administration and your account](administration.md) | `/me`, API tokens, in-app notifications, users, role assignments, roles, organization structure, audit log, workers, MFA |
| [Notifications and outbound webhooks](notifications.md) | SMTP, notification rules, email templates, delivery history, outbound webhooks |
| [Connectors](connectors.md) | Kinds catalogue, one list over every connection, health checks and history, AI troubleshooting of a connector (flag `connectors`) |
| [Remediation and security gates](remediation-and-gates.md) | Remediation items, fix verification with before-and-after evidence, saved views, security gates at every stage, gate decisions, exceptions and approvals (flag `remediation_workspace`) |
| [Continuous monitoring](monitoring.md) | The feed of the lifecycle feedback loops, architecture drift between CodeGraph snapshots, drift alert settings, developer feedback on gate failures, version stamps of every export (flag `continuous_monitoring`) |
| [Product metadata, diagnostics and feature flags](diagnostics.md) | `GET /api/v1/meta`, the error catalogue, AI troubleshooting, feature flags |
| [Worker protocol (internal)](worker-protocol.md) | The internal API scan workers use; not for API clients |

## Base URL

All endpoints are relative to the PATHOS public URL, for example `https://pathos.example.com`. The versioned API lives under `/api/v1`. Sign-in lives under `/api/auth`, the source provider webhook receivers under `/api/webhooks`, and the MCP endpoint at `/mcp`. `GET /healthz` and `GET /readyz` are unauthenticated health checks.

Requests and responses use JSON (`application/json; charset=utf-8`) unless stated otherwise. Timestamps are RFC 3339 in UTC; dates are `YYYY-MM-DD`. IDs are UUIDs (version 7). Every response carries an `X-Request-Id` header; a client may send its own `X-Request-Id` (1–64 characters of letters, digits, `-` and `_`).

## Authentication

Every `/api/` path except login, callback and the webhook receivers needs either a browser session or a REST API token. Without one the response is `401 unauthenticated`.

### Browser session

1. The browser opens `GET /api/auth/login` (optional `return_to` path). PATHOS redirects to the identity provider (Keycloak, OpenID Connect with PKCE).
2. After sign-in, `GET /api/auth/callback` creates the session and sets an HttpOnly cookie: `__Host-pathos_session` over HTTPS (`pathos_session` on plain-HTTP development setups), `SameSite=Lax`.
3. Sessions expire after `PATHOS_SESSION_IDLE_TTL` of inactivity (default 8 hours) and at the latest after `PATHOS_SESSION_ABSOLUTE_TTL` (default 24 hours). `POST /api/auth/logout` ends the session.

Deactivated users lose their sessions at once.

### CSRF protection

Every session request other than `GET`, `HEAD` and `OPTIONS` must send the session's CSRF token:

- Read it from `csrf_token` in [`GET /api/v1/me`](administration.md#the-current-user).
- Send it as `X-CSRF-Token: <csrf-token>`.
- If the request has an `Origin` header, it must equal the PATHOS public origin.

A missing or wrong token, or a foreign `Origin`, returns `403 csrf_failed`.

```http
GET /api/v1/me HTTP/1.1
Host: pathos.example.com
Cookie: __Host-pathos_session=<session-cookie>
```

### REST API tokens

Scripts and integrations use a personal API token instead of a session:

```
curl -H "Authorization: Bearer pathos_pat_…" "https://pathos.example.com/api/v1/findings?severity=critical"
```

- Create tokens with [`POST /api/v1/me/tokens`](administration.md#api-tokens) from a signed-in session. A token lives 1–90 days and carries scopes:
  - `api:read` — `GET` and `HEAD` under `/api/`; other methods return `403 token_read_only`.
  - `api:write` — every method under `/api/`.
  - `mcp` — only the MCP endpoint `/mcp` (see [AI providers, finding reviews and MCP](ai-and-mcp.md#pathos-mcp-endpoint)). An `mcp`-only token is rejected on `/api/` (`401 invalid_token`), and an `api:*`-only token is rejected by `/mcp`.
- A token acts with its owner's **current** role assignments, never more. It stops working when the owner is deactivated, the token is revoked or it expires. A wrong, expired or revoked token returns `401 invalid_token`.
- No CSRF token is needed (no cookie is involved). If a request carries both a session cookie and a bearer token, the session is used.
- Tokens can never call `/api/v1/me/tokens`, `/api/v1/me/mfa`, `/api/v1/me/recovery-codes` or `/api/auth/*` (`403 token_not_allowed`).
- Audit entries made with a token carry `metadata.api_token_id`; the token's `last_used_at` is updated on every use.

In this reference, "Session or API token" in an endpoint's *Authentication* row means either method works; mutations need `X-CSRF-Token` with a session and the `api:write` scope with a token.

### Request bodies

JSON bodies must be sent with `Content-Type: application/json` (otherwise `415 unsupported_media_type`). Bodies are limited to 1 MiB unless an endpoint says otherwise, must contain exactly one JSON object, and **unknown fields are rejected** with `400 invalid_request` (for example sending the read-only `repository_key`). Exceptions include [CSV import](repositories.md#import-repositories-from-csv) (`text/csv`), [upload parts](imports.md#upload-a-part) (raw bytes) and the file uploads of [result and SBOM imports](result-imports.md).

### Webhook receivers

The [webhook receivers](integrations.md#webhook-receivers) under `/api/webhooks` are public. They authenticate each delivery with the connection's webhook secret (HMAC signature, token or Basic authentication, depending on the provider).

## Errors

Errors use one JSON shape. PATHOS 3.0 adds diagnostic fields inside `error`; every field that existed before is unchanged, so clients that match `error.code` keep working.

```json
{
  "error": {
    "code": "scm_error",
    "message": "scm: authentication failed (check the token and its scopes) (HTTP 401 from api.github.com)",
    "error_code": "PTH-CONN-1007",
    "title": "Provider rejected the credential",
    "cause": { "confirmed": true, "text": "The provider rejected the connection's credential (HTTP 401)." },
    "probable_causes": ["The token was revoked or regenerated", "A token for another host or account"],
    "impact": "All operations of this connection fail until the credential is replaced.",
    "actions": ["Create a new token with the scopes in docs/user-guide/provider-integrations.md.", "Edit the connection and paste the new token."],
    "verify": ["Test connection reports the authenticated account."],
    "docs_url": "/help/troubleshooting/conn#PTH-CONN-1007",
    "ai_help": true,
    "request_id": "qjxkbtnmwpzrfhdcylvsageo"
  },
  "request_id": "qjxkbtnmwpzrfhdcylvsageo"
}
```

| Member | Description |
|---|---|
| `error.code` | Stable machine-readable short code (`not_found`, `scm_error`, ...). Unchanged since 1.0; match on it in scripts. |
| `error.message` | Human-readable explanation. |
| `error.details` | Optional structured data, for example `items` for `invalid_items` or `missing_parts` for incomplete uploads. |
| `error.fields` | Optional map of field name to message, for `validation_failed`. |
| `error.error_code` | The error catalogue code, `PTH-<AREA>-<NNNN>` (areas `PLAT`, `AUTH`, `CONN`, `SYNC`, `ONB`, `DISC`, `GRAPH`, `TM`, `REA`, `SCAN`, `WORK`, `AI`, `GATE`, `REM`, `REP`, `MON`). Always present; `PTH-PLAT-0001` when nothing closer applies. The same code is logged as `error_code` on the server's log lines for the request. |
| `error.title` | Short title of the catalogue entry. |
| `error.cause` | `confirmed` is `true` when the check that raised the error proves the cause (`text` then states it); otherwise work through `probable_causes`. |
| `error.probable_causes` | Probable causes, most likely first. |
| `error.impact` | What the failure affects. |
| `error.actions` | Corrective actions, in order. |
| `error.verify` | How to check the fix worked. |
| `error.docs_url` | In-app help page of the code (`/help/troubleshooting/<area>#<code>`); the same pages are in `docs/troubleshooting/`. |
| `error.ai_help` | Whether [AI troubleshooting](diagnostics.md#troubleshoot-an-error) is offered for the code. |
| `error.request_id`, `request_id` | Same value as the `X-Request-Id` response header; quote it (and the `error_code`) when reporting problems. |

The catalogue of every code is served by [`GET /api/v1/diagnostics/codes`](diagnostics.md#list-the-error-catalogue). Responses that add their own top-level members (an import record with `invalid_report`, an inventory run with `inventory_failed`) keep them next to `error` and `request_id`.

Common status codes and codes (pages list further, endpoint-specific codes):

| Status | Code | When |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON, unknown field, invalid parameter, failed simple validation, a referenced item that does not exist, or "not supported by this provider". |
| 401 | `unauthenticated` | No valid session or token. |
| 401 | `invalid_token` | Invalid, expired or revoked API token. |
| 401 | `invalid_signature` | Webhook verification failed. |
| 403 | `forbidden` | Authenticated but not permitted. |
| 403 | `csrf_failed` | Missing or invalid CSRF token, or foreign `Origin`. |
| 403 | `token_read_only` | A write request with an `api:read` token. |
| 403 | `token_not_allowed` | An API token on an endpoint that requires a session. |
| 404 | `not_found` | The resource does not exist, **or is outside the caller's scope** (existence is not disclosed). Malformed path IDs and unknown `/api/` paths also return 404. |
| 409 | `conflict` | State conflict (already archived, must archive first, in use, duplicate name). |
| 413 | `too_large` | Upload or payload too large. |
| 415 | `unsupported_media_type` | Wrong `Content-Type`. |
| 422 | `validation_failed` | Asset metadata failed validation; see `fields`. |
| 422 | `invalid_items` | Import items have blocking problems; see `details.items`. |
| 422 | `checksum_mismatch` | An upload part does not match its SHA-256. |
| 422 | `mandatory_tags_missing` | Bulk tagging would leave a mandatory tag category empty. |
| 429 | `rate_limited` | Rate limit exceeded; see `Retry-After`. |
| 429 | `too_many_uploads` | Too many open uploads for this user. |
| 500 | `internal` | Unexpected error; details are only in the server log. |
| 502 | `scm_error` | The SCM provider refused a live call (authentication, permission, not found, rate limit, expired authorization, blocked address). |
| 502 | `idp_error` | Keycloak could not be reached (MFA endpoints). |
| 503 | `uploads_unavailable` | Local uploads are not configured on the server. |

## Pagination

There is no single pagination style; each list endpoint documents its own. The common patterns:

| Style | Examples |
|---|---|
| Keyset cursor: `limit` and `cursor`, response `next_cursor` (`null` on the last page) | [List repositories](repositories.md#list-repositories) (`limit` 1–200, default 50; keep `sort` unchanged while paging), [list users](administration.md#list-users) (1–200, default 50), [audit log](administration.md#audit-log) (fixed 50) |
| Cursor with a fixed page size | [List import jobs](imports.md#list-import-jobs) (25), [list executions](scans.md) (50), [notification deliveries](notifications.md#delivery-history) (100, `before`) |
| Provider page token: pass `next_page_token` as `page_token`; `""` on the last page | [List remote repositories](integrations.md#list-remote-repositories) (50 per page) |
| Bounded list, no further pages | [Search tags](assets.md#search-tags) and [directory lookups](assets.md#search-users) (`limit`), [list applications](applications.md#list-applications) (up to 500), sync runs and snapshots (100 most recent), API tokens (100), in-app notifications (50) |

Cursors and page tokens are opaque; pass them back unchanged.

## Rate limits

When rate limiting is enabled (it is unless `PATHOS_RATE_LIMIT_SCALE=0`), requests are limited per class with a token-bucket style (GCRA) limiter shared by all API replicas. Defaults (multiplied by `PATHOS_RATE_LIMIT_SCALE`):

| Class | Key | Sustained | Burst |
|---|---|---|---|
| Authenticated reads (`GET`, `HEAD` under `/api/`, session or token) | user | 25 / s | 150 |
| Authenticated writes (other methods under `/api/`) | user | 5 / s | 40 |
| Unauthenticated API calls | client IP | 5 / s | 50 |
| Login and callback (`/api/auth/*` except logout) | client IP | 1 / s | 20 |
| Webhooks (`/api/webhooks/*`) | connection | 50 / s | 200 |
| MCP (`/mcp`) | bearer token | 10 / s | 60 |

Exceeding a limit returns `429 rate_limited` with a `Retry-After` header (seconds). If the limiter backend is unavailable, requests are allowed.

## Idempotency

- [Start an import](imports.md#start-an-import) requires an idempotency key (8–100 characters) in `idempotency_key` or the `Idempotency-Key` header. Repeating a key returns the existing job (`200`) instead of creating a new one. Keys are scoped to the requesting user.
- [Complete an upload](imports.md#complete-an-upload) and [Upload a part](imports.md#upload-a-part) can be repeated safely.
- Imports never register the same SCM repository twice for a connection (result `already_imported`). Duplicate archives and clone URLs need `allow_duplicate`.
- Webhook deliveries are de-duplicated by delivery ID.

## Permissions

Permissions are granted through roles at a scope: organization, region, business unit (including all units below it) or a single repository. [`GET /api/v1/permissions`](administration.md#roles-and-permissions) lists the catalog and [`GET /api/v1/roles`](administration.md#roles-and-permissions) the roles; which role carries which permission is in `docs/RBAC_MATRIX.md`.

- Permissions marked **org-only** in the catalog (for example `users.manage`, `scm.manage`, `settings.manage`, `notifications.manage`, `audit.read`) only take effect when granted at organization scope.
- "At any scope" in this reference means the caller holds the permission at some scope; such endpoints then return only the data inside the caller's scopes.
- "Organization-wide" or "org-wide" means a grant at organization scope.
- Each page lists the permission per endpoint. Asset owners (business, technical or application owner, or a member of the responsible team) may edit descriptive and ownership metadata of their repositories without `repos.manage`; see [Update a repository](repositories.md#update-a-repository).

## Not available

The following are not implemented in this version:

- A separate `/api/v1/assets` resource (assets are repositories).
- Reading a single application by ID, unarchiving or deleting applications, and linking non-repository assets to applications (see [Applications](applications.md#capabilities-at-a-glance)).
- Creating or editing custom roles, and editing regions and countries.
- Reporting the credential's write or admin permission in remote repository details (`permission` is always `read`).
