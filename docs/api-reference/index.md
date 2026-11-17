---
title: API reference overview
section: api-reference
order: 1
version: "1.0"
updated: 2026-11-17
summary: Conventions of the PATHOS Repository and Asset Management API (authentication, errors, pagination, rate limits, permissions) and a list of every endpoint.
---

# API reference overview

This reference covers the Repository and Asset Management module of PATHOS: repositories (assets), asset settings and catalogs, tags, applications, SCM integrations, imports and uploads. It is derived from the implemented server code.

| Page | Contents |
|---|---|
| [Assets](assets.md#what-an-asset-is-in-pathos) | What an asset is, asset settings, classification catalogs, tags, directory lookups |
| [Repositories](repositories.md#the-repository-object) | List, get, update, archive, delete, tag, sync, snapshots, insights, scan, legacy imports |
| [SCM integrations](integrations.md#providers-and-authentication-methods) | Providers, connections, discovery, OAuth applications, webhooks |
| [Imports and uploads](imports.md#upload-sessions) | Chunked uploads and asynchronous import jobs |
| [Applications](applications.md#the-application-object) | Applications and how repositories link to them |
| [Scans](scans.md#the-execution-object) | Start, list, monitor, retry, cancel and compare scan executions; stages, logs, findings, history, overview |
| [Scan schedules](schedules.md#the-schedule-object) | Schedules with execution plans, scan windows, retries, concurrency limits and activation history |
| [Result and SBOM imports, custom rules](result-imports.md#importing-results) | Import SARIF, Grype or PATHOS JSON results and CycloneDX or SPDX SBOMs; custom Opengrep rules |
| [Vulnerability intelligence](vulnerability-intelligence.md#osv-feed) | OSV records, reachability, attack paths, related findings, suppression rules |
| [AI Security Analyst](ai-analyst.md#analyst) | Conversations over your security data, AI-written reports, AI usage |
| [Posture](posture.md#endpoints) | Application posture and risk rollup, coverage, unmanaged and shadow repositories, benchmarking, dependency graphs, blast radius, context graph |
| [Scan targets](scan-targets.md#endpoints) | Container images, web applications (DAST), APIs (OpenAPI) and SBOMs as scan targets |
| [Risk and vulnerability intelligence](risk-intelligence.md#finding-fields-and-filters) | Contextual risk scores and model, EPSS and KEV feeds, CVE lookups, lifecycle statuses |
| [Human Eye reviews](human-reviews.md#queue) | Review queue, assessment workspace, decisions, independent review, evidence, AI suggestions, reports and configuration |

## Base URL

All endpoints are relative to the PATHOS public URL, for example `https://pathos.example.com`. The versioned API lives under `/api/v1`. Webhook receivers live under `/api/webhooks`.

Requests and responses use JSON (`application/json; charset=utf-8`) unless stated otherwise. Timestamps are RFC 3339 in UTC; dates are `YYYY-MM-DD`. IDs are UUIDs (version 7). Every response carries an `X-Request-Id` header; a client may send its own `X-Request-Id` (1–64 characters of letters, digits, `-` and `_`).

## Authentication

### Browser session

`/api/v1` accepts **only a browser session**:

1. The browser opens `GET /api/auth/login` (optional `return_to` path). PATHOS redirects to the identity provider (Keycloak, OpenID Connect with PKCE).
2. After sign-in, `GET /api/auth/callback` creates the session and sets an HttpOnly cookie: `__Host-pathos_session` over HTTPS (`pathos_session` on plain-HTTP development setups), `SameSite=Lax`.
3. Sessions expire after `PATHOS_SESSION_IDLE_TTL` of inactivity (default 8 hours) and at the latest after `PATHOS_SESSION_ABSOLUTE_TTL` (default 24 hours). `POST /api/auth/logout` ends the session.

A request without a valid session to any `/api/` path (except login, callback and webhooks) returns `401 unauthenticated`. Deactivated users lose their sessions.

**Bearer tokens are not accepted on `/api/v1`.** Personal API tokens exist only for the MCP endpoint (`/mcp`, `Authorization: Bearer <personal-access-token>`). The session middleware reads only the session cookie, so an `Authorization` header on `/api/v1` is ignored and the request is treated as unauthenticated.

### CSRF protection

Every request other than `GET`, `HEAD` and `OPTIONS` that carries a session must send the session's CSRF token:

- Read it from `csrf_token` in `GET /api/v1/me`.
- Send it as `X-CSRF-Token: <csrf-token>`.
- If the request has an `Origin` header, it must equal the PATHOS public origin.

A missing or wrong token, or a foreign `Origin`, returns `403 csrf_failed`.

```http
GET /api/v1/me HTTP/1.1
Host: pathos.example.com
Cookie: __Host-pathos_session=<session-cookie>
```

```json
{
  "user": { "id": "0190c0de-2222-7000-8000-000000000001", "email": "dana.owner@example.com", "...": "user fields" },
  "permissions": ["repos.read", "repos.manage", "scans.run"],
  "org_wide_permissions": ["repos.read"],
  "role_assignments": [],
  "csrf_token": "<csrf-token>"
}
```

### Request bodies

JSON bodies must be sent with `Content-Type: application/json` (otherwise `415 unsupported_media_type`). Bodies are limited to 1 MiB, must contain exactly one JSON object, and **unknown fields are rejected** with `400 invalid_request` (for example sending the read-only `repository_key`). Exceptions: [CSV import](repositories.md#import-repositories-from-csv) (`text/csv`) and [upload parts](imports.md#upload-a-part) (raw bytes).

### Webhooks

The [webhook receivers](integrations.md#webhook-receivers) are public. They authenticate each delivery with the connection's webhook secret (HMAC signature, token or Basic authentication, depending on the provider).

## Errors

Errors use one JSON shape:

```json
{
  "error": {
    "code": "validation_failed",
    "message": "check the highlighted fields: business_owner_id",
    "fields": { "business_owner_id": "user does not exist or is deactivated" }
  },
  "request_id": "9c1e7a3b5d2f4e6a8b0c1d2e"
}
```

| Member | Description |
|---|---|
| `error.code` | Stable machine-readable code. |
| `error.message` | Human-readable explanation. |
| `error.details` | Optional structured data, for example `items` for `invalid_items` or `missing_parts` for incomplete uploads. |
| `error.fields` | Optional map of field name to message, for `validation_failed`. |
| `request_id` | Same value as the `X-Request-Id` response header; quote it when reporting problems. |

Status codes and codes used by this module:

| Status | Code | When |
|---|---|---|
| 400 | `invalid_request` | Malformed JSON, unknown field, invalid parameter, failed simple validation, a referenced item that does not exist, or "not supported by this provider". |
| 401 | `unauthenticated` | No valid session. |
| 401 | `invalid_signature` | Webhook verification failed. |
| 403 | `forbidden` | Authenticated but not permitted. |
| 403 | `csrf_failed` | Missing or invalid CSRF token, or foreign `Origin`. |
| 404 | `not_found` | The resource does not exist, **or is outside the caller's scope** (existence is not disclosed). Malformed path IDs also return 404. |
| 409 | `conflict` | State conflict (already archived, must archive first, in use, duplicate name). |
| 413 | `too_large` | Upload or webhook payload too large. |
| 415 | `unsupported_media_type` | Wrong `Content-Type`. |
| 422 | `validation_failed` | Asset metadata failed validation; see `fields`. |
| 422 | `invalid_items` | Import items have blocking problems; see `details.items`. |
| 422 | `checksum_mismatch` | An upload part does not match its SHA-256. |
| 422 | `mandatory_tags_missing` | Bulk tagging would leave a mandatory tag category empty. |
| 429 | `rate_limited` | Rate limit exceeded; see `Retry-After`. |
| 429 | `too_many_uploads` | Too many open uploads for this user. |
| 500 | `internal` | Unexpected error; details are only in the server log. |
| 502 | `scm_error` | The SCM provider rejected or failed a live call (authentication, permission, not found, rate limit, expired authorization, blocked address). |
| 503 | `uploads_unavailable` | Local uploads are not configured on the server. |

## Pagination

| Endpoint | Style |
|---|---|
| [List repositories](repositories.md#list-repositories) | Keyset cursor: `limit` (1–200, default 50) and `cursor`; the response has `next_cursor` (`null` on the last page). Keep `sort` unchanged while paging. |
| [List import jobs](imports.md#list-import-jobs) | Keyset cursor, fixed 25 per page; `next_cursor`. |
| [List remote repositories](integrations.md#list-remote-repositories) | Provider page token: pass `next_page_token` as `page_token`; `""` on the last page. Fixed 50 per page. |
| [Search tags](assets.md#search-tags), [directory lookups](assets.md#search-users) | `limit` only (no further pages). |
| [List applications](applications.md#list-applications) | Up to 500 items, no pagination. |
| [List executions](scans.md#list-executions) | Keyset cursor, fixed 50 per page; `next_cursor`. |
| Sync runs, snapshots | The 100 most recent. |

Cursors and page tokens are opaque.

## Rate limits

When rate limiting is enabled (it is unless `PATHOS_RATE_LIMIT_SCALE=0`), requests are limited per class with a token-bucket style (GCRA) limiter shared by all API replicas. Defaults (multiplied by `PATHOS_RATE_LIMIT_SCALE`):

| Class | Key | Sustained | Burst |
|---|---|---|---|
| Authenticated reads (`GET`, `HEAD` under `/api/`) | user | 25 / s | 150 |
| Authenticated writes (other methods under `/api/`) | user | 5 / s | 40 |
| Unauthenticated API calls | client IP | 5 / s | 50 |
| Login and callback (`/api/auth/*`) | client IP | 1 / s | 20 |
| Webhooks (`/api/webhooks/*`) | connection | 50 / s | 200 |
| MCP (`/mcp`) | bearer token | 10 / s | 60 |

Exceeding a limit returns `429 rate_limited` with a `Retry-After` header (seconds). If the limiter backend is unavailable, requests are allowed.

## Idempotency

- [Start an import](imports.md#start-an-import) requires an idempotency key (8–100 characters) in `idempotency_key` or the `Idempotency-Key` header. Repeating a key returns the existing job (`200`) instead of creating a new one. Keys are scoped to the requesting user.
- [Complete an upload](imports.md#complete-an-upload) and [Upload a part](imports.md#upload-a-part) can be repeated safely.
- Imports never register the same SCM repository twice for a connection (result `already_imported`). Duplicate archives and clone URLs need `allow_duplicate`.
- Webhook deliveries are de-duplicated by delivery ID.

## Permissions

Permissions are granted through roles at a scope: organization, region, business unit (including all units below it) or a single repository. See `docs/RBAC_MATRIX.md` for the roles.

| Permission | Org-wide only | Used for |
|---|:-:|---|
| `repos.read` | no | Reading repositories, insights, tags, catalogs, directory lookups, applications, connection names, provider catalog. Asset owners with `repos.read` anywhere can read the repositories they own. |
| `repos.manage` | no | Editing, archiving, deleting, tagging and syncing repositories; creating imports and uploads (at the placement); applications (at their business unit). Discovery needs it at organization, region or business-unit scope. |
| `scm.manage` | yes | Connections, OAuth applications, OAuth flow, webhook secrets, resync. |
| `tags.manage` | yes | Tag categories and tags. |
| `assets.configure` | yes | Asset settings and classification catalogs. |
| `scans.run` | no | Starting, retrying and cancelling scans. |
| `scans.compare` | no | Scan history and comparison. |
| `findings.read` | no | Open finding counts in the repository security summary. |

"At any scope" in this reference means the caller holds the permission at some scope (used to allow list endpoints). "Organization-wide" means a grant at organization scope.

Asset owners (business owner, technical owner, application owner, or member of the responsible team) may edit descriptive and ownership metadata of their repositories without `repos.manage`; see [Update a repository](repositories.md#update-a-repository).

## Endpoints

70 endpoints are documented.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/asset-settings` | [Get asset settings](assets.md#get-asset-settings) |
| `PATCH` | `/api/v1/asset-settings` | [Update asset settings](assets.md#update-asset-settings) |
| `POST` | `/api/v1/asset-classifications` | [Create a classification entry](assets.md#create-a-classification-entry) |
| `PATCH` | `/api/v1/asset-classifications/{id}` | [Update a classification entry](assets.md#update-a-classification-entry) |
| `GET` | `/api/v1/tag-categories` | [List tag categories](assets.md#list-tag-categories) |
| `POST` | `/api/v1/tag-categories` | [Create a tag category](assets.md#create-a-tag-category) |
| `PATCH` | `/api/v1/tag-categories/{id}` | [Update a tag category](assets.md#update-a-tag-category) |
| `DELETE` | `/api/v1/tag-categories/{id}` | [Delete a tag category](assets.md#delete-a-tag-category) |
| `POST` | `/api/v1/tag-categories/{id}/tags` | [Create a tag](assets.md#create-a-tag) |
| `GET` | `/api/v1/tags` | [Search tags](assets.md#search-tags) |
| `PATCH` | `/api/v1/tags/{id}` | [Update a tag](assets.md#update-a-tag) |
| `DELETE` | `/api/v1/tags/{id}` | [Delete a tag](assets.md#delete-a-tag) |
| `GET` | `/api/v1/directory/users` | [Search users](assets.md#search-users) |
| `GET` | `/api/v1/directory/teams` | [Search teams](assets.md#search-teams) |
| `GET` | `/api/v1/repositories` | [List repositories](repositories.md#list-repositories) |
| `GET` | `/api/v1/repositories/insights` | [Get repository insights](repositories.md#get-repository-insights) |
| `GET` | `/api/v1/repositories/{id}` | [Get a repository](repositories.md#get-a-repository) |
| `PATCH` | `/api/v1/repositories/{id}` | [Update a repository](repositories.md#update-a-repository) |
| `GET` | `/api/v1/repositories/{id}/security` | [Get the security summary of a repository](repositories.md#get-the-security-summary-of-a-repository) |
| `GET` | `/api/v1/repositories/{id}/branches` | [List branches of a repository](repositories.md#list-branches-of-a-repository) |
| `PUT` | `/api/v1/repositories/{id}/scan-profile` | [Set the scan profile of a repository](repositories.md#set-the-scan-profile-of-a-repository) |
| `POST` | `/api/v1/repositories/bulk-tags` | [Add or remove tags on many repositories](repositories.md#add-or-remove-tags-on-many-repositories) |
| `POST` | `/api/v1/repositories/{id}/archive` | [Archive a repository](repositories.md#archive-a-repository) |
| `POST` | `/api/v1/repositories/{id}/unarchive` | [Unarchive a repository](repositories.md#unarchive-a-repository) |
| `DELETE` | `/api/v1/repositories/{id}` | [Delete a repository](repositories.md#delete-a-repository) |
| `POST` | `/api/v1/repositories/{id}/sync` | [Synchronize a repository](repositories.md#synchronize-a-repository) |
| `GET` | `/api/v1/repositories/{id}/sync-runs` | [List sync runs of a repository](repositories.md#list-sync-runs-of-a-repository) |
| `GET` | `/api/v1/repositories/{id}/snapshots` | [List source snapshots of a repository](repositories.md#list-source-snapshots-of-a-repository) |
| `POST` | `/api/v1/repositories/{id}/scan` | [Request a scan of a repository](repositories.md#request-a-scan-of-a-repository) |
| `POST` | `/api/v1/repositories/import` | [Import repositories synchronously](repositories.md#import-repositories-synchronously) (legacy) |
| `POST` | `/api/v1/repositories/import-csv` | [Import repositories from CSV](repositories.md#import-repositories-from-csv) (legacy) |
| `GET` | `/api/v1/scm-providers` | [List providers](integrations.md#list-providers) |
| `GET` | `/api/v1/scm-connections` | [List connections](integrations.md#list-connections) |
| `POST` | `/api/v1/scm-connections` | [Create a connection](integrations.md#create-a-connection) |
| `GET` | `/api/v1/scm-connections/{id}` | [Get a connection](integrations.md#get-a-connection) |
| `PATCH` | `/api/v1/scm-connections/{id}` | [Update a connection](integrations.md#update-a-connection) |
| `DELETE` | `/api/v1/scm-connections/{id}` | [Delete a connection](integrations.md#delete-a-connection) |
| `POST` | `/api/v1/scm-connections/{id}/test` | [Test a connection](integrations.md#test-a-connection) |
| `POST` | `/api/v1/scm-connections/{id}/webhook-secret` | [Rotate the webhook secret](integrations.md#rotate-the-webhook-secret) |
| `POST` | `/api/v1/scm-connections/{id}/resync` | [Resynchronize a connection](integrations.md#resynchronize-a-connection) |
| `GET` | `/api/v1/scm-connections/{id}/organizations` | [List remote organizations](integrations.md#list-remote-organizations) |
| `GET` | `/api/v1/scm-connections/{id}/projects` | [List remote projects](integrations.md#list-remote-projects) |
| `GET` | `/api/v1/scm-connections/{id}/remote-repositories` | [List remote repositories](integrations.md#list-remote-repositories) |
| `GET` | `/api/v1/scm-connections/{id}/remote-repositories/details` | [Get remote repository details](integrations.md#get-remote-repository-details) |
| `GET` | `/api/v1/scm-connections/{id}/discover` | [List all remote repositories (legacy)](integrations.md#list-all-remote-repositories-legacy) |
| `GET` | `/api/v1/scm-oauth-apps` | [List OAuth applications](integrations.md#list-oauth-applications) |
| `POST` | `/api/v1/scm-oauth-apps` | [Create an OAuth application](integrations.md#create-an-oauth-application) |
| `PATCH` | `/api/v1/scm-oauth-apps/{id}` | [Update an OAuth application](integrations.md#update-an-oauth-application) |
| `DELETE` | `/api/v1/scm-oauth-apps/{id}` | [Delete an OAuth application](integrations.md#delete-an-oauth-application) |
| `POST` | `/api/v1/scm-connections/oauth/start` | [Start an OAuth connection](integrations.md#start-an-oauth-connection) |
| `GET` | `/api/v1/scm-oauth/callback` | [Complete an OAuth connection](integrations.md#complete-an-oauth-connection) |
| `POST` | `/api/webhooks/github/{id}` | [Webhook receivers](integrations.md#webhook-receivers) (GitHub, GitHub Enterprise) |
| `POST` | `/api/webhooks/azure-devops/{id}` | [Webhook receivers](integrations.md#webhook-receivers) (Azure DevOps) |
| `POST` | `/api/webhooks/gitlab/{id}` | [Webhook receivers](integrations.md#webhook-receivers) (GitLab) |
| `POST` | `/api/webhooks/bitbucket/{id}` | [Webhook receivers](integrations.md#webhook-receivers) (Bitbucket) |
| `POST` | `/api/v1/source-uploads` | [Create an upload session](imports.md#create-an-upload-session) |
| `GET` | `/api/v1/source-uploads/{id}` | [Get an upload session](imports.md#get-an-upload-session) |
| `PUT` | `/api/v1/source-uploads/{id}/parts/{n}` | [Upload a part](imports.md#upload-a-part) |
| `POST` | `/api/v1/source-uploads/{id}/complete` | [Complete an upload](imports.md#complete-an-upload) |
| `DELETE` | `/api/v1/source-uploads/{id}` | [Delete an upload](imports.md#delete-an-upload) |
| `POST` | `/api/v1/repository-imports/validate` | [Validate an import](imports.md#validate-an-import) |
| `POST` | `/api/v1/repository-imports` | [Start an import](imports.md#start-an-import) |
| `GET` | `/api/v1/repository-imports` | [List import jobs](imports.md#list-import-jobs) |
| `GET` | `/api/v1/repository-imports/{id}` | [Get an import job](imports.md#get-an-import-job) |
| `POST` | `/api/v1/repository-imports/{id}/cancel` | [Cancel an import job](imports.md#cancel-an-import-job) |
| `POST` | `/api/v1/repository-imports/{id}/retry` | [Retry an import job](imports.md#retry-an-import-job) |
| `GET` | `/api/v1/applications` | [List applications](applications.md#list-applications) |
| `POST` | `/api/v1/applications` | [Create an application](applications.md#create-an-application) |
| `PATCH` | `/api/v1/applications/{id}` | [Update an application](applications.md#update-an-application) |
| `POST` | `/api/v1/applications/{id}/archive` | [Archive an application](applications.md#archive-an-application) |

Related endpoints documented elsewhere: [Scans](scans.md) and [Scan schedules](schedules.md). Not documented here: `GET /api/v1/repositories/{id}/sbom` (SBOM), `GET /api/v1/me` (current user).

## Not available

The following capabilities are not implemented in this version:

- A separate `/api/v1/assets` resource (assets are repositories).
- `GET /api/v1/applications/{id}` (retrieve a single application), application unarchive and delete.
- Linking APIs or other non-repository assets to applications.
- Bearer-token (personal API token) access to `/api/v1`; tokens work only for `/mcp`.
- Reporting the credential's write or admin permission in remote repository details (`permission` is always `read`).
