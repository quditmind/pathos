---
title: Repositories
section: api-reference
order: 3
version: "1.0"
updated: 2026-11-19
summary: List, inspect, edit, archive, delete, tag, synchronize and scan registered repositories (assets), plus the legacy synchronous imports.
---

# Repositories

A repository is the registered asset in PATHOS. It holds the source location (an SCM connection or an uploaded archive), the asset metadata (ownership, placement, classification, application URLs, public exposure) and its synchronization and scan state.

All endpoints on this page are under `/api/v1` and accept a browser session (mutations also need the `X-CSRF-Token` header) or a REST API token. See [Authentication](index.md#authentication) and [Errors](index.md#errors).

New repositories are created through [imports](imports.md#start-an-import). The two synchronous import endpoints at the end of this page are older and still supported.

## Access rules for a single repository

Endpoints that act on one repository (`/repositories/{id}...`) check access like this:

1. The caller needs the permission on the repository's scope. A grant at organization scope, at the region of the repository's country, at the repository's business unit or one of its ancestors, or on the repository itself all count.
2. **Asset owners.** A user who holds `repos.read` at any scope and is the repository's business owner, technical owner, application owner or a member of its responsible team can read it. On `PATCH /repositories/{id}` and `POST /repositories/{id}/sync`, such an owner also passes the `repos.manage` check, but with limits: see [Update a repository](#update-a-repository).
3. If the caller may not see the repository, the API returns `404 not_found`, the same as when it does not exist. If the caller can see it but lacks the permission for the action, the API returns `403 forbidden`. A caller with neither the permission nor `repos.read` at any scope gets `403 forbidden`.
4. An `{id}` that is not a UUID returns `404 not_found`.

## The Repository object

`GET`, `PATCH`, archive, unarchive and sync all return this object (Go `repos.Repository`, frontend type `Repository`).

```json
{
  "id": "0190c0de-5555-7000-8000-000000000042",
  "scm_connection_id": "0190c0de-6666-7000-8000-000000000001",
  "scm_connection_name": "GitHub Example Org",
  "provider": "github",
  "source_type": "scm",
  "scm_organization": "example-org",
  "scm_project": "",
  "external_id": "812345678",
  "full_name": "example-org/payments-api",
  "name": "payments-api",
  "url": "https://github.com/example-org/payments-api",
  "default_branch": "main",
  "scan_branch": "",
  "visibility": "private",
  "description": "Card payment authorization service",
  "technologies": ["Go"],
  "application": { "id": "0190c0de-4444-7000-8000-000000000001", "name": "Payments Platform" },
  "business_unit": { "id": "0190c0de-1111-7000-8000-000000000101", "name": "Payments" },
  "country": { "id": "0190c0de-1111-7000-8000-000000000301", "name": "Germany", "code": "DE" },
  "region": { "id": "0190c0de-1111-7000-8000-000000000201", "name": "Europe" },
  "environment": "production",
  "criticality": "high",
  "scan_enabled": true,
  "scan_profile_id": null,
  "remote_archived": false,
  "last_pushed_at": "2026-11-16T14:02:11Z",
  "archived_at": null,
  "created_at": "2026-10-01T09:30:00Z",
  "tags": [
    {
      "id": "0190c0de-7777-7000-8000-000000000011",
      "name": "PCI",
      "color": "red",
      "category_id": "0190c0de-7777-7000-8000-000000000001",
      "category_name": "Compliance"
    }
  ],
  "display_name": "Payments API",
  "asset_name": "payments-api-prod",
  "business_purpose": "Authorizes card payments for the web shop",
  "application_type": "api",
  "business_owner": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" },
  "technical_owner": { "id": "0190c0de-2222-7000-8000-000000000002", "name": "Omar Tech", "email": "omar.tech@example.com" },
  "application_owner": null,
  "responsible_team": { "id": "0190c0de-3333-7000-8000-000000000001", "name": "Payments Engineering" },
  "supporting_team": null,
  "department": null,
  "cost_centre": "CC-4711",
  "business_region": { "id": "0190c0de-1111-7000-8000-000000000201", "name": "Europe", "code": "EU" },
  "data_residency_region": null,
  "hosting_region": "europe",
  "operational_location": "Frankfurt",
  "data_classification": "confidential",
  "internet_exposure": "public",
  "compliance_scopes": ["pci_dss"],
  "lifecycle_status": "active",
  "go_live_date": "2025-03-01",
  "retirement_date": null,
  "color": "#1f6feb",
  "full_history": false,
  "latest_commit_sha": "9f2c4b1e0d8a7c6b5a4f3e2d1c0b9a8f7e6d5c4b",
  "latest_commit_at": "2026-11-16T14:01:58Z",
  "size_bytes": 18350080,
  "file_count": null,
  "languages": { "Go": 912345, "Shell": 4321 },
  "last_sync_at": "2026-11-17T06:00:04Z",
  "last_sync_ok_at": "2026-11-17T06:00:04Z",
  "sync_status": "ok",
  "sync_error": "",
  "current_snapshot": null,
  "can_edit": true,
  "can_manage": true,
  "repository_key": "QD-REPO-000042",
  "staging_url": "https://staging.payments.example.com",
  "production_url": "https://payments.example.com",
  "public_exposure": "yes",
  "public_urls": ["https://payments.example.com"],
  "public_domains": ["payments.example.com"],
  "public_ips": ["203.0.113.10"],
  "exposure_notes": "Behind the corporate WAF",
  "registered_by": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" },
  "updated_at": "2026-11-17T08:12:45Z",
  "last_scan_status": "succeeded",
  "last_scan_at": "2026-11-17T06:20:31Z"
}
```

Field notes:

| Field | Notes |
|---|---|
| `repository_key` | The **Repository ID**, for example `QD-REPO-000042`. The database assigns it on insert from the organization's `repository_key_prefix` and a global sequence, and refuses any later change. It is read-only in the API and never reused. |
| `provider` | Provider of the SCM connection, or `upload` for uploaded repositories. |
| `source_type` | `scm` or `upload`. |
| `scm_connection_id` | `null` for uploaded repositories. |
| `visibility` | `public`, `private` or `internal`, as reported by the provider. |
| `region` | Region of `country` (derived). `business_region` is the separately chosen business region. |
| `public_exposure` | `yes`, `no` or `unknown`. |
| `sync_status` | `never`, `ok`, `failed`, `missing`, `permission_denied` or `archived_upstream`. |
| `current_snapshot` | For uploaded repositories: the current source snapshot (`id`, `created_at`, `archive_filename`, `archive_sha256`, `snapshot_sha256`, `file_count`, `uncompressed_bytes`, `malware_scan`). `null` for SCM repositories. |
| `can_manage` | The caller holds `repos.manage` on this repository. |
| `can_edit` | `can_manage`, or the caller is an asset owner (see [Access rules](#access-rules-for-a-single-repository)). For archived repositories, `can_edit` equals `can_manage`. |
| `last_scan_status`, `last_scan_at` | Status and finish (or queue) time of the most recent scan job, or `null`. |
| `go_live_date`, `retirement_date` | `YYYY-MM-DD` or `null`. |

Database entities: `repositories`, `repository_tags`, `tags`, `tag_categories`, `repository_compliance_scopes`, `repository_public_endpoints`, `applications`, `business_units`, `countries`, `regions`, `users`, `teams`, `source_snapshots`, `scan_jobs`.

## Listing and reading

### List repositories

Returns a page of repositories the caller can see, with filters, sorting and keyset pagination.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/repositories` |
| Authentication | Session or API token |
| Permission | `repos.read` at any scope. The result contains repositories inside the caller's `repos.read` scopes plus repositories the caller owns. Without `repos.read` anywhere: `403 forbidden`. |
| Request headers | `Cookie` |

Query parameters (all optional):

| Name | Type | Description |
|---|---|---|
| `limit` | integer | Page size, 1–200. Default 50. |
| `sort` | string | `name` (default), `repository_key`, `created_at`, `criticality`, `last_sync_at`. Prefix with `-` for descending, for example `-created_at`. `name` sorts by display name, falling back to the full name. |
| `cursor` | string | The `next_cursor` value of the previous page. Use it with the same `sort`. |
| `status` | string | `active` (default), `archived` or `all`. |
| `q` | string | Case-insensitive substring search in full name, description, display name, asset name, Repository ID, production URL, staging URL and public endpoints. |
| `scm_connection_id` | UUID | Repositories of one connection. |
| `application_id` | UUID | Repositories linked to one application. |
| `business_unit_id` | UUID | Repositories in this business unit or any unit below it. |
| `country_id` | UUID | Repositories in this country. |
| `region_id` | UUID | Repositories whose country is in this region. |
| `business_region_id` | UUID | Repositories with this business region. |
| `business_owner_id` | UUID | Repositories with this business owner. |
| `technical_owner_id` | UUID | Repositories with this technical owner. |
| `responsible_team_id` | UUID | Repositories with this responsible team. |
| `tag_id` | UUID | Repositories that carry this tag. |
| `criticality` | string | `low`, `medium`, `high` or `critical`. |
| `environment`, `data_classification`, `lifecycle_status`, `internet_exposure`, `source_type`, `application_type`, `hosting_region` | string | Exact match on the catalog key (max 63 characters). |
| `repository_key` | string | Exact Repository ID, case-insensitive (max 40 characters). |
| `public_exposure` | string | `yes`, `no` or `unknown`. |
| `production_url`, `staging_url` | string | Case-insensitive substring match (max 300 characters). |
| `missing_production_url` | string | `true` (no production URL) or `false` (has one). |
| `sync_status` | string | `never`, `ok`, `failed`, `missing`, `permission_denied` or `archived_upstream`. |
| `provider` | string | Provider key of the connection, or `upload`. |
| `compliance` | string | Repositories with this compliance scope key. |
| `missing_owner` | string | `business`, `technical` or `any` (either missing). |
| `owner` | string | `none`: repositories without an application. |

```http
GET /api/v1/repositories?business_unit_id=0190c0de-1111-7000-8000-000000000101&public_exposure=yes&sort=-created_at&limit=2 HTTP/1.1
Host: pathos.example.com
Cookie: __Host-pathos_session=<session-cookie>
```

Response `200 OK`:

```json
{
  "items": [
    { "id": "0190c0de-5555-7000-8000-000000000042", "repository_key": "QD-REPO-000042", "full_name": "example-org/payments-api", "...": "full Repository object" }
  ],
  "next_cursor": "2026-10-01T09:30:00+00:00|0190c0de-5555-7000-8000-000000000042"
}
```

Each item is a full [Repository object](#the-repository-object). `next_cursor` is `null` when the page is shorter than `limit`. Treat the cursor as opaque.

| Status | Meaning |
|---|---|
| 200 | Page returned. |
| 400 `invalid_request` | Bad `limit`, `sort`, `status`, `cursor`, UUID filter, `criticality`, `public_exposure`, `sync_status`, `missing_owner`, `missing_production_url`, or an over-long value. |
| 401 `unauthenticated` | No session. |
| 403 `forbidden` | No `repos.read` anywhere. |

```json
{
  "error": { "code": "invalid_request", "message": "sort must be name, repository_key, created_at, criticality or last_sync_at (prefix - for descending)" },
  "request_id": "6f1c2a9e0b7d4c3e2a1f0e9d"
}
```

Database entities: `repositories`, `repository_public_endpoints`, `repository_tags`, `repository_compliance_scopes`, `scm_connections`, `countries`, `business_units`.

### Get a repository

Returns one repository.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/repositories/{id}` |
| Authentication | Session or API token |
| Permission | `repos.read` on the repository, or asset owner with `repos.read` anywhere |
| Request headers | `Cookie` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Repository UUID (not the Repository ID). To find a repository by Repository ID, use [List repositories](#list-repositories) with `repository_key=QD-REPO-000042`. |

Response `200 OK`: a [Repository object](#the-repository-object).

| Status | Meaning |
|---|---|
| 200 | Repository returned. |
| 401 `unauthenticated` | No session. |
| 403 `forbidden` | Visible to the caller, but not readable (rare), or no `repos.read` anywhere. |
| 404 `not_found` | Does not exist or is outside the caller's scope. |

Database entities: `repositories` and the related tables listed under [The Repository object](#the-repository-object).

### Get repository insights

Returns totals and breakdowns for the dashboards, computed over the repositories the caller can see.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/repositories/insights` |
| Authentication | Session or API token |
| Permission | `repos.read` at any scope (same visibility as [List repositories](#list-repositories)) |
| Request headers | `Cookie` |

Query parameters: the same filters as [List repositories](#list-repositories) (no `limit`, `sort` or `cursor`). Here `status` defaults to `all`, so totals cover active and archived repositories. Breakdowns always count active repositories only.

Response `200 OK`:

```json
{
  "totals": {
    "total": 128,
    "active": 120,
    "archived": 8,
    "critical": 9,
    "without_business_owner": 3,
    "without_technical_owner": 11,
    "production": 87,
    "confidential_or_restricted": 40,
    "pending_imports": 2,
    "failed_imports": 1,
    "sync_failures": 4,
    "last_successful_sync_at": "2026-11-17T06:00:04Z",
    "publicly_exposed": 21,
    "not_public": 70,
    "exposure_unknown": 29,
    "missing_production_url": 35,
    "missing_ownership": 12
  },
  "by_provider": [{ "key": "github", "label": "GitHub", "count": 80 }, { "key": "upload", "label": "Local upload", "count": 6 }],
  "by_business_region": [{ "key": "0190c0de-1111-7000-8000-000000000201", "label": "Europe", "count": 64 }],
  "by_business_unit": [{ "key": "0190c0de-1111-7000-8000-000000000101", "label": "Payments", "count": 22 }],
  "by_business_owner": [{ "key": "0190c0de-2222-7000-8000-000000000001", "label": "Dana Owner", "count": 15 }],
  "by_criticality": [{ "key": "high", "label": "High", "count": 30, "color": "#e16f24" }],
  "by_data_classification": [{ "key": "confidential", "label": "Confidential", "count": 33, "color": "#e16f24" }],
  "by_environment": [{ "key": "production", "label": "Production", "count": 87 }],
  "by_lifecycle": [{ "key": "active", "label": "Active", "count": 101, "color": "#2da44e" }],
  "by_public_exposure": [{ "key": "yes", "label": "Publicly exposed", "count": 21, "color": "#cf222e" }],
  "by_compliance": [{ "key": "pci_dss", "label": "PCI DSS", "count": 12 }]
}
```

Buckets with an empty key are labelled `Not set`. `pending_imports` counts import items in an active status. `failed_imports` counts items that failed or need attention in the last 30 days. Both count only the caller's own imports unless the caller holds `repos.manage` or `repos.read` organization-wide.

| Status | Meaning |
|---|---|
| 200 | Insights returned. |
| 400 `invalid_request` | Bad filter value (see [List repositories](#list-repositories)). |
| 403 `forbidden` | No `repos.read` anywhere. |

Database entities: `repositories`, `repository_compliance_scopes`, `repository_import_items`, `repository_import_jobs`, `asset_classifications`, `regions`, `business_units`, `users`.

### Get the security summary of a repository

Returns the most recent scan job of the repository and its open findings by severity.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/repositories/{id}/security` |
| Authentication | Session or API token |
| Permission | `repos.read` on the repository, or asset owner. Finding counts are filled only when the caller also holds `findings.read` on the repository; otherwise they are all `0`. |
| Request headers | `Cookie` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Repository UUID. |

Response `200 OK`:

```json
{
  "latest_scan": {
    "id": "0190c0de-dddd-7000-8000-000000000001",
    "status": "succeeded",
    "trigger": "onboarding",
    "commit_sha": "9f2c4b1e0d8a7c6b5a4f3e2d1c0b9a8f7e6d5c4b",
    "snapshot_id": null,
    "profile_name": "Default",
    "queued_at": "2026-11-17T06:10:00Z",
    "finished_at": "2026-11-17T06:20:31Z",
    "scanners": [
      { "key": "gitleaks", "version": "8.21.2", "status": "succeeded", "findings": 0 },
      { "key": "opengrep", "version": "1.2.0", "status": "succeeded", "findings": 4 }
    ]
  },
  "open_findings": { "critical": 0, "high": 1, "medium": 3, "low": 0, "info": 0 },
  "scan_on_import": true
}
```

`latest_scan` is `null` when the repository was never scanned. Open findings are those with status `open`, `in_progress` or `needs_review`.

| Status | Meaning |
|---|---|
| 200 | Summary returned. |
| 403 `forbidden` / 404 `not_found` | See [Access rules](#access-rules-for-a-single-repository). |

Database entities: `scan_jobs`, `scan_results`, `scan_profiles`, `scan_profile_versions`, `findings`, `asset_settings`.

### List branches of a repository

Lists the branch names of an SCM repository, live from the provider.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/repositories/{id}/branches` |
| Authentication | Session or API token |
| Permission | `repos.read` on the repository, or asset owner |
| Request headers | `Cookie` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Repository UUID. |

Response `200 OK`:

```json
{ "items": ["develop", "main", "release/2026.11"], "default_branch": "main" }
```

| Status | Meaning |
|---|---|
| 200 | Branches returned, sorted by name. |
| 404 `not_found` | Repository not visible, or its connection was deleted or archived. |
| 409 `conflict` | Uploaded repository: "uploaded repositories have no branches; upload a new version instead". |
| 502 `scm_error` | The provider rejected or failed the call (authentication, permission, not found, rate limit, expired token, blocked address). |

Database entities: `repositories`, `scm_connections`.

## Editing

### Update a repository

Changes asset metadata and scan settings. Absent fields stay unchanged. An explicit `null` (UUID and date fields) or `""` (text fields) clears an optional value.

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/repositories/{id}` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` on the repository, or asset owner (limited fields, see below). Archived repositories are read-only for owners. Changing `business_unit_id` or `country_id`, or sending `new_application`, also needs `repos.manage` at the destination scope (the business unit, else the region of the country, else the organization). |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Repository UUID. |

Request body: any subset of the following fields. Unknown fields are rejected, including `repository_key`.

| Field | Type | Owner may edit | Rules |
|---|---|:-:|---|
| `display_name` | string | yes | Max 200 characters. |
| `asset_name` | string | no | Max 200 characters. Unique (case-insensitive) among active repositories. |
| `description` | string | yes | Max 2000 characters. |
| `application_id` | UUID or null | no | Existing, non-archived application. |
| `new_application` | object | no | `{ "name": "...", "external_ref": "..." }`: creates an application and links it. Name 1–200 characters and not already used by an active application; `external_ref` max 100 characters. |
| `application_type` | string | yes | Active key of the `application_type` catalog, or `""`. |
| `business_purpose` | string | yes | Max 2000 characters. |
| `business_owner_id` | UUID or null | yes | Active user of the organization. |
| `technical_owner_id` | UUID or null | yes | Active user. |
| `application_owner_id` | UUID or null | yes | Active user. |
| `business_unit_id` | UUID or null | no | Existing, non-archived business unit. |
| `department_id` | UUID or null | no | A non-archived unit below `business_unit_id`. |
| `responsible_team_id` | UUID or null | yes | Existing team. |
| `supporting_team_id` | UUID or null | yes | Existing team. |
| `cost_centre` | string | yes | Max 100 characters. |
| `business_region_id` | UUID or null | no | Existing region. |
| `country_id` | UUID or null | no | Existing country. |
| `hosting_region` | string | yes | Active key of the `hosting_region` catalog, or `""`. |
| `data_residency_region_id` | UUID or null | no | Existing region. |
| `operational_location` | string | yes | Max 200 characters. |
| `criticality` | string | no | `low`, `medium`, `high` or `critical`. Cannot be empty. |
| `data_classification` | string | yes | Active key of the `data_classification` catalog, or `""`. |
| `environment` | string | no | Active key of the `environment` catalog. Cannot be empty. |
| `internet_exposure` | string | yes | Active key of the `internet_exposure` catalog. `""` is stored as `unknown`. |
| `compliance_scopes` | string array | yes | Active keys of the `compliance` catalog, max 30. |
| `tag_ids` | UUID array | yes | Replaces all tags. Max 50; mandatory tag categories must be covered; single-value categories allow one tag. |
| `color` | string | yes | `#rrggbb` (lower-cased) or `""`. |
| `lifecycle_status` | string | yes | Active key of the `lifecycle_status` catalog. Cannot be empty. |
| `go_live_date` | string or null | yes | `YYYY-MM-DD`. |
| `retirement_date` | string or null | yes | `YYYY-MM-DD`, not before `go_live_date`. |
| `staging_url` | string | yes | Absolute `http://` or `https://` URL without credentials, max 2048 characters, or `""`. Normalized (lower-case host, default port and fragment removed). |
| `production_url` | string | yes | Same rules as `staging_url`. |
| `public_exposure` | string | yes | `yes`, `no` or `unknown`. |
| `public_urls` | string array | yes | Absolute URLs, max 50, deduplicated. |
| `public_domains` | string array | yes | Domain names, `*.` wildcard allowed, IDNs converted to ASCII, max 50. |
| `public_ips` | string array | yes | Public IPv4/IPv6 addresses (private, loopback, link-local, multicast, CGNAT and unspecified addresses are rejected), max 50. |
| `exposure_notes` | string | yes | Max 2000 characters. |
| `scan_enabled` | boolean | no | Scheduled and event-driven scans run only when `true`. |
| `scan_branch` | string | no | Branch to track and scan; `""` means the default branch. Max 255 characters, valid Git ref characters. |
| `technologies` | string array | no | Max 30, each 1–50 characters. A scan setting: needs `repos.manage`. |
| `full_history` | boolean | no | Clone the full history for scans. |

Public exposure rules:

- `public_exposure: "yes"` needs at least one public URL, domain or IP, and `internet_exposure` must not be `internal` or `private`.
- `public_exposure: "no"` allows no public endpoints, and `internet_exposure` must not be `public`.
- `public_urls`, `public_domains` and `public_ips` each replace the stored list when sent.

Required fields on update: the organization's required fields (see [Asset settings](assets.md#get-asset-settings)) plus the always-required `business_owner`, `business_unit`, `business_region` and `public_exposure` cannot be cleared **when they are part of the request**. Gaps in fields that the request does not touch do not block the update. Catalog values and deactivated users that are already stored stay valid even if they were archived or deactivated later.

```http
PATCH /api/v1/repositories/0190c0de-5555-7000-8000-000000000042 HTTP/1.1
Host: pathos.example.com
Cookie: __Host-pathos_session=<session-cookie>
X-CSRF-Token: <csrf-token>
Content-Type: application/json
```

```json
{
  "display_name": "Payments API",
  "technical_owner_id": "0190c0de-2222-7000-8000-000000000002",
  "production_url": "https://payments.example.com",
  "staging_url": "https://staging.payments.example.com",
  "public_exposure": "yes",
  "public_urls": ["https://payments.example.com"],
  "public_domains": ["payments.example.com"],
  "public_ips": ["203.0.113.10"],
  "internet_exposure": "public",
  "scan_branch": "main"
}
```

Response `200 OK`: the updated [Repository object](#the-repository-object). The change is written to the audit log as `repository.update` (or `repository.update_as_owner`).

| Status | Meaning |
|---|---|
| 200 | Updated. |
| 400 `invalid_request` | Malformed JSON, unknown field (for example `repository_key`), invalid date format, invalid branch name, invalid `technologies`, or a referenced item that no longer exists. |
| 403 `forbidden` | No edit right, an owner changed a field outside the owner list or a scan setting, or no `repos.manage` at the new placement. |
| 404 `not_found` | Repository not visible. |
| 409 `conflict` | Unique constraint violation. |
| 415 `unsupported_media_type` | `Content-Type` is not `application/json`. |
| 422 `validation_failed` | One or more fields are invalid; `fields` maps each field to a message. |

```json
{
  "error": {
    "code": "validation_failed",
    "message": "check the highlighted fields: public_urls, production_url",
    "fields": {
      "production_url": "enter an absolute http:// or https:// URL",
      "public_urls": "add at least one public URL, domain or IP address"
    }
  },
  "request_id": "a81f3c0b2d4e5f60718293a4"
}
```

```json
{
  "error": { "code": "invalid_request", "message": "invalid JSON body: json: unknown field \"repository_key\"" },
  "request_id": "b02e4d1c3a5f6e7d8c9b0a1f"
}
```

```json
{
  "error": { "code": "forbidden", "message": "changing business_unit_id requires repos.manage for this repository" },
  "request_id": "c13f5e2d4b6a7f8e9d0c1b2a"
}
```

Database entities: `repositories`, `repository_public_endpoints`, `repository_compliance_scopes`, `repository_tags`, `applications` (for `new_application`), `asset_settings`, `asset_classifications`, `audit_logs`.

### Set the scan profile of a repository

Assigns a scan profile, or reverts to the organization default.

| Property | Value |
|---|---|
| Method | `PUT` |
| Path | `/api/v1/repositories/{id}/scan-profile` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` on the repository (asset owners do not qualify) |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Repository UUID. |

```json
{ "profile_id": "0190c0de-ffff-7000-8000-000000000001" }
```

Send `{ "profile_id": null }` to use the organization's default profile.

Response: `204 No Content`.

| Status | Meaning |
|---|---|
| 204 | Saved. |
| 400 `invalid_request` | "scan profile does not exist" (also for an archived profile) or malformed JSON. |
| 403 `forbidden` | No `repos.manage` on the repository. |
| 404 `not_found` | Repository does not exist. |
| 415 `unsupported_media_type` | Wrong `Content-Type`. |

Database entities: `repositories.scan_profile_id`, `scan_profiles`, `audit_logs` (`repository.set_scan_profile`).

### Add or remove tags on many repositories

Adds and removes tags on up to 500 repositories in one transaction.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repositories/bulk-tags` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` on **every** listed repository |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

```json
{
  "repository_ids": ["0190c0de-5555-7000-8000-000000000042", "0190c0de-5555-7000-8000-000000000043"],
  "add": ["0190c0de-7777-7000-8000-000000000011"],
  "remove": ["0190c0de-7777-7000-8000-000000000012"]
}
```

`repository_ids` must hold 1–500 entries and `add` plus `remove` at least one tag. After the change each repository must still satisfy the tag rules (at most 50 tags, mandatory categories covered, one tag in single-value categories). Any failure rolls back the whole request.

Response `200 OK`:

```json
{ "updated": 2 }
```

| Status | Meaning |
|---|---|
| 200 | All repositories updated. |
| 400 `invalid_request` | Counts out of range, "unknown repository {id}", "unknown tag", "only one tag allowed in: ...", "at most 50 tags per repository". Messages name the failing repository. |
| 403 `forbidden` | No `repos.manage` on one of the repositories. |
| 422 `mandatory_tags_missing` | A mandatory tag category would become empty: "repository {id}: a tag is required in: Owner Team". |

Database entities: `repository_tags`, `tags`, `tag_categories`, `audit_logs`.

## Archiving and deletion

### Archive a repository

Archives (soft-deletes) a repository. Archived repositories are hidden from the default list, are not scanned and are read-only for asset owners.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repositories/{id}/archive` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` on the repository (asset owners do not qualify) |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Repository UUID. |

Response `200 OK`: the [Repository object](#the-repository-object) with `archived_at` set.

| Status | Meaning |
|---|---|
| 200 | Archived. |
| 403 `forbidden` / 404 `not_found` | See [Access rules](#access-rules-for-a-single-repository). |
| 409 `conflict` | "repository is already archived". |

Database entities: `repositories.archived_at`, `audit_logs`.

### Unarchive a repository

Restores an archived repository.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repositories/{id}/unarchive` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` on the repository |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response `200 OK`: the [Repository object](#the-repository-object) with `archived_at: null`.

| Status | Meaning |
|---|---|
| 200 | Restored. |
| 403 `forbidden` / 404 `not_found` | See [Access rules](#access-rules-for-a-single-repository). |
| 409 `conflict` | "repository is not archived". |

Database entities: `repositories.archived_at`, `audit_logs`.

### Delete a repository

Permanently deletes an **archived** repository, its source snapshots (database rows and stored objects), its repository-scoped role assignments, and the data that cascades from it. The Repository ID is never reused.

| Property | Value |
|---|---|
| Method | `DELETE` |
| Path | `/api/v1/repositories/{id}` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` on the repository |
| Request headers | `Cookie`, `X-CSRF-Token` |

Response: `204 No Content`.

| Status | Meaning |
|---|---|
| 204 | Deleted. |
| 403 `forbidden` / 404 `not_found` | See [Access rules](#access-rules-for-a-single-repository). |
| 409 `conflict` | "archive the repository before deleting it". |

Database entities: `repositories`, `source_snapshots`, `role_assignments`, `audit_logs` (`repository.delete`).

## Synchronization and snapshots

### Synchronize a repository

Refreshes one SCM repository's metadata, default branch, head commit of the tracked branch and languages from the provider, and records a sync run. Source code is not downloaded.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repositories/{id}/sync` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` on the repository, or asset owner (not on archived repositories) |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response `200 OK`. Provider failures do not fail the request: they are reported in `run.status` and `run.error`.

```json
{
  "run": {
    "id": "0190c0de-eeee-7000-8000-000000000001",
    "trigger": "manual",
    "status": "ok",
    "branch": "main",
    "previous_commit_sha": "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d",
    "commit_sha": "9f2c4b1e0d8a7c6b5a4f3e2d1c0b9a8f7e6d5c4b",
    "changed": true,
    "error": "",
    "triggered_by": null,
    "started_at": "2026-11-17T08:15:00Z",
    "finished_at": "2026-11-17T08:15:02Z"
  },
  "repository": { "id": "0190c0de-5555-7000-8000-000000000042", "...": "full Repository object" }
}
```

Run `status` values: `ok`, `failed`, `missing` (repository not found at the provider), `permission_denied`, `archived_upstream`. A newly failing repository raises a `repository.sync_failed` notification event.

| Status | Meaning |
|---|---|
| 200 | Sync run recorded (check `run.status`). |
| 403 `forbidden` / 404 `not_found` | See [Access rules](#access-rules-for-a-single-repository). 404 also when the connection was deleted or archived. |
| 409 `conflict` | Uploaded repository: "uploaded repositories are updated by uploading a new version" (see [version uploads](imports.md#upload-a-new-version-of-an-uploaded-repository)). |

Database entities: `repositories`, `repository_sync_runs`, `notification_events`, `audit_logs`.

### List sync runs of a repository

Returns the 100 most recent sync runs, newest first.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/repositories/{id}/sync-runs` |
| Authentication | Session or API token |
| Permission | `repos.read` on the repository, or asset owner |
| Request headers | `Cookie` |

Response `200 OK`:

```json
{
  "items": [
    {
      "id": "0190c0de-eeee-7000-8000-000000000001",
      "trigger": "manual",
      "status": "ok",
      "branch": "main",
      "previous_commit_sha": "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d",
      "commit_sha": "9f2c4b1e0d8a7c6b5a4f3e2d1c0b9a8f7e6d5c4b",
      "changed": true,
      "error": "",
      "triggered_by": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" },
      "started_at": "2026-11-17T08:15:00Z",
      "finished_at": "2026-11-17T08:15:02Z"
    }
  ]
}
```

`trigger` is `manual`, `schedule`, `webhook`, `import` or `upload`. For uploaded repositories, `commit_sha` holds the snapshot SHA-256.

| Status | Meaning |
|---|---|
| 200 | Runs returned. |
| 403 `forbidden` / 404 `not_found` | See [Access rules](#access-rules-for-a-single-repository). |

Database entities: `repository_sync_runs`, `users`.

### List source snapshots of a repository

Returns the 100 most recent source snapshots of an uploaded repository, newest first. SCM repositories return an empty list.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/repositories/{id}/snapshots` |
| Authentication | Session or API token |
| Permission | `repos.read` on the repository, or asset owner |
| Request headers | `Cookie` |

Response `200 OK`:

```json
{
  "items": [
    {
      "id": "0190c0de-bbbb-7000-8000-000000000001",
      "created_at": "2026-11-10T12:00:00Z",
      "archive_filename": "billing-batch-2026.11.zip",
      "archive_sha256": "3b1f0c9e8d7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c",
      "snapshot_sha256": "7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d",
      "file_count": 1532,
      "uncompressed_bytes": 48211234,
      "malware_scan": "clean",
      "archive_size": 9123456,
      "snapshot_size": 8456789,
      "languages": { "Java": 30211000, "XML": 120000 },
      "manifests": ["pom.xml"],
      "skipped": { "symlink": 2 },
      "malware_engine": "ClamAV 1.4.1",
      "created_by": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" }
    }
  ]
}
```

`malware_scan` is `clean`, `not_configured` or `unavailable`.

| Status | Meaning |
|---|---|
| 200 | Snapshots returned. |
| 403 `forbidden` / 404 `not_found` | See [Access rules](#access-rules-for-a-single-repository). |

Database entities: `source_snapshots`, `users`.

## Scanning

### Request a scan of a repository

Queues a manual scan. If the repository already has a queued scan, the request merges into it (`coalesced: true`) and raises its priority.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repositories/{id}/scan` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `scans.run` on the repository |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response `202 Accepted`:

```json
{ "job_id": "0190c0de-dddd-7000-8000-000000000002", "coalesced": false }
```

Manual scans run even when `scan_enabled` is `false`. Uploaded repositories are scanned from their current snapshot.

| Status | Meaning |
|---|---|
| 202 | Scan queued or merged. |
| 403 `forbidden` | No `scans.run` on the repository. |
| 404 `not_found` | Repository does not exist or is outside every scope of the caller. |
| 409 `conflict` | "repository is archived or scanning is disabled". |
| 409 `conflict` | The repository cannot be scanned yet: no scan profile exists, the uploaded repository has no snapshot, or it has no default branch (the message says which). |

Bulk scanning (`POST /api/v1/scans`) and scan job endpoints belong to the scanning API and are not covered here.

Database entities: `scan_jobs`, `scan_profiles`, `audit_logs` (`scan.request`).

## Legacy synchronous imports

These endpoints register SCM repositories synchronously, without import jobs, upload support, idempotency or asset-policy validation. They only set placement (application, business unit, country), environment, criticality, scan branch and tags. New integrations should use [repository imports](imports.md#start-an-import).

### Import repositories synchronously

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repositories/import` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` at any scope to call; each item needs `repos.manage` at its placement (business unit, else region of the country, else organization) |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

Request body:

| Field | Type | Required | Description |
|---|---|---|---|
| `scm_connection_id` | UUID | yes | Connection to import from. |
| `repositories` | array | yes | 1–1000 items. |
| `repositories[].external_id` | string | one of | Provider repository ID. |
| `repositories[].full_name` | string | one of | Used when `external_id` does not match. |
| `repositories[].application_id`, `business_unit_id`, `country_id` | UUID | no | Placement. |
| `repositories[].environment` | string | no | Active environment key; default `production`. |
| `repositories[].criticality` | string | no | `low`, `medium`, `high`, `critical`; default `medium`. |
| `repositories[].scan_branch` | string | no | Valid branch name. |
| `repositories[].tag_ids` | UUID array | no | Must satisfy the tag rules. |
| `defaults` | object | no | Values for fields an item leaves empty. Only `application_id`, `business_unit_id`, `country_id`, `environment`, `criticality` and `tag_ids` are taken from it; other fields are ignored. |
| `dry_run` | boolean | no | Validate without saving. |

```json
{
  "scm_connection_id": "0190c0de-6666-7000-8000-000000000001",
  "defaults": {
    "business_unit_id": "0190c0de-1111-7000-8000-000000000101",
    "country_id": "0190c0de-1111-7000-8000-000000000301",
    "environment": "production",
    "criticality": "high"
  },
  "repositories": [
    { "external_id": "812345678" },
    { "full_name": "example-org/payments-worker", "scan_branch": "main" }
  ],
  "dry_run": false
}
```

Response `200 OK`:

```json
{
  "results": [
    { "external_id": "812345678", "full_name": "example-org/payments-api", "status": "imported", "repository_id": "0190c0de-5555-7000-8000-000000000042" },
    { "external_id": "", "full_name": "example-org/payments-worker", "status": "error", "error": "repository not found in the SCM connection" }
  ],
  "imported": 1,
  "dry_run": false
}
```

Result `status`: `imported`, `would_import` (dry run), `already_imported` or `error`.

| Status | Meaning |
|---|---|
| 200 | Processed; check each result. |
| 400 `invalid_request` | Item count out of range or malformed JSON. |
| 415 `unsupported_media_type` | `Content-Type` is not `application/json`. |
| 403 `forbidden` | No `repos.manage` anywhere. |
| 404 `not_found` | Connection does not exist. |
| 502 `scm_error` | Listing the connection's repositories failed. |

Database entities: `repositories`, `repository_tags`, `audit_logs`.

### Import repositories from CSV

Same as [Import repositories synchronously](#import-repositories-synchronously), with the items read from a CSV file.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repositories/import-csv` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | As for [Import repositories synchronously](#import-repositories-synchronously) |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: text/csv` (or `text/plain`) |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `scm_connection_id` | UUID | yes | Connection to import from. |
| `dry_run` | string | no | `true` to validate without saving. |

Body: CSV, at most 2 MB, with a header row. Allowed columns (case-insensitive): `repository` (required, the full name), `application`, `business_unit`, `country` (ISO alpha-2 code), `environment`, `criticality`, `tags` (`Category:Tag` pairs separated by `;`), `scan_branch`. Names are resolved case-insensitively.

```bash
curl -X POST "https://pathos.example.com/api/v1/repositories/import-csv?scm_connection_id=0190c0de-6666-7000-8000-000000000001&dry_run=true" \
  -H "Cookie: __Host-pathos_session=<session-cookie>" \
  -H "X-CSRF-Token: <csrf-token>" \
  -H "Content-Type: text/csv" \
  --data-binary $'repository,application,business_unit,country,environment,criticality,tags,scan_branch\nexample-org/payments-api,Payments Platform,Payments,DE,production,high,Compliance:PCI,main\n'
```

Response `200 OK`: as above; each result also carries `line` (CSV line number). Rows with unknown names are reported as `error` results.

| Status | Meaning |
|---|---|
| 200 | Processed. |
| 400 `invalid_request` | Missing `scm_connection_id`, body over 2 MB, invalid CSV, no data rows (rows with an empty `repository` cell are skipped, so such a file returns `200` with no results), unknown column, no `repository` column. |
| 403 `forbidden` | No `repos.manage` anywhere. |
| 404 `not_found` | Connection does not exist. |
| 415 `unsupported_media_type` | "Content-Type must be text/csv". |
| 502 `scm_error` | Listing the connection's repositories failed. |

Database entities: `repositories`, `repository_tags`, `applications`, `business_units`, `countries`, `tags`, `tag_categories`, `audit_logs`.
