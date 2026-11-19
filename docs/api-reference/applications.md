---
title: Applications
section: api-reference
order: 6
version: "1.0"
updated: 2026-11-19
summary: List, create, update and archive applications, and link repositories to them.
---

# Applications

An application groups repositories into a business application, for example "Payments Platform". It has an owner, a security owner, an optional business unit and a criticality. Repositories link to at most one application through their `application_id`.

All endpoints are under `/api/v1` and accept a browser session (with `X-CSRF-Token` on mutations) or a REST API token. See [Authentication](index.md#authentication).

## Capabilities at a glance

| Capability | Endpoint |
|---|---|
| List applications | [`GET /api/v1/applications`](#list-applications) |
| Create an application | [`POST /api/v1/applications`](#create-an-application), or `new_application` during an [import](imports.md#the-import-request) or a [repository update](repositories.md#update-a-repository) |
| Update an application | [`PATCH /api/v1/applications/{id}`](#update-an-application) |
| Archive an application | [`POST /api/v1/applications/{id}/archive`](#archive-an-application) |
| Link a repository to an application | [`PATCH /api/v1/repositories/{id}`](#link-repositories-to-an-application) with `application_id` |
| View the repositories of an application | [`GET /api/v1/repositories?application_id=...`](#view-the-repositories-of-an-application) |
| Retrieve one application by ID | [`GET /api/v1/applications/{id}`](#get-an-application) (PATHOS 3.0 M3) |
| Classify an application, set its tags | [`PATCH /api/v1/applications/{id}/classification`](#classify-an-application) (flag `onboarding`) |
| Onboard repositories into an application | [Onboarding endpoints](#onboarding) (flag `onboarding`) |
| Tag framework: rules, bulk tagging, history | [Tag framework](#tag-framework) (flag `onboarding`) |
| Lifecycle of an application, lifecycle overview | [Lifecycle](#lifecycle) (flags `onboarding`, `lifecycle_overview`) |
| Unarchive an application | **Not available.** |
| Delete an application | **Not available.** Applications are archived, never deleted. |
| Link APIs and other assets | **Not available.** Only repositories can be linked to an application. |

## The Application object

```json
{
  "id": "0190c0de-4444-7000-8000-000000000001",
  "application_key": "QD-APP-000001",
  "name": "Payments Platform",
  "description": "Card payments, refunds and settlement",
  "business_unit": { "id": "0190c0de-1111-7000-8000-000000000101", "name": "Payments" },
  "owner": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" },
  "security_owner": { "id": "0190c0de-2222-7000-8000-000000000003", "name": "Sam Security", "email": "sam.security@example.com" },
  "technical_owner": null,
  "lifecycle": "active",
  "environment": "production",
  "criticality": "high",
  "external_ref": "APP-0193",
  "repository_count": 4,
  "archived_at": null,
  "created_at": "2026-09-20T10:00:00Z"
}
```

| Field | Notes |
|---|---|
| `application_key` | Permanent application ID assigned by PATHOS (for example `QD-APP-000001`). |
| `business_unit`, `owner`, `security_owner`, `technical_owner` | `null` when not set. |
| `lifecycle` | `planned`, `development`, `active` (default), `maintenance`, `deprecated` or `retired`. |
| `environment` | `production` (default), `staging`, `development`, `test` or `other`. |
| `criticality` | `low`, `medium`, `high` or `critical`. Default `medium`. |
| `external_ref` | The organization's application identifier (for example a CMDB ID); `""` when not set. |
| `repository_count` | Linked active (non-archived) repositories. |

Database entities: `applications` (`owner_user_id`, `security_owner_user_id`, `business_unit_id`, `external_ref`, `archived_at`), `business_units`, `users`, `repositories.application_id`.

## Application endpoints

### List applications

Returns up to 500 applications, sorted by name. There is no pagination.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/applications` |
| Authentication | Session or API token |
| Permission | `repos.read` at any scope. With an organization-wide grant, all applications are returned. Otherwise: applications placed in a business unit the caller has `repos.read` on (including units below it), plus applications that contain a repository the caller can read through a grant. |
| Request headers | `Cookie` |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `q` | string | no | Case-insensitive substring of the name. |
| `status` | string | no | `archived` returns archived applications; any other value (or none) returns active ones. |

Response `200 OK`:

```json
{
  "items": [
    {
      "id": "0190c0de-4444-7000-8000-000000000001",
      "application_key": "QD-APP-000001",
      "name": "Payments Platform",
      "description": "Card payments, refunds and settlement",
      "business_unit": { "id": "0190c0de-1111-7000-8000-000000000101", "name": "Payments" },
      "owner": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" },
      "security_owner": null,
      "technical_owner": null,
      "lifecycle": "active",
      "environment": "production",
      "criticality": "high",
      "external_ref": "APP-0193",
      "repository_count": 4,
      "archived_at": null,
      "created_at": "2026-09-20T10:00:00Z"
    }
  ]
}
```

| Status | Meaning |
|---|---|
| 200 | Returned. |
| 401 `unauthenticated` | No session. |
| 403 `forbidden` | No `repos.read` anywhere. |

Database entities: `applications`, `repositories`, `business_units`, `users`.

### Create an application

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/applications` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` on the business unit given in `business_unit_id` (or a scope above it); without a business unit, `repos.manage` organization-wide |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | 1–200 characters. Unique among active applications (case-insensitive). |
| `description` | string | no | Max 2000 characters. |
| `business_unit_id` | UUID or null | no | Placement of the application. |
| `owner_user_id` | UUID or null | no | Application owner (a user of the organization). |
| `security_owner_user_id` | UUID or null | no | Security owner (a user of the organization). |
| `technical_owner_user_id` | UUID or null | no | Technical owner (a user of the organization). |
| `lifecycle` | string | no | `planned`, `development`, `active` (default), `maintenance`, `deprecated` or `retired`. |
| `environment` | string | no | `production` (default), `staging`, `development`, `test` or `other`. |
| `criticality` | string | no | `low`, `medium` (default), `high` or `critical`. |
| `external_ref` | string | no | Application identifier (for example a CMDB ID), max 100 characters, no line breaks. |

```json
{
  "name": "Payments Platform",
  "description": "Card payments, refunds and settlement",
  "business_unit_id": "0190c0de-1111-7000-8000-000000000101",
  "owner_user_id": "0190c0de-2222-7000-8000-000000000001",
  "security_owner_user_id": "0190c0de-2222-7000-8000-000000000003",
  "criticality": "high"
}
```

Response `201 Created`: the [Application object](#the-application-object).

| Status | Meaning |
|---|---|
| 201 | Created. |
| 400 `invalid_request` | "name is required", "name must be 1-200 characters", "description must be at most 2000 characters", "invalid criticality", "lifecycle must be one of …", "environment must be one of …", "external_ref must be at most 100 characters", "business unit does not exist", unknown user ("a referenced item ... does not exist"), malformed JSON or unknown field. |
| 403 `forbidden` | No `repos.manage` at the placement. |
| 409 `conflict` | "an item with this name already exists". |
| 415 `unsupported_media_type` | Wrong `Content-Type`. |

```json
{
  "error": { "code": "conflict", "message": "an item with this name already exists" },
  "request_id": "1b68eadc9f0a2b3c4d5e6f70"
}
```

Database entities: `applications`, `audit_logs` (`application.create`).

### Update an application

Changes the fields that are present. Explicit `null` clears `business_unit_id`, `owner_user_id`, `security_owner_user_id` or `technical_owner_user_id`.

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/applications/{id}` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` at the application's current placement (its business unit, else organization-wide). When `business_unit_id` is sent, also `repos.manage` at the new placement. |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Application ID. |

Body: any of the fields of [Create an application](#create-an-application), with the same rules.

```json
{ "security_owner_user_id": "0190c0de-2222-7000-8000-000000000003", "criticality": "critical" }
```

Response `200 OK`: the updated [Application object](#the-application-object). Archived applications can also be updated.

| Status | Meaning |
|---|---|
| 200 | Updated. |
| 400 `invalid_request` | Validation error as for create. |
| 403 `forbidden` | No `repos.manage` at the current or new placement. |
| 404 `not_found` | Unknown application, or the new business unit does not exist. |
| 409 `conflict` | Name already used. |

Database entities: `applications`, `audit_logs` (`application.update`).

### Archive an application

Archives the application and **unlinks all its repositories** (their `application_id` becomes `null`). There is no unarchive endpoint.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/applications/{id}/archive` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` at the application's placement (its business unit, else organization-wide) |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response: `204 No Content`. The audit entry `application.archive` records `repositories_unlinked`, the number of linked **active** repositories (archived repositories are unlinked too but not counted). Archiving an already archived application is not refused; it sets a new archive time and writes another audit entry.

| Status | Meaning |
|---|---|
| 204 | Archived. |
| 403 `forbidden` | No `repos.manage` at the placement. |
| 404 `not_found` | Unknown application. |

Database entities: `applications.archived_at`, `repositories.application_id`, `audit_logs`.

### Get an application

PATHOS 3.0 M3. The application profile: the fields of the [Application object](#the-application-object) plus classification, onboarding status and tags. Not behind a feature flag.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/applications/{id}` |
| Authentication | Session or API token |
| Permission | `repos.read`, with the visibility rule of [List applications](#list-applications). An application the caller cannot see answers `404`. |

Response `200`:

```json
{
  "id": "0190c0de-4444-7000-8000-000000000001",
  "application_key": "QD-APP-000001",
  "name": "Payments Platform",
  "description": "",
  "external_ref": "",
  "business_unit": null,
  "owner": null, "security_owner": null, "technical_owner": null,
  "criticality": "high", "lifecycle": "active", "environment": "production",
  "application_type": "api",
  "languages": ["Go", "TypeScript"], "frameworks": ["chi", "React"], "runtimes": ["Go", "Node.js"],
  "data_classification": "confidential", "internet_exposure": "public", "compliance_scopes": ["pci_dss"],
  "authentication_model": "oidc_sso", "hosting_region": "europe", "data_residency_region": { "id": "…", "name": "Europe" },
  "onboarding_status": "draft",
  "detected": { "languages": { "source": "repository", "detail": "Language statistics of acme/payments-api" },
                "frameworks": { "source": "sbom", "detail": "Packages in the SBOM of acme/payments-api" } },
  "progress": { "filled": 6, "required": 9, "missing": ["owner", "business_unit", "data_classification"],
                "missing_tag_categories": [], "label": "Onboarding: 6 of 9 fields" },
  "tags": [{ "id": "…", "name": "pci-dss", "color": "red", "category_id": "…", "category_name": "Compliance",
             "category_color": "#cf222e", "source": "rule" }],
  "repository_count": 2, "can_manage": true, "archived_at": null,
  "created_at": "2026-11-20T10:00:00Z", "updated_at": "2026-11-20T10:05:00Z"
}
```

| Field | Notes |
|---|---|
| `application_type`, `data_classification`, `internet_exposure`, `compliance_scopes`, `authentication_model`, `hosting_region` | Keys of the organization's classification catalogues (`GET /api/v1/asset-settings`); `""`/`[]` when not set. `unknown` exposure or authentication model counts as not set. |
| `data_residency_region` | A region of the organization structure, or `null`. |
| `onboarding_status` | `draft` (incomplete; shown as *Onboarding: N of M fields*) or `complete`. Applications created before M3 and with `POST /api/v1/applications` are `complete`. |
| `detected` | Fields filled automatically, with their source: `repository` (repository metadata), `sbom` or `scm` (provider discovery). A field a person edits loses its entry. |
| `progress` | Mandatory fields (`GET /api/v1/application-settings`) filled and missing, mandatory tag categories missing, and the status label. |
| `tags[].source` | `manual`, `rule`, `bulk` or `onboarding`. |

Errors: `404` (PTH-PLAT-0004).

### Classify an application

Flag `onboarding`. Saves any subset of fields; drafts may stay incomplete. Tag IDs replace the application's tags. Afterwards the enabled automatic tagging rules for applications run. Audited as `application.classify`; tag changes are recorded in the [tag history](#tag-history).

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/applications/{id}/classification` |
| Permission | `repos.manage` on the application's business unit (or the organization); moving to another business unit needs it there too |

Body (every field optional): `description`, `business_unit_id`, `owner_user_id`, `security_owner_user_id`, `technical_owner_user_id` (UUID or `null`), `criticality`, `environment`, `lifecycle`, `external_ref`, `application_type`, `languages`, `frameworks`, `runtimes` (string lists, at most 50/50/20 values of 60 characters), `data_classification`, `internet_exposure`, `compliance_scopes`, `authentication_model`, `hosting_region` (catalogue keys), `data_residency_region_id`, `tag_ids`.

Response `200`: the application profile. Errors: `400 validation_failed` with `error.fields` (PTH-PLAT-0003, for example an archived catalogue value), `400` for an unknown tag or two tags in a single-value category, `403`, `404`, `404 feature_disabled` (PTH-PLAT-1007).

## Onboarding

Flag `onboarding` for every endpoint below. Repositories are identified by a **source key**: host and path in lower case, without scheme, credentials, `.git` or trailing slash (`github.com/acme/payments-api`). The table `asset_onboardings` is unique on (organization, source key), on (connection, external ID) and on the repository: the second onboarding of a repository fails, also under concurrency, and rolls back everything it would have created.

A **source** is either `{ "repository_id": "…" }` (a repository already in PATHOS) or a discovered repository `{ "scm_connection_id": "…", "external_id": "101", "full_name": "acme/payments-api", "url": "https://github.com/acme/payments-api", "organization": "acme", "project": "", "language": "Go" }` (`language` is the provider's primary language, a detection hint).

### Find existing assets

`POST /api/v1/onboarding/match` · permission `repos.read` at any scope · creates nothing.

Body: `{ "repositories": [source, …] (1-50), "application_name": "optional" }`.

Response `200`:

```json
{
  "sources": [{ "…source fields…": "", "source_key": "github.com/acme/payments-api",
                "existing_repository": { "id": "…", "name": "payments-api", "full_name": "acme/payments-api", "url": "…", "application": null },
                "registered_elsewhere": false,
                "onboarding": null }],
  "candidates": [{ "id": "…", "application_key": "QD-APP-000142", "name": "Payments Platform", "onboarding_status": "complete",
                   "repository_count": 2, "score": 0.83, "reasons": ["Shares the owner or team acme", "Name similar to \"payments-api\" (75%)"] }],
  "suggested_name": "Payments API"
}
```

`existing_repository`: the same repository is registered (same connection and external ID, or same source key). `registered_elsewhere`: it is registered in a scope the caller cannot see (no details). `onboarding`: the repository is already being onboarded (application name omitted when not visible). `candidates`: up to five visible applications scoring at least 0.4 from containing the repository (1.0), an onboarding of it (1.0), a shared owner namespace (0.3) and name similarity (similarity × 0.7).

Errors: `400` (no repositories, unknown connection, the same repository twice).

### Register

`POST /api/v1/onboarding` · permission `repos.manage` (on the business unit for a new application; on the application to link; on each existing repository).

Body: `{ "mode": "new", "application": { "name": "Payments Platform", "description": "", "business_unit_id": null, "external_ref": "" }, "repositories": [source, …] }` or `{ "mode": "link", "application_id": "…", "repositories": [...] }`.

A new application is created as a **draft**. Each source gets an onboarding record (`linked_existing` when the repository is in PATHOS, else `registered_new`). Empty fields are filled from repository metadata, the SBOM and provider hints (see `detected`), and application rules run. Audited as `application.onboard`.

Response `201`: `{ "application": <profile>, "sources": [<onboarding source>] }` where an onboarding source is `{ "id", "full_name", "url", "scm_connection_id", "external_id", "organization", "project", "decision", "status" ("draft" | "saved" | "discovery_started"), "repository_id", "repository_name", "import_job_id", "import_status", "language", "created_at" }`.

Errors: `409 already_onboarding` (PTH-ONB-1008, `error.details.application_id` when visible), `409 application_exists` (PTH-ONB-1011), `409 already_registered` (PTH-ONB-1004, registered in a scope the caller cannot see), `400`, `403`, `404`.

### List drafts

`GET /api/v1/onboarding` · `repos.read`. Visible draft applications (at most 200, latest first): `{ "items": [{ "id", "application_key", "name", "progress", "repository_count", "updated_at" }] }`.

### Get an onboarding

`GET /api/v1/applications/{id}/onboarding` · `repos.read` (visibility as above). `{ "application": <profile>, "sources": [...] }`. Sources whose repository was imported since registration are linked to it.

### Save to inventory

`POST /api/v1/applications/{id}/onboarding/complete` · `repos.manage` on the application and on each linked repository. Requires every mandatory field and mandatory tag category; links existing repositories to the application (`repositories.application_id`), marks the sources `saved` and the application `complete`. Audited as `application.onboarding_complete`. Response `200`: the onboarding. Errors: `422 mandatory_fields_missing` with `error.fields` (PTH-ONB-1009), `422 mandatory_tags_missing` (PTH-ONB-1010), `403`, `404`.

Repositories still to import are registered by the client with the existing [import endpoint](imports.md#the-import-request) (`metadata.application_id` set to the application), which keeps the repository validation, mandatory repository tags and job history.

### Start discovery

`POST /api/v1/applications/{id}/onboarding/discovery` · `repos.manage`. Body `{ "import_job_id": "optional" }`: records the import job on the sources without a repository and marks every source `discovery_started`. Scans of linked repositories are started with `POST /api/v1/scans`. Errors: `409 onboarding_incomplete` (PTH-ONB-1009) before Save to inventory, `400` unknown import job.

### Detect again

`POST /api/v1/applications/{id}/detect` · `repos.manage`. Fills empty fields from repository metadata and SBOMs again (for example after the first scan) and runs application rules. Response: the onboarding.

### Application fields settings

`GET /api/v1/application-settings` (`repos.read`) and `PATCH /api/v1/application-settings` (`assets.configure`, organization-wide) with `{ "required_fields": ["owner", "criticality", …] }`. Fields: `description`, `owner`, `security_owner`, `technical_owner`, `business_unit`, `criticality`, `external_ref`, `application_type`, `languages`, `frameworks`, `runtimes`, `data_classification`, `internet_exposure`, `compliance_scopes`, `authentication_model`, `hosting_region`, `data_residency`, `environment`, `lifecycle`. Response: `{ "required_fields", "fields", "labels" }`. Audited as `asset_settings.application_fields` with old and new values. Errors: `400` unknown field.

## Tag framework

Flag `onboarding`. Builds on the [tag categories and tags](repositories.md) of the repository API.

| Method and path | Permission | Purpose |
|---|---|---|
| `GET /api/v1/tag-framework` | `repos.read` at any scope | Categories with `color`, `is_mandatory` (repositories), `allow_multiple`, `mandatory_asset_types`, tags with repository and application counts, `noncompliant_applications`; the rules; `rule_fields` |
| `PATCH /api/v1/tag-categories/{id}/framework` | `tags.manage` | `{ "color": "#rrggbb" or "", "mandatory_asset_types": ["all" or application type keys] }` → `204`. Audited as `tag_category.framework` (old and new) |
| `POST /api/v1/tag-rules` | `tags.manage` | Create a rule (below) → `201 { "rule", "applied" }` |
| `PATCH /api/v1/tag-rules/{id}` | `tags.manage` | Change any rule field → `200` rule. Audited with old and new |
| `DELETE /api/v1/tag-rules/{id}` | `tags.manage` | `204`; tags it added stay |
| `POST /api/v1/tag-rules/{id}/apply` | `tags.manage` | Run on every active asset (at most 5000) → `{ "tagged": n }`; `409` when the rule is disabled |
| `POST /api/v1/tag-assignments/bulk` | per asset: `repos.manage` on the application or repository | Bulk tagging (below) |
| `GET /api/v1/tag-history` | asset visibility with `target_type` and `target_id`; otherwise `tags.manage` or `audit.read` organization-wide | Tag changes, latest first (200) |

### Automatic tagging rules

```json
{ "name": "PCI scope", "tag_id": "…", "target_type": "application", "condition": "classification",
  "field": "compliance_scopes", "value": "pci_dss", "enabled": true, "apply": true }
```

| Condition | `target_type` | Matches |
|---|---|---|
| `classification` | `application` | `field` (one of `rule_fields`) equals `value`, or a list field contains it (case-insensitive) |
| `repository_topic` | `application` or `repository` | A repository's technology labels contain `value` (applications: any of their repositories). Provider topics are not fetched yet |
| `path_pattern` | `application` or `repository` | A repository's full name matches the glob `value` (`*` and `?` within a segment, `**` across segments, case-insensitive) |

Rules only add tags. In a single-value category they never replace an existing tag. `apply: true` runs the new rule on existing assets.

### Bulk tagging

Body: `{ "target_type": "application" | "repository", "ids": [… 1-500], "add_tag_ids": […], "remove_tag_ids": […] }` (1-50 tags in total). A tag added to a single-value category replaces the asset's other tag there. Removing the last tag of a category mandatory for repositories is refused for that repository (PTH-ONB-1006). Each asset is authorized and changed separately. Response `200`: `{ "items": [{ "id", "status": "updated" | "unchanged" | "error", "error" }], "updated": n }`; assets that do not exist or are not permitted report `not found or not permitted`.

### Tag history

`GET /api/v1/tag-history?target_type=application&target_id=…`: `{ "items": [{ "id", "target_type", "target_id", "target_name", "category_id", "category_name", "old_tags", "new_tags", "source", "rule_id", "actor_email", "created_at" }] }`. One entry per changed category per change. Covers application tags and changes made through the tag framework (rules, bulk); repository tag edits through `PATCH /api/v1/repositories/{id}` stay in the audit log.

## Lifecycle

| Method and path | Flag | Permission | Response |
|---|---|---|---|
| `GET /api/v1/applications/{id}/lifecycle` | `onboarding` | `repos.read` (visibility) | One application: `{ "id", "application_key", "name", "onboarding_status", "criticality", "last_scan_at", "phases": [...], "phases_with_data" }` |
| `GET /api/v1/lifecycle/overview` | `lifecycle_overview` | `repos.read` at any scope | `{ "items": [<same>], "phase_totals": [9 counts], "truncated" }`, at most 500 applications by name |
| `GET /api/v1/applications/{id}/activity` | `onboarding` | `repos.read` (visibility); audit entries need `audit.read` organization-wide | `{ "items": [{ "at", "kind": "audit" | "tags", "action", "actor", "target", "summary" }], "audit_visible" }` |

A phase is `{ "number", "key", "title", "available", "has_data", "summary", "metrics", "restricted" }`. Keys and their real data: `connect` (repositories, repositories in onboarding), `inventory` (always has data; summary says draft or registered), `discover` (SBOM components; `sbom.read`), `threat_model` and `reverse_engineering` (`available: false`, no data until M5 and M10), `assess` (scans, findings, open findings; findings counts need `findings.read`), `validate` (AI and human reviews), `remediate` (fix pull requests, risk acceptances, pull request checks), `report` (release versions, runtime mappings). Counts only include repositories the caller can read; `restricted: true` when the caller lacks the permission for the phase.

## Repositories and applications

### Link repositories to an application

There is no dedicated link endpoint. A repository's application is part of its asset metadata:

- **Existing repository:** `PATCH /api/v1/repositories/{id}` with `application_id` (an active application) or `null` to unlink. See [Update a repository](repositories.md#update-a-repository). Asset owners without `repos.manage` cannot change the application.
- **New repositories:** set `metadata.application_id` in [Start an import](imports.md#start-an-import). The legacy synchronous imports accept `application_id` per item (see [Import repositories synchronously](repositories.md#import-repositories-synchronously)).
- **Create and link in one step:** send `new_application: { "name": "...", "external_ref": "..." }` instead of `application_id`, in an import's `metadata` or a repository update. The application is created with the repository's business unit, application owner and criticality. Creating it needs `repos.manage` at the repository's placement. Within one import job, all items share the created application.

```json
{
  "new_application": { "name": "Billing Batch", "external_ref": "APP-0193" }
}
```

Errors are reported as `422 validation_failed` with the field `application_id` ("application does not exist or is archived") or `new_application` ("application name must be 1-200 characters", "application ID must be at most 100 characters", "an application with this name already exists; select it instead").

Database entities: `repositories.application_id`, `applications`.

### View the repositories of an application

Use [List repositories](repositories.md#list-repositories) with the `application_id` filter. Only repositories the caller can see are returned, so the count can be lower than the application's `repository_count`.

```http
GET /api/v1/repositories?application_id=0190c0de-4444-7000-8000-000000000001&status=active HTTP/1.1
Host: pathos.example.com
Cookie: __Host-pathos_session=<session-cookie>
```

`GET /api/v1/repositories?owner=none` lists repositories without an application.

Database entities: `repositories`.

## Application versions

Versions (releases) of an application, with frozen SBOM and findings snapshots and VEX export, are described in [Application versions, VEX and component policies](releases-and-vex.md#application-versions).
