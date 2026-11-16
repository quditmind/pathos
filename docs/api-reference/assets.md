---
title: Assets
section: api-reference
order: 2
version: "1.0"
updated: 2026-11-17
summary: How assets map to repositories, and the asset settings, classification catalogs, tags and directory lookups that describe them.
---

# Assets

## What an asset is in PATHOS

PATHOS models an **asset** as a **registered repository plus its metadata**: ownership, placement, classification, compliance scopes, tags, application URLs and public exposure. There is **no separate `/api/v1/assets` resource**. Asset operations use the repository and import endpoints:

| Asset operation | How it is done |
|---|---|
| Create an asset | Done through an import: [Start an import](imports.md#start-an-import) (`source` `git`, `devops` or `upload`). The legacy [synchronous import](repositories.md#import-repositories-synchronously) and [CSV import](repositories.md#import-repositories-from-csv) are still supported. |
| List assets | [List repositories](repositories.md#list-repositories) |
| Get an asset | [Get a repository](repositories.md#get-a-repository) |
| Find an asset by Repository ID | [List repositories](repositories.md#list-repositories) with `repository_key=QD-REPO-000042` |
| Update asset metadata | [Update a repository](repositories.md#update-a-repository) |
| Archive or restore an asset | [Archive a repository](repositories.md#archive-a-repository), [Unarchive a repository](repositories.md#unarchive-a-repository) |
| Delete an asset | [Delete a repository](repositories.md#delete-a-repository) (archive first) |
| Tag many assets | [Add or remove tags on many repositories](repositories.md#add-or-remove-tags-on-many-repositories) |
| Asset dashboards | [Get repository insights](repositories.md#get-repository-insights) |
| Group assets into applications | [Applications](applications.md#list-applications) |

The endpoints on this page configure how assets are described: the organization's asset policy, the classification catalogs, tags and the user and team lookups used by owner pickers.

All endpoints are under `/api/v1`, need a browser session, and need `X-CSRF-Token` on mutations. See [Authentication](index.md#authentication).

## Asset settings

### Get asset settings

Returns the organization's asset policy, the classification catalogs and the upload limits.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/asset-settings` |
| Authentication | Session cookie |
| Permission | `repos.read` at any scope |
| Request headers | `Cookie` |

Response `200 OK` (catalogs shortened):

```json
{
  "required_fields": ["technical_owner", "data_classification", "production_url"],
  "always_required": ["business_owner", "business_unit", "business_region", "public_exposure"],
  "scan_on_import": true,
  "repository_key_prefix": "QD-REPO",
  "classifications": {
    "criticality": [
      { "id": "0190c0de-cccc-7000-8000-000000000001", "kind": "criticality", "key": "critical", "label": "Critical", "description": "Outage or compromise causes severe business, financial, legal or safety impact", "color": "#cf222e", "sort_order": 10, "is_system": true, "archived": false }
    ],
    "data_classification": [],
    "environment": [],
    "application_type": [],
    "internet_exposure": [],
    "compliance": [],
    "hosting_region": [],
    "lifecycle_status": []
  },
  "suggested_colors": [
    { "key": "critical", "label": "Critical", "color": "#cf222e" },
    { "key": "high", "label": "High", "color": "#e16f24" },
    { "key": "medium", "label": "Medium", "color": "#d4a72c" },
    { "key": "low", "label": "Low", "color": "#2da44e" },
    { "key": "general", "label": "Internal / general", "color": "#1f6feb" },
    { "key": "inactive", "label": "Archived / inactive", "color": "#6e7781" }
  ],
  "upload": { "max_bytes": 2147483648, "chunk_size": 8388608, "formats": ["zip", "tar", "tar.gz"] }
}
```

| Field | Notes |
|---|---|
| `required_fields` | Policy field names required on every new asset (and that cannot be cleared on update). |
| `always_required` | Required regardless of policy. |
| `scan_on_import` | When `false`, imports never queue onboarding scans. |
| `repository_key_prefix` | Prefix of Repository IDs generated from now on. Existing IDs never change. |
| `classifications` | Every catalog, including archived entries (`archived: true`), ordered by `sort_order` and label. |

Policy field names usable in `required_fields`: `description`, `application`, `application_type`, `business_purpose`, `business_owner`, `technical_owner`, `application_owner`, `business_unit`, `department`, `responsible_team`, `supporting_team`, `cost_centre`, `business_region`, `country`, `hosting_region`, `data_residency_region`, `operational_location`, `criticality`, `data_classification`, `environment`, `internet_exposure` (the value `unknown` counts as empty), `compliance_scopes`, `tags`, `lifecycle_status`, `staging_url`, `production_url`, `public_exposure`.

| Status | Meaning |
|---|---|
| 200 | Returned. |
| 403 `forbidden` | No `repos.read` anywhere. |

Database entities: `asset_settings`, `asset_classifications`.

### Update asset settings

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/asset-settings` |
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | Organization-wide `assets.configure` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Field | Type | Required | Description |
|---|---|---|---|
| `required_fields` | string array | no | Replaces the list. Values from the policy field names above; duplicates and always-required fields are dropped. |
| `scan_on_import` | boolean | no | Allow imports to queue onboarding scans. |
| `repository_key_prefix` | string | no | Upper-cased; letters, digits and single hyphens, starting with a letter, max 20 characters, for example `QD-REPO`. Applies to Repository IDs generated afterwards only. |

```json
{
  "required_fields": ["technical_owner", "data_classification", "production_url"],
  "scan_on_import": true,
  "repository_key_prefix": "QD-REPO"
}
```

Response `200 OK`: the same body as [Get asset settings](#get-asset-settings).

| Status | Meaning |
|---|---|
| 200 | Updated. |
| 400 `invalid_request` | "unknown field X", invalid `repository_key_prefix`, malformed JSON. |
| 403 `forbidden` | No organization-wide `assets.configure`. |
| 415 `unsupported_media_type` | Wrong `Content-Type`. |

Database entities: `asset_settings`, `audit_logs` (`asset_settings.update`).

## Classification catalogs

Catalog kinds: `criticality`, `data_classification`, `environment`, `application_type`, `internet_exposure`, `compliance`, `hosting_region`, `lifecycle_status`. Each organization is seeded with defaults. Assets store the catalog `key`; labels and colours are display data.

Built-in entries (`is_system: true`) cannot be archived because code relies on their keys: all four criticality levels; environments `production`, `staging`, `test`, `development`, `other`; internet exposure `unknown`; lifecycle `active` and `retired`. They can be renamed and recoloured.

Archived entries cannot be chosen for new values, but assets that already use them stay valid.

To list catalogs, use [Get asset settings](#get-asset-settings) (`classifications`).

### Create a classification entry

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/asset-classifications` |
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | Organization-wide `assets.configure` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Field | Type | Required | Description |
|---|---|---|---|
| `kind` | string | yes | A catalog kind other than `criticality` (its four levels are fixed). |
| `key` | string | yes | `^[a-z0-9][a-z0-9_]{0,62}$`, unique within the kind. Permanent. |
| `label` | string | yes | 1–100 characters. |
| `description` | string | no | Max 1000 characters. |
| `color` | string | no | `#rrggbb` or `""`. |
| `sort_order` | integer | no | −100000 to 100000. Default: after the last entry. |

```json
{ "kind": "compliance", "key": "dora", "label": "DORA", "description": "EU Digital Operational Resilience Act", "color": "" }
```

Response `201 Created`:

```json
{
  "id": "0190c0de-cccc-7000-8000-000000000101",
  "kind": "compliance",
  "key": "dora",
  "label": "DORA",
  "description": "EU Digital Operational Resilience Act",
  "color": "",
  "sort_order": 80,
  "is_system": false,
  "archived": false
}
```

| Status | Meaning |
|---|---|
| 201 | Created. |
| 400 `invalid_request` | Unknown kind, `criticality` kind, invalid key, missing or invalid label, description too long, invalid colour, `sort_order` out of range. |
| 403 `forbidden` | No organization-wide `assets.configure`. |
| 409 `conflict` | The key already exists in this kind. |

Database entities: `asset_classifications`, `audit_logs` (`asset_classification.create`).

### Update a classification entry

Changes the label, description, colour or sort order, or archives / restores an entry. `kind` and `key` cannot be changed.

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/asset-classifications/{id}` |
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | Organization-wide `assets.configure` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Classification entry ID. |

| Field | Type | Required | Description |
|---|---|---|---|
| `label` | string | no | 1–100 characters. |
| `description` | string | no | Max 1000 characters. |
| `color` | string | no | `#rrggbb` or `""`. |
| `sort_order` | integer | no | −100000 to 100000. |
| `archived` | boolean | no | `true` archives, `false` restores. |

```json
{ "label": "Highly critical", "color": "#a40e26" }
```

Response `200 OK`: the updated entry (same shape as for create).

| Status | Meaning |
|---|---|
| 200 | Updated. |
| 400 `invalid_request` | "kind and key cannot be changed" or a validation error. |
| 403 `forbidden` | No organization-wide `assets.configure`. |
| 404 `not_found` | Unknown entry. |
| 409 `conflict` | "built-in entries cannot be archived; rename them instead". |

Database entities: `asset_classifications`, `audit_logs` (`asset_classification.update`).

## Tags

Tags belong to categories. A **mandatory** category must have at least one tag on every repository when it is imported or when its tags are edited. A category with `allow_multiple: false` allows one tag per repository. A repository can carry at most 50 tags. Assign tags with `tag_ids` in [Update a repository](repositories.md#update-a-repository), in [import metadata](imports.md#the-import-request), or with [bulk tagging](repositories.md#add-or-remove-tags-on-many-repositories).

### List tag categories

Returns all categories with their tags and usage counts.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/tag-categories` |
| Authentication | Session cookie |
| Permission | `repos.read` at any scope |
| Request headers | `Cookie` |

Response `200 OK`:

```json
{
  "items": [
    {
      "id": "0190c0de-7777-7000-8000-000000000001",
      "name": "Compliance",
      "description": "Regulatory scope",
      "is_mandatory": true,
      "allow_multiple": true,
      "tags": [
        { "id": "0190c0de-7777-7000-8000-000000000011", "name": "PCI", "color": "red", "description": "Cardholder data", "repository_count": 12 }
      ],
      "noncompliant_repositories": 3
    }
  ]
}
```

`noncompliant_repositories` counts active repositories without a tag in a mandatory category (0 for optional categories).

| Status | Meaning |
|---|---|
| 200 | Returned. |
| 403 `forbidden` | No `repos.read` anywhere. |

Database entities: `tag_categories`, `tags`, `repository_tags`, `repositories`.

### Create a tag category

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/tag-categories` |
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | Organization-wide `tags.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | 1–100 characters, no `:`. Unique. |
| `description` | string | no | Free text. |
| `is_mandatory` | boolean | no | Default `false`. |
| `allow_multiple` | boolean | no | Default `true`. |

```json
{ "name": "Owner Team", "description": "Team accountable for remediation", "is_mandatory": true, "allow_multiple": false }
```

Response `201 Created`:

```json
{
  "id": "0190c0de-7777-7000-8000-000000000002",
  "name": "Owner Team",
  "description": "Team accountable for remediation",
  "is_mandatory": true,
  "allow_multiple": false,
  "tags": [],
  "noncompliant_repositories": 0
}
```

| Status | Meaning |
|---|---|
| 201 | Created. |
| 400 `invalid_request` | "name must be 1-100 characters and must not contain ':'". |
| 403 `forbidden` | No organization-wide `tags.manage`. |
| 409 `conflict` | Name already used. |

Database entities: `tag_categories`, `audit_logs` (`tag_category.create`).

### Update a tag category

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/tag-categories/{id}` |
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | Organization-wide `tags.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

Body: any of `name`, `description`, `is_mandatory`, `allow_multiple` (rules as for create). Making a category mandatory does not change existing repositories; they must be fixed at their next tag edit.

```json
{ "is_mandatory": true }
```

Response: `204 No Content`.

| Status | Meaning |
|---|---|
| 204 | Updated. |
| 400 `invalid_request` | Invalid name. |
| 403 `forbidden` | No organization-wide `tags.manage`. |
| 404 `not_found` | Unknown category. |
| 409 `conflict` | Name already used. |

Database entities: `tag_categories`, `audit_logs` (`tag_category.update`).

### Delete a tag category

Deletes the category, its tags and their assignments to repositories.

| Property | Value |
|---|---|
| Method | `DELETE` |
| Path | `/api/v1/tag-categories/{id}` |
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | Organization-wide `tags.manage` |
| Request headers | `Cookie`, `X-CSRF-Token` |

Response: `204 No Content`.

| Status | Meaning |
|---|---|
| 204 | Deleted. |
| 403 `forbidden` | No organization-wide `tags.manage`. |
| 404 `not_found` | Unknown category. |

Database entities: `tag_categories`, `tags`, `repository_tags` (cascade), `audit_logs` (`tag_category.delete`).

### Create a tag

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/tag-categories/{id}/tags` |
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | Organization-wide `tags.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Category ID. |

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | 1–100 characters, no `:` or `;`. Unique within the category. |
| `color` | string | no | `slate` (default), `blue`, `green`, `amber`, `red`, `purple`, `teal`, `pink`, or `#rrggbb`. |
| `description` | string | no | Max 500 characters. |

```json
{ "name": "PCI", "color": "red", "description": "Cardholder data" }
```

Response `201 Created`:

```json
{ "id": "0190c0de-7777-7000-8000-000000000011", "name": "PCI", "color": "red", "description": "Cardholder data", "repository_count": 0 }
```

| Status | Meaning |
|---|---|
| 201 | Created. |
| 400 `invalid_request` | "name is required", invalid name, colour or description. |
| 403 `forbidden` | No organization-wide `tags.manage`. |
| 404 `not_found` | Unknown category. |
| 409 `conflict` | Name already used in this category. |

Database entities: `tags`, `audit_logs` (`tag.create`).

### Search tags

A flat, searchable tag list for pickers.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/tags` |
| Authentication | Session cookie |
| Permission | `repos.read` at any scope |
| Request headers | `Cookie` |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `q` | string | no | Case-insensitive substring of the tag name, category name or tag description, max 100 characters. |
| `limit` | integer | no | 1–200, default 50. |

Response `200 OK`:

```json
{
  "items": [
    {
      "id": "0190c0de-7777-7000-8000-000000000011",
      "name": "PCI",
      "color": "red",
      "description": "Cardholder data",
      "repository_count": 12,
      "category_id": "0190c0de-7777-7000-8000-000000000001",
      "category_name": "Compliance"
    }
  ]
}
```

| Status | Meaning |
|---|---|
| 200 | Returned, sorted by category and tag name. |
| 400 `invalid_request` | Bad `limit` or `q` too long. |
| 403 `forbidden` | No `repos.read` anywhere. |

Database entities: `tags`, `tag_categories`, `repository_tags`.

### Update a tag

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/tags/{id}` |
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | Organization-wide `tags.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

Body: any of `name`, `color`, `description` (rules as for create).

```json
{ "color": "#cf222e" }
```

Response `200 OK`:

```json
{ "id": "0190c0de-7777-7000-8000-000000000011", "name": "PCI", "color": "#cf222e", "description": "Cardholder data", "repository_count": 12 }
```

| Status | Meaning |
|---|---|
| 200 | Updated. |
| 400 `invalid_request` | Invalid name, colour or description. |
| 403 `forbidden` | No organization-wide `tags.manage`. |
| 404 `not_found` | Unknown tag. |
| 409 `conflict` | Name already used in the category. |

Database entities: `tags`, `audit_logs` (`tag.update`).

### Delete a tag

Deletes the tag and removes it from all repositories.

| Property | Value |
|---|---|
| Method | `DELETE` |
| Path | `/api/v1/tags/{id}` |
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | Organization-wide `tags.manage` |
| Request headers | `Cookie`, `X-CSRF-Token` |

Response: `204 No Content`.

| Status | Meaning |
|---|---|
| 204 | Deleted. |
| 403 `forbidden` | No organization-wide `tags.manage`. |
| 404 `not_found` | Unknown tag. |

Database entities: `tags`, `repository_tags` (cascade), `audit_logs` (`tag.delete`).

## Directory lookups

Owner and team pickers use these lookups. They return only ID, name and e-mail (users) or ID, name and member count (teams).

### Search users

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/directory/users` |
| Authentication | Session cookie |
| Permission | `repos.read` or `repos.manage` at any scope |
| Request headers | `Cookie` |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `q` | string | no | Case-insensitive substring of display name or e-mail, max 100 characters. |
| `ids` | string | no | Comma-separated user UUIDs (max 100) to resolve specific users; when set, `q` is ignored. Invalid UUIDs are skipped. |
| `limit` | integer | no | 1–100, default 20. |

Deactivated users are never returned.

Response `200 OK`:

```json
{
  "items": [
    { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" }
  ]
}
```

| Status | Meaning |
|---|---|
| 200 | Returned, sorted by name. |
| 400 `invalid_request` | Bad `limit` or `q` too long. |
| 403 `forbidden` | Neither permission. |

Database entities: `users`.

### Search teams

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/directory/teams` |
| Authentication | Session cookie |
| Permission | `repos.read` or `repos.manage` at any scope |
| Request headers | `Cookie` |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `q` | string | no | Case-insensitive substring of the team name, max 100 characters. |
| `limit` | integer | no | 1–100, default 20. |

Response `200 OK`:

```json
{
  "items": [
    { "id": "0190c0de-3333-7000-8000-000000000001", "name": "Payments Engineering", "member_count": 7 }
  ]
}
```

| Status | Meaning |
|---|---|
| 200 | Returned, sorted by name. |
| 400 `invalid_request` | Bad `limit` or `q` too long. |
| 403 `forbidden` | Neither permission. |

Database entities: `teams`, `team_members`.
