---
title: Applications
section: api-reference
order: 6
version: "1.0"
updated: 2026-11-17
summary: List, create, update and archive applications, and link repositories to them.
---

# Applications

An application groups repositories into a business application, for example "Payments Platform". It has an owner, a security owner, an optional business unit and a criticality. Repositories link to at most one application through their `application_id`.

All endpoints are under `/api/v1`, need a browser session, and need `X-CSRF-Token` on mutations. See [Authentication](index.md#authentication).

## Capabilities at a glance

| Capability | Endpoint |
|---|---|
| List applications | [`GET /api/v1/applications`](#list-applications) |
| Create an application | [`POST /api/v1/applications`](#create-an-application), or `new_application` during an [import](imports.md#the-import-request) or a [repository update](repositories.md#update-a-repository) |
| Update an application | [`PATCH /api/v1/applications/{id}`](#update-an-application) |
| Archive an application | [`POST /api/v1/applications/{id}/archive`](#archive-an-application) |
| Link a repository to an application | [`PATCH /api/v1/repositories/{id}`](#link-repositories-to-an-application) with `application_id` |
| View the repositories of an application | [`GET /api/v1/repositories?application_id=...`](#view-the-repositories-of-an-application) |
| Retrieve one application by ID | **Not available.** There is no `GET /api/v1/applications/{id}`. Use the list endpoint and filter by `id`, or by name with `q`. |
| Unarchive an application | **Not available.** |
| Delete an application | **Not available.** Applications are archived, never deleted. |
| Link APIs and other assets | **Not available.** Only repositories can be linked to an application. |

## The Application object

```json
{
  "id": "0190c0de-4444-7000-8000-000000000001",
  "name": "Payments Platform",
  "description": "Card payments, refunds and settlement",
  "business_unit": { "id": "0190c0de-1111-7000-8000-000000000101", "name": "Payments" },
  "owner": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" },
  "security_owner": { "id": "0190c0de-2222-7000-8000-000000000003", "name": "Sam Security", "email": "sam.security@example.com" },
  "criticality": "high",
  "external_ref": "APP-0193",
  "repository_count": 4,
  "archived_at": null,
  "created_at": "2026-09-20T10:00:00Z"
}
```

| Field | Notes |
|---|---|
| `business_unit`, `owner`, `security_owner` | `null` when not set. |
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
| Authentication | Session cookie |
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
      "name": "Payments Platform",
      "description": "Card payments, refunds and settlement",
      "business_unit": { "id": "0190c0de-1111-7000-8000-000000000101", "name": "Payments" },
      "owner": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" },
      "security_owner": null,
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
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | `repos.manage` on the business unit given in `business_unit_id` (or a scope above it); without a business unit, `repos.manage` organization-wide |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | 1–200 characters. Unique among active applications (case-insensitive). |
| `description` | string | no | Max 2000 characters. |
| `business_unit_id` | UUID or null | no | Placement of the application. |
| `owner_user_id` | UUID or null | no | Application owner (a user of the organization). |
| `security_owner_user_id` | UUID or null | no | Security owner (a user of the organization). |
| `criticality` | string | no | `low`, `medium` (default), `high` or `critical`. |
| `external_ref` | string | no | Application identifier (for example a CMDB ID), max 100 characters. Also accepted on update. |

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
| 400 `invalid_request` | "name is required", "name must be 1-200 characters", "description must be at most 2000 characters", "invalid criticality", "business unit does not exist", unknown user ("a referenced item ... does not exist"), malformed JSON or unknown field. |
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

Changes the fields that are present. Explicit `null` clears `business_unit_id`, `owner_user_id` or `security_owner_user_id`.

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/applications/{id}` |
| Authentication | Session cookie and `X-CSRF-Token` |
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
| Authentication | Session cookie and `X-CSRF-Token` |
| Permission | `repos.manage` at the application's placement (its business unit, else organization-wide) |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response: `204 No Content`. The audit entry `application.archive` records how many repositories were unlinked.

| Status | Meaning |
|---|---|
| 204 | Archived. |
| 403 `forbidden` | No `repos.manage` at the placement. |
| 404 `not_found` | Unknown application. |

Database entities: `applications.archived_at`, `repositories.application_id`, `audit_logs`.

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
