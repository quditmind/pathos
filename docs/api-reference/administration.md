---
title: Administration and your account
section: api-reference
order: 51
version: "1.0"
updated: 2026-11-19
summary: Users, role assignments, roles and permissions, organization structure, audit log, scan workers, MFA, and the caller's own endpoints (/me, API tokens, in-app notifications).
---

# Administration and your account

All endpoints are under `/api/v1` and use the [common conventions](index.md#authentication) (session with `X-CSRF-Token`, or a REST API token). Permissions marked *org-wide* must be granted at organization scope; the others are checked as described per endpoint. Permission keys are listed by [`GET /api/v1/permissions`](#roles-and-permissions); which roles carry them is in `docs/RBAC_MATRIX.md`.

## Your account (`/me`)

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/me` | signed in | [The current user](#the-current-user) |
| `GET` | `/api/v1/me/tokens` | signed in (session only) | [List your API tokens](#api-tokens) |
| `POST` | `/api/v1/me/tokens` | `findings.read` at any scope (session only) | [Create an API token](#api-tokens) |
| `DELETE` | `/api/v1/me/tokens/{id}` | signed in (session only) | [Revoke an API token](#api-tokens) |
| `GET` | `/api/v1/me/notifications` | signed in | [Your in-app notifications](#in-app-notifications) |
| `POST` | `/api/v1/me/notifications/read` | signed in | [Mark notifications as read](#in-app-notifications) |
| `GET` | `/api/v1/me/mfa` | signed in (session only) | [Your MFA status](#mfa-and-recovery-codes) |
| `POST` | `/api/v1/me/recovery-codes` | signed in (session only) | [New recovery codes for yourself](#mfa-and-recovery-codes) |

"Session only": API tokens get `403 token_not_allowed` on these paths, so a token can never create tokens or change sign-in security.

### The current user

`GET /api/v1/me` returns the user, the caller's effective permissions and the CSRF token of the session:

```json
{
  "user": {
    "id": "0190c0de-2222-7000-8000-000000000001",
    "organization_id": "0190c0de-0000-7000-8000-000000000001",
    "email": "dana.owner@example.com",
    "display_name": "Dana Owner",
    "status": "active",
    "last_login_at": "2026-11-19T08:01:12Z",
    "deactivated_at": null,
    "created_at": "2026-01-10T09:00:00Z",
    "updated_at": "2026-11-19T08:01:12Z"
  },
  "permissions": ["repos.read", "repos.manage", "scans.run"],
  "org_wide_permissions": ["repos.read"],
  "role_assignments": [],
  "csrf_token": "<csrf-token>"
}
```

`permissions` are held at some scope, `org_wide_permissions` at organization scope. `role_assignments` has the [assignment objects](#role-assignments). `csrf_token` is empty when the request was authenticated with an API token.

### API tokens

Personal tokens authenticate the REST API (`api:read`, `api:write`) and the MCP endpoint (`mcp`); see [REST API tokens](index.md#rest-api-tokens) for how they are used.

**List** — `GET /api/v1/me/tokens` returns your 100 most recent tokens, newest first, including expired and revoked ones, and the MCP endpoint URL:

```json
{
  "items": [
    {
      "id": "0190c0de-9999-7000-8000-000000000001",
      "name": "CI export",
      "prefix": "pathos_pat_AbC123",
      "scopes": ["api:read"],
      "expires_at": "2026-12-19T10:00:00Z",
      "last_used_at": "2026-11-19T09:12:00Z",
      "revoked_at": null,
      "created_at": "2026-11-19T10:00:00Z"
    }
  ],
  "mcp_url": "https://pathos.example.com/mcp"
}
```

**Create** — `POST /api/v1/me/tokens`:

| Field | Type | Description |
|---|---|---|
| `name` | string | Required, at most 100 characters. |
| `days` | integer | Lifetime in days, 1–90. Default 30. |
| `scopes` | string[] | Any of `mcp`, `api:read`, `api:write`. Default `["mcp"]`. `api:write` allows every method; `api:read` only `GET` and `HEAD`. |

Returns `201` with `{ token, secret, mcp_url, api_url }`. The `secret` (`pathos_pat_…`) is shown **only in this response**; PATHOS stores its SHA-256 hash. A user can have at most 10 active tokens (`409 conflict` otherwise). Audited as `api_token.create` (name, days, scopes).

**Revoke** — `DELETE /api/v1/me/tokens/{id}` returns `204`. `404` if the token does not exist, is not yours or is already revoked. Audited as `api_token.revoke`.

### In-app notifications

`GET /api/v1/me/notifications` returns your 50 most recent in-app notifications, newest first, and the number of unread ones. `?unread=1` returns only unread ones.

```json
{
  "items": [
    {
      "id": "0190c0de-7777-7000-8000-000000000001",
      "event_key": "finding.assigned",
      "channel": "in_app",
      "recipient": "",
      "subject": "[PATHOS] Assigned to you: SQL injection in OrderController",
      "link": "https://pathos.example.com/findings/0190c0de-5555-7000-8000-000000000001",
      "status": "sent",
      "attempts": 0,
      "last_error": "",
      "rule_name": "Assigned to me",
      "sent_at": "2026-11-19T09:00:00Z",
      "read_at": null,
      "created_at": "2026-11-19T09:00:00Z"
    }
  ],
  "unread": 1
}
```

`POST /api/v1/me/notifications/read` with `{ "ids": ["<uuid>", "…"] }` (at most 500) or `{ "all": true }` marks them as read and returns `204`. One of the two is required (`400`).

Which events create in-app notifications is configured with [notification rules](notifications.md#notification-rules).

## Users

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/users` | `users.read` (org-wide) | [List users](#list-users) |
| `POST` | `/api/v1/users` | `users.manage` (org-wide) | [Invite a user](#invite-a-user) |
| `GET` | `/api/v1/users/{id}` | `users.read` (org-wide) | A user (same object as `user` in [`/me`](#the-current-user)) |
| `POST` | `/api/v1/users/{id}/deactivate` | `users.manage` (org-wide) | [Deactivate a user](#deactivate-and-reactivate) |
| `POST` | `/api/v1/users/{id}/reactivate` | `users.manage` (org-wide) | [Reactivate a user](#deactivate-and-reactivate) |

A user's `status` is `invited` (created, not yet signed in), `active` or `deactivated`. Requests refused for lack of permission on these endpoints are audited as `authz.denied`.

### List users

`GET /api/v1/users`, sorted by email.

| Parameter | Description |
|---|---|
| `q` | Case-insensitive substring of email or display name. |
| `status` | `invited`, `active` or `deactivated`. |
| `limit` | 1–200, default 50. |
| `cursor` | `next_cursor` from the previous page. |

Response: `{ "items": [User], "next_cursor": "…" }`; `next_cursor` is `null` on the last page.

### Invite a user

`POST /api/v1/users`

```json
{
  "email": "sam.security@example.com",
  "display_name": "Sam Security",
  "roles": [
    { "role_key": "security_analyst", "scope_type": "business_unit", "scope_id": "0190c0de-1111-7000-8000-000000000101" }
  ]
}
```

| Field | Description |
|---|---|
| `email` | Required, a single valid address (stored in lower case). `409 conflict` if a user with it exists. |
| `display_name` | Optional, at most 200 characters. |
| `roles` | Optional, at most 20 role grants, each validated like [Grant a role](#role-assignments). If any grant is refused, nothing is created. |

Returns `201`:

```json
{
  "user": { "id": "0190c0de-2222-7000-8000-000000000003", "email": "sam.security@example.com", "status": "invited", "...": "user fields" },
  "role_assignments": [],
  "provisioning": { "status": "created", "message": "invitation email sent" }
}
```

`provisioning.status` reports what happened in Keycloak after the user was saved: `created` (account created, invitation email sent), `linked_existing` (an existing Keycloak account with that email was linked), `skipped` (Keycloak provisioning is not configured; create the account in Keycloak or allow self-registration) or `failed` (the PATHOS user exists and is linked at first sign-in). Audited as `user.invite`, and `user.provision` when provisioning is configured.

### Deactivate and reactivate

`POST /api/v1/users/{id}/deactivate` sets the status to `deactivated`, ends all of the user's PATHOS sessions at once, and disables and signs out the Keycloak account (when provisioning is configured). Their API tokens stop working. Errors: `400` for your own account, `409` if already deactivated or if this is the last active organization-wide super administrator. Audited as `user.deactivate`.

`POST /api/v1/users/{id}/reactivate` re-enables the user. A user who never signed in returns to `invited`, others to `active`. `409` if the user is not deactivated. Audited as `user.reactivate`.

Both return the updated user (`200`).

## Role assignments

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/users/{id}/role-assignments` | `roles.read` (org-wide) | The user's assignments |
| `POST` | `/api/v1/users/{id}/role-assignments` | `roles.assign` (see below) | Grant a role at a scope → `201` with the assignment |
| `DELETE` | `/api/v1/role-assignments/{id}` | `roles.assign` (see below) | Revoke an assignment → `204` |

Grant request:

| Field | Description |
|---|---|
| `role_key` | Key of a system or custom role (from [`GET /api/v1/roles`](#roles-and-permissions)). |
| `scope_type` | `organization`, `region`, `business_unit` or `repository`. A business-unit grant also covers the units below it. |
| `scope_id` | ID of the region, business unit or repository. For `organization` it may be omitted (or must be the organization ID). |

Assignment object:

```json
{
  "id": "0190c0de-3333-7000-8000-000000000001",
  "user_id": "0190c0de-2222-7000-8000-000000000003",
  "role_id": "0190c0de-3333-7000-8000-000000000101",
  "role_key": "security_analyst",
  "role_name": "Security Analyst",
  "scope_type": "business_unit",
  "scope_id": "0190c0de-1111-7000-8000-000000000101",
  "scope_name": "Payments",
  "created_by": "0190c0de-2222-7000-8000-000000000001",
  "created_at": "2026-11-19T10:00:00Z"
}
```

Rules that prevent privilege escalation: to grant **or revoke** a role at a scope, the caller needs `roles.assign` at that scope **and** every permission the role carries at that scope. `super_admin` can only be granted at organization scope, and the last active organization-wide super administrator cannot be removed (`409`).

Errors: `400` for an invalid scope type, a missing or unknown scope, or an unknown role; `403` when the caller may not grant the role there; `409` if the user is deactivated or already has the role at that scope. Audited as `role_assignment.create` and `role_assignment.delete` (role, scope type and scope ID in the metadata).

## Roles and permissions

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/roles` | `roles.read` (org-wide) | System roles and the organization's custom roles: `id`, `key`, `name`, `description`, `is_system`, `permissions[]` |
| `GET` | `/api/v1/permissions` | `roles.read` (org-wide) | The permission catalog in display order: `key`, `category`, `description`, `org_only` |

Both return `{ "items": [...] }`. `org_only` permissions only take effect when granted at organization scope. There is no API to create or edit custom roles in this version.

## Organization structure

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/organization` | signed in | `{ id, name, slug, created_at }` |
| `GET` | `/api/v1/regions` | `org.read` at any scope | Regions with their countries: `{ items: [{ id, code, name, countries: [{ id, code, name }] }] }`, sorted by name |
| `GET` | `/api/v1/business-units` | `org.read` at any scope | Active (not archived) business units: `{ items: [{ id, parent_id, name, description, created_at }] }`, sorted by name |
| `POST` | `/api/v1/business-units` | `org.manage` (org-wide) | Create a business unit → `201` |

Create request: `name` (required, at most 200 characters), `description` (at most 2,000), `parent_id` (optional parent business unit). `409` if a unit with that name exists under the same parent; `400` if the parent does not exist. Audited as `business_unit.create`. Regions and countries have no write API.

## Audit log

`GET /api/v1/audit-logs` — permission `audit.read` (org-wide). Returns 50 entries per page, newest first.

| Parameter | Description |
|---|---|
| `action` | An action (`user.invite`) or a prefix before the dot (`user` matches `user.*`). |
| `actor_id` | UUID of the user who acted. |
| `target_type`, `target_id` | The affected object, for example `repository` and its ID. |
| `outcome` | `success`, `denied` or `failure`. |
| `cursor` | `next_cursor` from the previous page. |

```json
{
  "items": [
    {
      "id": "0190c0de-8888-7000-8000-000000000001",
      "actor_id": "0190c0de-2222-7000-8000-000000000001",
      "actor_email": "dana.owner@example.com",
      "action": "role_assignment.create",
      "target_type": "user",
      "target_id": "0190c0de-2222-7000-8000-000000000003",
      "outcome": "success",
      "ip": "203.0.113.10",
      "user_agent": "Mozilla/5.0 …",
      "request_id": "9c1e7a3b5d2f4e6a8b0c1d2e",
      "metadata": { "role": "security_analyst", "scope_type": "business_unit" },
      "created_at": "2026-11-19T10:00:00Z"
    }
  ],
  "next_cursor": "2026-11-19T10:00:00Z|0190c0de-8888-7000-8000-000000000001"
}
```

`next_cursor` is `null` on the last page. Entries written while authenticated with an API token carry `metadata.api_token_id`. System actions (for example `worker.register`) have no actor. The audit actions of each area are listed on its API page.

## Scan workers

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/workers` | `scans.read` at any scope | Registered workers |
| `POST` | `/api/v1/workers/{id}/revoke` | `scanners.manage` (org-wide) | Revoke a worker → `204` |
| `DELETE` | `/api/v1/workers/{id}` | `scanners.manage` (org-wide) | Delete a worker record → `204` |

List response, sorted by name:

```json
{
  "items": [
    {
      "id": "0190c0de-6666-7000-8000-000000000001",
      "name": "worker-core-1",
      "family": "core",
      "version": "1.4.0",
      "scanners": { "opengrep": "1.10.0", "gitleaks": "8.21.2" },
      "last_seen_at": "2026-11-19T10:00:03Z",
      "revoked_at": null,
      "created_at": "2026-10-01T08:00:00Z",
      "online": true,
      "active_jobs": 1
    }
  ]
}
```

`online` means the worker contacted the API in the last 2 minutes and is not revoked. `active_jobs` counts the jobs it currently holds.

**Revoke** invalidates the worker's credential and returns its running jobs to the queue. A revoked worker name cannot register again (`403 worker_revoked`) until its record is deleted. **Delete** removes the record and also requeues its running jobs; the worker can then register again with the bootstrap token. Both return `404` for an unknown worker and are audited as `worker.revoke` and `worker.delete`.

How workers register and receive jobs is described in [Worker protocol](worker-protocol.md).

## Secret validation settings

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/settings/secret-validation` | `settings.manage` (org-wide) | Providers and limits of [live secret validation](../user-guide/secret-validation.md) |
| `PUT` | `/api/v1/settings/secret-validation` | `settings.manage` (org-wide) | Replace them |

`GET` returns:

```json
{
  "providers": [
    { "id": "aws", "name": "AWS access key", "hosts": ["sts.amazonaws.com"], "checkable": true,
      "endpoint": "POST https://sts.amazonaws.com/ Action=GetCallerIdentity (SigV4, us-east-1)", "note": "…", "enabled": false },
    { "id": "pypi", "name": "PyPI API token", "hosts": null, "checkable": false, "endpoint": "", "note": "…", "enabled": false }
  ],
  "rate_per_second": 1,
  "max_checks_per_scan": 50,
  "updated_at": null,
  "can_manage": true,
  "offline": false
}
```

Every provider is listed; `hosts` are the egress allowlist entries the provider needs (Squid syntax, a leading dot matches subdomains). Nothing is enabled by default.

`PUT` body (all fields required):

```json
{ "providers": ["aws", "github"], "rate_per_second": 2, "max_checks_per_scan": 100 }
```

`providers` must be known, checkable provider IDs (`400` otherwise; an empty list turns validation off), `rate_per_second` 1–10, `max_checks_per_scan` 1–500. Returns the settings as `GET` does. Audited as `secret_validation.settings.update` with the previous and new providers.

## MFA and recovery codes

Multi-factor authentication is managed in Keycloak; PATHOS shows the status and can require enrolment.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/me/mfa` | signed in (session only) | Your status |
| `POST` | `/api/v1/me/recovery-codes` | signed in (session only) | Generate new recovery codes at your next sign-in (Keycloak shows them once; old codes stop working). Audited as `user.recovery_codes` |
| `GET` | `/api/v1/users/{id}/mfa` | `users.read` (org-wide) | A user's status |
| `POST` | `/api/v1/users/{id}/require-mfa` | `users.manage` (org-wide) | The user must set up an authenticator at the next sign-in. Audited as `user.require_mfa` |
| `POST` | `/api/v1/users/{id}/recovery-codes` | `users.manage` (org-wide) | The user must generate new recovery codes at the next sign-in. Audited as `user.require_recovery_codes` |

The status object is `{ configured, pending, recovery_codes, recovery_pending }`: an authenticator is set up, enrolment is required at the next sign-in, the user has recovery codes, new codes will be generated at the next sign-in. The `POST` endpoints return `{ "changed": true, "mfa": { …status } }`; `changed` is `false` when the requirement was already set.

Errors: `409 mfa_unavailable` when Keycloak provisioning is not configured or the account is not linked to Keycloak yet; `502 idp_error` when Keycloak cannot be reached.
