---
title: Source provider (SCM) connections
section: api-reference
order: 4
version: "1.0"
updated: 2026-11-19
summary: SCM providers and connections, repository discovery, SCM inventory, OAuth applications and the webhook receivers for provider events.
---

# Source provider (SCM) connections

An SCM connection stores the credential PATHOS uses to read repositories from a source-code platform. Connections feed repository discovery and [imports](imports.md#start-an-import), keep repositories in sync, and receive webhooks.

Credentials are encrypted at rest and never returned by the API. All endpoints are under `/api/v1` and use the [common authentication](index.md#authentication) (a session with `X-CSRF-Token` on mutations, or a REST API token), except the [webhook receivers](#webhook-receivers), which are public and verified by signature.

Outbound webhooks (PATHOS notifying other systems) are in [Notifications](notifications.md#outbound-webhooks); Jira and ServiceNow are in [Ticketing and reports](integrations-reporting.md#ticketing-jira-servicenow).

## Providers and authentication methods

| Provider key | Label | Category (`source` for imports) | Default base URL | Auth types |
|---|---|---|---|---|
| `github` | GitHub | `git` | `https://api.github.com` | `github_app`, `pat`, `oauth` |
| `github_enterprise` | GitHub Enterprise Server | `git` | none (required, e.g. `https://github.example.com/api/v3`) | `github_app`, `pat`, `oauth` |
| `gitlab` | GitLab | `git` | `https://gitlab.com` | `pat`, `oauth` |
| `bitbucket` | Bitbucket Cloud | `git` | `https://api.bitbucket.org/2.0` | `pat`, `api_token`, `oauth` |
| `azure_devops` | Azure DevOps Services | `devops` | `https://dev.azure.com` (or `https://dev.azure.com/<organization>` when `owner` is set) | `service_principal`, `pat`, `oauth` |
| `azure_devops_server` | Azure DevOps Server | `devops` | none (required, the collection URL) | `pat` |

Request fields per authentication type for [Create a connection](#create-a-connection):

| `auth_type` | Providers | Required fields | Optional fields |
|---|---|---|---|
| `pat` | all | `token` | `organizations` (Azure DevOps: limits discovery). Bitbucket: set `owner` to the workspace, access tokens cannot list workspaces. |
| `github_app` | `github`, `github_enterprise` | `github_app_id` (> 0), `github_installation_id` (> 0), `private_key` (RSA PEM) | |
| `api_token` | `bitbucket` | `username` (Atlassian account e-mail), `token` | |
| `service_principal` | `azure_devops` | `tenant_id`, `client_id`, and either `client_secret` or `certificate_pem` with `private_key_pem`; `organizations` when the base URL is `https://dev.azure.com` | |
| `oauth` | `github`, `github_enterprise`, `gitlab`, `bitbucket`, `azure_devops` | Not created with this endpoint: use [Start an OAuth connection](#start-an-oauth-connection) | |

### List providers

Returns the provider catalog that drives the connection wizard: labels, base URL help, capabilities and the input fields of each authentication method.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-providers` |
| Authentication | Session or API token |
| Permission | `repos.read` at any scope, or organization-wide `scm.manage` |
| Request headers | `Cookie` |

Response `200 OK` (one provider shown):

```json
{
  "items": [
    {
      "key": "bitbucket",
      "label": "Bitbucket Cloud",
      "category": "git",
      "default_base_url": "https://api.bitbucket.org/2.0",
      "base_url_required": false,
      "base_url_help": "Bitbucket Cloud only; the API URL is fixed.",
      "owner_label": "Workspace (required for access tokens)",
      "capabilities": { "organizations": true, "projects": true, "server_search": true },
      "auth_methods": [
        {
          "key": "api_token",
          "label": "API token",
          "description": "Atlassian account API token with scopes read:user, read:workspace, read:project and read:repository for Bitbucket.",
          "oauth": false,
          "fields": [
            { "name": "username", "label": "Atlassian account e-mail", "type": "text", "required": true, "secret": false, "help": "" },
            { "name": "token", "label": "API token", "type": "password", "required": true, "secret": true, "help": "Create it at id.atlassian.com → Security → API tokens (\"with scopes\", app Bitbucket)." }
          ],
          "docs_url": "https://support.atlassian.com/bitbucket-cloud/docs/using-api-tokens/"
        }
      ]
    }
  ]
}
```

Field `type` is `text`, `password`, `textarea`, `number` or `list`. `capabilities.projects` is `true` for Bitbucket and both Azure DevOps providers; `server_search` is `true` for GitHub, GitHub Enterprise, GitLab and Bitbucket.

| Status | Meaning |
|---|---|
| 200 | Catalog returned. |
| 403 `forbidden` | Neither permission. |

Database entities: none (static catalog).

## Connections

### The Connection object

```json
{
  "id": "0190c0de-6666-7000-8000-000000000001",
  "name": "GitHub Example Org",
  "provider": "github",
  "base_url": "https://api.github.com",
  "auth_type": "github_app",
  "owner": "example-org",
  "github_app_id": 123456,
  "github_installation_id": 78901234,
  "status": "ok",
  "status_message": "authenticated as example-org (installation 78901234)",
  "last_checked_at": "2026-11-17T08:00:00Z",
  "webhook_url": "https://pathos.example.com/api/webhooks/github/0190c0de-6666-7000-8000-000000000001",
  "repository_count": 42,
  "created_at": "2026-09-01T10:00:00Z",
  "oauth_app_id": null,
  "account": "example-org (installation 78901234)",
  "organizations": [],
  "token_expires_at": null,
  "capabilities": { "organizations": true, "projects": false, "server_search": true }
}
```

| Field | Notes |
|---|---|
| `status` | `untested`, `ok`, `error`, `expired` (OAuth token could not be refreshed) or `revoked` (deleted). |
| `repository_count` | Active (non-archived) repositories of this connection. |
| `webhook_url` | The URL to configure at the provider. Empty in [List connections](#list-connections) unless the caller holds organization-wide `scm.manage`. |
| `account` | Identity reported by the last successful test. |
| `organizations` | Organizations to discover (Azure DevOps). |
| `oauth_app_id`, `token_expires_at` | Set for `oauth` connections. |
| `has_ca_bundle`, `ca_certificates` | Whether a private CA bundle is set and, per certificate, `subject`, `issuer`, `not_after`, `sha256_fingerprint`, `is_ca`, `expired` (empty when none). The PEM itself is never returned; send `ca_bundle_pem` again to replace it, `""` to remove it. |
| `ssh_known_hosts`, `ssh_host_keys` | Generic Git over SSH: the pinned `known_hosts` lines and, per key, `hosts`, `key_type`, `fingerprint` (`SHA256:…`). Empty otherwise. |

Database entities: `scm_connections`, `secrets` (credential and webhook secret, encrypted).

### List connections

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-connections` |
| Authentication | Session or API token |
| Permission | `repos.read` at any scope (connection names are needed to show repositories). Credentials are never included. |
| Request headers | `Cookie` |

Response `200 OK`: `{ "items": [Connection, ...] }`, sorted by name, without deleted connections.

| Status | Meaning |
|---|---|
| 200 | Returned. |
| 403 `forbidden` | No `repos.read` anywhere. |

Database entities: `scm_connections`, `repositories` (count).

### Get a connection

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-connections/{id}` |
| Authentication | Session or API token |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Connection ID. |

Response `200 OK`: the [Connection object](#the-connection-object).

| Status | Meaning |
|---|---|
| 200 | Returned. |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 404 `not_found` | Unknown or deleted connection. |

Database entities: `scm_connections`.

### Create a connection

Creates a connection with a PAT, GitHub App, Bitbucket API token or Azure DevOps service principal, generates its webhook secret, and tests it immediately. A failed test does not fail the request; it is reported in `status` and `status_message`.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/scm-connections` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Field | Type | Required | Description |
|---|---|---|---|
| `name` | string | yes | 1–200 characters, unique. |
| `provider` | string | yes | A provider key. |
| `auth_type` | string | yes | Allowed for the provider (see the table above). |
| `base_url` | string | provider-dependent | Absolute `https` URL without credentials, query or fragment. Defaults per provider. Private and blocked addresses are rejected by the outbound network policy. |
| `owner` | string | no | Organization, user, group, workspace or project (see the provider's `owner_label`), max 200 characters. |
| `token` | string | see table | PAT, access token or API token. |
| `private_key` | string | `github_app` | GitHub App private key (PEM). |
| `github_app_id`, `github_installation_id` | integer | `github_app` | Positive integers. |
| `username` | string | `api_token` | Atlassian account e-mail. |
| `tenant_id`, `client_id`, `client_secret`, `certificate_pem`, `private_key_pem` | string | `service_principal` | Microsoft Entra ID app registration. |
| `organizations` | string array | `service_principal` on `https://dev.azure.com` | Organization names, max 100, each `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`. |
| `ca_bundle_pem` | string | no | **Connectors feature only.** PEM `CERTIFICATE` blocks (max 20 certificates, 64 KiB) added to the system trust store for this connection and its clones. Stored as configuration; the connection returns `has_ca_bundle` and the certificates' metadata (`ca_certificates`), not the PEM. Private keys are refused. |
| `ssh_private_key`, `ssh_passphrase` | string | `ssh_key` (Generic Git) | OpenSSH or PEM private key (deploy key) and its optional passphrase. Write-only. |
| `ssh_known_hosts` | string | `ssh_key` | `known_hosts` lines with the server's host key (plain host names; `[host]:port` for other ports). Configuration. |
| `ssh_host_key_fingerprint` | string | `ssh_key` | `SHA256:…` fingerprint confirmed by the server administrator; must match a key in `ssh_known_hosts`. |

Providers added with the Connectors feature (`connectors` flag on; otherwise `400 unknown provider`):

| `provider` | `auth_type` | `base_url` | Credential fields |
|---|---|---|---|
| `bitbucket_data_center` (Bitbucket Data Center) | `pat` (project or repository HTTP access token, Bearer) or `api_token` (user token, Basic) | Instance root; a trailing `/rest/...` is removed | `token`; `username` for `api_token`. `owner` = optional project key |
| `generic_git` | `api_token` (HTTPS) or `ssh_key` (SSH) | The repository URL: `https://…` for `api_token`, `ssh://user@host[:port]/path` or `user@host:path` for `ssh_key` (stored as `ssh://`) | `token` and optional `username` (default `git`); or the `ssh_*` fields |

`base_url` of `github_enterprise` is normalized to end in `/api/v3`; for `gitlab` a trailing `/api/v4` is removed.

Any single-value credential (`token`) may be a secret reference `vault:<mount>/<path>#<key>` resolved at use time ([Secret references](../user-guide/secret-references.md)).

Example: Generic Git over SSH.

```json
{
  "name": "Payments (git.example.com)",
  "provider": "generic_git",
  "auth_type": "ssh_key",
  "base_url": "ssh://git@git.example.com/team/payments.git",
  "ssh_private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n<deploy-key>\n-----END OPENSSH PRIVATE KEY-----\n",
  "ssh_known_hosts": "git.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA<host-key>",
  "ssh_host_key_fingerprint": "SHA256:<fingerprint-from-the-server-administrator>"
}
```

Example: Bitbucket Data Center with a private CA.

```json
{
  "name": "Bitbucket DC",
  "provider": "bitbucket_data_center",
  "auth_type": "pat",
  "base_url": "https://bitbucket.example.com",
  "owner": "SEC",
  "token": "<http-access-token>",
  "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\n<private-ca>\n-----END CERTIFICATE-----\n"
}
```

Example: GitHub App.

```json
{
  "name": "GitHub Example Org",
  "provider": "github",
  "auth_type": "github_app",
  "owner": "example-org",
  "github_app_id": 123456,
  "github_installation_id": 78901234,
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\n<private-key>\n-----END RSA PRIVATE KEY-----\n"
}
```

Example: Azure DevOps service principal with a client secret.

```json
{
  "name": "Azure DevOps Example",
  "provider": "azure_devops",
  "auth_type": "service_principal",
  "tenant_id": "0190c0de-0000-7000-8000-00000000a001",
  "client_id": "0190c0de-0000-7000-8000-00000000a002",
  "client_secret": "<client-secret>",
  "organizations": ["example-org", "example-platform"]
}
```

Example: Bitbucket Cloud API token.

```json
{
  "name": "Bitbucket Example",
  "provider": "bitbucket",
  "auth_type": "api_token",
  "owner": "example-workspace",
  "username": "dana.owner@example.com",
  "token": "<api-token>"
}
```

Response `201 Created`: the [Connection object](#the-connection-object) after the test.

| Status | Meaning |
|---|---|
| 201 | Created (check `status`). |
| 400 `invalid_request` | "name is required (max 200 characters)", "unknown provider", "auth_type X is not available for ...", "base_url is required for this provider", invalid base URL, invalid organization name, "github_app_id and github_installation_id are required", "list the Azure DevOps organizations the service principal was added to", missing credential fields (for example "token is required", "tenant_id and client_id are required", "provide either client_secret or certificate_pem with private_key_pem"), an unparsable private key, or `auth_type: "oauth"` ("OAuth connections are created with POST /api/v1/scm-connections/oauth/start"). Connectors feature: `ca_bundle_pem` without the feature or not PEM certificates; unparsable SSH key or `known_hosts`; `ssh_host_key_fingerprint` not matching (`error_code` `PTH-CONN-1140`); `api_token` with an `ssh://` URL or `ssh_key` with an `https://` URL. |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 409 `conflict` | A connection with this name already exists. |
| 415 `unsupported_media_type` | Wrong `Content-Type`. |

Database entities: `scm_connections`, `secrets`, `audit_logs` (`scm_connection.create`).

### Update a connection

Renames a connection, changes `owner` or `organizations`, rotates its credential, or changes GitHub App IDs. `provider`, `auth_type` and `base_url` cannot be changed. Rotating the credential resets `status` to `untested`.

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/scm-connections/{id}` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

Body: any of `name`, `owner`, `organizations`, the credential fields of the connection's auth type (all required fields of that type must be sent together), `github_app_id`, `github_installation_id` (GitHub App connections only), `ca_bundle_pem` (Connectors feature; `""` removes the bundle), `ssh_known_hosts` with `ssh_host_key_fingerprint` (Generic Git SSH; replaces the pinned keys). Changing the CA bundle or the pinned keys resets `status` to `untested`.

```json
{ "name": "GitHub Example Org (prod)", "token": "<personal-access-token>" }
```

Response `200 OK`: the updated [Connection object](#the-connection-object).

| Status | Meaning |
|---|---|
| 200 | Updated. |
| 400 `invalid_request` | "provider, auth_type and base_url cannot be changed; create a new connection", invalid name or organizations, incomplete credential, credential fields on an OAuth connection ("OAuth connections are renewed with Reconnect ..."), app IDs on a non-GitHub-App connection. |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 404 `not_found` | Unknown or deleted connection. |
| 409 `conflict` | Name already used. |

Database entities: `scm_connections`, `secrets`, `audit_logs` (`scm_connection.update`).

### Test a connection

Checks the credential against the provider and stores the outcome.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/scm-connections/{id}/test` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response `200 OK`: the [Connection object](#the-connection-object) with the new `status` (`ok`, `error` or `expired`), `status_message` and `last_checked_at`.

| Status | Meaning |
|---|---|
| 200 | Tested (check `status`). |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 404 `not_found` | Unknown or deleted connection. |

Database entities: `scm_connections`.

### Rotate the webhook secret

Generates a new webhook secret and returns it **once**. Configure it at the provider; deliveries signed with the old secret are rejected from now on.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/scm-connections/{id}/webhook-secret` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response `200 OK`:

```json
{
  "webhook_url": "https://pathos.example.com/api/webhooks/github/0190c0de-6666-7000-8000-000000000001",
  "webhook_secret": "<webhook-secret>"
}
```

| Status | Meaning |
|---|---|
| 200 | Rotated. |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 404 `not_found` | Unknown or deleted connection. |

Database entities: `secrets`, `audit_logs` (`scm_connection.rotate_webhook_secret`).

### Resynchronize a connection

Reconciles every active repository of the connection with the provider: metadata, head commit of the tracked branch, deletion, archive and permission changes. Placement, classification and tags are not touched. The same reconciliation runs on a schedule.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/scm-connections/{id}/resync` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response `200 OK`:

```json
{ "checked": 42, "updated": 5, "missing": 1, "archived_upstream": 0 }
```

| Status | Meaning |
|---|---|
| 200 | Done. A sync run (trigger `schedule`) is recorded for each repository that changed, failed or changed sync status; the others only get a new `last_sync_at`. |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 404 `not_found` | Unknown or deleted connection. |
| 502 `scm_error` | "re-sync failed: ..." (for example the provider listing failed). |

Database entities: `repositories`, `repository_sync_runs`, `scm_connections.last_synced_at`, `audit_logs` (`scm.resync`).

### Refresh the SCM inventory

The SCM inventory is the list of every repository a connection's credential can see. The [unmanaged and shadow repository report](posture.md) compares it with the repositories registered in PATHOS. PATHOS refreshes each active connection's inventory once a day; this endpoint refreshes it now.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/scm-connections/{id}/inventory` |
| Permission | `repos.manage` at organization, region or business-unit scope (as for [Discovery](#discovery)) |

Response `200 OK`, the inventory run:

```json
{
  "id": "0190c0de-aaaa-7000-8000-000000000001",
  "scm_connection_id": "0190c0de-1234-7000-8000-000000000001",
  "started_at": "2026-11-19T10:00:00Z",
  "finished_at": "2026-11-19T10:00:41Z",
  "status": "succeeded",
  "repositories": 812,
  "truncated": false,
  "error": ""
}
```

At most 20,000 repositories are recorded per connection (`truncated: true` beyond that). When the provider listing fails, the response is `502` with `{ "error": { "code": "inventory_failed", "message": "…" }, "run": { … } }`. `403` without the permission, `404` for an unknown or deleted connection. Audited as `scm.inventory_refresh` (status and repository count).

### Delete a connection

Deletes a connection that has no active repositories. Before the stored credential is destroyed, PATHOS revokes it at the provider where an API exists (OAuth tokens on GitHub and GitLab); this is best effort and the outcome is written to the audit log as `provider_revocation` (`revoked`, `not_applicable` or `failed: ...`). The row is kept (archived, `status: "revoked"`) because historical repositories reference it; the credential and webhook secret are overwritten.

| Property | Value |
|---|---|
| Method | `DELETE` |
| Path | `/api/v1/scm-connections/{id}` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token` |

Response: `204 No Content`.

| Status | Meaning |
|---|---|
| 204 | Deleted. |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 404 `not_found` | Unknown or already deleted. |
| 409 `conflict` | "archive or delete the connection's repositories first". |

Database entities: `scm_connections`, `secrets`, `audit_logs` (`scm_connection.delete`).

## Discovery

Discovery endpoints browse what a connection's credential can see, live from the provider. Because the results can include repositories outside the caller's own scope, they require `repos.manage` granted at **organization, region or business-unit scope** (a grant on individual repositories is not enough). Placement is authorized later, when the import is created.

All discovery endpoints return `403 forbidden` without such a grant, `404 not_found` for an unknown connection, `400 invalid_request` "not supported by this provider" where the provider lacks the concept, and `502 scm_error` when the provider refuses the call (authentication, permission, not found, rate limit, expired token, blocked address). Other provider failures (provider `5xx`, network errors, timeouts) return `500 internal`.

### List remote organizations

Lists GitHub organizations and users, GitLab groups, Bitbucket workspaces or Azure DevOps organizations.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-connections/{id}/organizations` |
| Authentication | Session or API token |
| Permission | `repos.manage` at organization, region or business-unit scope |
| Request headers | `Cookie` |

Response `200 OK`:

```json
{
  "items": [
    { "id": "1234567", "name": "example-org", "display_name": "Example Org", "kind": "organization" },
    { "id": "7654321", "name": "dana-owner", "display_name": "Dana Owner", "kind": "user" }
  ]
}
```

`kind` is `user`, `organization`, `group` or `workspace`.

Database entities: none (provider call).

### List remote projects

Lists Azure DevOps projects or Bitbucket projects of an organization or workspace.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-connections/{id}/projects` |
| Authentication | Session or API token |
| Permission | `repos.manage` at organization, region or business-unit scope |
| Request headers | `Cookie` |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `organization` | string | provider-dependent | Organization or workspace name, max 200 characters. |

Response `200 OK`:

```json
{
  "items": [
    { "id": "0190c0de-0000-7000-8000-00000000b001", "name": "Payments", "display_name": "Payments", "description": "Payment services" }
  ]
}
```

For Bitbucket, `name` is the project key. Providers without projects (GitHub, GitLab) return `400 invalid_request` "not supported by this provider".

Database entities: none (provider call).

### List remote repositories

Returns one page (50) of repositories visible to the credential, with their import state.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-connections/{id}/remote-repositories` |
| Authentication | Session or API token |
| Permission | `repos.manage` at organization, region or business-unit scope |
| Request headers | `Cookie` |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `organization` | string | no | Limit to one organization, group or workspace (max 200). Empty: everything the credential can see. |
| `project` | string | no | Azure DevOps or Bitbucket project (max 200). |
| `q` | string | no | Case-insensitive name filter, server-side where the provider supports it (max 100). |
| `page_token` | string | no | `next_page_token` of the previous page (opaque, max 4000). |

Response `200 OK`:

```json
{
  "items": [
    {
      "external_id": "812345678",
      "full_name": "example-org/payments-api",
      "name": "payments-api",
      "url": "https://github.com/example-org/payments-api",
      "clone_url": "https://github.com/example-org/payments-api.git",
      "default_branch": "main",
      "visibility": "private",
      "description": "Card payment authorization service",
      "language": "Go",
      "archived": false,
      "pushed_at": "2026-11-16T14:02:11Z",
      "organization": "example-org",
      "project": "",
      "size_bytes": 18350080,
      "imported_id": "0190c0de-5555-7000-8000-000000000042"
    }
  ],
  "next_page_token": "eyJwYWdlIjoyfQ"
}
```

`imported_id` is the PATHOS repository ID when the repository is already registered through this connection, otherwise `null`. `next_page_token` is `""` on the last page. `size_bytes` is `0` when unknown.

| Status | Meaning |
|---|---|
| 200 | Page returned. |
| 400 `invalid_request` | A parameter is too long, or not supported by this provider. |

Database entities: `repositories` (import state).

### Get remote repository details

Returns the import preview of one remote repository: metadata, branches with head commits, latest commit and languages. A successful response proves the credential can read the repository.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-connections/{id}/remote-repositories/details` |
| Authentication | Session or API token |
| Permission | `repos.manage` at organization, region or business-unit scope |
| Request headers | `Cookie` |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `external_id` | string | one of | Provider repository ID (authoritative when set). Max 300. |
| `full_name` | string | one of | Repository path, for example `example-org/payments-api`. Max 300. |
| `organization` | string | no | Helps providers addressed by path. Max 300. |
| `project` | string | no | Azure DevOps or Bitbucket project. Max 300. |

Response `200 OK`:

```json
{
  "repository": {
    "external_id": "812345678",
    "full_name": "example-org/payments-api",
    "name": "payments-api",
    "url": "https://github.com/example-org/payments-api",
    "clone_url": "https://github.com/example-org/payments-api.git",
    "default_branch": "main",
    "visibility": "private",
    "description": "Card payment authorization service",
    "language": "Go",
    "archived": false,
    "pushed_at": "2026-11-16T14:02:11Z",
    "organization": "example-org",
    "project": "",
    "size_bytes": 18350080,
    "imported_id": null
  },
  "branches": [
    { "name": "develop", "commit_sha": "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d", "is_default": false },
    { "name": "main", "commit_sha": "9f2c4b1e0d8a7c6b5a4f3e2d1c0b9a8f7e6d5c4b", "is_default": true }
  ],
  "latest_commit": {
    "sha": "9f2c4b1e0d8a7c6b5a4f3e2d1c0b9a8f7e6d5c4b",
    "message": "Add 3-D Secure fallback",
    "author": "Omar Tech",
    "committed_at": "2026-11-16T14:01:58Z"
  },
  "languages": { "Go": 912345, "Shell": 4321 },
  "permission": "read"
}
```

`latest_commit` is `null` for empty repositories. `languages` holds bytes or percentages, as the provider reports them. `permission` is always `read` in this version (the repository could be read with the credential); the provider's write or admin level is not reported here.

| Status | Meaning |
|---|---|
| 200 | Preview returned. |
| 400 `invalid_request` | "external_id or full_name is required", or a parameter is too long. |
| 502 `scm_error` | Not found or not visible to the credential, or refused by the provider (see [Discovery](#discovery)). |

Database entities: `repositories` (import state).

### List all remote repositories (legacy)

Lists every repository the credential can see in one response (up to 5,000), with import state. Prefer the paginated [List remote repositories](#list-remote-repositories).

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-connections/{id}/discover` |
| Authentication | Session or API token |
| Permission | `repos.manage` at organization, region or business-unit scope |
| Request headers | `Cookie` |

Response `200 OK`:

```json
{
  "items": [
    { "external_id": "812345678", "full_name": "example-org/payments-api", "name": "payments-api", "...": "same fields as above", "imported_id": null }
  ],
  "truncated": false
}
```

`truncated` is `true` when the 5,000 limit was reached.

Database entities: `repositories` (import state).

## OAuth applications

Administrators register an OAuth application per provider (GitHub OAuth App, GitLab application, Bitbucket OAuth consumer, Microsoft Entra ID app registration). Users then create `oauth` connections through the browser consent flow. The redirect URI to register at the provider is `<PUBLIC_URL>/api/v1/scm-oauth/callback` (returned as `redirect_uri`).

### The OAuth application object

```json
{
  "id": "0190c0de-aaaa-7000-8000-000000000001",
  "provider": "gitlab",
  "name": "GitLab (self-managed)",
  "base_url": "https://gitlab.example.com",
  "tenant_id": "",
  "client_id": "<client-id>",
  "scopes": "",
  "redirect_uri": "https://pathos.example.com/api/v1/scm-oauth/callback",
  "connection_count": 2,
  "created_at": "2026-09-15T12:00:00Z"
}
```

The client secret is never returned. Empty `scopes` means the provider default (GitHub `repo read:org`; GitLab `read_api read_repository`; Azure DevOps `499b84ac-1321-427f-aa17-267ca6975798/.default offline_access` (the Azure DevOps resource); Bitbucket: none are sent, scopes are set on the consumer).

Database entities: `scm_oauth_apps`, `secrets`.

### List OAuth applications

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-oauth-apps` |
| Authentication | Session or API token |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie` |

Response `200 OK`:

```json
{
  "items": [{ "id": "0190c0de-aaaa-7000-8000-000000000001", "provider": "gitlab", "name": "GitLab (self-managed)", "...": "OAuth application object" }],
  "redirect_uri": "https://pathos.example.com/api/v1/scm-oauth/callback"
}
```

| Status | Meaning |
|---|---|
| 200 | Returned. |
| 403 `forbidden` | No organization-wide `scm.manage`. |

Database entities: `scm_oauth_apps`, `scm_connections` (count).

### Create an OAuth application

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/scm-oauth-apps` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Field | Type | Required | Description |
|---|---|---|---|
| `provider` | string | yes | `github`, `github_enterprise`, `gitlab`, `bitbucket` or `azure_devops`. |
| `name` | string | yes | 1–200 characters. |
| `client_id` | string | yes | 1–300 characters. |
| `client_secret` | string | yes | Max 4000 characters. |
| `base_url` | string | `github_enterprise` | Only for GitHub Enterprise (required) and self-managed GitLab. `https` URL. |
| `tenant_id` | string | no | Azure DevOps only: tenant GUID, domain, `organizations` (default) or `common`. Max 100. |
| `scopes` | string | no | Overrides the default scopes, max 500 characters. |

```json
{
  "provider": "azure_devops",
  "name": "Entra ID for Azure DevOps",
  "tenant_id": "example.onmicrosoft.com",
  "client_id": "<client-id>",
  "client_secret": "<client-secret>"
}
```

Response `201 Created`: the [OAuth application object](#the-oauth-application-object).

| Status | Meaning |
|---|---|
| 201 | Created. |
| 400 `invalid_request` | Unknown provider, missing name, `client_id` or `client_secret`, `base_url` on a provider that does not take one, "base_url is required for GitHub Enterprise", `tenant_id` on a non-Azure provider, length violations. |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 409 `conflict` | Name already used. |

Database entities: `scm_oauth_apps`, `secrets`, `audit_logs` (`scm_oauth_app.create`).

### Update an OAuth application

Changes `name`, `base_url`, `tenant_id`, `client_id`, `scopes`, or rotates `client_secret`. `provider` cannot be changed.

| Property | Value |
|---|---|
| Method | `PATCH` |
| Path | `/api/v1/scm-oauth-apps/{id}` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

```json
{ "client_secret": "<client-secret>" }
```

Response `200 OK`: the updated [OAuth application object](#the-oauth-application-object).

| Status | Meaning |
|---|---|
| 200 | Updated. |
| 400 `invalid_request` | "provider cannot be changed" or a validation error as for create. |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 404 `not_found` | Unknown or deleted application. |
| 409 `conflict` | "an item with this name already exists". |

Database entities: `scm_oauth_apps`, `secrets`, `audit_logs` (`scm_oauth_app.update`).

### Delete an OAuth application

| Property | Value |
|---|---|
| Method | `DELETE` |
| Path | `/api/v1/scm-oauth-apps/{id}` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token` |

Response: `204 No Content`. The application is archived and its client secret overwritten.

| Status | Meaning |
|---|---|
| 204 | Deleted. |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 404 `not_found` | Unknown or deleted application. |
| 409 `conflict` | "delete the connections that use this OAuth application first". |

Database entities: `scm_oauth_apps`, `secrets`, `audit_logs` (`scm_oauth_app.delete`).

### Start an OAuth connection

Starts the authorization-code flow (with PKCE, except for Bitbucket, which does not use it) for a new `oauth` connection, or for reconnecting an existing one. The client then navigates the browser to `authorize_url`. The flow must finish within 10 minutes.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/scm-connections/oauth/start` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Organization-wide `scm.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Field | Type | Required | Description |
|---|---|---|---|
| `oauth_app_id` | UUID | yes | OAuth application to use. |
| `name` | string | new connections | Connection name, 1–200 characters. Ignored when reconnecting. |
| `owner` | string | no | As for other connections, max 200 characters. |
| `connection_id` | UUID | reconnect | Existing `oauth` connection created with the same OAuth application. Its stored token is replaced. |
| `return_to` | string | no | Same-origin path to return to after consent. Default `/admin/scm`. Anything else (absolute URLs, `//...`, backslashes, control characters, more than 300 characters) falls back to the default. |

```json
{
  "oauth_app_id": "0190c0de-aaaa-7000-8000-000000000001",
  "name": "GitLab Example Group",
  "owner": "example-group",
  "return_to": "/admin/scm"
}
```

Response `200 OK`:

```json
{ "authorize_url": "https://gitlab.example.com/oauth/authorize?client_id=<client-id>&code_challenge=<challenge>&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fpathos.example.com%2Fapi%2Fv1%2Fscm-oauth%2Fcallback&response_type=code&scope=read_api+read_repository&state=<state>" }
```

| Status | Meaning |
|---|---|
| 200 | Flow started. |
| 400 `invalid_request` | "unknown OAuth application", "name is required (max 200 characters)", "reconnect must use the OAuth application the connection was created with". |
| 403 `forbidden` | No organization-wide `scm.manage`. |
| 404 `not_found` | `connection_id` does not exist. |

Database entities: `scm_oauth_states` (state hash, PKCE verifier, return path), `scm_oauth_apps`.

### Complete an OAuth connection

The provider redirects the browser here after consent. Every outcome is a redirect back into the web application; this endpoint is not meant to be called by scripts.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/scm-oauth/callback` |
| Authentication | Session cookie (the browser's session; without one the response is `401 unauthenticated` JSON) |
| Permission | Must be the same user who started the flow, and still hold organization-wide `scm.manage` |
| Request headers | `Cookie` |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `state` | string | yes | Echoed by the provider (max 200). Single use. |
| `code` | string | on success | Authorization code (max 2000). |
| `error`, `error_description` | string | on refusal | Set by the provider when consent was declined. |

Behaviour:

- Success: `303 See Other` to `<return_to>?oauth=success&connection=<connection-id>`. A new connection is created (or the existing one gets the new token and `status: "untested"`), then tested.
- Failure: `303 See Other` to `<return_to>?oauth=error&message=<url-encoded reason>`, for example "the authorization request expired or was already used; start again", "this authorization was started by another user", "the provider declined the authorization: ...", "token exchange failed: ...", "a connection with this name already exists". If the state is unknown, the default path `/admin/scm` is used.

```http
HTTP/1.1 303 See Other
Location: /admin/scm?oauth=success&connection=0190c0de-6666-7000-8000-000000000002
```

Database entities: `scm_oauth_states` (consumed), `scm_connections`, `secrets`, `audit_logs` (`scm_connection.create`, `scm_connection.reconnect`, or a denied `scm_connection.oauth_callback`).

## GitLab webhook signing token

GitLab 19.0 and later sign deliveries when the webhook has a **signing token** (GitLab: *Generate signing token*; shown once, starts with `whsec_`; Standard Webhooks HMAC-SHA256). Store it on the connection:

| Method | Path | Permission | Body | Response |
|---|---|---|---|---|
| `PUT` | `/api/v1/scm-connections/{id}/webhook-signing-token` | `scm.manage` (organization) | `{"token": "whsec_…"}` | `200 {"webhook_signed": true}` |
| `DELETE` | `/api/v1/scm-connections/{id}/webhook-signing-token` | `scm.manage` (organization) | — | `200 {"webhook_signed": false}` |

The token is stored encrypted (kind `webhook`) and never returned; the connection view shows `webhook_signed`. Errors: `400` for a connection that is not GitLab, `404`, `422 validation_failed` (`fields.token`) for a malformed token. Both are audited (`scm_connection.set_webhook_signing_token`, `scm_connection.remove_webhook_signing_token`). With the token set, only signed deliveries are accepted; remove it for GitLab versions before 19.0, which only send the secret token.

## Webhook receivers

Webhook endpoints are **public** (no session, no CSRF token). Each delivery is authenticated with the connection's webhook secret (see [Rotate the webhook secret](#rotate-the-webhook-secret)). The connection's `webhook_url` already contains the right provider path and connection ID.

| Endpoint | Providers | Verification | Event header | Delivery ID |
|---|---|---|---|---|
| `POST /api/webhooks/github/{id}` | `github`, `github_enterprise` | `X-Hub-Signature-256: sha256=<hex HMAC-SHA256 of the raw body>` | `X-GitHub-Event` | `X-GitHub-Delivery` |
| `POST /api/webhooks/azure-devops/{id}` | `azure_devops`, `azure_devops_server` | `Authorization: Basic ...`; any user name, the password is the webhook secret | from the payload | from the payload |
| `POST /api/webhooks/gitlab/{id}` | `gitlab` | With a [signing token](#gitlab-webhook-signing-token): `webhook-signature: v1,<base64 HMAC-SHA256 of "<webhook-id>.<webhook-timestamp>.<raw body>">`, timestamp within 5 minutes (the legacy token alone is refused). Without one: `X-Gitlab-Token: <webhook secret>` | `X-Gitlab-Event` | `X-Gitlab-Event-UUID` |
| `POST /api/webhooks/bitbucket/{id}` | `bitbucket` | `X-Hub-Signature: sha256=<hex HMAC-SHA256 of the raw body>` | `X-Event-Key` | `X-Request-UUID` |
| `POST /api/webhooks/bitbucket-data-center/{id}` | `bitbucket_data_center` (Bitbucket Data Center) | `X-Hub-Signature: sha256=<hex HMAC-SHA256 of the raw body>` | `X-Event-Key` (`repo:refs_changed`, `pr:opened`, `pr:from_ref_updated`, `pr:merged`, `diagnostics:ping`) | `X-Request-Id` |

Common behaviour of all four receivers:

| Property | Value |
|---|---|
| Method | `POST` |
| Authentication | Public; signature or token verification as above |
| Permission | None |
| Path parameter `id` | Connection ID (UUID). An unknown or deleted connection, or a connection of another provider, returns `404 not_found`. |
| Body | Provider JSON payload, max 25 MB (larger: `413 too_large`, `PTH-CONN-1106`). |

Events are normalized to `push`, `pull_request`, `merge`, `ping` or `ignored`. For a verified delivery:

- The delivery is stored once per (connection, delivery ID). Without a delivery ID (or with one longer than 200 characters), the SHA-256 of the body is used. Replays return `200` with `{"status": "duplicate"}`.
- A `push` to the tracked branch of a registered repository updates its head commit and records a sync run with trigger `webhook`.
- A `push` or `merge` to the repository's scan branch (or default branch) queues a scan (trigger `push` or `merge`), if scanning is enabled.
- Deliveries for repositories that are not registered are stored with status `unknown_repository`.

```http
POST /api/webhooks/github/0190c0de-6666-7000-8000-000000000001 HTTP/1.1
Host: pathos.example.com
Content-Type: application/json
X-GitHub-Event: push
X-GitHub-Delivery: 0190c0de-0000-7000-8000-00000000c001
X-Hub-Signature-256: sha256=<hex-hmac-of-body>
```

Response `202 Accepted`:

```json
{ "status": "received", "event": "push" }
```

| Status | Meaning |
|---|---|
| 202 | Delivery recorded (`status` is `received` or `unknown_repository`). |
| 200 | Duplicate delivery: `{"status": "duplicate"}`. |
| 400 `invalid_request` | Payload could not be parsed. |
| 401 `invalid_signature` | "webhook signature verification failed" (also written to the audit log as `webhook.rejected`). |
| 403 `csrf_failed` | The request carried an `Origin` header that is not the PATHOS origin (SCM providers do not send one). |
| 404 `not_found` | Unknown connection, deleted connection, or wrong provider path. |
| 413 `too_large` | "payload too large" (over 5 MiB). |
| 429 `rate_limited` | Webhook rate limit for the connection exceeded. |

Database entities: `webhook_deliveries`, `repositories`, `repository_sync_runs`, `scan_jobs`, `audit_logs`.
