---
title: Connectors
section: api-reference
order: 15
version: "3.0"
updated: 2026-11-20
summary: The Connectors hub API (behind the connectors flag) - the kinds catalogue, one list over every connection, real health checks and their history, kinds stored in the registry, and AI troubleshooting of a connector.
---

# Connectors

Quditmind PATHOS · applies to v3.0 (unreleased) · status: Prototype (feature flag `connectors`, off by default)

All endpoints are under `/api/v1/connectors` and follow the [common conventions](index.md#authentication). Errors use the [error envelope](index.md#errors) (`error.error_code` is a catalogue code).

**Feature flag.** While the organization's `connectors` flag is off, every endpoint answers `404` with `error.code` `feature_disabled` and `error.error_code` `PTH-PLAT-1007`. The existing endpoints (`/scm-connections`, `/ticket-connections`, `/notifications/webhooks`, `/notifications/smtp`, `/runtime/clusters`, `/runtime/registries`, `/ai/providers`) work as before whatever the flag.

**Permissions.** There is no new permission. Each connector reuses the permissions of the page that manages it today:

| Kinds | Read | Manage (run a check; create, edit, delete) |
|---|---|---|
| `github`, `github_enterprise`, `gitlab`, `bitbucket`, `azure_devops`, `azure_devops_server` | `repos.read` (any scope) | `scm.manage` (organization) |
| `jira`, `servicenow` | `findings.triage` (any scope) or `settings.manage` | `settings.manage` |
| `webhook`, `slack`, `teams`, `smtp` | `notifications.manage` | `notifications.manage` |
| `kubernetes`, `container_registry` | `findings.read` or `settings.manage` (organization) | `settings.manage` |
| `ai_provider` | `ai.review` (any scope) or `ai.configure` | `ai.configure` |
| `vulnerability_feed` | `findings.read` (any scope) | `settings.manage` |
| `secret_validation`, `object_storage`, `egress_proxy`, kinds stored in the registry | `settings.manage` | `settings.manage` |

A connector of a kind the caller cannot read is absent from lists and answers `404`. A caller who can read no kind gets `403` naming the permissions that would grant access.

**Where checks run.** Kinds with `checked_by: "api"` are checked by the API server (it already calls them for its test buttons). Kinds with `checked_by: "jobs"` (`kubernetes`, `container_registry`, `egress_proxy`) are checked only by the jobs service: the API server never calls a cluster, a registry or the egress proxy.

## The kinds catalogue

`GET /api/v1/connectors/kinds` — any read permission above.

```json
{
  "categories": [{ "key": "scm_ide", "label": "SCM & IDE" }, { "key": "cicd", "label": "CI/CD" }, "…"],
  "items": [
    {
      "kind": "github",
      "category": "scm_ide",
      "label": "GitHub",
      "status": "existing",
      "auth_methods": ["github_app", "pat", "oauth"],
      "docs_slug": "connectors#github",
      "offline_ok": false,
      "direction": "outbound",
      "managed_at": "/admin/scm",
      "creatable": false,
      "checked_by": "api"
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `status` | `existing`, `partial` (exists, part of the design missing; see `note`) or `planned` (not built) |
| `docs_slug` | User-guide page and anchor: `/help/user-guide/connectors#github` |
| `offline_ok` | The kind can work with `PATHOS_OFFLINE=true` (internal systems); per connection, an internet-only host is still disabled |
| `direction` | `outbound` (PATHOS calls the system), `inbound` (it calls PATHOS: CLI, IDE, CI, MCP) or `platform` (part of the installation) |
| `managed_at` | The page that creates and edits connections of an existing kind until the Connectors page reaches parity |
| `creatable` | `POST /api/v1/connectors` accepts the kind: `vault` (stored in the registry), `generic_git` and `bitbucket_data_center` (stored in `scm_connections` by the SCM service) |
| `config_fields` | Creatable kinds only: the form of the Add connector dialog, `[{key, label, type, required, options?, help?}]`; `type` is `text`, `url`, `pem`, `textarea`, `secret_ref`, `select` or `boolean` |
| `secret_refs` | The credential may be a `vault:<mount>/<path>#<key>` reference ([Secret references](../user-guide/secret-references.md)) |
| `checked_by` | `api`, `jobs`, or `""` (catalogue only: inbound and planned kinds have no connector rows) |
| `note` | Optional: what a partial or planned kind lacks |

Categories: `scm_ide`, `cicd`, `cloud`, `containers`, `security`, `iam_secrets`, `apis`, `databases`, `monitoring`.

## List connectors

`GET /api/v1/connectors?category=&kind=&status=` — read permission of each kind (rows of other kinds are left out).

A view over the existing connection tables plus the kinds stored in the registry. Nothing is copied from the existing tables except the source key; credentials are never returned.

```json
{
  "items": [
    {
      "id": "0193f0c2-…",
      "kind": "github",
      "category": "scm_ide",
      "name": "GitHub acme",
      "status": "healthy",
      "enabled": true,
      "last_check_at": "2026-11-20T10:00:00Z",
      "last_ok_at": "2026-11-20T10:00:00Z",
      "last_error_code": "",
      "last_sync_at": "2026-11-20T03:00:00Z",
      "check_requested_at": null,
      "checked_by": "api",
      "managed_at": "/admin/scm",
      "can_manage": true,
      "source": { "table": "scm_connections", "id": "0192…" }
    }
  ]
}
```

| Field | Meaning |
|---|---|
| `status` | `healthy`, `degraded`, `failing`, `unknown` or `disabled`. Never `healthy` without a successful check; `unknown` when never checked or when the last check is older than twice the check interval (`PATHOS_CONNECTOR_CHECK_INTERVAL`, default 1 h); `disabled` when the connection is off, not configured, or needs the internet in offline mode (`last_error_code` `PTH-CONN-1015`) |
| `last_error_code` | Catalogue code of the last failing or degraded check |
| `last_sync_at` | From the source: last inventory re-sync (SCM), ticket status refresh, webhook delivery, e-mail sent, runtime sync, successful feed run |
| `source` | `{table, id}` of the row behind the connector: an existing table (`scm_connections`, `ticket_connections`, `outbound_webhooks`, `runtime_clusters`, `registry_connections`, `ai_providers`, `smtp_settings`, `intel_feeds` with the feed name as id, `secret_validation_settings`, `installation_object_store`, `installation_egress_proxy`) or `connectors` for kinds stored in the registry. Singletons have `id` `""` |
| `can_manage` | The caller may run a check (and edit a registry kind) |

Rows are sorted by category, then name.

## Get a connector

`GET /api/v1/connectors/{id}` — read permission of the kind.

The list item plus:

```json
{
  "metadata": { "host": "https://api.github.com", "auth_method": "github_app", "api_version": "REST 2022-11-28" },
  "config": {},
  "credential": { "set": false },
  "last_check": {
    "id": "0193…",
    "status": "failing",
    "trigger": "user",
    "checked_at": "2026-11-20T10:00:00Z",
    "duration_ms": 412,
    "steps": [{ "check": "authentication", "status": "fail", "error_code": "PTH-CONN-1007", "detail": "scm: authentication failed (HTTP 401 from api.github.com)" }],
    "observed": { "api_version": "REST 2022-11-28" },
    "error": {
      "code": "connector_check_failing",
      "message": "scm: authentication failed (HTTP 401 from api.github.com)",
      "error_code": "PTH-CONN-1007",
      "title": "Provider rejected the credential",
      "cause": { "confirmed": true, "text": "The provider rejected the connection's credential (HTTP 401)." },
      "probable_causes": ["…"],
      "impact": "…",
      "actions": ["…"],
      "verify": ["…"],
      "docs_url": "/help/troubleshooting/conn#PTH-CONN-1007",
      "ai_help": true,
      "request_id": "…"
    }
  }
}
```

- `metadata` is the non-secret description of the connection: host (scheme and host only), authentication method name, API version, `allow_private`, and kind-specific facts (for example `webhook_verification` for GitLab, `token_type` for Jira, `trigger_auth` for Teams). `ca_bundle_set` (`yes`/`no`) says whether an SCM connection, registry connection, outbound webhook or ticket connection has a private CA bundle; the PEM and its certificates stay on the connection's own API. A check of a registry or ticket connection that fails on an untrusted certificate reports `PTH-CONN-1702`.
- `config` is the stored configuration of a kind stored in the registry (`{}` for existing kinds).
- `credential.set` says whether a credential is stored (registry kinds); the value is never returned.
- `last_check.error` is the full [error envelope](index.md#errors) of a failing or degraded check, `null` when the check passed. `steps[].status` is `pass`, `warn`, `fail` or `skipped`. Messages are redacted: URLs are reduced to scheme and host, e-mail addresses and token-shaped strings removed.

Errors: `404` (unknown id, another organization, or a kind the caller cannot read).

## Run a health check

`POST /api/v1/connectors/{id}/check[?trigger=verify]` — manage permission of the kind. No body.

Runs a **real** check now and records it (`trigger` `user`, or `verify` from the error panel's Verify button). Every check is read-only; webhooks, Slack, Teams and e-mail never send a message (see the [user guide](../user-guide/connectors.md#checking-a-connection) for what each check does).

- `checked_by: "api"`: `200` with the result.
- `checked_by: "jobs"`: the request is queued for the jobs service; the API waits up to 25 seconds for the result (`200`), otherwise answers `202` with `status: "pending"`. Poll `GET /checks`.

```json
{
  "status": "healthy",
  "connector": { "id": "0193…", "status": "healthy", "…": "…" },
  "result": { "id": "0193…", "status": "healthy", "trigger": "user", "checked_at": "…", "duration_ms": 120, "steps": [], "observed": {}, "error": null }
}
```

```json
{ "status": "pending", "connector": { "…": "…", "check_requested_at": "2026-11-20T10:00:00Z" }, "result": null, "requested_at": "2026-11-20T10:00:00Z" }
```

A connector whose check fails is a `200` with a failing result, not an HTTP error. Errors: `400` (catalogue-only kind), `403` (no manage permission), `404`.

The check is audited (`connector.check`).

## Check history

`GET /api/v1/connectors/{id}/checks?limit=50&cursor=` — read permission of the kind.

`{"items": [<result>], "next_cursor": "…"}`, newest first; `limit` 1–200 (default 50); pass `next_cursor` back as `cursor` for the next page (`""` when there is none). History is kept 30 days, and at least the last 200 checks of each connector.

## Kinds stored in the registry

Existing kinds keep their own create endpoints; these endpoints accept only kinds with `creatable: true`:

- `vault` (HashiCorp Vault / OpenBao) is stored in the registry; `PUT` and `DELETE` below apply.
- `generic_git` and `bitbucket_data_center` are created by the SCM service in `scm_connections` (exactly as `POST /api/v1/scm-connections` would, connection test included, `scm.manage` required) and then appear in the hub through that source: the `201` answer is the registry row with `source.table = "scm_connections"`. Config keys: `base_url`, `auth_method`, `username`, `project_key`, `ssh_known_hosts`, `ssh_host_key_fingerprint`, `ca_bundle_pem`, `credential_ref` (instead of `credential`); a non-empty `proxy_url` is refused (`400`). They are created enabled (`enabled: false` → `422`) and are edited and deleted on SCM connections (`PUT`/`DELETE` here answer `400`); the CA bundle is changed with `PATCH /api/v1/scm-connections/{id}` (`ca_bundle_pem`, `""` removes it).

### Create

`POST /api/v1/connectors` — manage permission of the kind.

```json
{ "kind": "<creatable kind>", "name": "Production", "config": { "…": "…" }, "credential": "…", "enabled": true }
```

`credential` is write-only: stored encrypted (secret kind `integration`), never returned, never logged, never sent to AI. `201` with the connector (as `GET`).

Errors: `400` (an existing kind: the response names the page that creates it; a planned kind), `403`, `409` (name already used), `422` `validation_failed` (`fields.name`, `fields.config`, `fields.credential`).

### Update

`PUT /api/v1/connectors/{id}` — manage permission. Body as for create (`kind` may be omitted). Omit `credential` to keep it; `""` removes an optional credential. A change resets the status to `unknown` until the next check. Errors: `400` for a connector of an existing kind (edit it on its page), `403`, `404`, `409`, `422`.

### Delete

`DELETE /api/v1/connectors/{id}` — manage permission. Deletes the connector, its credential and its history. `204`. Errors: `400` for an existing kind, `403`, `404`.

All three are audited (`connector.create`, `connector.update`, `connector.delete`).

## AI troubleshooting of a connector

Use [`POST /api/v1/diagnostics/troubleshoot`](diagnostics.md) with a subject; the server builds the context:

```json
{ "code": "PTH-CONN-1007", "subject": { "kind": "connector", "id": "0193…" } }
```

With a subject, client-supplied `context` and `message` are ignored. The server sends the connector's kind and category, its non-secret metadata (host without path or query, authentication method name, API version, `allow_private`, token type), the last check's status, error code, redacted message and steps, the PATHOS version and whether offline mode is on. It never sends the credential, a webhook URL (only its host), a request or response body, an e-mail address or source code. The caller needs read permission on the connector and the `connectors` flag (`404` otherwise; `422` for an unknown subject kind).

## Related changes to existing endpoints

| Endpoint | Change |
|---|---|
| `POST /api/webhooks/{github,gitlab,bitbucket,azure-devops}/{id}` | The body limit is 25 MB (was 5 MiB); larger deliveries answer `413` with `PTH-CONN-1106` |
| `POST /api/webhooks/gitlab/{id}` | With a signing token set, a valid `webhook-signature` (Standard Webhooks HMAC-SHA256 over `webhook-id.webhook-timestamp.body`, timestamp within 5 minutes) is required and `X-Gitlab-Token` alone is refused. Without one, `X-Gitlab-Token` is checked as before |
| `PUT /api/v1/scm-connections/{id}/webhook-signing-token` | New (`scm.manage`). Body `{"token": "whsec_…"}` (the token GitLab generated). `200 {"webhook_signed": true}`. `400` for a non-GitLab connection, `422` for a malformed token. Audited `scm_connection.set_webhook_signing_token` |
| `DELETE /api/v1/scm-connections/{id}/webhook-signing-token` | New (`scm.manage`). Back to the legacy token. `200 {"webhook_signed": false}`. Audited `scm_connection.remove_webhook_signing_token` |
| `GET /api/v1/scm-connections…` | Adds `webhook_signed` (boolean) |
| `POST`/`PUT /api/v1/ticket-connections…` (Jira) | `config.token_type` (`unscoped`, default, or `scoped`) and `config.cloud_id` (optional UUID; looked up from the site when empty). A scoped token uses basic authentication and is called through `https://api.atlassian.com/ex/jira/{cloudId}` |
| `POST`/`PUT /api/v1/notifications/webhooks…` (Teams) | `trigger_auth: {tenant_id, client_id, client_secret, audience}` (client secret write-only; omit to keep, `tenant_id: ""` to remove). Responses add `trigger_auth: {tenant_id, client_id, audience}` or `null`. Office 365 connector URLs (`webhook.office.com`) are refused with `400` `PTH-CONN-1310` |
| SCM read calls (listing, discovery, re-sync) | A rate-limited answer (`429`, or `403` with rate-limit headers) with `Retry-After` up to 60 s is waited for and retried at most twice; writes are never retried this way |
