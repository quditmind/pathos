---
title: Notifications and outbound webhooks
section: api-reference
order: 52
version: "1.0"
updated: 2026-11-19
summary: Notification events, SMTP settings, notification rules, email templates, delivery history and outbound webhooks (signed JSON, Slack, Teams).
---

# Notifications and outbound webhooks

PATHOS turns platform events (new findings, failed scans, SLA breaches, …) into email and in-app notifications according to **notification rules**, and can also post them to **outbound webhooks**. Emails and webhook calls are sent by the background jobs process, so the API only queues them.

Every endpoint on this page needs `notifications.manage` at organization scope (`403` otherwise). A user reads their own in-app notifications with [`GET /api/v1/me/notifications`](administration.md#in-app-notifications). All endpoints follow the [common conventions](index.md#authentication).

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/notifications/events` | [Notification events](#notification-events) |
| `GET` | `/api/v1/notifications/smtp` | [Get SMTP settings](#smtp-settings) |
| `PUT` | `/api/v1/notifications/smtp` | [Update SMTP settings](#smtp-settings) |
| `POST` | `/api/v1/notifications/smtp/test` | [Send a test email](#smtp-settings) |
| `GET` | `/api/v1/notifications/rules` | [List rules](#notification-rules) |
| `POST` | `/api/v1/notifications/rules` | [Create a rule](#notification-rules) |
| `PUT` | `/api/v1/notifications/rules/{id}` | [Update a rule](#notification-rules) |
| `DELETE` | `/api/v1/notifications/rules/{id}` | [Delete a rule](#notification-rules) |
| `GET` | `/api/v1/notifications/templates` | [List templates](#email-templates) |
| `PUT` | `/api/v1/notifications/templates/{event}` | [Customize a template](#email-templates) |
| `DELETE` | `/api/v1/notifications/templates/{event}` | [Reset a template to the default](#email-templates) |
| `POST` | `/api/v1/notifications/templates/{event}/preview` | [Preview a template](#email-templates) |
| `GET` | `/api/v1/notifications/deliveries` | [Delivery history](#delivery-history) |
| `GET` | `/api/v1/notifications/deliveries/{id}` | [One delivery with its body](#delivery-history) |
| `POST` | `/api/v1/notifications/deliveries/{id}/retry` | [Retry a failed email](#delivery-history) |
| `GET` | `/api/v1/notifications/webhooks` | [List outbound webhooks](#outbound-webhooks) |
| `POST` | `/api/v1/notifications/webhooks` | [Create an outbound webhook](#outbound-webhooks) |
| `PUT` | `/api/v1/notifications/webhooks/{id}` | [Update an outbound webhook](#outbound-webhooks) |
| `DELETE` | `/api/v1/notifications/webhooks/{id}` | [Delete an outbound webhook](#outbound-webhooks) |
| `POST` | `/api/v1/notifications/webhooks/{id}/test` | [Send a test message](#outbound-webhooks) |
| `GET` | `/api/v1/notifications/webhooks/{id}/deliveries` | [Webhook deliveries](#outbound-webhooks) |

## Notification events

`GET /api/v1/notifications/events` returns `{ items, dynamic }`. Each item has `key`, `label`, `description`, `severity` (the event carries a severity, so rules may filter on it), `repository` (the event belongs to a repository, so rules may be scoped), `dynamic` (dynamic recipients that apply), `default_subject` and `default_body`. `dynamic` maps dynamic recipient keys to labels.

| Event | Severity | Repository | Dynamic recipients |
|---|:-:|:-:|---|
| `findings.new` | yes | yes | `owners` |
| `change.material` | yes | yes | `owners` |
| `scan.failed` | | yes | `owners` |
| `finding.sla_breached` | yes | yes | `assignee`, `owners` |
| `policy.violated` | yes | yes | `assignee`, `owners` |
| `report.scheduled` | | | `report_recipients` |
| `finding.assigned` | yes | yes | `assignee` |
| `risk.requested` | yes | yes | `approvers`, `owners` |
| `risk.decided` | yes | yes | `requester`, `assignee` |
| `schedule.missed` | | | |
| `repository.sync_failed` | | yes | `owners` |
| `import.failed` | | | `requester` |
| `schedule.completed` | | | `requester` |
| `schedule.failed` | | | `requester` |
| `worker.offline` | | | |
| `review.assigned` | yes | yes | `assignee` |
| `review.independent_requested` | yes | yes | `independent_reviewers` |
| `review.independent_decided` | yes | yes | `requester`, `assignee` |
| `review.overdue` | yes | yes | see the `events` response |
| `secret.pushed` | yes | yes | `owners` |
| `gate.failed` | yes | yes | `requester`, `owners` (PATHOS 3.0 M9: a gate blocked or required approval under a policy; needs `continuous_monitoring`) |
| `architecture.drift` | yes | yes | `owners` (PATHOS 3.0 M9: only when drift alerts are on in [monitoring settings](monitoring.md#settings)) |

Dynamic recipients: `assignee` (the finding's or review's assignee), `requester` (who asked for it), `approvers` (users who may accept risk for the repository, except the requester), `owners` (the application owner and security owner of the repository's application, plus the repository's business, technical and application owners), `independent_reviewers` (the named independent reviewer, otherwise users with `reviews.approve` for the repository, except the requester) and `report_recipients`. Only active users receive notifications.

## SMTP settings

`GET /api/v1/notifications/smtp`:

```json
{
  "enabled": true,
  "host": "smtp.example.com",
  "port": 587,
  "tls_mode": "starttls",
  "username": "pathos",
  "has_password": true,
  "from_address": "pathos@example.com",
  "from_name": "PATHOS",
  "updated_at": "2026-11-19T10:00:00Z"
}
```

The password is never returned. Before anything is saved, the response shows the defaults (port 587, `starttls`, from name `PATHOS`). On first start, PATHOS copies the `PATHOS_SMTP_*` environment variables (the ones Keycloak uses) into these settings; after that, only the API changes them.

`PUT /api/v1/notifications/smtp` replaces the settings and returns them:

| Field | Description |
|---|---|
| `enabled` | Send emails. When `false` and `host` is empty, nothing else is validated. |
| `host` | Host name or IP of the relay. Private addresses are allowed; loopback, link-local and cloud metadata addresses are refused. |
| `port` | 1–65535. |
| `tls_mode` | `starttls` (fails if the server does not offer STARTTLS), `tls` (implicit TLS) or `none`. |
| `username` | Optional. Authentication requires `starttls` or `tls`. |
| `password` | Omit to keep the stored password, `""` to delete it, or a new value. Stored encrypted. |
| `from_address` | Required when enabled; one valid address. |
| `from_name` | Default `PATHOS`, at most 100 characters. |

Audited as `notifications.smtp_update` (without the password; `password_changed` tells whether it changed).

`POST /api/v1/notifications/smtp/test` with an optional body `{ "to": "ops@example.com" }` (default: the caller's email) queues a test email and returns `202` with `{ id, to }`. Follow its outcome in the [delivery history](#delivery-history). Audited as `notifications.smtp_test`.

## Notification rules

A rule says which event notifies whom, on which channels. PATHOS seeds built-in rules (for example *New critical findings*, *Scan failures*, *Assigned to me*); they can be edited and disabled but not deleted, and their event cannot change.

Rule object:

```json
{
  "id": "0190c0de-7777-7000-8000-000000000101",
  "name": "New critical findings",
  "enabled": true,
  "event_key": "findings.new",
  "min_severity": "critical",
  "scope_type": "organization",
  "scope_id": null,
  "scope_name": "Organization",
  "recipients": { "roles": ["security_manager"], "users": [], "emails": [], "dynamic": ["owners"] },
  "email": true,
  "in_app": true,
  "system": true,
  "updated_at": "2026-11-19T10:00:00Z"
}
```

`GET /api/v1/notifications/rules` returns `{ items }`, built-in rules first. `POST /api/v1/notifications/rules` creates a rule (`201`), `PUT /api/v1/notifications/rules/{id}` replaces it (`200`) and `DELETE /api/v1/notifications/rules/{id}` removes it (`204`).

| Field | Description |
|---|---|
| `name` | Required, at most 120 characters. |
| `enabled` | Default `true`. |
| `event_key` | One of the [events](#notification-events). |
| `min_severity` | `critical`, `high`, `medium`, `low` or `info`; only for events that carry a severity. Empty or `null` means all. |
| `scope_type`, `scope_id` | `organization` (default; `scope_id` ignored), or `region`, `business_unit`, `repository` with an ID. Narrower scopes only for repository events. |
| `recipients.roles` | Role keys (at most 20). Active users holding the role at a scope that covers the event's repository; for events without a repository, only organization-wide holders. |
| `recipients.users` | User IDs (at most 100). |
| `recipients.emails` | External addresses (at most 50); need the email channel. |
| `recipients.dynamic` | Dynamic recipients that apply to the event. |
| `email`, `in_app` | Channels; at least one. |

At least one recipient is required. Errors are `400` with a message (unknown event, role or user, a dynamic recipient that does not apply, …). `409` when changing the event of a built-in rule or deleting one. Audited as `notifications.rule_create`, `notifications.rule_update` and `notifications.rule_delete`.

## Email templates

`GET /api/v1/notifications/templates` returns every event (and the SMTP test email `smtp.test`) with `event_key`, `label`, the current `subject` and `body`, `default_subject`, `default_body` and `customized`.

`PUT /api/v1/notifications/templates/{event}` with `{ subject, body }` stores an organization-specific template (`204`). Subject (at most 300 characters) and body (at most 20,000) are required. Templates use Go `text/template` syntax with the event data, for example `{{.Repository}}`, `{{.Count}}`, `{{range .Findings}}…{{end}}` and `{{.Link}}`; the default templates show the fields of each event. A template is test-rendered with sample data when saved, so a broken template is refused with `400`. Emails are plain text. Audited as `notifications.template_update`.

`DELETE /api/v1/notifications/templates/{event}` restores the default (`204`, audited as `notifications.template_reset`).

`POST /api/v1/notifications/templates/{event}/preview` with `{ subject, body }` renders them with sample data and returns `{ subject, body }` without saving.

An unknown `{event}` returns `404` for `PUT` and preview.

## Delivery history

`GET /api/v1/notifications/deliveries` lists email and in-app notifications, newest first, 100 per page.

| Parameter | Description |
|---|---|
| `status` | `pending`, `sent`, `failed` or `suppressed`. |
| `channel` | `email` or `in_app`. |
| `event_key` | An event key. |
| `q` | Substring of the subject or recipient address. |
| `before` | `next_cursor` of the previous page (an RFC 3339 timestamp). |

```json
{
  "items": [
    {
      "id": "0190c0de-7777-7000-8000-000000000001",
      "event_key": "scan.failed",
      "channel": "email",
      "recipient": "sam.security@example.com",
      "subject": "[PATHOS] Scan failed: payments/api",
      "link": "https://pathos.example.com/scans/0190c0de-…",
      "status": "failed",
      "attempts": 5,
      "last_error": "dial tcp: connection refused",
      "rule_name": "Scan failures",
      "sent_at": null,
      "read_at": null,
      "created_at": "2026-11-19T10:00:00Z"
    }
  ],
  "next_cursor": "",
  "email_last_7_days": { "sent": 120, "pending": 0, "failed": 1, "suppressed": 0 }
}
```

`next_cursor` is `""` on the last page. `GET /api/v1/notifications/deliveries/{id}` returns one delivery including its `body`.

Email delivery: a failed attempt is retried after 1 minute, 5 minutes, 30 minutes and 2 hours; after 5 attempts the email is `failed`. When SMTP is disabled, emails are `suppressed`. `POST /api/v1/notifications/deliveries/{id}/retry` queues a `failed` or `suppressed` email again (`204`; `409` for other emails). Audited as `notifications.retry`.

## Outbound webhooks

Outbound webhooks post events to chat tools and other systems. (Webhooks that source providers send *to* PATHOS are described in [Webhook receivers](integrations.md#webhook-receivers).)

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/notifications/webhooks` | Endpoints: `id`, `name`, `format`, `host` (never the full URL), `signed`, `events`, `min_severity`, `allow_private`, `enabled`, `created_at`, `last_status`, `last_delivery_at`, `failed_24h` |
| `POST` | `/api/v1/notifications/webhooks` | `{ name, format: json\|slack\|teams, url, events[], min_severity?, allow_private?, enabled?, sign?, trigger_auth? }` → `201` with `{ webhook, signing_secret? }` (the secret is shown once) |
| `PUT` | `/api/v1/notifications/webhooks/{id}` | Same fields; `url` is optional (the stored one is kept) |
| `DELETE` | `/api/v1/notifications/webhooks/{id}` | Removes the endpoint and its stored secrets → `204` |
| `POST` | `/api/v1/notifications/webhooks/{id}/test` | Sends a sample message now → `{ ok, status, error? }` |
| `GET` | `/api/v1/notifications/webhooks/{id}/deliveries` | The last 100 deliveries: `id`, `event_key`, `status`, `attempts`, `response_status`, `error`, `created_at`, `delivered_at`, `next_attempt_at` |

**Fields**: `name` is required (at most 120 characters, unique; `409` for a duplicate). `events` are [event keys](#notification-events) (at least one). `min_severity` filters events that carry a severity. `sign` creates a signing secret (JSON format only). Creating a webhook needs the secrets store (`409 secrets_unavailable` if it is not configured).

**Teams trigger authentication** (`trigger_auth`, Teams format only): `{ tenant_id, client_id, client_secret, audience? }` for a Workflows trigger whose *Who can trigger the flow* is *Any user in my tenant* or *Specific users in my tenant*. PATHOS obtains a token from Microsoft Entra with the client credentials grant (`POST https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`, scope `<audience>/.default`) and sends `Authorization: Bearer <token>` with each message. `audience` is the flow service of the cloud, matched exactly: `https://service.flow.microsoft.com/` (default, public cloud), `https://gov.service.flow.microsoft.us/` (GCC), `https://high.service.flow.microsoft.us/` (GCC High), `https://service.flow.appsplatform.us/` (DoD) or `https://service.powerautomate.cn/` (China). For *Specific users*, add the app's service principal object ID to the trigger. The client secret is write-only (encrypted, kind `integration`); responses return `trigger_auth: { tenant_id, client_id, audience }` or `null`. On update, omit `trigger_auth` to keep it, send a new `client_secret` to replace it, or `{"tenant_id": ""}` to remove it. Microsoft documents no signature or shared-secret header for this trigger; sources: [Teams connector, *When a Teams webhook request is received*](https://learn.microsoft.com/en-us/connectors/teams/) and [OAuth authentication for HTTP request triggers](https://learn.microsoft.com/en-us/power-automate/oauth-authentication) (checked 2026-11-20). Office 365 connector URLs (`*.webhook.office.com`, retired in May 2026) are refused with `400` (`PTH-CONN-1310`).

**URL**: `https` only, no credentials. Loopback, link-local (cloud metadata) and CGNAT addresses are always refused, private networks only with `allow_private`. The address is checked again after DNS resolution on every request, and redirects to other hosts are not followed. URLs and signing secrets are stored encrypted.

**JSON format**: `POST` with `Content-Type: application/json` and the headers `X-PATHOS-Event`, `X-PATHOS-Delivery` (unique ID; use it to de-duplicate), `X-PATHOS-Timestamp` (Unix seconds) and, when signed, `X-PATHOS-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>" with the signing secret>`. Body: `id`, `event`, `event_label`, `occurred_at`, `summary`, `organization`, `repository`, `severity`, `link`, `count`, `findings[]` (`id`, `title`, `severity`, `location`; at most 10), and `scan` or `policy` when relevant. `scan` is `{ id, trigger, new, fixed, gate_failed }`; for push and merge scans it adds `changes`: `{ base_commit, head_commit, new: {severity: n}, fixed: {severity: n}, new_total, fixed_total }` (the [change summary](scans.md#the-execution-object)). The default *New findings* e-mail shows the same summary; custom templates can use `{{with .Scan.Changes}}…{{.BaseShort}} {{.HeadShort}} {{.NewTotal}} {{.NewText}} {{.FixedTotal}} {{.FixedText}}…{{end}}`. **Slack**: an incoming-webhook message (`text`). **Teams**: a message with an Adaptive Card (works with Teams Workflows webhooks).

**Delivery**: queued with the event; a `2xx` response succeeds. Network errors, `408`, `429` and `5xx` are retried after 1 minute, 5 minutes, 30 minutes, 2 hours and 6 hours; other `4xx` responses fail at once.

Audited as `webhook.create`, `webhook.update`, `webhook.delete` and `webhook.test`.
