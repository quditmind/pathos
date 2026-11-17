---
title: API tokens, webhooks, ticketing and reports
section: api-reference
order: 9.7
version: "1.0"
updated: 2026-11-18
summary: REST API tokens, outbound webhooks (signed JSON, Slack, Teams), Jira and ServiceNow connectors, the executive overview and custom reports.
---
# API tokens, webhooks, ticketing and reports

## REST API tokens

Create a personal token with `POST /api/v1/me/tokens` (`{ name, days (1–90), scopes }`) from a signed-in session. Scopes: `mcp` (MCP server), `api:read` (GET and HEAD on `/api/v1`), `api:write` (every method). The secret (`pathos_pat_…`) is returned once.

```
curl -H "Authorization: Bearer pathos_pat_…" https://pathos.example.com/api/v1/findings?severity=critical
```

- A token acts with its owner's **current** permissions and stops working when the owner is deactivated, the token is revoked or it expires.
- No CSRF token is needed (no cookies are involved). Read-only tokens get `403 token_read_only` for other methods.
- Tokens can never call `/api/v1/me/tokens`, `/api/auth/*` or the MFA endpoints (`403 token_not_allowed`).
- Audit entries made with a token carry `metadata.api_token_id`. `last_used_at` is updated on every use.

## Outbound webhooks

Permission: `notifications.manage` (organization-wide).

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/notifications/webhooks` | Endpoints (host only, never the URL), last status, failures in 24 h |
| `POST` | `/api/v1/notifications/webhooks` | `{ name, format: json\|slack\|teams, url, events[], min_severity?, allow_private?, sign? }` → `{ webhook, signing_secret? }` (secret shown once) |
| `PUT` | `/api/v1/notifications/webhooks/{id}` | Same fields; `url` optional (keeps the stored one) |
| `DELETE` | `/api/v1/notifications/webhooks/{id}` | Removes the endpoint and its stored secrets |
| `POST` | `/api/v1/notifications/webhooks/{id}/test` | Sends a sample message now → `{ ok, status, error? }` |
| `GET` | `/api/v1/notifications/webhooks/{id}/deliveries` | Last 100 deliveries |

**Events**: any notification event key (`GET /api/v1/notifications/events`). `min_severity` filters events that carry a severity. **URL**: `https` only, no credentials; loopback, link-local (cloud metadata) and CGNAT addresses are always refused, private networks only with `allow_private`; checked again after DNS resolution on every request; redirects to other hosts are not followed. URLs and signing secrets are stored encrypted.

**JSON format**: `POST` with `Content-Type: application/json` and headers `X-PATHOS-Event`, `X-PATHOS-Delivery` (unique id, use it to de-duplicate), `X-PATHOS-Timestamp` (Unix seconds) and, when signed, `X-PATHOS-Signature: sha256=<hex HMAC-SHA256 of "<timestamp>.<body>" with the signing secret>`. Body: `id`, `event`, `event_label`, `occurred_at`, `summary`, `organization`, `repository`, `severity`, `link`, `count`, `findings[]` (`id`, `title`, `severity`, `location`; at most 10), and `scan` or `policy` when relevant. **Slack**: an incoming-webhook message (`text`). **Teams**: a message with an Adaptive Card (works with Teams Workflows webhooks).

**Delivery**: queued with the event; a 2xx response succeeds. Network errors, `408`, `429` and `5xx` are retried after 1 min, 5 min, 30 min, 2 h and 6 h; other `4xx` fail at once.

## Ticketing (Jira, ServiceNow)

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/ticket-connections` | `findings.triage` or `settings.manage` | Connections (triage users see id, kind, name only) |
| `POST` | `/api/v1/ticket-connections` | `settings.manage` | `{ kind: jira\|servicenow, name, base_url, auth_type: basic\|bearer, username, secret, config, allow_private? }` |
| `PUT` / `DELETE` | `/api/v1/ticket-connections/{id}` | `settings.manage` | Update (`secret` optional) / delete (links removed; tickets stay in the tracker) |
| `POST` | `/api/v1/ticket-connections/{id}/test` | `settings.manage` | Checks credentials (and the Jira project) → `{ ok, identity, error? }` |
| `GET` | `/api/v1/findings/{id}/tickets` | `findings.read` | Linked tickets with remote status |
| `POST` | `/api/v1/findings/{id}/tickets` | `findings.triage` | `{ connection_id }` → creates the ticket. `409` if the finding already has one in that connection |

Jira (`config`: `project_key`, `issue_type` default `Bug`, `labels`): Cloud with e-mail + API token (`basic`) or Data Center with a personal access token (`bearer`); REST API v2. ServiceNow (`config`: `table` default `incident`, `assignment_group`, `caller_id`): user + password (`basic`) or an OAuth token (`bearer`); urgency and impact from the severity. The ticket contains the finding's title, severity, type, repository, location, package, vulnerability, CWE, risk, description and a link to PATHOS; secrets are redacted and code snippets are never sent. Statuses are refreshed every 10 minutes (each ticket at most every 15); a done ticket does not close the finding (a scan does).

## Executive overview

`GET /api/v1/executive?days=30|90|180|365` (`findings.read`; computed over the caller's scope): `open_by_severity`, `open_actively_exploited`, `open_critical_risk`, `open_past_sla`, `new_in_period`, `fixed_in_period`, `mean_days_to_fix` by severity, `fixed_within_sla_percent`, `repositories`, `repositories_scanned_30_days`, weekly `trend` (`new`, `fixed`, `open_at_end`, excluding false positives and accepted risks), `top_applications` and `business_units` (open critical, high, total, KEV, max risk).

## Custom reports

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/reports` | `findings.read` | Own, shared and received reports, plus the available groupings and columns |
| `POST` | `/api/v1/reports` | `findings.read` (`findings.export` to schedule) | `{ name, description, definition: { filters, group_by, columns }, shared, schedule: daily\|weekly\|monthly\|null, recipients[] }` |
| `POST` | `/api/v1/reports/preview` | `findings.read` | Run a definition without saving (first 200 rows) |
| `GET` / `PUT` / `DELETE` | `/api/v1/reports/{id}` | owner or `settings.manage` to change | |
| `GET` | `/api/v1/reports/{id}/run?format=csv` | `findings.read` (`findings.export` for CSV) | Result as JSON or CSV (at most 5,000 rows; cells starting with `= + - @` are prefixed with `'`) |

`filters` are the Findings list query parameters (`status`, `severity`, `category`, `scanner`, `repository_id`, `application_id`, `assignee`, `sla`, `human_review`, `lifecycle`, `kev`, `risk_min`, `malicious`, `control`, `target_kind`, `q`). A report always runs **as the person who opens it**: sharing or scheduling never shows anyone findings outside their own scope. Scheduled reports send the `report.scheduled` notification (a link, no data) to the recipients.
