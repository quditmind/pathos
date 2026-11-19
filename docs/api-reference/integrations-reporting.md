---
title: Ticketing and reports
section: api-reference
order: 7
version: "1.0"
updated: 2026-11-19
summary: Jira and ServiceNow ticketing connectors, the executive overview and custom reports.
---
# Ticketing and reports

All endpoints follow the [common conventions](index.md#authentication). API tokens are created under [Your account](administration.md#api-tokens); outbound webhooks (JSON, Slack, Teams) are in [Notifications](notifications.md#outbound-webhooks).


## Ticketing (Jira, ServiceNow)

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/ticket-connections` | `findings.triage` or `settings.manage` | Connections (triage users see id, kind, name only) |
| `POST` | `/api/v1/ticket-connections` | `settings.manage` (org-wide) | `{ kind: jira\|servicenow, name, base_url, auth_type: basic\|bearer, username, secret, config, allow_private? }` |
| `PUT` / `DELETE` | `/api/v1/ticket-connections/{id}` | `settings.manage` (org-wide) | Update (`secret` optional) / delete (links removed; tickets stay in the tracker) |
| `POST` | `/api/v1/ticket-connections/{id}/test` | `settings.manage` (org-wide) | Checks credentials (and the Jira project) → `{ ok, identity, error? }` |
| `GET` | `/api/v1/findings/{id}/tickets` | `findings.read` | Linked tickets with remote status |
| `POST` | `/api/v1/findings/{id}/tickets` | `findings.triage` | `{ connection_id }` → creates the ticket. `409` if the finding already has one in that connection |

Jira (`config`: `project_key`, `issue_type` default `Bug`, `labels`, `token_type`, `cloud_id`): Cloud with e-mail + API token (`basic`) or Data Center with a personal access token (`bearer`); REST API v2. A Jira Cloud API token **with scopes** needs `token_type: "scoped"` (basic authentication only): PATHOS then calls the Atlassian API gateway `https://api.atlassian.com/ex/jira/{cloudId}/rest/api/2/…` instead of the site URL, with `cloud_id` (a UUID) or, when it is empty, the cloud ID read from `https://<site>/_edge/tenant_info`; issue links still use the site URL. `token_type` defaults to `unscoped` (site URL), because scoped and unscoped tokens cannot be told apart. ServiceNow (`config`: `table` default `incident`, `assignment_group`, `caller_id`): user + password (`basic`) or an OAuth token (`bearer`); urgency and impact from the severity. The ticket contains the finding's title, severity, type, repository, location, package, vulnerability, CWE, risk, description and a link to PATHOS; secrets are redacted and code snippets are never sent. Statuses are refreshed every 10 minutes (each ticket at most every 15); a done ticket does not close the finding (a scan does).

## Executive overview

`GET /api/v1/executive?days=30|90|180|365` (default 90; `findings.read`; computed over the caller's scope, `scope` says "Organization" or "Repositories you can access"): `open_by_severity`, `open_actively_exploited`, `open_critical_risk`, `open_past_sla`, `new_in_period`, `fixed_in_period`, `mean_days_to_fix` by severity, `fixed_within_sla_percent`, `repositories`, `repositories_scanned_30_days`, weekly `trend` (`new`, `fixed`, `open_at_end`, excluding false positives and accepted risks), `top_applications` and `business_units` (open critical, high, total, KEV, max risk).

## Custom reports

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/reports` | `findings.read` | Own, shared and received reports, plus the available groupings and columns |
| `POST` | `/api/v1/reports` | `findings.read` (`findings.export` to schedule) | `{ name, description, definition: { filters, group_by, columns }, shared, schedule: daily\|weekly\|monthly\|null, recipients[] }` |
| `POST` | `/api/v1/reports/preview` | `findings.read` | Run a definition without saving (first 200 rows) |
| `GET` / `PUT` / `DELETE` | `/api/v1/reports/{id}` | owner or `settings.manage` to change | |
| `GET` | `/api/v1/reports/{id}/run?format=csv` | `findings.read` (`findings.export` for CSV) | Result as JSON or CSV (at most 5,000 rows; cells starting with `= + - @` are prefixed with `'`) |

`filters` are the Findings list query parameters (`status`, `severity`, `category`, `scanner`, `repository_id`, `application_id`, `assignee`, `sla`, `human_review`, `lifecycle`, `kev`, `risk_min`, `malicious`, `control`, `target_kind`, `q`). A report always runs **as the person who opens it**: sharing or scheduling never shows anyone findings outside their own scope. Scheduled reports send the `report.scheduled` notification (a link, no data) to the recipients.

Audit actions: `ticket_connection.create`, `ticket_connection.update`, `ticket_connection.delete`, `finding.ticket_create`, `report.create`, `report.update`, `report.delete` and `report.export` (CSV runs).
