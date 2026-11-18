---
title: Dashboard and global search
section: api-reference
order: 29
version: "1.0"
updated: 2026-11-19
summary: The security dashboard summary (KPIs and charts) and the global search used by the top bar.
---
# Dashboard and global search

Both endpoints are read-only and accept a browser session or an API token with `api:read`.

## Dashboard

`GET /api/v1/dashboard` — the KPI cards and chart panels of the security dashboard. Permission: `dashboard.read` at any scope (`403` otherwise).

| Query parameter | Description |
|---|---|
| `days` | Reporting period: `7`, `30` (default), `90` or `365`. Any other value → `400` |
| `region_id`, `country_id`, `business_unit_id` | Optional geography filters (UUIDs). An invalid UUID → `400` |

Response:

| Field | Description |
|---|---|
| `filters` | The filters applied (`days` and any geography filter) |
| `period_start`, `period_end` | The reporting window (UTC) |
| `groups` | KPI group names in display order |
| `kpis[]` | `key`, `label`, `group`, `description`, `unit`, `polarity` (whether higher is better), `drill` (UI link), `status`, `value`, `previous` (the value for the preceding period), `sparkline[]` (`date`, `value`), `org_wide` |
| `charts[]` | `key`, `title`, `kind`, `status`, `drill`, `series[]` (`name`, `points[]`) or `categories[]` (`label`, `value`) for bar and donut charts |

Each KPI and chart has a `status`:

- `ok` — `value`, series or categories are filled in.
- `restricted` — the caller lacks the permission behind it. Organization-only permissions need an organization-wide grant; others are filtered to the caller's scope.
- `not_yet_available` — reserved for figures that a later release adds.

`org_wide: true` marks a KPI that ignores the geography filters because it is not tied to a region, country or business unit, so the UI can label it.

## Global search

`GET /api/v1/search?q=` — the top-bar search across entity names. A query shorter than 2 characters returns `{"items": []}`; longer than 100 characters → `400`. Matching is case-insensitive and by substring; at most 5 results per type.

Each item has `type`, `id`, `title`, `subtitle` and `href` (the UI page to open). Which types a caller sees depends on their permissions:

| `type` | Searched by | Requires |
|---|---|---|
| `repository` | Full name or Repository ID; archived repositories are excluded | `repos.read`, filtered to the caller's scope |
| `application` | Name; only applications with a repository in the caller's scope (all applications for organization-wide `repos.read`) | `repos.read` |
| `user` | E-mail or display name | Organization-wide `users.read` |
| `business_unit`, `region`, `country` | Name (regions and countries also by code) | `org.read` at any scope |
