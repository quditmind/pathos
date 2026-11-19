---
title: Material changes and developer insights
section: api-reference
order: 31
version: "1.0"
updated: 2026-11-19
summary: Security-material changes per scan and repository, the rule catalog, developer attribution settings, per-developer, per-team and trend views, and git author to user links.
---
# Material changes and developer insights

See the user guide [Material changes and developer insights](../user-guide/developer-insights.md) for the concepts. All endpoints accept a session or an API token; mutations need `X-CSRF-Token` with a session and the `api:write` scope with a token.

## Permissions

| Endpoints | Permission |
|---|---|
| Rule catalog | `scans.read` at any scope |
| Material changes of a scan or repository | `scans.read` on the repository (others get `404`) |
| Read attribution settings | `settings.manage`, `users.manage` or `insights.people` at organization scope |
| Change attribution settings | `settings.manage` at organization scope |
| Developers, teams, trend | `insights.people` at organization scope; `409 attribution_disabled` while attribution is off |
| Identity links | `users.manage` at organization scope; `409 attribution_disabled` while attribution is off |

## Material changes

### The change object

| Field | Type | Description |
|---|---|---|
| `id`, `scan_job_id` | UUID | The change and its scan execution |
| `category`, `category_label` | string | `auth`, `api_endpoint`, `dependency`, `crypto`, `iac_exposure`, `secrets_handling`, `cicd`, `sensitive_data` |
| `rule_id`, `rule_title`, `level` | string | The rule that matched and its level (`high`, `medium`, `low`) |
| `file_path`, `change_type` | string | File and how it changed (`added`, `modified`, `deleted`, `renamed`); empty for dependencies |
| `side` | string | `added` (new lines), `removed` (removed lines) or `file` (the file change itself matched) |
| `start_line`, `end_line` | integer or null | Line range on that side (new file for added lines, old file for removed lines) |
| `match_count` | integer | Matching lines merged into this range |
| `snippet` | string | The first matching line (or the dependency), redacted for secrets |
| `explanation` | string | Why the change is security-material |
| `detail` | string | Dependency name, version and type (dependency changes) |
| `author_name` | string | Author of the newest commit in the range that touched the file; only with attribution on and `insights.people` |
| `created_at` | timestamp | When it was recorded |
| `commit_sha`, `base_sha` | string | The compared commits |

### The comparison run

`run` / `runs[]` objects: `scan_job_id`, `repository_id`, `status` (`computed`, `baseline`, `unchanged`, `unavailable`), `reason`, `base_sha`, `head_sha`, `files_changed`, `truncated` (the diff exceeded 32 MB or 1,000 changes), `change_count`, `dependency_status` (`computed`, `baseline`, `none`), `commits_complete` (attribution saw the whole commit range), `created_at`.

### List the rules

`GET /api/v1/material-changes/rules` → `{ items: [{ id, category, category_label, title, explanation, level, applies }], categories: [{ key, label }] }`.

### Material changes of a scan

`GET /api/v1/scans/{id}/material-changes` → `{ run, items }`. `run` is `null` when no comparison was recorded (pull request checks, uploads, scan targets, older workers). Items are ordered by level, category and file.

### Material changes of a repository

`GET /api/v1/repositories/{id}/material-changes`

| Query parameter | Description |
|---|---|
| `category` | One category (`400` for unknown values) |
| `days` | 1–3650, default 90 |
| `limit` | 1–1000, default 200 |

→ `{ items, truncated, runs }`: the newest changes first; `truncated` is true when more than `limit` exist; `runs` are the 20 most recent comparison runs.

## Developer attribution

### Settings

`GET /api/v1/insights/settings` → `{ attribution_enabled, updated_at, can_manage, can_view_people, can_link_identities }` (off by default).

`PUT /api/v1/insights/settings` with `{ "attribution_enabled": true|false }` → the settings. Turning attribution **off deletes** all finding attributions, stored commits, identity links and the authors on material changes of the organization. Audited as `insights.settings.update` (with the number of erased rows).

### Developers

`GET /api/v1/insights/developers?days=90` (`days` 7–730) → `{ days, items }`. Each item: `author_name`, `user` (`{ id, name }` or `null` when not linked), `introduced`, `introduced_critical_high`, `still_open` (introduced and still open), `fixed`, `mean_time_to_fix_hours` (first detection to fix, for the findings this author fixed; `null` without fixes), `repositories`.

### Teams

`GET /api/v1/insights/teams?days=90` → `{ days, items }`: `id` (`null` for the synthetic rows "Linked users without a team" and "Not linked to a user"), `name`, `developers`, `introduced`, `introduced_critical_high`, `still_open`, `fixed`, `mean_time_to_fix_hours` (weighted by fixes). A developer in several teams counts in each.

### Trend

`GET /api/v1/insights/trend?days=180&author=<name>` → `{ days, author, items: [{ week, introduced, fixed }] }`, one item per week (Monday, `YYYY-MM-DD`). Without `author`, everyone.

### Identity links

`GET /api/v1/insights/identities` → `{ items: [{ id, author_name, user_id, user_name, created_at }], unlinked_authors: [string] }` (up to 1,000 author names seen in scans that are not linked).

`POST /api/v1/insights/identities` with `{ "author_name": "Ada Lovelace", "user_id": "<uuid>" }` → `201 { id }`. Names are unique per organization, case-insensitively (`409 conflict`); an unknown user is `400`. Audited as `insights.identity.link`.

`DELETE /api/v1/insights/identities/{id}` → `204`. Audited as `insights.identity.unlink`.

## Related

- Notification event `change.material`: [Notifications](notifications.md#notification-events)
- Policy condition `material_change_categories`: [Security policies](governance.md)
- Worker upload `POST /internal/worker/v1/jobs/{id}/changes`: [Worker protocol](worker-protocol.md#material-changes)
