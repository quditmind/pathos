---
title: Findings
section: api-reference
order: 20
version: "1.0"
updated: 2026-11-19
summary: List, filter and read findings; change status, assign and bulk triage; status history; risk acceptances, suppression rules and SLA policies.
---
# Findings

A finding is one security issue in a repository (or in one of its [scan targets](scan-targets.md)), de-duplicated across scans and scanners. Scans and [result imports](result-imports.md) create and update findings; people triage them through the endpoints below.

All endpoints are under `/api/v1`, need a browser session, and mutations need `X-CSRF-Token` (see [API reference overview](index.md)). Errors use the common `{"error": {"code", "message"}}` body. A finding outside the caller's scope returns `404`.

## Permissions

| Permission | Used for |
|---|---|
| `findings.read` | Reading findings, summaries, history, risk acceptances, suppression rules, SLA policies |
| `findings.triage` | Status changes, assignment, bulk changes, requesting a risk acceptance, proposing a suppression rule |
| `findings.accept_risk` | Approving, rejecting and revoking risk acceptances and suppression rules; closing a Critical finding as a false positive |
| `settings.manage` (organization-wide) | Changing SLA policies |

`findings.read` and `findings.triage` are checked on the finding's repository.

## The finding object

`GET /api/v1/findings` and `GET /api/v1/findings/{id}` return:

| Field | Description |
|---|---|
| `id`, `repository_id`, `repository_name`, `repository_key` | The finding and its repository |
| `application_id`, `application_name` | The repository's application (`null` without one) |
| `scan_target_id`, `scan_target_kind`, `scan_target_name` | The [scan target](scan-targets.md) the finding belongs to; `null` for the repository's source code |
| `category` | `secrets`, `sast`, `sca`, `iac`, `container`, `license`, `dast`, `malware`, `misconfiguration`, `binary`, `eol` ([end of life](supply-chain.md#end-of-life)), `supply-chain` ([required signatures](scan-targets.md#signature-verification)), `other` |
| `scanner_keys` | Every scanner that reported it |
| `rule_id`, `title`, `description` | As reported |
| `severity` | `critical`, `high`, `medium`, `low`, `info` (scanner severity) |
| `cwe`, `cve`, `cvss` | Classification |
| `cvss_version`, `cvss_vector` | As reported by the scanner, or filled from OSV ([OSV feed](risk-intelligence.md#osv-feed)) |
| `package_name`, `package_version`, `fixed_version` | Dependency findings |
| `file_path`, `start_line` | Location |
| `status` | Stored status: `open`, `in_progress`, `needs_review`, `false_positive`, `accepted_risk`, `fixed` |
| `lifecycle_status` | Unified status, derived (see below) |
| `first_seen_at`, `last_seen_at`, `resolved_at` | Timestamps |
| `recurrence_count` | Times it came back after being fixed |
| `assignee_id`, `assignee_name` | Assigned user |
| `sla_due_at` | Remediation deadline from the [SLA policy](#sla-policies) (or a stricter [security policy](governance.md#security-policies)) |
| `accepted_until` | End of an approved risk acceptance |
| `ai_status` | AI review state, for example `none`, `queued`, `pending_approval`, `reviewed`, `failed` ([AI finding reviews](ai-and-mcp.md#finding-reviews)) |
| `human_review_id`, `human_review_key`, `human_review_status`, `human_disposition`, `human_severity` | [Human Eye](human-reviews.md) review and its outcome. The scanner data is not changed by it |
| `risk_score` | Contextual risk 0–100, `null` until scored ([risk explanation](risk-intelligence.md#risk-explanation)) |
| `confidence` | `high`, `medium`, `low`, `unknown` |
| `epss`, `epss_percentile` | FIRST EPSS probability and percentile for the CVE |
| `kev`, `kev_due_date` | Listed in the CISA KEV catalog, with its due date |
| `exploit_available` | Known exploitation |
| `reachability`, `reachability_basis` | `reachable`, `not_reachable`, `unknown`, and why ([reachability](vulnerability-intelligence.md#reachability)) |
| `malicious` | The package itself is malware ([malicious packages](supply-chain.md#malicious-packages)) |
| `introduced_commit` | Commit of the scan that first detected it |
| `introduced_status`, `introduced_commit_sha`, `introduced_author`, `introduced_at` | The commit that introduced the code (git blame of the scanned commit; `sast`, `secrets` and `iac` findings with a file and line). `introduced_status`: `known`, `shallow_clone` (unknown: the repository is cloned without history), `not_found` (the line is not in the scanned commit) or `""` (not determined). Only the author's name is stored, never the e-mail address. Once known it does not change |
| `suppression_rule_id` | The [suppression rule](#suppression-rules) that decided the status |

`GET /api/v1/findings/{id}` adds `snippet` and `snippet_start_line` (code captured by the scanner, when available) and `occurrences[]` (the 50 latest sightings: `scan_job_id`, `scanner_key`, `commit_sha`, `file_path`, `start_line`, `seen_at`).

### Lifecycle status

`lifecycle_status` is derived; the stored `status` stays unchanged (history, SLA and AI policy depend on it). The first matching row wins:

| Lifecycle | Derived from |
|---|---|
| `resolved` | status `fixed` |
| `false_positive`, `accepted_risk` | the same status |
| `under_review` | status `needs_review`, or a Human Eye review is open |
| `confirmed` | a Human Eye reviewer confirmed the finding (still open) |
| `in_progress` | status `in_progress` |
| `reopened` | open again after a fix (recurrence) |
| `new` | first seen by the latest scan; not assigned, triaged or reviewed |
| `open` | any other open finding |

## List findings

`GET /api/v1/findings` — 100 per page. Permission: `findings.read` at any scope (only findings in the caller's scope are listed; archived repositories are excluded).

| Parameter | Description |
|---|---|
| `status` | `open` (default: `open`, `in_progress` and `needs_review`), `all`, or one stored status |
| `lifecycle` | Comma-separated lifecycle statuses. Spans every stored status unless `status` is also given |
| `severity` | Comma-separated severities |
| `category` | One category |
| `scanner` | Reported by this scanner key |
| `repository_id`, `application_id` | UUIDs |
| `assignee` | `me`, `none` or a user ID |
| `sla` | `breached` or `due_soon` (due within 7 days); open findings only |
| `kev` | `true` or `false` |
| `epss_min` | Minimum EPSS percentile (0–1) |
| `risk_min` | Minimum risk score (0–100) |
| `confidence` | `high`, `medium`, `low`, `unknown` |
| `reachability` | `reachable`, `not_reachable`, `unknown` |
| `scan_target_id` | Findings of one scan target |
| `target_kind` | `repository` (source code only), `image`, `url`, `api`, `sbom`, `artifact`, `endpoints` |
| `malicious` | `true`: malicious packages only |
| `human_review` | `none` (no review), `open` (review not completed) or a disposition (`confirmed`, `false_positive`, `duplicate`, `not_exploitable`, `accepted_risk`, `mitigated`, `out_of_scope`) |
| `control` | `<framework>:<control>`: findings mapped to a compliance control ([compliance](governance.md#compliance)) |
| `q` | Case-insensitive search in title, rule ID, file path, package name and CVE |
| `sort` | `severity` (default; then last seen) or `risk` (risk score; unscored last) |
| `cursor` | `next_cursor` of the previous page, passed back unchanged (keep `sort` unchanged) |

Response `200`: `{ "items": [finding…], "next_cursor": "…" }`; `next_cursor` is `null` on the last page. Invalid parameters return `400 invalid_request`.

```http
GET /api/v1/findings?severity=critical,high&kev=true&sort=risk HTTP/1.1
```

## Summary

`GET /api/v1/findings/summary` takes the same filters as the list (not `sort` or `cursor`) and returns the number of matching findings per severity:

```json
{ "critical": 3, "high": 17, "medium": 42, "low": 60, "info": 8 }
```

## Get a finding

`GET /api/v1/findings/{id}` — the finding with `snippet` and `occurrences`. Permission `findings.read` on its repository.

## Triage

### Change the status

`POST /api/v1/findings/{id}/status` — permission `findings.triage`.

```json
{ "status": "false_positive", "reason": "Test fixture, never deployed" }
```

| From | Allowed manual changes |
|---|---|
| `open`, `in_progress`, `needs_review` | Any other of these three, `false_positive` or `fixed` |
| `false_positive`, `fixed` | `open` |
| `accepted_risk` | None (use [risk acceptances](#risk-acceptances)) |

- `false_positive` and `fixed` need a `reason` of at least 5 characters.
- Closing a **Critical** finding as `false_positive` also needs `findings.accept_risk`.
- A manually fixed finding is verified by the next scan, which reopens it if it is still detected.

Response `204`. Errors: `400` (missing reason), `403`, `404`, `409 conflict` (change not allowed). Audited (`finding.status`).

### Assign

`POST /api/v1/findings/{id}/assign` — `{ "assignee_id": "<user-id>" }`, or `null` to unassign. The assignee must be an active user. Permission `findings.triage`. Response `204`. Audited (`finding.assign`).

### Bulk changes

`POST /api/v1/findings/bulk` — one change to 1–500 findings, all or nothing. Permission `findings.triage` on every finding.

```json
{ "finding_ids": ["0190c0de-0000-7000-8000-000000000001"], "action": "status", "status": "in_progress" }
```

| Field | Description |
|---|---|
| `finding_ids` | 1–500 IDs |
| `action` | `status` or `assign` |
| `status`, `reason` | For `status` (same rules as a single status change) |
| `assignee_id` | For `assign` (`null` unassigns) |

Response `200 { "updated": 12 }`. When one finding fails, nothing changes and the error message names that finding. Each finding is audited as in the single endpoints.

### Status history

`GET /api/v1/findings/{id}/history` — permission `findings.read`. Up to 500 entries, oldest first:

```json
{ "items": [ { "from_status": "open", "to_status": "false_positive", "actor": "Dana Owner", "source": "user", "reason": "Test fixture, never deployed", "created_at": "2026-11-17T09:00:00Z" } ] }
```

`source` tells what made the change: `user`, `scanner`, `ai`, `expiry`, `suppression_rule` or `system`. `from_status` is `null` for the first entry.

## Risk acceptances

Accepted risk is reached only through this approval workflow (or a [Human Eye decision](human-reviews.md#decisions)).

| Method | Path | Permission | Description |
|---|---|---|---|
| `POST` | `/api/v1/findings/{id}/risk-acceptance` | `findings.triage` | Request: `{ "justification", "expires_at" }` → `201 { "id", "status": "pending" }` |
| `GET` | `/api/v1/risk-acceptances?status=&finding_id=` | `findings.read` | Up to 200 acceptances in scope, newest first |
| `POST` | `/api/v1/risk-acceptances/{id}/{action}` | See below | `action` is `approve`, `reject`, `revoke` or `withdraw`; optional body `{ "note" }` → `204` |

Request rules: `justification` 10–4000 characters; `expires_at` more than one hour and at most 365 days in the future; only open findings (`open`, `in_progress`, `needs_review`). `409` when an acceptance is already pending or active for the finding.

| Action | Permission | Rules | Effect |
|---|---|---|---|
| `approve` | `findings.accept_risk` | Pending; not the requester; expiry not passed | Finding becomes `accepted_risk` with `accepted_until` |
| `reject` | `findings.accept_risk` | Pending | None |
| `revoke` | `findings.accept_risk` | Approved | Finding reopens |
| `withdraw` | `findings.triage` | Pending; the requester only | None |

Broken rules return `409 conflict`; an unknown action returns `404`. Acceptances opened by a Human Eye decision are approved or rejected by the review's independent reviewer, not here (`409`). When an approved acceptance expires, the jobs service reopens the finding.

Acceptance fields: `id`, `finding_id`, `finding_title`, `finding_severity`, `repository_name`, `requested_by`, `justification`, `expires_at`, `status` (`pending`, `approved`, `rejected`, `expired`, `revoked`, `withdrawn`), `decided_by`, `decided_at`, `decision_note`, `created_at`.

Audit actions: `risk_acceptance.request`, `risk_acceptance.<action>`, `risk_acceptance.expire`.

## Suppression rules

A suppression rule gives one decision (accepted risk or false positive) to every finding that matches a pattern, for example a rule ID in test code, a vendored path or a package an advisory does not affect. Findings are never hidden or deleted.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/suppression-rules?status=` | `findings.read` | Rules (repository rules only for readable repositories) |
| `POST` | `/api/v1/suppression-rules/preview` | `findings.triage` on the scope | Same body as create → `{ "matching_open_findings", "examples" }` (up to 20 examples) |
| `POST` | `/api/v1/suppression-rules` | `findings.triage` on the scope | Propose; returns the rule with `status: pending` |
| `POST` | `/api/v1/suppression-rules/{id}/{action}` | See below | `action` is `approve`, `reject`, `revoke` or `withdraw`; optional body `{ "note" }` (at most 2000 characters) → `{ "rule", "findings_changed" }` |

| Action | Permission | Rules | Effect |
|---|---|---|---|
| `approve` | `findings.accept_risk` on the scope | Pending; not the proposer; expiry not passed | Activates the rule and applies it to matching open findings |
| `reject` | `findings.accept_risk` | Pending | None |
| `revoke` | `findings.accept_risk` | Active | Reopens the findings it decided |
| `withdraw` | `findings.triage`; the proposer only | Pending | None |

The scope needs the permission at the matching level: organization and application rules need it organization-wide; repository rules need it on the repository. Broken rules return `409 conflict`.

Rule fields:

- `name` (at most 200 characters)
- `scope_type` (`organization`, `application` or `repository`) and `scope_id` (required for application and repository)
- match fields `match_rule_id` and `match_path` (globs with `*` and `?`), plus `match_package`, `match_cve`, `match_scanner` and `match_category` (each at most 300 characters). At least one of the first four is required; patterns that match everything are refused
- `decision` (`accepted_risk` or `false_positive`)
- `justification` (20–4000 characters)
- `expires_at` (future, at most one year)
- read-only: `scope_name`, `status` (`pending`, `active`, `rejected`, `revoked`, `expired`, `withdrawn`), `requested_by`, `requested_by_id`, `requested_at`, `decided_by`, `decided_at`, `decision_note`, `findings` (findings it currently decides)

Findings decided by a rule carry `suppression_rule_id`, and their status history has `source: suppression_rule` with the rule, the approver and the justification. Findings detected later that match an active rule get the same decision when their scan finishes. Rules expire in the jobs service, which reopens their findings.

Audit actions: `suppression_rule.request`, `suppression_rule.<action>`, `suppression_rule.expire`.

## SLA policies

Remediation deadlines per severity, in days: `sla_due_at` = first seen + the severity's days.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/sla-policies` | `findings.read` at any scope | `{ "critical": 7, "high": 30, "medium": 90, "low": 180, "info": null }` (`null` = no SLA) |
| `PUT` | `/api/v1/sla-policies` | `settings.manage` (organization-wide) | Same shape, any subset of severities; days 1–3650 or `null` → `204` |

The defaults are the values above. A change recomputes the deadline of every finding of the organization and re-applies [security policies](governance.md#security-policies) that tighten deadlines. Audited (`sla_policy.update`).

## Fix pull requests

PATHOS can open a pull (merge) request that upgrades a vulnerable dependency to its fixed version, on GitHub, GitLab, Bitbucket Cloud and Azure DevOps. It is opt-in per repository. A [worker](worker-protocol.md#fix-jobs) clones the scan branch and edits the manifest as text (no package manager, build tool, hook or repository code runs); the API then creates a branch under `pathos/fix/`, commits the edited files and opens the pull request with the repository connection's credential. PATHOS never writes to any other branch. The pull request's state is tracked, but the finding keeps its status: only a later scan of the branch that no longer detects the vulnerability marks it fixed.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/repositories/{id}/fix-pr-settings` | `scans.read` on the repository | `{ "enabled": false, "grouping": "package", "source_type": "scm", "provider": "github" }` |
| `PUT` | `/api/v1/repositories/{id}/fix-pr-settings` | `repos.manage` on the repository | Body `{ "enabled": true, "grouping": "package" \| "finding" }`. `400` for uploaded repositories. Audited (`repository.fix_prs`). |
| `GET` | `/api/v1/findings/{id}/fix-pr` | `findings.read` on the repository | Eligibility and the fix pull requests covering the finding (below) |
| `POST` | `/api/v1/findings/{id}/fix-pr` | `findings.triage` **and** `repos.manage` on the repository | Request a fix pull request → `202` with the fix PR object |
| `GET` | `/api/v1/repositories/{id}/fix-prs` | `findings.read` on the repository | `{ "items": [fix PR, …] }`, newest first (200 at most) |
| `POST` | `/api/v1/fix-prs/{id}/refresh` | `findings.triage` on the repository | Read the pull request's state from the SCM now → the fix PR object; `502` with the reason when the SCM call fails |

Requesting needs both permissions because a fix pull request changes how a finding is handled and writes to the repository. No new permission exists for it.

**Eligibility** (`GET …/fix-pr`): `{ eligible, reason, ecosystem, package_name, target_version, support: { supported, reason, edits }, enabled, grouping, can_request, requests[] }`. A finding is eligible when it is a dependency (`sca`) finding of the repository itself (not of a scan target), open / in progress / needs review, the repository has fix PRs enabled and an SCM connection, a fixed version is known, and its ecosystem is supported. `reason` explains, in plain words, why not. The ecosystem comes from the package URL in the repository's SBOM, or else from the file the scanner reported. `target_version` is the lowest fixed version above the current one on the same major line (else the lowest above it); releases are preferred over pre-releases.

| Ecosystem | What is edited | Not supported |
|---|---|---|
| PyPI | `requirements*.txt` / `constraints*.txt`: the package is pinned to `==<target>` (extras, markers and comments kept) | Files with `--hash` entries (hashes need pip-compile); Pipfile, Poetry and uv lockfiles |
| Maven / Gradle | `pom.xml` dependency or `dependencyManagement` version, literal or `${property}` (also a property in another `pom.xml` of the repository); Gradle `group:artifact:version` strings, map notation and `libs.versions.toml` (literal or `version.ref`) | Versions defined outside the repository (parent POM, BOM); projects whose `gradle.lockfile` pins the package |
| NuGet | `PackageReference` / `PackageVersion` / `packages.config` versions (attribute or child element) | Projects with `packages.lock.json` |
| npm | `package.json` dependency ranges, only when the project has **no** lockfile | Any `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` or `bun.lock`: the lockfile must be regenerated with npm, yarn or pnpm, which are not in the worker image, and PATHOS does not hand-edit lockfiles |
| Go, Cargo, Composer, Bundler | — | Not supported: `go.sum`, `Cargo.lock`, `composer.lock` and `Gemfile.lock` need the ecosystem's tool |

A transitive dependency (not declared in an editable manifest) ends as `not_supported` with an explanation.

**Request** (`POST …/fix-pr`): optional body `{ "target_version": "4.2.11", "grouping": "package" }`. `target_version` overrides the computed version (a plain version above the current one). `grouping` overrides the repository default: `package` covers every open finding of the same package version in the repository with one pull request; `finding` covers only this one. Errors: `422 fix_pr_not_available` (with the eligibility reason), `409 conflict` when a fix pull request covering one of the findings is queued, running, being created or open. Audited (`fix_pr.request`).

**The fix PR object**: `id`, `repository_id`, `repository_name`, `ecosystem`, `package_name`, `current_version`, `target_version`, `grouping`, `status`, `error`, `base_branch`, `branch`, `changed_files[]`, `pr_number`, `pr_url`, `finding_ids[]`, `requested_by` (e-mail), `created_at`, `updated_at`, `state_checked_at`.

| `status` | Meaning |
|---|---|
| `queued` | Waiting for a worker |
| `running` | A worker is editing the manifest (lease 10 minutes, at most 3 attempts) |
| `creating` | The API is creating the branch, commit and pull request |
| `open` | The pull request is open (`pr_url`, `pr_number`) |
| `merged`, `closed` | Recorded from the SCM (polled every 15 minutes by the jobs process, or `refresh`). The finding is **not** changed. |
| `failed` | `error` says why, for example that the credential lacks permission to create branches and pull requests (GitHub contents and pull requests write, GitLab Developer role with the `api` scope, Bitbucket `repository:write` and `pullrequest:write`, Azure DevOps Code read & write) |
| `not_supported` | The worker could not produce a correct edit; `error` explains (for example a lockfile that must be regenerated) |

State changes are audited: `fix_pr.request`, `fix_pr.opened`, `fix_pr.failed`, `fix_pr.not_supported`, `fix_pr.merged`, `fix_pr.closed`.

## Other finding endpoints

These endpoints belong to other features and are described on their pages:

| Method | Path | Described in |
|---|---|---|
| `GET` | `/api/v1/findings/{id}/risk` | [Risk explanation](risk-intelligence.md#risk-explanation) |
| `GET` | `/api/v1/findings/{id}/related` | [Related findings](vulnerability-intelligence.md#related-findings) |
| `GET` | `/api/v1/findings/{id}/dependency-paths` | [Posture](posture.md#endpoints) |
| `GET` | `/api/v1/findings/{id}/policies` | [Security policies](governance.md#security-policies) |
| `GET`, `POST` | `/api/v1/findings/{id}/tickets` | [Ticketing](integrations-reporting.md#ticketing-jira-servicenow) |
| `POST` | `/api/v1/findings/{id}/ai-review` | [AI finding reviews](ai-and-mcp.md#finding-reviews) |
| `GET` | `/api/v1/findings/{id}/ai-reviews` | [AI finding reviews](ai-and-mcp.md#finding-reviews) |
| `GET` | `/api/v1/scans/{id}/findings` | [Findings of an execution](scans.md#findings-of-an-execution) |
| `POST` | `/api/v1/human-reviews` | [Human Eye: add findings](human-reviews.md#add-findings) |
