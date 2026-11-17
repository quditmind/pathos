---
title: Human reviews
section: api-reference
order: 9
version: "1.0"
updated: 2026-11-17
summary: Review queue, assessment workspace, decisions, independent review, evidence, AI suggestions, reports and configuration of the Human Review module.
---
# Human reviews

A human review is a manual assessment of one finding. Each review references an existing finding (`finding_id` is unique) and has a permanent key (`review_key`, e.g. `QD-HR-000042`). Wherever a path takes `{id}`, either the review ID or the finding ID is accepted.

Review status, final disposition and remediation status are separate fields:

| Field | Values |
|---|---|
| `status` | `pending`, `assigned`, `in_progress`, `awaiting_information`, `awaiting_independent_review`, `completed`, `reopened` |
| `disposition` | `confirmed`, `false_positive`, `duplicate`, `not_exploitable`, `accepted_risk`, `mitigated`, `needs_more_information`, `out_of_scope` |
| `remediation_status` | `not_required`, `open`, `in_progress`, `fixed`, `pending_verification`, `verified`, `reopened` |
| `priority` | `p1` (most urgent) … `p4` |

Permissions: `reviews.read` (read; read-only users see completed reviews only), `reviews.assess`, `reviews.assign`, `reviews.approve` (all scoped to repositories), `reviews.configure` (organization). Reviews outside the caller's scope return `404`.

## Queue

### List reviews

`GET /api/v1/human-reviews`

| Parameter | Description |
|---|---|
| `q` | Search: review key, finding ID, title, rule, repository name or key, file path, CVE |
| `status` | Comma-separated statuses; `open` = not completed; `all` = every status |
| `disposition`, `remediation_status`, `severity` (assessed, else scanner), `priority`, `scanner`, `category` | Comma-separated values |
| `repository_id`, `application_id` | Comma-separated UUIDs |
| `reviewer`, `independent_reviewer` | `me`, `none` or a user ID |
| `overdue` | `true` / `false` |
| `source` | `automatic` / `manual` |
| `branch` | Exact branch |
| `from`, `to` | Creation date range (`YYYY-MM-DD` or RFC 3339) |
| `sort` | `review_key`, `title`, `severity`, `scanner`, `repository`, `application`, `branch`, `file_path`, `detected_at`, `reviewer`, `priority`, `status`, `due_at`, `created_at`, `updated_at`, `completed_at` |
| `order` | `asc` (default) or `desc` |
| `page`, `page_size` | Offset pagination (page size 1–200, default 25) |

Response: `{ "items": [Review], "total": 42, "page": 1, "page_size": 25 }`.

### Add findings

`POST /api/v1/human-reviews` (`reviews.assign` on each finding's repository)

```json
{ "finding_ids": ["…"], "reason": "Pentest scope", "priority": "p2", "due_at": "2026-12-01T17:00:00Z", "reviewer_id": "…" }
```

Returns `201 { "created": [review IDs], "existing": [review IDs] }`. Findings that already have a review are not duplicated.

### Bulk changes

`POST /api/v1/human-reviews/bulk` — `{ "review_ids": [...], "action": "assign" | "priority" | "due_date", "reviewer_id", "priority", "due_at", "note" }`. Up to 500 reviews, all or nothing.

### Run ingestion now

`POST /api/v1/human-review/sync` (`reviews.assign` or `reviews.configure`) → `{ "created": 3 }`.

## A review

| Method | Path | Permission | Purpose |
|---|---|---|---|
| `GET` | `/api/v1/human-reviews/{id}` | read | Workspace payload: finding data, original scanner output, assessment, decisions with approvals, AI review and triage state, capabilities (`can`) |
| `PATCH` | `/api/v1/human-reviews/{id}` | assign | `{ "priority", "due_at" }` |
| `POST` | `/api/v1/human-reviews/{id}/assign` | assign | `{ "reviewer_id", "independent_reviewer_id", "due_at", "priority", "note" }`. Reviewers need `reviews.assess`, independent reviewers `reviews.approve` on the repository; they must be different people |
| `POST` | `/api/v1/human-reviews/{id}/start` | assess | Self-assign (if allowed) and move to `in_progress` |
| `POST` | `/api/v1/human-reviews/{id}/status` | assess | `{ "status": "in_progress" \| "awaiting_information", "note" }` |
| `PUT` | `/api/v1/human-reviews/{id}/assessment` | assess | Merge changed keys of `answers`, `fields`, `reproduction`, `risk`, `remediation`, `dataflow_notes`; optional `ai_recommendation_id` when an AI suggestion was used |
| `PUT` | `/api/v1/human-reviews/{id}/severity` | assess | `{ "severity", "cvss_vector", "cvss_score", "justification" }`. Justification required (≥ 10 characters). CVSS 3.x scores are computed from the vector; 4.0 vectors are validated |
| `POST` | `/api/v1/human-reviews/{id}/decision` | assess | See below |
| `POST` | `/api/v1/human-reviews/{id}/independent-review` | approve | `{ "outcome": "approved" \| "rejected" \| "information_requested", "comments" }` |
| `POST` | `/api/v1/human-reviews/{id}/reopen` | assign or approve | `{ "reason" }` (≥ 10 characters) |
| `PUT` | `/api/v1/human-reviews/{id}/remediation` | assess or `findings.triage` | `{ "status", "owner_id", "due_at", "priority", "link", "note" }` for completed Confirmed reviews; `verified` requires that scans no longer detect the finding |
| `GET` | `/api/v1/human-reviews/{id}/history` | read | Immutable activity history |
| `GET`, `POST` | `/api/v1/human-reviews/{id}/comments` | read / assess, assign or approve | `{ "body" }` |

Assessment keys are listed by `GET /api/v1/human-review/catalog` (questions, fields with allowed options, reproduction, risk and remediation fields, evidence types). Answers are `yes`, `no`, `unknown`, `not_applicable`.

### Decisions

```json
{
  "disposition": "accepted_risk",
  "reason": "Internal tool, decommissioned in Q1; WAF rule PAY-12 blocks the payload.",
  "risk_owner_id": "…", "risk_expires_at": "2027-03-31T17:00:00Z"
}
```

Other fields: `duplicate_of` (finding ID) or `duplicate_reference_unavailable: true`; `remediation_owner_id`, `remediation_due_at`, `remediation_priority` for `confirmed`. Validation failures return `422 validation_failed` with per-field messages in `error.fields` (`reason`, `duplicate_of`, `risk_owner_id`, `risk_expires_at`, `evidence`, `assessment`).

Outcome: completed (`status: completed`), sent to an independent reviewer (`awaiting_independent_review`; always for accepted risk, which opens a pending risk acceptance), or kept open (`needs_more_information` → `awaiting_information`). An independent reviewer cannot approve their own decision; approving accepted risk requires `findings.accept_risk`. Risk acceptances linked to a review cannot be approved or rejected from `/api/v1/risk-acceptances` (`409`).

## Source code and data flow

`GET /api/v1/human-reviews/{id}/source?path=&commit=` (also requires `findings.read`) returns the file at the scanned commit (default) or another commit SHA for comparison:

```json
{ "available": true, "origin": "scm", "commit_sha": "…", "branch": "main", "path": "app/db.py", "language": "python",
  "lines": ["…"], "focus_line": 42, "scanned": true, "truncated": false, "redacted": false }
```

When unavailable: `available: false`, `unavailable_code` (`not_configured`, `no_commit`, `no_snapshot`, `not_found`, `credential_rejected`, `forbidden`, `too_large`, `binary`, `rate_limited`, `provider_unreachable`, `connection_unavailable`, …) and `unavailable_message`, plus `scanner_context` when the scanner captured code.

`GET /api/v1/human-reviews/{id}/source/commits?path=` lists the scanned commit, commits where scans detected the finding, the branch head and the file history.

`GET /api/v1/human-reviews/{id}/dataflow` returns `status` (`confirmed`, `incomplete`, `inferred`, `unavailable`), `reason`, `paths` (nodes with `role`: `source`, `intermediate`, `sink`), `related` locations and the reviewer's `notes`.

## Evidence

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/human-reviews/{id}/evidence` | `{ items, uploads_enabled, allowed_extensions }` |
| `POST` | `/api/v1/human-reviews/{id}/evidence` | `multipart/form-data`: `evidence_type`, `classification` (`internal`, `confidential`, `restricted`), `description`, `comments`, and either `file` or `text` |
| `GET` | `/api/v1/human-reviews/{id}/evidence/{eid}/content` | Download (attachment; `?inline=1` previews images). Sandboxed |
| `DELETE` | `/api/v1/human-reviews/{id}/evidence/{eid}?reason=` | Removes the content; the record stays |

Files are checked by extension and content; size limit per configuration (`413 too_large`).

## AI suggestions

`POST /api/v1/human-reviews/{id}/ai` — `{ "kind": "explanation" | "code_summary" | "code_paths" | "investigation_questions" | "false_positive_indicators" | "evidence_suggestions" | "remediation" | "secure_code" | "references" | "assessment_summary" }` → `201` with `content { summary, points, references, code }`, model and the SHA-256 of what was transmitted. `GET` lists previous suggestions. Errors: `409 ai_disabled` / `ai_not_configured`, `429 rate_limited` (200 per user per day), `502 ai_failed`. Suggestions never change the review.

## Reports and configuration

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/human-review/overview` | Metrics, distributions (severity, status, disposition, scanner), workload, daily trend, confirmed findings awaiting remediation. Accepts the list filters |
| `GET` | `/api/v1/human-review/workload` | Open, pending, in-progress, completed and overdue reviews per analyst |
| `GET` | `/api/v1/human-review/reviewers?repository_id=` | Users who can assess or approve (for pickers) |
| `GET` | `/api/v1/human-review/reports` | Reviews completed between `from` and `to` (default 30 days), by severity, scanner, repository, disposition and analyst; severity adjustments; independent review results |
| `GET` | `/api/v1/human-review/reports/export` | CSV (`findings.export`), up to 50,000 rows |
| `GET`, `PUT` | `/api/v1/human-review/settings` | Configuration (`PUT` needs `reviews.configure`): automatic queue triggers, scanners, categories and minimum severity; priority and review SLA per severity; assignment strategy and pool; self-assignment; independent review severities and dispositions; required evidence and fields; notifications; AI assistance; evidence size |
