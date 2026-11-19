---
title: Remediation and security gates
section: api-reference
order: 16
version: "3.0"
updated: 2026-11-20
summary: The remediation workspace API (items, fix verification with before-and-after evidence, saved views) and security gates at every stage (IDE, pre-commit, pull request, CI, release, deploy) with decisions, exceptions and approvals. Behind the remediation_workspace flag.
---

# Remediation and security gates

Quditmind PATHOS · applies to v3.0 (unreleased) · status: Prototype (feature flag `remediation_workspace`, off by default)

Every endpoint on this page answers `404 feature_disabled` (`PTH-PLAT-1007`) while the flag is off for the organization, like an unknown path. Every change is written to the audit log. Errors use the [standard envelope](index.md#errors) with the catalogue code in `error.error_code` ([troubleshooting: REM](../troubleshooting/rem.md), [GATE](../troubleshooting/gate.md)).

Permissions (new in 3.0, [RBAC matrix](../RBAC_MATRIX.md)): `remediation.read` (every role), `remediation.manage` (security manager, security analyst, AppSec engineer, application owner, developer), `gates.manage` (organization-only: super and platform administrators, security manager), `gates.approve_exception` (security manager, independent reviewer). Repository-scoped permissions apply to the item's, gate's or decision's repository.

**Rule 7: no gate blocks without a policy.** A gate always references a security policy; the database refuses a gate without one and refuses a `block` or `approval_required` decision without at least one policy id (`gate_decisions_block_needs_policy`). With no gate configured the decision is `pass`, with the reason `no_policy`.

## Remediation items

An item covers one finding or a group of findings of one repository.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/remediation/items` | `remediation.read` (rows in scope) | List. Query: `status` (comma list, or `active` = not closed or won't fix), `priority`, `owner_id`, `unassigned=true`, `repository_id`, `application_id`, `overdue=true`, `q` (title, root cause, finding title or file), `sort` (`due_at` default, `-due_at`, `priority`, `status`, `created_at`, `-created_at`), `limit` (1–200, default 50), `cursor`. Returns `{ items, next_cursor, total }` |
| `POST` | `/api/v1/remediation/items` | `remediation.manage` on each finding's repository | `{ finding_ids, mode: "per_finding" \| "group", title?, kind?, owner_id?, due_at?, priority?, root_cause? }` → `201 { items }`. Defaults: kind from the finding category (SCA → `dependency_upgrade`, IaC/container → `configuration`, else `code_fix`), priority from the highest severity, due date from the SLA engine (earliest `sla_due_at`, `due_source: sla`; `manual` when given). Only open findings; a group covers one repository |
| `GET` | `/api/v1/remediation/items/{id}` | `remediation.read` | Item with `findings`, `guidance`, `fix_prs`, `verifications`, `can_verify`, `verify_unavailable_reason` |
| `PATCH` | `/api/v1/remediation/items/{id}` | `remediation.manage` | `{ title?, status?, owner_id?, clear_owner?, due_at?, clear_due?, priority?, root_cause?, fix_pull_request_id? }`. `clear_due` returns the due date to the SLA engine |
| `POST` | `/api/v1/remediation/items/bulk` | `remediation.manage` on every item | `{ ids (1–200), owner_id? \| clear_owner?, due_at?, status?, priority? }` → `{ updated }`. All items are checked first; one invalid item fails the request |
| `POST` | `/api/v1/remediation/items/{id}/verify` | `remediation.manage` and `scans.run` | `{ scan_job_id? }` → `202` verification. See [Fix verification](#fix-verification) |
| `GET` | `/api/v1/remediation/items/{id}/verifications` | `remediation.read` | `{ items }`, newest first |

**Item** fields: `id, title, kind, status, priority, repository_id, repository_name, application_id, application_name, owner_id, owner_email, due_at, due_source (sla|manual|none), overdue, root_cause, finding_count, open_finding_count, top_severity, affected_files, fix_pull_request {id, status, pr_url, kind} | null, last_verification {id, status, result, created_at} | null, created_at, updated_at, closed_at`. The fix pull request is the one linked with `fix_pull_request_id`, else the latest non-failed [fix pull request](findings.md#fix-pull-requests) (dependency upgrade or verified AI fix) of one of its findings.

**Statuses.** `open`, `planned`, `in_progress`, `fix_submitted`, `verifying`, `closed`, `wont_fix`. People move between the first four and `wont_fix`, and reopen `closed` or `wont_fix`. **`closed` is set only by a verification that proved the fix** (a database CHECK requires the proving verification); `verifying` is set while a verification runs. Other changes answer `409 invalid_transition` (`PTH-REM-1101`).

**Guidance** entries `{ source, evidence, title, text, link? }` come from what PATHOS already holds, each with its evidence label: `verified_ai_fix` (`verified`: a worker proved the scanner no longer reports the finding on the patched file), `dependency_upgrade` (`scanner`: target version chosen from the advisory's fixed versions), `human_review` (`human`: the Human Eye reviewer's remediation), `ai_review` (`ai_inferred`: applied AI reviews only), `finding` (`scanner`: the advisory text). Nothing is generated by this endpoint.

Errors: `409 finding_already_tracked` (`PTH-REM-1103`) when a finding belongs to an active item; `400` for invalid fields or closed findings; `404` outside your scope.

## Fix verification

`POST /api/v1/remediation/items/{id}/verify`:

- **Targeted rescan** (no body): queues a verification (`status: queued`, item `verifying`). A worker that has the scanners of the item's open findings clones the repository at the commit where the findings were last reported (`before`) and at the head of the scan branch (`after`), runs each scanner on the affected files only and reports the results in those files ([worker protocol](worker-protocol.md#fix-verification-jobs-remediation)). PATHOS compares them per finding (rule and file; lines may move):
  - `fixed`: every finding reproduced before and gone after, and no new result in the affected files → the item **closes** (`closed_by_verification_id`);
  - `regressed`: the findings are gone but new results appeared in the affected files → `regressions` lists them; the item returns to `in_progress`;
  - `still_present`: a finding is still reported → `in_progress`;
  - `inconclusive`: a finding was not reproduced before (absence proves nothing) → `in_progress`.
- **With a finished scan** (`{ "scan_job_id": "…" }`): a succeeded scan of the scan branch (not a pull request scan) decides immediately: a finding is gone when that scan's results do not contain it while one of its scanners succeeded in that scan; findings that scan first reported in the affected files are regressions.

Findings are never changed by a verification (scans resolve them). Unavailable (`409 fix_not_verifiable`, `PTH-REM-1102`): imported-only findings, findings without a file or recorded commit, uploaded repositories or no SCM connection, no open finding (use a scan), a scan that did not succeed. `409 verification_running` (`PTH-REM-1104`) while one is queued or running. A failed rescan (`PTH-REM-1105`) records the redacted reason and changes nothing.

**Verification** fields: `id, item_id, status (queued|running|completed|failed), result (fixed|still_present|regressed|inconclusive|null), trigger (manual|fix_pr_merged|existing_scan), scanner_keys, scanner_versions, files, before {scan_job_id, commit, result_count}, after {scan_job_id, commit, ref, result_count}, findings [{finding_id, rule_id, file, scanner_key, status_before, status_after, reproduced, removed}], regressions [{rule_id, file, line, title}], fix_pull_request_id, failure_reason, requested_by_email, created_at, finished_at`. Finished verifications are immutable (database trigger).

**Fix merged → targeted rescan.** The jobs service checks every minute, in organizations with the flag on, for items whose fix pull request was merged after their last verification, and queues a targeted rescan (`trigger: fix_pr_merged`, `fix_pull_request_id`). An item that cannot be rescanned gets a `failed` verification with the reason, so it is not retried until the next merge.

## Saved views

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/remediation/views` | `remediation.read` | Your views and views shared in the organization: `{ items: [{ id, name, filters, shared, owner_email, mine, created_at }] }` |
| `POST` | `/api/v1/remediation/views` | `remediation.read` | `{ name, filters: { status?, owner_id?, unassigned?, priority?, repository_id?, application_id?, overdue?, q?, sort? }, shared }` → `201`. Filters are validated like the list query; `409` for a duplicate name |
| `DELETE` | `/api/v1/remediation/views/{id}` | owner only | `204`; `404` for someone else's view |

## Security gates

A gate is `{ stage, policy, mode }`: at the stage, when its enabled policy matches the evidence, the gate `block`s, `warn`s or `require_approval`s.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/gates?stage=` | `remediation.read` | `{ items }` (gates bound to a repository only when it is in your scope) |
| `POST` | `/api/v1/gates` | `gates.manage` | `{ name, stage, policy_id, mode, allow_exceptions? (true), application_id?, repository_id?, enabled? }` → `201`. `422 gate_policy_required` (`PTH-GATE-1101`) without an existing user-managed policy |
| `GET` | `/api/v1/gates/{id}` | `remediation.read` | Gate |
| `PUT` | `/api/v1/gates/{id}` | `gates.manage` | Same fields as create |
| `DELETE` | `/api/v1/gates/{id}` | `gates.manage` | `204` |

Stages: `ide`, `pre_commit`, `pull_request`, `ci`, `release`, `deploy` (hyphens accepted). Modes: `block`, `warn`, `require_approval`. **Gate** fields: `id, name, stage, mode, allow_exceptions, application_id, repository_id, repository_name, enabled, managed, policy {id, name, version, enabled}, created_at, updated_at`. **Managed** gates and policies are generated from a repository's [pull request settings](supply-chain.md#pull-request-checks) (decision C6); they change only there (`409 managed_gate` / `managed_policy`, `PTH-GATE-1105`). A policy used by gates cannot be deleted (`409 policy_in_use`, `PTH-GATE-1108`); disable it instead (its gates are then skipped).

### Evaluate

`POST /api/v1/gates/evaluate` — permission `scans.read` on the repository (or on every repository of the application). Session or API token (`api:read` is enough; the call records a decision).

```json
{ "stage": "deploy", "repository_id": "…", "commit_sha": "9f2c…", "pull_request": 0, "scan_id": null }
```

Give exactly one of `repository_id` or `application_id`. What the gates look at (`evidence.scope`):

| Call | Evidence |
|---|---|
| `stage: pull_request` with `pull_request` (and optionally `commit_sha` or `scan_id`) | The new findings of the latest finished pull request check (`409 gate_evidence_incomplete`, `PTH-GATE-1107`, when none) |
| `scan_id` (CI) | Findings that scan first reported (`new`); the scan must have succeeded or be partial (else `409`, `PTH-GATE-1107`) |
| otherwise (IDE, pre-commit, release, deploy, CI without a scan) | The repository's or application's open findings (`open`) |

Security policies with the **block** action also block `pull_request` and `ci` (with `scan_id`) decisions by themselves, as they always failed pull request checks and scan gates.

Response — the recorded **decision**:

```json
{
  "id": "0193…", "stage": "deploy", "outcome": "block",
  "repository_id": "…", "repository_name": "acme/payments", "application_id": "…", "scan_job_id": null,
  "commit_sha": "9f2c…", "pull_request": null,
  "gates": [{ "id": "…", "name": "No criticals in production", "mode": "block", "managed": false, "matched": true, "count": 2,
              "effect": "block", "policy": { "id": "…", "name": "Critical findings", "version": 3 } }],
  "policy_ids": ["…"], "policy_versions": [3],
  "reasons": [{ "code": "policy_matched", "message": "policy \"Critical findings\" matched 2 finding(s); gate \"No criticals in production\": block", "gate_id": "…", "policy_id": "…", "count": 2 }],
  "evidence": { "scope": "open", "total": 14, "by_severity": { "critical": 2, "high": 5, "medium": 7, "low": 0, "info": 0 }, "finding_ids": ["…"], "scan_job_id": null },
  "exceptions": [], "requested_by_email": "ci@acme.test", "created_at": "2026-11-20T10:00:00Z",
  "docs_url": "/help/user-guide/remediation#security-gates"
}
```

`outcome` is the strongest effect: `block` > `approval_required` > `warn` > `exception_applied` > `pass`. Reason codes: `no_policy` (nothing applies; pass), `policy_matched`, `policy_not_matched`, `policy_disabled` and `condition_unavailable` (gate skipped, for example a branch-only condition at the pull request stage), `security_policy_block`, `exception_applied`, `approval_granted`, `no_policy_downgraded` (the service-side rule 7 check). `finding_ids` is a sample of at most 20 matched rows (pull request finding ids for the pull request stage). Callers treat `block` and `approval_required` as failing; `pass`, `warn` and `exception_applied` as passing.

### Decisions

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/gates/decisions` | `remediation.read` (rows in scope) | `?stage=&outcome=&repository_id=&application_id=&limit=(1–200, 50)&cursor=` → `{ items, next_cursor }`, newest first |
| `GET` | `/api/v1/gates/decisions/{id}` | `remediation.read` | Decision with the exceptions requested on it |

Decisions are append-only (database trigger).

### Exceptions and approvals

| Method | Path | Permission | Description |
|---|---|---|---|
| `POST` | `/api/v1/gates/decisions/{id}/exceptions` | `remediation.manage` | `{ reason, expires_at (≤ 365 days), gate_id? (when several gates block), scope?: "decision" \| "repository" }` → `201`, `status: requested`. For a `require_approval` gate the record is an **approval** (`kind: approval`), otherwise an **exception**. `scope: decision` (default) covers the decision's pull request or commit; `repository` covers any evaluation of the repository until it expires. `409 gate_exceptions_not_allowed` (`PTH-GATE-1102`) when the gate does not allow exceptions or the decision has no blocking gate |
| `GET` | `/api/v1/gate-exceptions?status=` | `remediation.read` (rows in scope) | `{ items }`; `can_decide` tells the caller whether they may approve or reject |
| `POST` | `/api/v1/gate-exceptions/{id}/approve` | `gates.approve_exception` | `{ note }` → exception, `status: approved` |
| `POST` | `/api/v1/gate-exceptions/{id}/reject` | `gates.approve_exception` | `{ note }` |
| `POST` | `/api/v1/gate-exceptions/{id}/revoke` | `gates.approve_exception`, or the requester with `remediation.manage` | `{ note }`; a requested or approved exception |

**Four eyes.** The requester never approves or rejects their own request (`409 self_approval`, `PTH-GATE-1103`; also a database CHECK). Only `requested` exceptions are decided (`409 exception_not_pending`, `PTH-GATE-1104`). Exceptions expire at `expires_at` (shown as `expired`). An approved, unexpired exception whose scope covers a later evaluation turns that gate's effect into `exception_applied`; re-evaluate (or re-run the pipeline step) after approval. Exception fields: `id, gate_id, gate_name, decision_id, kind, repository_id, repository_name, application_id, scope, reason, status, requested_by_id, requested_by_email, decided_by_email, decision_note, expires_at, created_at, decided_at, can_decide`.

## Using gates from CI/CD

- **CLI:** `pathos gate --stage ci --repo acme/payments --scan "$SCAN_ID"`, `pathos gate --stage pre-commit --repo acme/payments --commit "$(git rev-parse HEAD)"` — exit 1 on `block` or `approval_required`, 0 otherwise ([user guide](../user-guide/remediation.md#security-gates)). Without `--stage`, `pathos gate --fail-on` keeps calling the [scan gate](scans.md#evaluate-the-security-gate): the threshold is the caller's own explicit policy.
- **Release and deploy:** call `POST /api/v1/gates/evaluate` from the pipeline or the CD tool with an API token (`api:read`). No PATHOS agent is installed in the cluster. Generic:

```sh
curl -fsS -X POST "$PATHOS_URL/api/v1/gates/evaluate" -H "Authorization: Bearer $PATHOS_TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"stage\":\"deploy\",\"repository_id\":\"$REPO_ID\",\"commit_sha\":\"$GIT_SHA\"}" \
  | jq -e '.outcome | IN("pass","warn","exception_applied")'
```

- **Argo CD:** a `PreSync` hook Job runs the same call; a failing Job stops the sync. See the [user guide](../user-guide/remediation.md#release-and-deploy-gates-argo-cd-and-generic-cd) for the manifest.
