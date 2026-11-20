---
title: AI providers, finding reviews and MCP
section: api-reference
order: 40
version: "1.0"
updated: 2026-11-19
summary: AI providers and versioned AI configurations, AI reviews of findings with their approval queue, the MCP server registry and the PATHOS MCP endpoint.
---
# AI providers, finding reviews and MCP

PATHOS can ask an AI model to triage findings. Administrators register **providers** (API credentials) and **configurations** (model, policy, limits). Reviews are queued, run in the background and, depending on the approval policy, change the finding's status directly or wait for a person to approve them.

Other AI features are described elsewhere: [AI suggestions in Human Eye reviews](human-reviews.md#ai-suggestions) and the [AI Security Analyst, AI reports and AI usage](ai-analyst.md).

All endpoints are under `/api/v1`, need a browser session, and mutations need `X-CSRF-Token` (see [API reference overview](index.md)).

## Permissions

| Permission | Used for |
|---|---|
| `ai.configure` (organization-wide) | Providers and configurations |
| `ai.review` | Requesting AI reviews; reading providers, configurations and the MCP registry; requesting MCP servers |
| `ai.review` and `findings.triage` | Approving and rejecting AI reviews (on the finding's repository) |
| `findings.read` | Reading AI reviews |
| `mcp.manage` (organization-wide) | Deciding on MCP servers, their tools, deleting them |
| `ai.fix` | Requesting AI-proposed code fixes (on the finding's repository) |
| `ai.fix`, `findings.triage` and `repos.manage` | Opening a pull request from a verified AI fix |

## Providers

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/ai/providers` | `ai.review` at any scope or `ai.configure` | `{ items }` |
| `POST` | `/api/v1/ai/providers` | `ai.configure` | Create, then test the credentials → `201` provider |
| `POST` | `/api/v1/ai/providers/{id}/test?model=` | `ai.configure` | Test the credentials again → `200` provider with the new `status` |
| `DELETE` | `/api/v1/ai/providers/{id}` | `ai.configure` | Archive and revoke the stored key → `204`. `409` while a configuration uses it |

Request body:

| Field | Description |
|---|---|
| `name` | 1–200 characters |
| `kind` | `anthropic`, `openai`, `xai` or `self_hosted` (an OpenAI-compatible server such as Ollama) |
| `api_key` | Required except for `self_hosted`; at most 1000 characters. Stored encrypted and never returned |
| `base_url` | Optional for hosted providers (must be `https://`). Required for `self_hosted`; plain `http` and private networks are allowed (for example `http://host.docker.internal:11434/v1`), loopback, link-local and metadata addresses are not |
| `test_model` | Optional model for the credential test |

Provider fields: `id`, `name`, `kind`, `base_url`, `status` (`ok` or `error` after a test), `status_message`, `default_model` (a default exists only for `anthropic`), `created_at`.

A failed test does not fail the request: the provider is saved with `status: error`. Audit actions: `ai_provider.create`, `ai_provider.delete`.

## Configurations

A configuration selects a provider and model and sets the review policy. Every save creates a new immutable version. The **default** configuration is used for all reviews; the first configuration created becomes the default.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/ai/configurations` | `ai.review` at any scope or `ai.configure` | `{ items: [{ id, name, is_default, current, used_today }] }`, default first |
| `POST` | `/api/v1/ai/configurations` | `ai.configure` | Create → `201 { "id" }` |
| `PUT` | `/api/v1/ai/configurations/{id}` | `ai.configure` | New version → `200 { "id" }`; `name` is optional |

`used_today` counts automated reviews of the configuration in the last 24 hours.

| Field | Default | Rules |
|---|---|---|
| `name` | — | Required on create |
| `is_default` | — | `true` makes this the default configuration |
| `provider_id` | — | Required; an existing provider (`400` otherwise) |
| `model` | Provider default | Required when the provider has no default; at most 200 characters |
| `effort` | `medium` | `low`, `medium`, `high` |
| `instructions` | `""` | Extra instructions for the model, at most 8000 characters |
| `auto_review` | `false` | Queue new findings for review when a scan finishes |
| `categories` | `["sast", "sca", "iac"]` | Categories reviewed automatically: `secrets`, `sast`, `sca`, `iac`, `container`, `license`, `other` |
| `min_severity` | `medium` | Lowest severity reviewed automatically |
| `approval_policy` | `always` | `always` (every review waits for approval), `false_positives` (only false-positive verdicts wait) or `never` |
| `allow_self_approval` | `false` | Lets the submitter of an interactive (MCP) review approve it (single-person installations) |
| `daily_limit` | `200` | 1–100000 automated reviews per 24 hours |
| `send_code_context` | `false` | Send the code snippet captured by the scanner |
| `redaction_patterns` | `[]` | Extra regular expressions redacted before sending |
| `change_note` | `""` | Stored with the version |

Audited (`ai_configuration.save`).

## Finding reviews

| Method | Path | Permission | Description |
|---|---|---|---|
| `POST` | `/api/v1/findings/{id}/ai-review` | `ai.review` on the finding's repository | Queue a review with the default configuration → `202 { "status": "queued" }`. `409` when no default configuration exists |
| `GET` | `/api/v1/findings/{id}/ai-reviews` | `findings.read` | The 20 latest reviews of the finding, plus its `ai_status` |
| `GET` | `/api/v1/ai/reviews?status=` | `findings.read` | Up to 200 reviews in scope, newest first. `status`: `pending_approval`, `applied`, `rejected`, `superseded` |
| `POST` | `/api/v1/ai/reviews/{id}/approve` | `ai.review` and `findings.triage` | Approve a pending review and apply its verdict → `204` |
| `POST` | `/api/v1/ai/reviews/{id}/reject` | `ai.review` and `findings.triage` | Reject a pending review → `204` |

Approve and reject take an optional `{ "note" }` (at most 2000 characters). Errors: `409` when the review is not pending, or when the person who submitted an interactive review approves it without `allow_self_approval`; `400` when approving a false-positive verdict on a Critical finding without a note.

Review fields: `id`, `finding_id`, `finding_title`, `finding_severity`, `finding_status`, `repository_name`, `source` (`automated` or `interactive_mcp`), `provider`, `model`, `verdict` (`true_positive`, `false_positive`, `needs_review`), `confidence` (0–1), `suggested_severity`, `rationale`, `remediation`, `evidence_cited`, `status`, `reviewed_by` (MCP submitter), `decided_by`, `decided_at`, `decision_note`, `transmitted_sha256` (hash of what was sent to the provider), `created_at`.

**What a verdict does.** `false_positive` sets the finding to `false_positive`, `needs_review` sets it to `needs_review`, `true_positive` leaves the status unchanged; only open findings (`open`, `needs_review`) change. Whether this happens at once or after approval follows the configuration's `approval_policy`, except that a **false-positive verdict always waits for a person's approval** whatever the policy (PATHOS 3.0 M7: no silent suppression; `never` still applies `needs_review` at once). A false-positive verdict on a **Critical** finding is proposed as `needs_review`. A new review supersedes a pending one for the same finding.

**Queue.** Reviews run in the background, one finding at a time, each with a 4-minute timeout. Provider rate limits are retried up to 5 times with growing delays; other errors set the finding's `ai_status` to `failed`.

Audit actions: `ai_review.request`, `ai_review.create`, `ai_review.approve`, `ai_review.reject`.

Every review has an AI evidence record (`evidence_record_id` on the review; approving or rejecting the review records the decision on it too): see [AI evidence, model per task and correlation](ai-evidence.md). With the `ai_intelligence` flag on, the configuration of a queued review is the triage task's ([model per task](ai-evidence.md#get-apiv1aitask-assignments)) instead of the default.

## AI-proposed fixes

A user with `ai.fix` asks the organization's **default AI configuration** for a code fix of a SAST, secrets or IaC finding. The provider returns a unified diff; PATHOS checks it, a worker verifies it, and only a **verified** fix can become a pull request, opened by a person. Nothing is merged automatically, and the finding is resolved only by a later scan. The user guide explains the flow: [AI-proposed fixes](../user-guide/findings.md#ai-proposed-fixes).

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/findings/{id}/ai-fixes` | `findings.read` | Whether a fix can be proposed (`available`, `reason`), the scanner that will verify it (`scanner`), the repository's `test_runner` and `fix_prs_enabled`, the caller's `can_request` and `can_open_pr`, and the 10 latest `proposals` (without test logs) |
| `POST` | `/api/v1/findings/{id}/ai-fixes` | `ai.fix` on the finding's repository | Request a fix → `202` with the proposal (`status: "generating"`). The provider call runs in the background; poll the proposal |
| `GET` | `/api/v1/ai-fixes/{id}` | `findings.read` | One proposal with its diff, steps, scanner evidence and test log |
| `GET` | `/api/v1/ai-fixes/{id}/reports/{before\|after}` | `findings.read` | The scanner's raw report on the original or the fixed files (download) |
| `POST` | `/api/v1/ai-fixes/{id}/pull-request` | `ai.fix`, `findings.triage` and `repos.manage` | Open a pull request from a verified fix → `202` with the [fix pull request](scans.md) (`kind: "ai_code"`, `status: "creating"`) |
| `GET` / `PUT` | `/api/v1/repositories/{id}/ai-fix-settings` | `scans.read` / `repos.manage` | `{ "test_runner": "" \| "go" \| "python" }`: the repository's tests run during verification only when a runner is chosen (off by default) |

**When a fix cannot be requested** (`available: false`, and `422 ai_fix_not_available` on `POST`), `reason` says why: the finding is not SAST, secrets or IaC; it comes from a scan target or an uploaded repository; it is not open; it has no file; it comes only from an imported report (the tool cannot be re-run); its last scan recorded no commit; **no AI provider and default configuration exist** (the feature is off until an administrator adds them); or the default configuration does not allow sending code (`send_code_context`).

**Other errors:** `409` when a fix for the finding is already being prepared or verified; `429 rate_limited` after 10 requests per user per hour or 200 per organization per day (counted over all proposals); `502 source_unavailable` when the file cannot be read at the scanned commit through the SCM connection. On `pull-request`: `422 not_verified`, `422 fix_pr_not_available` (fix pull requests not enabled for the repository, or the finding is not open), `409` when a pull request was already opened for the fix (a failed one can be retried).

**Proposal fields:** `id`, `finding_id`, `repository_id`, `status`, `failure_reason`, `scanner_key`, `rule_id`, `file_path`, `commit_sha` (the scanned commit), `base_commit` (the commit the fix was verified on), `test_runner`, `provider`, `model`, `transmitted_sha256` (hash of what was sent to the provider), `summary`, `diff`, `changed_files`, `steps`, `scan_evidence`, `test_log`, `has_reports`, `pull_request`, `requested_by`, `created_at`, `updated_at`, `finished_at`.

**Statuses:** `generating` (provider call) → `rejected` (the diff failed the checks below) or `queued` → `running` (worker: apply and re-scan) → `tests_queued` → `testing` (only with a test runner) → `verified` or `failed`. Proposals stuck in `generating` for 20 minutes fail; worker leases expire after 20 minutes, at most 3 attempts.

**Steps** (`key`, `label`, `status` `pending|running|passed|failed|skipped`, `detail`):

1. `policy`: the diff parses as a unified diff and changes the finding's file, optionally up to two other files in the same directory (at most 3 files, 20,000 bytes, 200 changed lines, 30 hunks). It may not create, delete, rename or change the mode of a file, contain a binary patch, or change a CI/CD definition, build script, dependency manifest or lockfile or repository control file (`.git/`, hooks, `.gitmodules`, CODEOWNERS) other than the finding's own file. Added lines may not contain the redaction marker `[REDACTED]`, and a whitespace-only change is refused.
2. `apply`: the worker clones the scanned commit, checks the diff again and applies it. Each hunk must match the file's text (lines containing `[REDACTED]` match any value there); symbolic links, binary files and files over 1 MiB are refused.
3. `scan`: the worker runs the scanner that reported the finding, with its profile configuration, on the changed files only, once with the original and once with the fixed content. The fix passes when the scanner reported the finding's rule in its file before, reports it fewer times after and not on the changed lines, and reports no new result (any rule) in the changed files. `scan_evidence` holds both result lists and the verdict; the raw reports are stored.
4. `tests` (only when the repository has a test runner): the worker-fuzz worker runs the tests without and with the fix in the sandbox runner (no network, its own UID, no worker credentials, CPU, memory and time limits). The tests must pass both times; tests that already fail without the fix fail the step. Without a sandbox runner the step is `skipped` ("tests not run: no sandbox") and the repository code is not run anywhere.

**Provider request:** the finding (rule, title, description, severity, CWE, file, lines) and the file's code (whole files up to 200 lines, otherwise 60 lines around the finding, at most 24,000 bytes), JSON-encoded inside a per-request nonce delimiter. All text passes the built-in and organization redaction patterns; for secrets findings the values on the finding's lines (and every other occurrence of those values) are replaced by `[REDACTED]` as well. The schema is `{ "summary", "diff" }`, unknown fields rejected; an empty diff fails with the model's explanation.

Audit actions: `ai_fix.request`, `ai_fix.proposed`, `ai_fix.rejected`, `ai_fix.verified`, `ai_fix.failed`, `ai_fix.rate_limited`, `ai_fix.pull_request` (target: the finding), `repository.ai_fix_tests`, and the `fix_pr.*` actions of the pull request.

## MCP server registry

The registry records which MCP servers may be used with PATHOS data and which of their tools are allowed. The built-in **PATHOS** server is seeded approved with its tools allowed; it can be disabled but not deleted. Other servers start as `pending`.

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/mcp-servers` | `ai.review` at any scope or `mcp.manage` | `{ items }`, built-in first |
| `POST` | `/api/v1/mcp-servers` | `ai.review` at any scope or `mcp.manage` | Request a server → `201 { "id", "status": "pending" }`. `409` when the name exists |
| `POST` | `/api/v1/mcp-servers/{id}/decision` | `mcp.manage` | `{ "status": "approved" \| "rejected" \| "disabled", "note" }` → `204` |
| `PUT` | `/api/v1/mcp-servers/{id}/tools` | `mcp.manage` | `{ "tools": [{ "tool", "access", "allowed" }] }` replaces the tool list → `204` |
| `DELETE` | `/api/v1/mcp-servers/{id}` | `mcp.manage` | `204`; `409` for the built-in server |

Request body for `POST`:

| Field | Description |
|---|---|
| `name` | 1–200 characters |
| `description` | At most 2000 characters |
| `transport` | `stdio` or `streamable_http` (endpoint must be an `https` URL without credentials) |
| `endpoint` | Command or URL, at most 1000 characters |
| `data_access` | `none` (default), `findings_redacted` or `findings_full` |
| `tools` | Up to 100 `{ "tool", "access": "read" \| "write" }`. Requested tools start disallowed |

Server fields: `id`, `name`, `description`, `transport`, `endpoint`, `status`, `data_access`, `built_in`, `requested_by`, `decided_by`, `decided_at`, `decision_note`, `tools[]` (`tool`, `access`, `allowed`), `created_at`.

Audit actions: `mcp_server.request`, `mcp_server.approved`, `mcp_server.rejected`, `mcp_server.disabled`, `mcp_server.set_tools`, `mcp_server.delete`.

## PATHOS MCP endpoint

`POST /mcp` is a JSON-RPC 2.0 (MCP streamable HTTP) endpoint for your own AI assistant. It is authenticated with a personal access token (`Authorization: Bearer <personal-access-token>`), not a session, and acts with the token owner's permissions. It returns `403` while the built-in PATHOS server is not `approved` in the registry, and offers only the tools allowed there:

| Tool | Access | Description |
|---|---|---|
| `list_pending_findings` | read | Open findings without an applied review, most severe first; filters `severity`, `category`, `repository`, `limit` (1–50, default 20) |
| `get_finding_evidence` | read | Redacted evidence for one finding (`finding_id`) |
| `submit_review` | write | Records a review (`finding_id`, `verdict`, `confidence`, `suggested_severity`, `rationale`, optional `remediation`, `evidence_cited`) with `source: interactive_mcp`. It follows the default configuration's approval policy; Critical findings are never closed without human approval |

Rate limits for `/mcp` are listed in the [API reference overview](index.md#rate-limits).
