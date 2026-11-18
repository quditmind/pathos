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

**What a verdict does.** `false_positive` sets the finding to `false_positive`, `needs_review` sets it to `needs_review`, `true_positive` leaves the status unchanged; only open findings (`open`, `needs_review`) change. Whether this happens at once or after approval follows the configuration's `approval_policy`. A false-positive verdict on a **Critical** finding always waits for approval and sets the finding to `needs_review` meanwhile. A new review supersedes a pending one for the same finding.

**Queue.** Reviews run in the background, one finding at a time, each with a 4-minute timeout. Provider rate limits are retried up to 5 times with growing delays; other errors set the finding's `ai_status` to `failed`.

Audit actions: `ai_review.request`, `ai_review.create`, `ai_review.approve`, `ai_review.reject`.

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
