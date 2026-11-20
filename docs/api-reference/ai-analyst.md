---
title: AI Security Analyst, reports and usage
section: api-reference
order: 41
version: "1.0"
updated: 2026-11-19
summary: Conversations with the AI Security Analyst, AI-written reports over PATHOS-computed figures, and AI usage.
---
# AI Security Analyst, reports and usage

The analyst and the report narratives use the organization's default [AI configuration](ai-and-mcp.md#configurations). AI reviews of findings and the MCP registry are described in [AI providers, finding reviews and MCP](ai-and-mcp.md).

## Analyst

The analyst needs `ai.review` and `findings.read`. Conversations belong to their author; other users get `404`.

| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/ai/analyst/conversations` | Your conversations |
| `POST` | `/api/v1/ai/analyst/conversations` | `{ title? }` → `201` |
| `GET` | `/api/v1/ai/analyst/conversations/{id}` | With `messages` |
| `DELETE` | `/api/v1/ai/analyst/conversations/{id}` | `204` |
| `POST` | `/api/v1/ai/analyst/conversations/{id}/messages` | `{ question }` (3–2000 characters) → `{ messages }` |

Each answer message has:
- `content` (Markdown)
- `citations[]` (`id`, `title`, `severity`): only findings that were in the answer's context
- `follow_ups[]`
- `context_findings`, `context_sha256`
- `model`, `input_tokens`, `output_tokens`

Errors:
- `409 ai_not_configured`
- `429 rate_limited` (200 questions per user per day, or the provider's limit)
- `502 ai_failed` (no usable answer)

How the context is built:
- It is limited to the caller's `findings.read` scope.
- It contains overall figures, the riskiest applications, up to 25 findings and OSV records for identifiers in the question.
- Findings are those matching the question's keywords, or the riskiest ones.
- Questions about KEV, "actively exploited" or exploits receive exactly those findings.
- The context is redacted and fenced as untrusted data.

## Reports

| Method | Path | Permission | Description |
|---|---|---|---|
| `POST` | `/api/v1/ai/reports` | `findings.read` on the scope; `ai.review` for the narrative | `{ kind: technical \| executive, scope_type: organization \| application \| repository, scope_id?, narrative? (default true) }` → `201` |
| `GET` | `/api/v1/ai/reports` | `findings.read` | Your reports (all reports with organization-wide `findings.read`) |
| `GET` | `/api/v1/ai/reports/{id}` | the author or organization-wide `findings.read` | The report |
| `GET` | `/api/v1/ai/reports/{id}/markdown` | same | `text/markdown` download |

`facts` contains:
- `open_by_severity`, `open_actively_exploited`, `open_with_critical_risk`
- `new_last_30_days`, `fixed_last_90_days`, `mean_days_to_fix`, `fixed_within_sla_percent`
- `repositories`, `scan_coverage_percent`
- `riskiest_findings`, `riskiest_applications`
- `lifecycle` (technical reports, PATHOS 3.0 M9): sections `codegraph`, `threat_models`, `remediation`, `gates`, each `{ key, title, available, reason?, evidence_label, evidence, metrics }` for the report's scope. `evidence` states where the figures come from; `available: false` with a `reason` when the module's flag is off or the author lacks the permission (`threats.read`, `remediation.read`). The Markdown export has one section per entry.

`narrative` is `{ summary, key_risks[], recommendations[] }`, written from `facts` only. It is `null` with a `narrative_error` explanation when AI is unavailable or disabled for the request.

## Usage

`GET /api/v1/ai/usage?days=7|30|90` needs organization-wide `ai.configure`. It returns `by_feature`, `by_model`, `by_user` and `by_day`, each with `requests`, `input_tokens` and `output_tokens`.

The features are `finding_review`, `human_eye_suggestion`, `analyst` and `report`.
