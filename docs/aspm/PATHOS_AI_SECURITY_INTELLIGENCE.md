Quditmind PATHOS · applies to v2.2.0 · status: Prototype

# PATHOS AI security intelligence

## Purpose

Milestone M7 makes every AI decision PATHOS stores **reproducible from its record** (the M7 "done when", build prompt §6). It adds the AI evidence record of [ADR-008](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-008-ai-evidence-record-and-reproducibility) to every AI call path, a model per task with a local (self-hosted) default for the tasks that carry code, a deterministic cross-phase correlation of findings with an optional AI explanation, and AI threat suggestions on M5 threat-model drafts, all under one rule: an AI conclusion is labelled `ai_inferred` and only proposes; a person decides. The user view is in the [user guide](../user-guide/ai-security-intelligence.md) and the endpoints in the [API reference](../api-reference/ai-evidence.md).

## Scope

In scope:

- AI evidence records (`ai_evidence_records`) for every model call: AI review (automated and on request), Human Eye assistance, analyst answers, report narratives, AI-proposed fixes, troubleshooting, threat suggestions, correlation explanations and replays; and a record (without prompt) for an AI review a person submits through MCP.
- The redacted prompt and response, envelope-encrypted (`ai_evidence_payloads`), kept 180 days by default (assessment §8.6), configurable per organization, deleted by the jobs service; records deleted with their finding.
- Reproduce (replay) with a comparison, and an explicit statement of whether the provider can be deterministic.
- Model per task (`ai_task_assignments`) and the local default for code-bearing tasks; code never sent where the configuration does not allow it.
- Correlation (`GET /api/v1/findings/{id}/correlation`) and its AI explanation.
- AI threat suggestions (`POST /api/v1/threat-models/{id}/suggest`), the M5 reserved path.
- No silent suppression: an AI false-positive verdict always waits for a person, whatever the approval policy.
- The evidence log page, the evidence panels in the finding drawer and threat detail, the model-per-task and retention settings.

Out of scope: AI-inferred CodeGraph edges (`graph_inference` is a reserved task; M4 has no AI path); the local model file digest (`model_digest` is empty: Ollama's digest needs its native API, which the OpenAI-compatible client does not call); asynchronous replay (replays run synchronously, see Known limitations).

## Architecture

```
 AI review worker · Human Eye assist · analyst · reports · AI fixes · troubleshooting · threat suggest · correlation explain · replay
                                         │  (each builds its redacted, fenced prompt)
                                         ▼
          Service.resolve(task) ──▶ task assignment │ local default (code-bearing) │ default      (internal/ai/tasks.go)
                                         ▼
          Service.invoke ── code allowed? ──no──▶ record status=disabled (PTH-AI-1101), no call
                 │ yes
                 ▼
          Provider.Review (temperature 0 + seed for local models) ──▶ interpreter[template] (schema validation)
                 ▼
          ai_evidence_records (+ ai_evidence_payloads, encrypted)   ◀── written for succeeded, invalid_output and failed calls
                 ▼
          caller stores its result with evidence_record_id (ai_reviews, human_review_recommendations, ai_messages, ai_reports,
          ai_fix_proposals, threats.ai_evidence_id) and applies nothing that suppresses a finding without a person
```

`Provider.Review` is called in exactly one place, `Service.invoke` (`internal/ai/evidence.go`); a unit test (`TestEveryModelCallWritesAnEvidenceRecord`) parses the backend and fails when a model call appears elsewhere or when a new call path has no record-completeness case in the integration test.

## Components

| Component | File | Role |
|---|---|---|
| Evidence writer | `backend/internal/ai/evidence.go` | `invoke`, `writeRecord`, tasks, subjects, interpreters per prompt template, determinism |
| Model per task | `backend/internal/ai/tasks.go` | `taskConfig` resolution, assignments and retention API, `Retain` |
| Evidence API | `backend/internal/ai/evidence_api.go` | list, read (with prompt and response), review, replay and comparison |
| Threat suggestions | `backend/internal/ai/suggest.go`, `backend/internal/threatmodel/suggest.go` | prompt, validation, per-suggestion records; endpoint, insertion, review hook, scope check |
| Correlation | `backend/internal/correlation`, `backend/internal/ai/correlation.go` | deterministic join; AI explanation |
| Callers | `internal/ai/service.go` (review, MCP), `assist.go`, `fix.go`, `troubleshoot.go`, `generate.go`; `internal/analyst`, `internal/review/aiassist.go`, `internal/scans/aifixes.go`, `internal/diagnostics` | pass the subject (`ai.WithSubject`) and store `evidence_record_id` |
| Retention job | `backend/cmd/pathos/main.go` (`runJobs`) | `ai.Retain` every maintenance tick |
| Web | `frontend/src/features/ai` | evidence log page, evidence panel, settings sections |

### Tasks and the local default

| Task | Operations | Code-bearing | Review on creation |
|---|---|---|---|
| `finding_validation` | `ai_review`, `interactive_mcp`, `assist:<kind>` | yes | `pending` (reviews), `not_required` (assistance) |
| `fix_proposal` | `fix_proposal` | yes | `pending` |
| `troubleshooting` | `troubleshoot` | yes | `not_required` |
| `threat_suggestion` | `threat_suggestion` (call), `threat_suggestion_item` | yes | `not_required` (call), `pending` (items) |
| `correlation` | `correlation_explain` | yes | `pending` |
| `analyst` | `analyst_answer` | no | `not_required` |
| `report` | `report_narrative` | no | `not_required` |
| `graph_inference` | reserved | yes | — |

With the `ai_intelligence` flag on, a task uses its assignment; without one, a code-bearing task uses a self-hosted configuration (the default one first) when one exists, and every other task the organization default. With the flag off, resolution is exactly as before M7 (the default configuration; troubleshooting prefers a self-hosted one), so turning the module off changes no model choice.

**Code to the cloud.** "Code-bearing" decides the routing. What is actually sent is governed by the configuration's existing *Send code context* setting (`ai_configuration_versions.send_code_context`), reused as the administrator's permission: callers leave source code out when it is off (review, assistance), and `invoke` refuses a call that contains code (`SentCode`) under a configuration that does not allow it, records the refusal (`status = disabled`, `PTH-AI-1101`) and never calls the provider (fix proposals). The record says whether code was sent (`sent_code`).

## Data flow

1. A caller sets the subject (`ai.WithSubject`: kind, id, finding, related references, requester) and calls its AI function.
2. The function resolves the task's configuration, builds the prompt (redaction with built-in and organization patterns, untrusted evidence fenced with a random nonce) and calls `invoke` with the template key (`finding_validation@1`, `assist@1`, `fix_proposal@1`, `troubleshooting@1`, `generate@1`, `threat_suggestion@1`, `correlation@1`).
3. `invoke` checks the code permission, calls the provider (temperature 0 and seed 0 for local models), validates the answer with the template's interpreter (steps, conclusion, verdict, confidence) and writes the record and its encrypted payload in one transaction. A failed or invalid answer is recorded too (`failed`, `invalid_output`, with its `PTH-AI` code).
4. The caller stores its own result with `evidence_record_id`. AI review decisions follow `Decide`: a false positive always needs approval.
5. A person reviews the conclusion (`POST /ai/evidence/{id}/review`): for a pending AI review this is the AI review approval; for a threat suggestion the threat-model hook keeps or removes the threat; otherwise only the record changes.
6. Reproduce decrypts the payload, re-sends system, user, schema, effort and output limit to the same configuration version, interprets the answer with the same template and writes a `replay` record with the comparison.
7. The jobs service purges payloads past retention; a finding's deletion cascades to its records.

## Dependencies

The AI providers and configurations of PATHOS 2.x (`ai_providers`, `ai_configurations`, `ai_configuration_versions`); the secrets store master key (`internal/platform/crypto`, the same keyring as credentials) for payload encryption; CodeGraph (M4) and threat models (M5) for correlation and suggestions; the feature-flag framework (M1).

## APIs

See the [API reference](../api-reference/ai-evidence.md): `GET /api/v1/ai/evidence`, `GET /api/v1/ai/evidence/{id}`, `POST /api/v1/ai/evidence/{id}/review`, `POST /api/v1/ai/evidence/{id}/replay`, `GET`/`PUT /api/v1/ai/task-assignments`, `PUT /api/v1/ai/evidence-settings`, `GET /api/v1/findings/{id}/correlation`, `POST /api/v1/findings/{id}/correlation/explain`, `POST /api/v1/threat-models/{id}/suggest`. All are behind `ai_intelligence` and answer `404` `PTH-PLAT-1007` while it is off.

## Protocols

HTTPS JSON (REST, the existing API conventions). Model calls use the existing provider adapters (Anthropic Messages, OpenAI-compatible Chat Completions with strict JSON schema).

## Authentication

The existing session or API token. New permission `ai.evidence_read` (category AI & MCP, not organization-only, part of the read-only set so every built-in role has it). A record is visible only with read access to its subject: `findings.read` on the finding's repository; `threats.read` on the threat model (checked by the threat-model module, `threatmodel.Service.EvidenceAccess`); for error, conversation and report subjects the requester or an organization-wide `ai.configure` holder. Reviewing and replaying need `ai.review` (findings) or `threats.manage` (threat models).

## Security requirements

- Rule 6: secrets are never sent and never stored. Prompts are redacted before sending (unchanged redaction); the payload stores exactly the redacted prompt. Code around a secrets finding is never sent.
- Payloads are envelope-encrypted (AES-256-GCM, per-record data key wrapped by the master key; the AAD binds the ciphertext to the record id). Reading them is audited (`ai_evidence.view_payload`).
- Records are immutable except the review (`ai_evidence_immutable` trigger; a decided review cannot change).
- Rule 4: no fake data. Records hold what the provider returned; stub providers exist only in tests.
- Rule 5: every AI conclusion carries `label: ai_inferred` and `confirmed` only after a person accepted it; correlation items carry `verified` or `observed`.
- No silent suppression: `ai.Decide` makes every false-positive verdict wait for approval; the correlation explanation and evidence reviews never change a finding's status.
- Replays are rate-limited (30 per organization per hour) because they cost tokens.
- Tenant isolation: every new table carries `organization_id` with the standard policy; the isolation suite probes every new route.

## Error handling

| Code | Meaning |
|---|---|
| `PTH-AI-1101` | Code may not be sent to the task's configuration (refused, recorded as `disabled`) |
| `PTH-AI-1102` | Invalid task assignment, retention or review decision |
| `PTH-AI-1103` | Record already decided or not reviewable |
| `PTH-AI-1201` | Replay: configuration or provider gone |
| `PTH-AI-1202` | Replay: prompt purged by retention or not stored |
| `PTH-AI-1203` | Replay limit (30 per hour) |
| `PTH-AI-1204` | Replay: produced outside PATHOS (MCP) |
| `PTH-AI-1205` | Retention job failed (jobs log) |
| `PTH-AI-1301` | Threat suggestions: the draft has no diagram |
| `PTH-AI-1302` | Submit refused: AI-suggested threats await a decision |

Provider errors keep their existing codes (`PTH-AI-1001`…`1011`) and are stored on the record (`error_code`). Generated pages: [troubleshooting/ai.md](../troubleshooting/ai.md).

## Operations

- Turn the module on per organization: Administration → Feature flags → `ai_intelligence`.
- Recommended setup for code-bearing tasks: a self-hosted provider (for example Ollama) with *Send code context* on; it becomes the default for those tasks automatically.
- Retention: AI → Settings → AI evidence (`retention_days`, `store_payloads`). The jobs service runs `ai.Retain` every maintenance tick, 5000 records per run; failures log `PTH-AI-1205`.
- Storage: one payload per call (the redacted prompt, at most about 60 KB, and the response); threat-suggestion items and MCP reviews have none.
- Key rotation: `pathosctl rotate-master-key` rewraps the evidence payloads with the credentials (`ai.RewrapPayloads`).

## Implementation status

Implemented in M7 behind `ai_intelligence` (off by default): migrations 00058 (records, payloads, settings), 00059 (task assignments), 00060 (link columns on `ai_reviews`, `ai_fix_proposals`, `ai_messages`, `ai_reports`, `human_review_recommendations`; foreign key from `threats.ai_evidence_id`; threat event `ai_accepted`). Records are written for every AI call path whatever the flag. Tests: the call-site test, interpreter, determinism and comparison unit tests, and `TestAIEvidence` (record completeness on every path with stub providers, reproduce local and cloud, retention, model per task and code to the cloud, no silent suppression, the suggestion flow), the tenant isolation suite, frontend unit tests and a Playwright spec.

## Known limitations

- `model_digest` is empty for self-hosted models (no call to the server's native API); a replay compares the reported model name instead (`model_changed`).
- Replays are synchronous (`201`), not queued (`202`, the API design's proposal); a slow local model holds the request up to the template's timeout.
- The evidence list filters access per record after reading a batch, so a page can be shorter than `limit` when many records are hidden (`next_cursor` continues).
- Threat-model subjects are checked through the model's scope (all repositories of an application-wide model).

## Future improvements

- AI-inferred CodeGraph edges (`graph_inference`) with `codegraph_evidence.kind = 'ai_record'`.
- The local model digest (Ollama `/api/show`) and queued replays.
- An evidence export bundle for audits.
