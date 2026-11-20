---
title: AI evidence, model per task and correlation
section: api-reference
order: 10
version: "3.0"
updated: 2026-11-20
summary: Read, review and reproduce the AI evidence record of every AI decision; assign an AI configuration per task; set evidence retention; get a finding's deterministic cross-phase correlation and an AI explanation; ask for AI threat suggestions on a threat model draft. Behind the ai_intelligence feature flag.
---
# AI evidence, model per task and correlation

PATHOS writes an **AI evidence record** for every call it makes to a model (AI review, Human Eye assistance, analyst answer, report narrative, fix proposal, troubleshooting, threat suggestion, correlation explanation, replay), and for an AI review a person submits through MCP. The records are written whatever the feature flag; the endpoints below answer `404` with `PTH-PLAT-1007` (`feature_disabled`) while the organization's `ai_intelligence` flag is off. The user view is in the [user guide](../user-guide/ai-security-intelligence.md); the design is [PATHOS_AI_SECURITY_INTELLIGENCE.md](../aspm/PATHOS_AI_SECURITY_INTELLIGENCE.md).

No endpoint closes, suppresses or accepts a finding from an AI conclusion: a conclusion is `ai_inferred` and only proposes.

## Permissions

| Operation | Permission |
|---|---|
| List and read records | `ai.evidence_read`, plus read access to the subject: `findings.read` on the finding's repository; `threats.read` on the threat model (and the `threat_models` flag); for error, conversation and report subjects, being the requester or holding `ai.configure` organization-wide |
| Review, replay | As read, plus `ai.review` on the finding's repository (an AI review awaiting approval also needs `findings.triage`, as on `/api/v1/ai/reviews/{id}/approve`); `threats.manage` for threat-model subjects |
| Task assignments, evidence settings | `ai.configure` (organization-wide) |
| Correlation | `findings.read` on the finding's repository; explain: `ai.review` too |
| Threat suggestions | `threats.manage` on the model's scope and `ai.review` |

Callers without access to a record's subject get `404`.

## The evidence record

```json
{ "id": "0196…", "task": "finding_validation", "task_label": "Triage and review", "operation": "ai_review",
  "subject_kind": "finding", "subject_id": "0196…", "finding_id": "0196…",
  "related": { "findings": ["0196…"], "codegraph_nodes": [{ "snapshot_id": "0196…", "key": "fn:go:internal/store.AddProduct", "type": "function" }] },
  "parent_id": null, "config_version_id": "0196…",
  "provider": "self_hosted", "provider_location": "local", "model": "qwen3-coder:30b", "model_reported": "qwen3-coder:30b", "model_digest": "",
  "prompt_template": "finding_validation@1",
  "parameters": { "effort": "medium", "max_output_tokens": 0, "temperature": 0, "seed": 0, "configuration_id": "0196…", "configuration_version": 3, "selected_by": "local_default" },
  "deterministic": true, "determinism_note": "Self-hosted model called with temperature 0 and a fixed seed: …",
  "sent_code": true, "input_sha256": "3782…", "response_sha256": "9a1c…",
  "steps": ["line 10: eval(x)", "x is assigned a literal"], "conclusion": "false_positive: The input is a constant.",
  "verdict": "false_positive", "confidence": 0.82,
  "status": "succeeded", "error_code": "", "error": "", "input_tokens": 500, "output_tokens": 80,
  "review_decision": "pending", "reviewer_id": null, "reviewer_name": null, "reviewed_at": null, "review_note": "",
  "replay_of": null, "comparison": null,
  "payload_expires_at": "2027-05-19T10:00:00Z", "payload_purged_at": null, "payload_available": true,
  "requested_by": "0196…", "requested_by_name": "Ana", "created_at": "2026-11-20T10:00:00Z",
  "label": "ai_inferred", "confirmed": false, "proposes_suppression": true,
  "replayable": true, "replay_unavailable": "", "can_review": true }
```

| Field | Values |
|---|---|
| `task` | `finding_validation`, `fix_proposal`, `troubleshooting`, `threat_suggestion`, `correlation`, `analyst`, `report` (`graph_inference` reserved) |
| `operation` | `ai_review`, `interactive_mcp`, `assist:<kind>`, `analyst_answer`, `report_narrative`, `fix_proposal`, `troubleshoot`, `threat_suggestion` (the call), `threat_suggestion_item` (one suggested threat, `parent_id` = the call), `correlation_explain`, `replay` |
| `subject_kind` | `finding`, `threat`, `threat_model`, `error`, `conversation`, `report`, `human_review` (with `finding_id`) |
| `provider_location` | `local` (self-hosted), `cloud`, `user` (an MCP review by a person's own assistant) |
| `status` | `succeeded`, `invalid_output`, `failed`, `disabled` (refused before sending) |
| `review_decision` | `pending`, `accepted`, `rejected`, `not_required` |
| `proposes_suppression` | `true` when the verdict is `false_positive` or `not_exploitable` |

Records are immutable except the review (a database trigger enforces it). The redacted prompt and response are stored envelope-encrypted and deleted after the organization's retention (`payload_purged_at`).

## Endpoints

### `GET /api/v1/ai/evidence`

Query: `task`, `status`, `review_decision`, `subject_kind`, `provider_location`, `subject_id`, `finding_id`, `threat_id` (the threat's records: the threat as subject, its suggestion record and the call), `include_items=true` (threat-suggestion items are listed under their call unless asked or filtered by threat), `limit` (1–200, default 50), `cursor`. Records the caller cannot read are skipped.

Response `200`: `{ "items": [record…], "next_cursor": "…" }` (no prompt or response bodies). Errors: `400` (unknown filter value, invalid cursor), `403` (no `ai.evidence_read`).

### `GET /api/v1/ai/evidence/{id}`

Query: `include=prompt,response`. Response `200`:

```json
{ "record": { … }, "related_records": [ { …item or replay… } ],
  "prompt": { "system": "…", "user": "…<untrusted_evidence id=\"…\">…", "schema": { … }, "request": { "effort": "low", "max_output_tokens": 2000 } },
  "response": "{\"verdict\":…}" }
```

`prompt` and `response` only with `include`; when the payload was purged or never stored, `payload_unavailable` says why. Reading them writes an audit entry (`ai_evidence.view_payload`). Errors: `404`.

### `POST /api/v1/ai/evidence/{id}/review`

Request: `{ "decision": "accepted" | "rejected", "note": "…" }` (note at most 2000 characters). Response `200`: the record.

- A record of an AI review that awaits approval is decided through the AI review flow (same checks as `POST /api/v1/ai/reviews/{id}/approve|reject`; accepting applies the review's status change).
- A threat-suggestion item: `accepted` keeps the threat in the draft; `rejected` deletes it from the draft. The model version must be a draft (`409`, `PTH-TM-1001`).
- Other records: the decision is recorded; the subject is not changed (accepting a *not exploitable* correlation does not close the finding).

Errors: `404`; `409` already decided or not reviewable (`PTH-AI-1103`); `422` invalid decision (`PTH-AI-1102`). Audit: `ai_evidence.review`.

### `POST /api/v1/ai/evidence/{id}/replay`

No body. Re-sends the stored prompt, schema and parameters to the record's AI configuration version (an item replays its call). Response `201`:

```json
{ "record": { …new record, "operation": "replay", "replay_of": "<id>" … }, "original": { … },
  "comparison": { "same_conclusion": true, "same_verdict": true, "identical_response": true, "model_changed": false,
                  "original_verdict": "not_exploitable", "replay_verdict": "not_exploitable",
                  "original_conclusion": "…", "replay_conclusion": "…", "steps_added": [], "steps_removed": [],
                  "original_model": "…", "replay_model": "…", "deterministic": true, "determinism_note": "…",
                  "original_confidence": 0.7, "replay_confidence": 0.7 } }
```

`502` with the same body and `error: {code, message}` when the provider failed (the failed replay is recorded). Errors: `409` provider or configuration gone (`PTH-AI-1201`), prompt purged or not stored (`PTH-AI-1202`), MCP review (`PTH-AI-1204`), code no longer allowed (`PTH-AI-1101`); `429` more than 30 replays in an hour (`PTH-AI-1203`). Audit: `ai_evidence.replay`.

### `GET /api/v1/ai/task-assignments`

Response `200`:

```json
{ "items": [ { "task": "fix_proposal", "label": "Fix proposals", "code_bearing": true, "description": "…",
               "configuration_id": null,
               "effective": { "configuration_id": "0196…", "configuration_name": "Local", "provider_kind": "self_hosted", "location": "local",
                              "model": "qwen3-coder:30b", "send_code_context": true, "source": "local_default" },
               "warning": "" } ],
  "evidence": { "retention_days": 180, "store_payloads": true, "updated_at": null } }
```

`source`: `assignment`, `local_default` (code-bearing task, self-hosted configuration), `default`, `troubleshooting_local`. `effective` is `null` when no configuration exists.

### `PUT /api/v1/ai/task-assignments`

Request: `{ "assignments": { "<task>": "<configuration_id>" | null } }` (`null` returns the task to automatic). Response `200`: as GET. Errors: `422` unknown task, or a configuration that does not exist or is archived (`PTH-AI-1102`). Audit: `ai_task_assignment.update`.

### `PUT /api/v1/ai/evidence-settings`

Request: `{ "retention_days": 180, "store_payloads": true }` (1–3650 days). Response `200`: the settings. Errors: `422` (`PTH-AI-1102`). Audit: `ai_evidence_settings.update`. The jobs service purges payloads older than the retention (measured from each record's creation).

### `GET /api/v1/findings/{id}/correlation`

The deterministic join (no AI). Response `200`:

```json
{ "finding": { "id": "0196…", "title": "…", "severity": "high", "status": "open", "category": "sast", "rule_id": "…", "cwe": ["CWE-89"], "cve": "",
               "file_path": "internal/store/store.go", "start_line": 38, "package_name": "", "package_version": "" },
  "deterministic": true,
  "codegraph": { "snapshot_id": "0196…", "snapshot_status": "ready",
                 "nodes": [ { "key": "fn:go:internal/store.AddProduct", "type": "function", "label": "AddProduct", "file_path": "…", "start_line": 30, "end_line": 52, "match": "location", "evidence": "verified" } ],
                 "edges": [ { "key": "…", "type": "writes", "source": "…", "target": "ds:postgresql", "evidence": "verified" } ], "note": "" },
  "threats": [ { "id": "0196…", "threat_model_id": "0196…", "model_status": "draft", "model_version": 1, "title": "…", "category": "tampering",
                 "severity": "high", "status": "open", "link": "finding", "evidence": "verified" } ],
  "threats_note": "",
  "components": [ { "name": "lodash", "version": "4.17.20", "purl": "pkg:npm/lodash@4.17.20", "type": "library", "licenses": ["MIT"], "evidence": "verified" } ],
  "runtime": { "status": "running", "exposed": true, "privileged": false, "alert": false, "context": { … }, "evidence": "observed" },
  "related_findings": [ { "id": "0196…", "relation": "same_location", "title": "…", "severity": "high", "status": "open", "evidence": "verified" } ] }
```

`codegraph` is `null` while the `codegraph` flag is off; threats need the `threat_models` flag and read access to each model (others are counted in `threats_note`). Errors: `404`.

### `POST /api/v1/findings/{id}/correlation/explain`

No body. Asks the correlation task's model to explain and prioritise the correlation (references and metadata only, no source code). Response `200`:

```json
{ "correlation": { … }, "explanation": { "priority": "low", "exploitability": "not_exploitable", "confidence": 0.7,
  "explanation": "…", "reasoning": ["…"] }, "evidence_record_id": "0196…", "label": "ai_inferred", "review_decision": "pending",
  "provider_location": "local", "model": "…", "proposes_suppression": true,
  "note": "AI-inferred: a proposal only. The finding is unchanged; a person decides in triage or Human Eye." }
```

The finding is not changed. Errors: `404`; `409` no AI configuration (`PTH-AI-1001`); `429` provider rate limit (`PTH-AI-1004`); `502` provider error or invalid answer (`PTH-AI-1006`); `503` AI not available (`PTH-AI-1007`). Audit: `ai.correlation_explain`.

### `POST /api/v1/threat-models/{id}/suggest`

Request: `{ "max_threats": 10 }` (optional, 1–20). The version must be a draft. Sends the draft's diagram (elements, flows, trust boundaries, existing threat titles; no source code) to the threat-suggestion model and adds the valid suggestions as threats with `method: "ai"`, `evidence_type: "ai_inferred"`, `ai_evidence_id` (one record per suggestion, `parent_id` = the call's record) and `ai_review: "pending"`. Suggestions naming elements outside the diagram, with an unknown category or already in the model are dropped (`dropped`).

Response `200`: `{ "items": [threat…], "evidence_record_id": "<call record>", "dropped": 1, "model": "…", "label": "AI-inferred", "note": "…" }`.

Errors: `404`; `409` not a draft (`PTH-TM-1001`), no diagram elements (`PTH-AI-1301`), no AI configuration (`PTH-AI-1001`), code not allowed (`PTH-AI-1101`); `422` invalid `max_threats`; `429`/`502` as above. Submitting a version with pending suggestions answers `422` `PTH-AI-1302`. Threats gain `ai_evidence_id` and `ai_review`; model counts gain `ai_pending`. Audit: `threat_model.ai_suggest`.

## Changes to existing endpoints

- `POST /api/v1/diagnostics/troubleshoot`: an AI answer carries `evidence_record_id`.
- AI reviews with policy `never` or `false_positives` no longer apply a *false positive* verdict without a person: it is `pending_approval` (no silent suppression). *Needs review* still applies directly under policy `never`.
- Without the `ai_intelligence` flag the configuration used by every AI feature is unchanged (the default; troubleshooting prefers a self-hosted one). With it, each task uses its assignment or the local default above.
