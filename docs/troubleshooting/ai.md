---
title: Troubleshooting: AI
section: troubleshooting
order: 112
version: "1.0"
updated: 2026-11-20
summary: AI providers and configurations: review, assistance, fixes and reports (21 codes, PTH-AI-*)
---

# Troubleshooting: AI

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

AI providers and configurations: review, assistance, fixes and reports.

| Code | Title | Severity |
|---|---|---|
| [PTH-AI-1001](#PTH-AI-1001) | No AI configuration | info |
| [PTH-AI-1002](#PTH-AI-1002) | AI assistance disabled | info |
| [PTH-AI-1003](#PTH-AI-1003) | AI provider rejected the API key | error |
| [PTH-AI-1004](#PTH-AI-1004) | AI provider rate limit reached | warning |
| [PTH-AI-1005](#PTH-AI-1005) | AI model declined to answer | info |
| [PTH-AI-1006](#PTH-AI-1006) | AI request failed | error |
| [PTH-AI-1007](#PTH-AI-1007) | AI service not available on this server | warning |
| [PTH-AI-1008](#PTH-AI-1008) | AI daily limit reached | info |
| [PTH-AI-1009](#PTH-AI-1009) | AI patch could not be applied | warning |
| [PTH-AI-1010](#PTH-AI-1010) | AI request needs more context | info |
| [PTH-AI-1011](#PTH-AI-1011) | AI request too large | warning |
| [PTH-AI-1101](#PTH-AI-1101) | Source code may not be sent to this AI configuration | info |
| [PTH-AI-1102](#PTH-AI-1102) | Invalid AI task assignment, evidence setting or review | info |
| [PTH-AI-1103](#PTH-AI-1103) | AI conclusion already decided or not reviewable | info |
| [PTH-AI-1201](#PTH-AI-1201) | Replay impossible: the model's configuration or provider is gone | warning |
| [PTH-AI-1202](#PTH-AI-1202) | Replay impossible: the prompt is no longer stored | info |
| [PTH-AI-1203](#PTH-AI-1203) | Replay limit reached | info |
| [PTH-AI-1204](#PTH-AI-1204) | Replay impossible: produced outside PATHOS | info |
| [PTH-AI-1205](#PTH-AI-1205) | AI evidence retention job failed | error |
| [PTH-AI-1301](#PTH-AI-1301) | No diagram to suggest threats from | info |
| [PTH-AI-1302](#PTH-AI-1302) | AI-suggested threats await a decision | info |

<a id="PTH-AI-1001"></a>

## PTH-AI-1001: No AI configuration

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `ai_not_configured` |
| Raised in | internal/ai/assist.go (ErrNotConfigured), internal/analyst/service.go, internal/review/aiassist.go |

**What it means.** The organization has no default AI configuration (provider and model), so AI features cannot run.

**Confirmed cause.** No default AI configuration exists. Confirmed automatically when this code is raised.

**Probable causes**

1. AI was never set up
2. The default configuration was archived

**Impact.** AI review, assistance, fixes and narratives are unavailable. Everything else works.

**How to fix**

1. An administrator with ai.configure adds a provider (a self-hosted model is recommended) and a default configuration (AI → Settings).

**Verify**

1. Request an AI review; it is queued.


<a id="PTH-AI-1002"></a>

## PTH-AI-1002: AI assistance disabled

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `ai_disabled` |
| Raised in | internal/review/aiassist.go |

**What it means.** AI assistance is switched off in the Human Eye settings of the organization.

**Confirmed cause.** AI assistance is disabled by the organization's settings. Confirmed automatically when this code is raised.

**Probable causes**

1. An administrator turned AI assistance off

**Impact.** Reviewers work without AI suggestions.

**How to fix**

1. An administrator enables AI assistance in Human review settings if policy allows.

**Verify**

1. The AI assist panel appears on a review.


<a id="PTH-AI-1003"></a>

## PTH-AI-1003: AI provider rejected the API key

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/ai/provider.go (ErrAuth), internal/ai/service.go |

**What it means.** The AI provider answered that the API key is invalid or not allowed.

**Confirmed cause.** The provider rejected the configured API key. Confirmed automatically when this code is raised.

**Probable causes**

1. The key was revoked or rotated
2. The key belongs to another provider or project

**Impact.** Every AI feature using this provider fails.

**How to fix**

1. Replace the key on the provider (AI → Providers) and use Test.

**Verify**

1. Test reports "credentials accepted".


<a id="PTH-AI-1004"></a>

## PTH-AI-1004: AI provider rate limit reached

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/ai/provider.go (ErrRateLimited), internal/ai/service.go |

**What it means.** The AI provider refused the request because of its rate limit.

**Confirmed cause.** The provider's rate limit for this key is exhausted. Confirmed automatically when this code is raised.

**Probable causes**

1. Many automated reviews after a large scan
2. A low quota on the provider account

**Impact.** AI work is retried later; findings stay pending meanwhile.

**How to fix**

1. Wait, or lower the configuration's daily limit and categories.
2. Use a self-hosted model for bulk work.

**Verify**

1. New AI reviews complete.


<a id="PTH-AI-1005"></a>

## PTH-AI-1005: AI model declined to answer

| | |
|---|---|
| Severity | info |
| Category | provider |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `ai_refused` |
| Raised in | internal/ai/provider.go (ErrRefused), internal/analyst/service.go, internal/review/aiassist.go |

**What it means.** The model refused the request (safety refusal).

**Confirmed cause.** The provider reported a refusal. Confirmed automatically when this code is raised.

**Probable causes**

1. The evidence resembles content the model will not discuss

**Impact.** No AI suggestion for this item; manual review continues.

**How to fix**

1. Review the item manually.

**Verify**

1. Not applicable.


<a id="PTH-AI-1006"></a>

## PTH-AI-1006: AI request failed

| | |
|---|---|
| Severity | error |
| Category | provider |
| HTTP status | 502 |
| AI help | offered |
| Short codes | `ai_failed`, `ai_provider_error` |
| Raised in | internal/analyst/service.go, internal/review/aiassist.go, internal/ai/service.go, internal/ai/provider.go (ErrTruncated) |

**What it means.** The AI request failed: network error, provider error, a response truncated at the token limit, or output that failed validation.

**Confirmed cause.** The AI call did not return a valid answer. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The model server is unreachable or overloaded
2. The output token limit is too low for the model
3. The model returned malformed JSON

**Impact.** No AI result for this request; nothing else is affected.

**How to fix**

1. Use Test on the provider.
2. For self-hosted models, check the server's log and capacity.
3. Retry.

**Verify**

1. A retried request returns a result.


<a id="PTH-AI-1007"></a>

## PTH-AI-1007: AI service not available on this server

| | |
|---|---|
| Severity | warning |
| Category | availability |
| HTTP status | 503 |
| AI help | not offered |
| Short codes | `ai_unavailable` |
| Raised in | internal/review/aiassist.go |

**What it means.** The API instance was started without the AI service.

**Confirmed cause.** The AI service is not wired on this server. Confirmed automatically when this code is raised.

**Probable causes**

1. A custom deployment without the AI component

**Impact.** AI assistance is unavailable.

**How to fix**

1. Deploy the standard API role.

**Verify**

1. The AI assist panel works.


<a id="PTH-AI-1008"></a>

## PTH-AI-1008: AI daily limit reached

| | |
|---|---|
| Severity | info |
| Category | capacity |
| HTTP status | 429 |
| AI help | not offered |
| Raised in | internal/analyst/service.go, internal/review/aiassist.go, internal/scans/aifixes.go |

**What it means.** The AI configuration's daily request limit for this feature is used up.

**Confirmed cause.** The configuration's daily limit is reached. Confirmed automatically when this code is raised.

**Probable causes**

1. Heavy use today
2. A low daily limit

**Impact.** Further AI requests wait until the 24-hour window moves on.

**How to fix**

1. Wait, or ask an administrator to raise the daily limit.

**Verify**

1. A new request is accepted.


<a id="PTH-AI-1009"></a>

## PTH-AI-1009: AI patch could not be applied

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 502 |
| AI help | not offered |
| Short codes | `invalid_patch` |
| Raised in | internal/review/aiassist.go |

**What it means.** The AI proposed a patch that does not apply to the source it was given.

**Confirmed cause.** The proposed patch failed validation against the source. Confirmed automatically when this code is raised.

**Probable causes**

1. The model invented context lines
2. The source changed since the request

**Impact.** No patch is offered; the suggestion text may still help.

**How to fix**

1. Request the suggestion again, or fix the code manually.

**Verify**

1. A new suggestion includes an applicable patch.


<a id="PTH-AI-1010"></a>

## PTH-AI-1010: AI request needs more context

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `source_required`, `not_scored`, `no_candidates` |
| Raised in | internal/review/aiassist.go |

**What it means.** The AI request needs the finding's source code or score, which is not available or not allowed to be sent.

**Confirmed cause.** The required source context or score is missing for this item. Confirmed automatically when this code is raised.

**Probable causes**

1. Sending code context is disabled in the AI configuration
2. The finding has no source location or score
3. No candidate findings match

**Impact.** This AI action is unavailable for the item.

**How to fix**

1. Enable code context in the AI configuration if policy allows, or choose another item.

**Verify**

1. The AI action runs.


<a id="PTH-AI-1011"></a>

## PTH-AI-1011: AI request too large

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 413 |
| AI help | not offered |
| Raised in | internal/ai/generate.go |

**What it means.** The redacted request payload exceeds the size PATHOS sends to a model.

**Confirmed cause.** The payload after redaction is above the limit. Confirmed automatically when this code is raised.

**Probable causes**

1. A report over many findings
2. Very long evidence

**Impact.** The request was not sent.

**How to fix**

1. Narrow the scope (fewer findings or repositories) and retry.

**Verify**

1. The narrower request completes.


<a id="PTH-AI-1101"></a>

## PTH-AI-1101: Source code may not be sent to this AI configuration

| | |
|---|---|
| Severity | info |
| Category | policy |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `ai_code_not_allowed` |
| Raised in | internal/ai/evidence.go (invoke), internal/ai/fix.go, internal/ai/evidence_api.go |

**What it means.** The request needs source code, and the AI configuration chosen for the task does not allow sending code ("Send code context" is off). For a cloud model this is the administrator's explicit permission; PATHOS never sends code to a cloud model without it. The refusal is recorded as an AI evidence record with status disabled.

**Confirmed cause.** The task's AI configuration has send code context off. Confirmed automatically when this code is raised.

**Probable causes**

1. The task uses a cloud configuration that does not allow code (the safe default)
2. No self-hosted configuration exists for code-bearing tasks
3. A replayed record sent code and its configuration no longer allows it

**Impact.** Fix proposals (and replays of records that sent code) are refused. Other AI features leave code out.

**How to fix**

1. Preferred: add a self-hosted (local) provider and configuration with Send code context on, and assign it to the task (AI → Settings → Model per task).
2. Or, if policy allows sending code to the cloud provider, an administrator turns Send code context on in that configuration.

**Verify**

1. Model per task shows the task on a local model, or the warning "Source code is sent to a cloud model".
2. The request runs.


<a id="PTH-AI-1102"></a>

## PTH-AI-1102: Invalid AI task assignment, evidence setting or review

| | |
|---|---|
| Severity | info |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `ai_task_invalid`, `ai_evidence_settings_invalid`, `ai_evidence_invalid` |
| Raised in | internal/ai/tasks.go, internal/ai/evidence_api.go |

**What it means.** A model-per-task assignment names an unknown task or a configuration that does not exist or is archived, the evidence retention is outside 1 to 3650 days, or an evidence review decision is not accepted or rejected.

**Confirmed cause.** The request failed validation (the message names the field). Confirmed automatically when this code is raised.

**Probable causes**

1. The configuration was archived meanwhile
2. A client sent an old task name

**Impact.** Nothing was changed.

**How to fix**

1. Reload AI settings and choose an existing configuration.
2. Use a retention between 1 and 3650 days.

**Verify**

1. Saving succeeds and Model per task shows the new assignment.


<a id="PTH-AI-1103"></a>

## PTH-AI-1103: AI conclusion already decided or not reviewable

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `ai_evidence_reviewed` |
| Raised in | internal/ai/evidence_api.go |

**What it means.** A person already accepted or rejected this AI evidence record, or the record proposes nothing to decide (a failed or refused call, a replay, or the call record of threat suggestions, whose items are decided one by one).

**Confirmed cause.** The record's review decision is final or the record is not reviewable. Confirmed automatically when this code is raised.

**Probable causes**

1. Another person decided it first
2. The decision was made through the AI review approval, which records it here too

**Impact.** Nothing was changed; the earlier decision stands.

**How to fix**

1. Reload the record to see who decided and when.
2. For threat suggestions, decide each suggested threat.

**Verify**

1. The record shows the reviewer and decision.


<a id="PTH-AI-1201"></a>

## PTH-AI-1201: Replay impossible: the model's configuration or provider is gone

| | |
|---|---|
| Severity | warning |
| Category | dependency |
| HTTP status | 409 |
| AI help | not offered |
| Raised in | internal/ai/evidence_api.go |

**What it means.** A replay re-sends the stored prompt to the same AI configuration version and provider. The provider was deleted or the record names no configuration version, so the same model cannot be called.

**Confirmed cause.** The record's configuration version or provider no longer exists. Confirmed automatically when this code is raised.

**Probable causes**

1. The AI provider was deleted
2. The record was produced before configuration versions were recorded

**Impact.** This record cannot be replayed; it still shows its prompt, response and conclusion.

**How to fix**

1. Compare manually: request a new AI answer for the subject with the current configuration; it gets its own record.

**Verify**

1. Not applicable.


<a id="PTH-AI-1202"></a>

## PTH-AI-1202: Replay impossible: the prompt is no longer stored

| | |
|---|---|
| Severity | info |
| Category | retention |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `ai_replay_unavailable` |
| Raised in | internal/ai/evidence_api.go, internal/ai/tasks.go (Retain) |

**What it means.** The redacted prompt and response are kept for the organization's AI evidence retention (180 days by default) and then deleted; with prompt storage off they are never kept. The record keeps its hashes, model, steps, conclusion and review.

**Confirmed cause.** The record's payload was purged by retention or never stored. Confirmed automatically when this code is raised.

**Probable causes**

1. The record is older than the retention period
2. Prompt storage is off in AI evidence settings
3. The call was refused before anything was sent

**Impact.** The record cannot be replayed or show its prompt.

**How to fix**

1. An administrator can lengthen the retention or turn prompt storage on for future records (AI → Settings → AI evidence).

**Verify**

1. New records show Reproduce.


<a id="PTH-AI-1203"></a>

## PTH-AI-1203: Replay limit reached

| | |
|---|---|
| Severity | info |
| Category | capacity |
| HTTP status | 429 |
| AI help | not offered |
| Raised in | internal/ai/evidence_api.go |

**What it means.** Replays send the stored prompt again and cost tokens, so an organization can replay at most 30 records per hour.

**Confirmed cause.** 30 replays were made in the organization in the last hour. Confirmed automatically when this code is raised.

**Probable causes**

1. Bulk reproduction of many records

**Impact.** Further replays wait until the hour moves on.

**How to fix**

1. Wait and replay again; replay the records that matter most first.

**Verify**

1. A new replay is accepted.


<a id="PTH-AI-1204"></a>

## PTH-AI-1204: Replay impossible: produced outside PATHOS

| | |
|---|---|
| Severity | info |
| Category | validation |
| HTTP status | 409 |
| AI help | not offered |
| Raised in | internal/ai/evidence_api.go |

**What it means.** The record holds an AI review a person submitted through the MCP server with their own assistant. PATHOS never saw the prompt, so it cannot replay it.

**Confirmed cause.** The record's provider is the person's own assistant (location user). Confirmed automatically when this code is raised.

**Probable causes**

1. An interactive MCP review

**Impact.** The record shows the conclusion and its author only.

**How to fix**

1. Request an AI review in PATHOS for a replayable record, or decide the finding manually.

**Verify**

1. Not applicable.


<a id="PTH-AI-1205"></a>

## PTH-AI-1205: AI evidence retention job failed

| | |
|---|---|
| Severity | error |
| Category | retention |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | cmd/pathos/main.go (runJobs), internal/ai/tasks.go (Retain) |

**What it means.** The background job that deletes redacted AI prompts and responses past the organization's retention failed; payloads past retention stay until the next successful run.

**Confirmed cause.** The retention query failed (see the jobs log). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The database was unavailable
2. A long-running lock on ai_evidence_payloads

**Impact.** Prompts may be kept longer than the retention period until the job succeeds.

**How to fix**

1. Check the jobs container log for the error and the database health.
2. The job runs every maintenance tick; confirm the next run logs no error.

**Verify**

1. The jobs log shows no PTH-AI-1205 and old records show "prompt deleted (retention)".


<a id="PTH-AI-1301"></a>

## PTH-AI-1301: No diagram to suggest threats from

| | |
|---|---|
| Severity | info |
| Category | dependency |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `threat_model_no_diagram` |
| Raised in | internal/threatmodel/suggest.go |

**What it means.** AI threat suggestions reason over the draft's data-flow diagram (CodeGraph elements, flows and trust boundaries), and the draft has no diagram elements.

**Confirmed cause.** The threat model draft has no elements. Confirmed automatically when this code is raised.

**Probable causes**

1. The model was created without generation
2. The model was imported without a diagram

**Impact.** No suggestions; nothing was sent to a model.

**How to fix**

1. Generate the model from CodeGraph (Generate) or link threats to CodeGraph elements, then ask for suggestions again.

**Verify**

1. Suggest threats adds AI-inferred threats to the draft.


<a id="PTH-AI-1302"></a>

## PTH-AI-1302: AI-suggested threats await a decision

| | |
|---|---|
| Severity | info |
| Category | workflow |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `threat_ai_pending` |
| Raised in | internal/threatmodel/service.go (submit), internal/threatmodel/suggest.go |

**What it means.** A threat model version cannot be submitted for review while it holds AI-suggested threats no person has accepted: every AI conclusion stays a proposal until a person decides it.

**Confirmed cause.** The draft has AI-inferred threats whose evidence record is pending. Confirmed automatically when this code is raised.

**Probable causes**

1. Suggestions were added and not yet decided

**Impact.** The version stays a draft.

**How to fix**

1. Open each threat labelled AI-inferred (awaiting decision) and Accept or Reject it in its AI evidence panel.

**Verify**

1. The draft shows no pending AI suggestions and Submit succeeds.

