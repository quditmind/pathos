---
title: Troubleshooting: AI
section: troubleshooting
order: 112
version: "1.0"
updated: 2026-11-20
summary: AI providers and configurations: review, assistance, fixes and reports (11 codes, PTH-AI-*)
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

