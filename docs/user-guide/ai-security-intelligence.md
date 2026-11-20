---
title: AI security intelligence
section: user-guide
group: validate
order: 35
version: "3.0"
updated: 2026-11-20
summary: Every AI decision PATHOS stores has an evidence record you can read and reproduce; choose a model per task (local by default for code); see a finding's cross-phase correlation; accept or reject AI-suggested threats. AI conclusions are AI-inferred proposals until a person decides.
---
# AI security intelligence

PATHOS uses AI in several places: AI review of findings, Human Eye assistance, AI-proposed fixes, AI troubleshooting of error codes, the AI Security Analyst and AI report narratives. This page covers what PATHOS 3.0 adds around them:

- an **AI evidence record** for every AI answer PATHOS stores, so you can see exactly what was asked, which model answered, what it concluded, how confident it was and who confirmed it, and **reproduce** it;
- a **model per task**, with a self-hosted (local) model by default for the tasks that carry code;
- a finding's **cross-phase correlation** (CodeGraph, threat model, SBOM, runtime) with an optional AI explanation;
- **AI threat suggestions** for a threat model draft.

The rule behind all of it: **an AI conclusion is labelled *AI-inferred* and only proposes.** AI never closes, suppresses or accepts anything by itself: a person decides, in triage, in Human Eye, in the AI review approval or on the record.

The pages and the API are a new module: an administrator turns them on with the **ai_intelligence** feature flag (Administration → Feature flags). Until then the sidebar item **AI evidence log** (group *7 · Validate & intelligence*) is shown as a roadmap item. Evidence records are written whatever the flag, so the history is complete when you turn it on.

## AI evidence log

**AI evidence log** (*7 · Validate & intelligence*) lists the records you can see, newest first. Filter by task (triage and review, fix proposals, troubleshooting, threat suggestions, correlation, analyst chat, report narratives), status, review decision, subject and where the model ran (local or cloud). Select a record to open it.

A record shows:

| Field | Meaning |
|---|---|
| Subject | The finding, threat model, threat, error code, conversation or report the answer is about, and the references it used: CodeGraph nodes and edges (snapshot and key), related findings, threats, components |
| Model | The configured model, the version the provider reported, the provider and whether it ran **local** (self-hosted) or in the **cloud** |
| Parameters | Effort, output limit, temperature and seed (local models run with temperature 0 and a fixed seed), the AI configuration and version, and why that configuration was chosen (task assignment, local default, organization default) |
| Prompt and response | The redacted prompt (system and user parts) and the raw response, the SHA-256 of each. Secrets are never sent and never stored: the prompt is redacted before it is sent. Select **Show prompt and response** to read them (the view is audited) |
| Steps and conclusion | The reasoning steps the model returned, its conclusion and verdict (for example *false positive*, *not exploitable*, *suggested*), and its confidence |
| Code sent | Whether source code was part of the prompt |
| Review | Pending, accepted or rejected, by whom, when and with which note; *not required* for answers that propose nothing (a chat answer, a failed call, a replay) |
| Status | Succeeded, invalid output (the answer did not match the schema), failed (with its `PTH-AI` code), or disabled (refused before sending, for example code not allowed) |

Failed and refused calls have records too, so you can see every time PATHOS called a model.

## AI evidence on a finding or threat

The finding drawer and the threat detail have an **AI evidence** panel with the records about that finding or threat. Each conclusion carries the **AI-inferred** label until a person accepts it; then it reads *AI-inferred · confirmed by* the person.

- **Accept** or **Reject** records your decision with an optional note (it is final). For an AI review that awaits approval, deciding here is the same as approving or rejecting it on **AI reviews**: the same rules apply (a different person than the one who submitted it, `findings.triage` on the repository, a note to close a Critical finding).
- When a conclusion would close or suppress the finding (*false positive*, *not exploitable*), the panel says **Proposal only**: nothing happens to the finding until a person changes its status, in triage, in Human Eye or by approving the AI review. Accepting an AI *correlation* explanation confirms the reasoning; the finding's status is still changed in triage.

## Reproduce

**Reproduce** sends the stored prompt again to the same AI configuration version (same provider, model and parameters) and compares the new answer with the record:

- **same conclusion** (same verdict, or the same conclusion text for answers without a verdict);
- **identical response** (the SHA-256 of the response matches);
- **model changed** (the provider reported another model version);
- reasoning **steps added** and **removed**.

The replay is a record of its own (*replay of* the original); it never changes the finding or threat. Whether the same answer can be expected is stated on every record:

- **Local (self-hosted) models** are called with temperature 0 and a fixed seed: the same model file on the same server returns the same answer (servers that ignore the seed may still vary).
- **Hosted (cloud) models** sample and can change behind the same model name: a replay can differ. PATHOS compares the answers and never assumes they are equal.
- **Reviews submitted through MCP** were produced by a person's own assistant: PATHOS never saw the prompt and cannot replay them.

An organization can replay at most 30 records per hour. Records whose prompt was deleted by retention keep their hashes, model, steps, conclusion and review, but cannot be replayed.

## Correlation

The finding drawer's **Correlation** section joins the finding to the other phases, without AI:

| Part | How it is joined | Label |
|---|---|---|
| CodeGraph | The latest ready snapshot of the repository: the functions, classes and file whose location holds the finding, or the component of its package, and the edges around them | verified |
| Threat model | Threats that name the finding, or that affect a CodeGraph element at the finding (models you can read) | the threat's own label |
| SBOM | The finding's package in the repository's latest SBOM | verified |
| Runtime | The runtime context from connected clusters (deployed, exposed, privileged, alert) | observed |
| Related findings | Other tools at the same place, or the same CVE in the repository | verified |

**Explain with AI** (needs `ai.review`) asks the correlation model to explain and prioritise the finding from this join. The answer is **AI-inferred**, has its own evidence record (with the CodeGraph nodes and edges it used) and is a proposal: a *not exploitable* conclusion is shown as **Proposal only** and the finding is unchanged.

## AI threat suggestions

On a threat model draft, **Suggest threats with AI** (needs `threats.manage` and `ai.review`) sends the draft's data-flow diagram (element names, kinds, CodeGraph node types, flows and trust boundaries, and the titles of the threats already there; never source code) to the threat-suggestion model. PATHOS keeps only suggestions that name elements of the diagram, use a STRIDE or LINDDUN category and are not already in the model. Each one is added to the draft as an **AI-inferred** threat (*awaiting decision*), with its own evidence record (reasoning steps, confidence, affected elements) linked to the record of the call (prompt and response).

Decide each suggestion in its AI evidence panel: **Accept** keeps it in the draft (edit it like any threat); **Reject** removes it from the draft (the record keeps the decision). The draft cannot be submitted for review while a suggestion awaits a decision (`PTH-AI-1302`).

## Model per task

**AI → Settings → Model per task** (needs `ai.configure`) assigns an AI configuration to each task:

| Task | Carries code | Without an assignment |
|---|---|---|
| Triage and review (AI review, Human Eye assistance) | yes | a self-hosted configuration if one exists, else the default |
| Fix proposals | yes | same |
| Troubleshooting | yes (error context) | same |
| Threat suggestions | yes (code structure) | same |
| Correlation | yes (code structure) | same |
| Analyst chat | no | the default configuration |
| Report narratives | no | the default configuration |

The page shows the configuration each task uses now, where it runs, and a warning when a code-bearing task uses a cloud model.

**Source code is only sent where the configuration allows it** (its *Send code context* setting). For a cloud model this is the administrator's explicit permission: without it, code is left out of reviews and assistance, and requests that cannot work without code (fix proposals) are refused (`PTH-AI-1101`) and recorded. Secrets are always redacted, whatever the model.

## Retention

**AI → Settings → AI evidence** sets how long the redacted prompt and response are kept: 180 days by default (1 to 3650). After that the jobs service deletes them; the record keeps its hashes, model, steps, conclusion and review. Turning **Store prompts and responses** off keeps hashes only for new records (they cannot be replayed). A finding's records are deleted with the finding.

## Permissions

| Permission | Allows |
|---|---|
| `ai.evidence_read` | See AI evidence records of subjects you can read (findings in your scope with `findings.read`; threat models with `threats.read`; troubleshooting, chat and report records you requested; AI administrators see all) |
| `ai.review` | Accept or reject AI conclusions about findings in your scope, replay them, ask for a correlation explanation or threat suggestions |
| `threats.manage` | Accept or reject AI-suggested threats, replay their records, ask for suggestions |
| `ai.configure` | Model per task and evidence retention |

All built-in roles have `ai.evidence_read` (it is part of the read-only set).

## Troubleshooting

| Code | What happened | What to do |
|---|---|---|
| `PTH-AI-1101` | The request needs source code and the task's AI configuration does not allow sending it (a cloud model without permission) | Assign a self-hosted configuration to the task (Model per task), or, if policy allows, turn *Send code context* on in that configuration |
| `PTH-AI-1102` | A task assignment names an unknown task or an archived configuration, the retention is out of range, or the decision is not accepted or rejected | Reload AI settings and choose an existing configuration; use 1 to 3650 days |
| `PTH-AI-1103` | The record was already decided, or proposes nothing to decide | Reload it to see who decided; decide threat suggestions one by one |
| `PTH-AI-1201` | Reproduce: the record's AI provider or configuration no longer exists | Request a new AI answer for the subject; it gets its own record |
| `PTH-AI-1202` | Reproduce: the prompt was deleted by retention or never stored | Lengthen the retention or turn prompt storage on for future records |
| `PTH-AI-1203` | 30 replays were made in the last hour | Wait and try again |
| `PTH-AI-1204` | Reproduce: the review was submitted through MCP by a person's own assistant | Request an AI review in PATHOS, or decide manually |
| `PTH-AI-1205` | The retention job failed (jobs log) | Check the jobs container log and the database |
| `PTH-AI-1301` | Threat suggestions: the draft has no diagram elements | Generate the model from CodeGraph, then ask again |
| `PTH-AI-1302` | Submit refused: AI-suggested threats await a decision | Accept or reject each AI-inferred threat |
| `PTH-AI-1001` | No AI configuration | An administrator adds a provider and a configuration (a self-hosted one is recommended) |
| `PTH-PLAT-1007` | The **ai_intelligence** feature flag is off | An administrator turns it on |

More detail for each code: [Troubleshooting: AI](../troubleshooting/ai.md).
