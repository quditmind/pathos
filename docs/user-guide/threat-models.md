---
title: Threat models
section: user-guide
group: threat-model
order: 40
version: "3.0"
updated: 2026-11-20
summary: Generate STRIDE threat models of an application from its CodeGraph and attack paths, see the evidence behind each threat, edit and approve them, and import or export OWASP Threat Dragon, PATHOS JSON and pytm models.
---
# Threat models

A threat model lists what can go wrong in an application and what is done about it. PATHOS builds it for you from the application's [CodeGraph](codegraph.md) (its routes, functions, data stores, data flows, external services, deployment and trust boundaries) and from its [attack paths](posture.md#attack-paths). People then review it: they change severities and statuses with a reason, write mitigations, add threats PATHOS cannot see, and approve the model.

Every threat answers five questions: **what is the evidence**, **which method found it**, **how severe is it**, **how confident is PATHOS**, and **what is the mitigation**.

Threat models are a new module. An administrator turns them on with the **threat_models** feature flag (Administration → Feature flags). Until then the sidebar item **Threat models** (group *4 · Threat model*) is shown disabled with an **Off** badge ("not enabled") and the pages and API answer "feature disabled" (`PTH-PLAT-1007`). Threat models need a CodeGraph, so the **codegraph** flag should be on too.

## Creating a threat model

1. Open **Threat models** and select **New threat model** (or open the application and its *Threat model* tab).
2. Choose the application and, optionally, one repository to narrow the model to.
3. Keep **Generate threats now** selected. Generation needs at least one finished CodeGraph snapshot of the application (build one from the CodeGraph page).

One model exists per application (and repository). Its versions keep its history.

## How threats are generated

Generation is deterministic: the same graph always gives the same threats. **No AI is used to generate threats.** Separately, with the **ai_intelligence** flag on, **Suggest threats with AI** on a draft adds AI-inferred threats that each wait for a person's acceptance ([AI threat suggestions](ai-security-intelligence.md#ai-threat-suggestions)). Each rule is documented, versioned and tested; the full catalogue with its exact logic is in [PATHOS_THREAT_MODELLING.md](../aspm/PATHOS_THREAT_MODELLING.md).

| Rule | STRIDE category | What it looks for |
|---|---|---|
| TM-S-001 | Spoofing | An HTTP entry point (route) with no authentication function on its handler chain |
| TM-E-001 | Elevation of privilege | A state-changing entry point (POST, PUT, PATCH, DELETE) with no authorization evidence |
| TM-T-001 | Tampering | A data store written from code reachable from an entry point |
| TM-R-001 | Repudiation | A write path with no audit record (no audit-like function, no audit data store) |
| TM-I-001 | Information disclosure | A data flow that crosses a trust boundary without TLS evidence |
| TM-I-003 | Information disclosure | A credential written as a literal in the code |
| TM-D-001 | Denial of service | Input from an entry point published to a queue without rate limiting |
| TM-D-002 | Denial of service | A deployment resource that opens the application to the internet, with no WAF, network policy or rate-limit resource in the graph |
| TM-E-002 | Elevation of privilege | A container image that runs as root (no non-root user) |
| TM-AP-001 | From the finding | An attack path of the application: a route from the internet to an open finding |

The diagram uses data-flow diagram elements: processes (routes, functions, containers), data stores (databases, queues, secret stores), external entities (external services, the internet), data flows (the graph's edges) and trust boundaries.

What the CodeGraph does not show produces no threat. The model page lists such gaps under the actions (for example "no routes found").

## Evidence labels

| Label | Meaning |
|---|---|
| **verified** | Found in the code, the SBOM, a scan result or the PATHOS inventory: the CodeGraph nodes and edges are listed with their file and line |
| **observed** | Runtime evidence was used (for example a workload seen in a connected Kubernetes cluster) |
| **imported, unverified** | Came from an imported file and is not yet linked to evidence |
| **manual, unverified** | Added by a person without a link to evidence |

Open a threat to see its evidence: the CodeGraph elements (each links to the CodeGraph page, with the snapshot and node selected), the edges with their file and line references, what the rule looked for and did **not** find, the exposure (internet-facing or not and why), runtime facts, the attack path and the linked findings.

## Severity and confidence

Each threat states how its severity and confidence were derived, for example "Base medium (rule TM-S-001); raised: internet-facing (Ingress shop, deploy/k8s/api.yaml:35)". Rules that rely on the *absence* of evidence (no authentication function found) have a lower confidence than rules that rely on something present (a literal credential). Runtime evidence raises the confidence.

## Editing threats

Only a **draft** can be edited. In a threat's detail:

- **Severity and status** (open, mitigated, accepted, not applicable): a **reason is required** for every change. The reason is kept in the threat's history.
- **Mitigation**: what is or will be done. Each generated threat starts with a proposed mitigation, its D3FEND countermeasures and links to its findings (where the fix guidance is).
- **Link evidence**: add CodeGraph element keys or finding ids. A manual or imported threat becomes *verified* once linked to evidence that exists.
- **Delete**: manual and imported threats only. A generated threat that does not apply is set to *not applicable* with a reason.

**Add manual threat** adds a threat PATHOS cannot see (for example a business-logic abuse). It is labelled *manual*.

## Regeneration keeps your edits

Generating again (or a new CodeGraph snapshot, see below) compares the new threats with the existing ones by their fingerprint (rule, repository and element):

- a threat found again keeps its status, reason, owner, any severity a person changed and any mitigation a person wrote; its evidence is refreshed and it is marked **changed** (evidence differs) or **unchanged**;
- a threat no longer found is kept and marked **resolved**;
- a threat found for the first time is marked **new**.

Manual and imported threats are never changed by generation.

**Architecture changes** feed back automatically: when a new CodeGraph snapshot of the application is ready, PATHOS regenerates its threat models into a draft (the existing draft, or a new draft version after the approved one). Administrators can turn this off in the threat-model settings (`auto_update`).

## Reviewing and approving

1. When the draft is complete, select **Submit for review**. PATHOS refuses the submission while an open or accepted threat has no mitigation (`PTH-TM-1004`) or a manual or imported threat is neither linked to evidence nor not applicable (`PTH-TM-1006`).
2. A person with the **threats.approve** permission opens the model and uses the **Approval** panel: **Approve**, **Request changes** or **Reject** (a note is required for the last two). The approver can never be the version's author or submitter (`PTH-TM-1005`); the panel says so when that is the case.
3. An approved version is read-only. **New version** (or **Regenerate in a new version**) starts the next draft with every human edit copied. When it is approved, the older approved version becomes *superseded*.

Every decision is recorded in the **Versions** tab and the audit log.

## Import and export

**Export** (any version):

| Format | Use |
|---|---|
| PATHOS JSON | Complete: elements, threats, evidence, mappings, approvals. Re-importable |
| OWASP Threat Dragon (JSON v2) | Open the model in Threat Dragon |
| pytm description (Python) | A description of the elements and data flows for OWASP pytm. Review it before running it; PATHOS never runs it |
| Markdown report | A readable report |

Every export carries the PATHOS version, build and time, and the MITRE notices when it includes framework names.

**Import** (Threat models → Import): OWASP Threat Dragon v2 JSON or PATHOS JSON, up to 10 MB. Imported threats are **imported, unverified** until linked to evidence; threats of a PATHOS export whose CodeGraph keys exist in the application's latest snapshot are linked at once. pytm models are Python code and cannot be imported.

## Frameworks

Threats are mapped to **STRIDE**, **MITRE ATT&CK** techniques, **CAPEC** attack patterns, **CWE** weaknesses (from the rules and from linked findings) and **D3FEND** countermeasures. The data ships with PATHOS (no internet access needed) from pinned, checksum-verified releases.

- ATT&CK, CAPEC and CWE are © The MITRE Corporation, reproduced under the MITRE terms of use; the notices are in `NOTICE` and in the PATHOS JSON and Markdown exports. D3FEND is MIT licensed.
- **LINDDUN** privacy categories (linking, identifying, non-repudiation, detecting, data disclosure, unawareness, non-compliance) can be chosen for manual threats. LINDDUN states no licence, so PATHOS only names the categories and cites [linddun.org](https://linddun.org); it ships no LINDDUN text.

## Permissions

| Permission | Allows |
|---|---|
| `threats.read` | See threat models, threats, diagrams, versions; export |
| `threats.manage` | Create, generate, edit, add and delete threats, submit, start new versions, import |
| `threats.approve` | Approve, reject or request changes (never on a version you wrote or submitted) |

An application-wide model needs the permission on every repository of the application (organization-wide roles cover all).

## Troubleshooting

| Code | What happened | What to do |
|---|---|---|
| `PTH-TM-1001` | The version's status does not allow the action (for example editing a version in review, or approving a draft) | Edit drafts only. To change an approved model start a **New version**; to change a model in review, request changes first |
| `PTH-TM-1002` | No finished CodeGraph snapshot exists for the application | Build the CodeGraph (CodeGraph page → Build) and generate again when it is ready |
| `PTH-TM-1003` | A linked CodeGraph key or finding does not exist | Copy the key from the CodeGraph inspector of the latest snapshot, or the finding id from the findings page |
| `PTH-TM-1004` | Submit refused: an open or accepted threat has no mitigation | Filter the threats by status and write the missing mitigations |
| `PTH-TM-1005` | You wrote or submitted this version, so you cannot approve it | Ask another person with `threats.approve` |
| `PTH-TM-1006` | Submit refused: a manual or imported threat is not linked to evidence | Link CodeGraph keys or findings, or set it not applicable with a reason |
| `PTH-TM-1007` | A severity or status change has no reason | Fill in the reason |
| `PTH-TM-1008` | A threat model already exists for the application (and repository) | Open the existing model; start a new version instead |
| `PTH-TM-1009` | A generated threat cannot be deleted | Set it *not applicable* with a reason |
| `PTH-TM-1010` | The generated threats could not be stored | Try again; if it persists, report it with the request id |
| `PTH-TM-1011` | A field is missing, too long or not allowed (for example a framework id that is not in the bundled data, or renaming a generated threat) | Correct the field the message names |
| `PTH-TM-1101` | The import file could not be parsed | Check it is a Threat Dragon v2 or PATHOS JSON file; the message names the position |
| `PTH-TM-1102` | The import format is not supported | Use Threat Dragon v2 or PATHOS JSON |
| `PTH-TM-1103` | The import file has too many elements or threats | Split the model or remove unused diagrams |
| `PTH-AI-1301` | Suggest threats with AI: the draft has no diagram elements | Generate the model from CodeGraph first |
| `PTH-AI-1302` | Submit refused: AI-suggested threats await a decision | Accept or reject each threat labelled *AI-inferred (awaiting decision)* in its AI evidence panel |

More detail for each code: [Troubleshooting: threat modelling](../troubleshooting/tm.md).
