Quditmind PATHOS · applies to v2.2.0 · status: Prototype

# PATHOS threat modelling

## Purpose

Threat modelling (milestone M5, phase 4 of the lifecycle) turns an application's [CodeGraph](PATHOS_CODEGRAPH_ARCHITECTURE.md) and its attack paths into a threat model people can review, edit and approve. Every threat says how PATHOS knows it (rule 5): the CodeGraph nodes and edges with their evidence references, the findings and the runtime facts it rests on, the rule and rule version that produced it, a severity and a confidence with their reasons, and a mitigation. This page describes the engine, the data, the API and the decisions; the user view is in the [user guide](../user-guide/threat-models.md) and the endpoints are in the [API reference](../api-reference/threat-models.md). The design decision is [ADR-007](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-007-threat-model-engine-and-framework-mappings).

## Scope

In scope: a deterministic STRIDE rule engine over CodeGraph snapshots (one per repository of the application); attack paths and blast radius brought in as threats and links; mappings to MITRE ATT&CK, CAPEC, CWE and D3FEND from bundled, pinned and checksum-verified data, plus LINDDUN category names; versioned, editable models with an approval workflow; regeneration that keeps human edits; the architecture feedback loop (a new snapshot regenerates a draft); import and export (OWASP Threat Dragon v2 JSON both ways, PATHOS JSON both ways, a pytm model description and Markdown out); the API behind the `threat_models` flag; the web pages and the application hub panel.

Out of scope: AI-suggested threats (no endpoint: the AI evidence record table of ADR-008 does not exist yet; the schema reserves `method = 'ai'` and `evidence_type = 'ai_inferred'`, which require an AI evidence record id); LINDDUN generation (no data-flow rule can tell that a flow carries personal data yet, so LINDDUN threats are manual or imported); pytm and Threagile import (pytm models are Python programs, which PATHOS never runs; Threagile YAML is not supported); TLS checks on data-store connections (CodeGraph does not record connection TLS settings).

## Architecture

```
 CodeGraph snapshots (ready, one per repository) ──▶ loadGraph ──▶ STRIDE rules (engine.go, rules.go) ──┐
 posture.QueryAttackPaths(application)  ─────────────────────────▶ FromAttackPath (TM-AP-001) ──────────┤
 open findings (file and line inside an evidence node) ──▶ linked findings, CWE mappings ─────────────────┤
 codegraph_evidence (references of every edge used) ──▶ evidence edges ──────────────────────────────────┤
                                                                                                            ▼
                                    apply(): match fingerprints, keep human edits, new / changed / unchanged / resolved
                                                                                                            ▼
                     threat_models (versions) · threat_model_elements (DFD) · threats · threat_elements · threat_findings
                     threat_framework_mappings · threat_events (history) · threat_model_approvals (append-only)
 codegraph ingest (snapshot stored) ──OnSnapshotReady──▶ regenerate in a draft (auto_update)
```

Generation is synchronous: rules run in memory on the snapshot's nodes and edges (modules, the repository node and `defines`/`owns` edges are not loaded); the evidence references are read afterwards for the edges a threat cites only.

### Element model (data-flow diagram)

| DFD element | CodeGraph nodes |
|---|---|
| Process | entry routes (routes crossing an ingress trust boundary), the functions on their paths to data stores, queues and external services, containers and infrastructure resources that cross a boundary or are built from a Dockerfile |
| Data store | `datastore`, `queue`, literal `secret_ref` |
| External entity | `external_service` |
| Trust boundary | `trust_boundary` (HTTP ingress, internet, external network) |
| Data flow | CodeGraph edges between the elements above: `calls`, `reads`, `writes`, `publishes`, `consumes`, `depends_on`, `exposes`, `crosses_boundary`, `deployed_as` |

At most 600 elements and 600 flows per repository are kept for the diagram. AI-inferred edges are never used by the rules or drawn.

## Components

| Component | Path | Role |
|---|---|---|
| Engine and rules | `backend/internal/threatmodel/engine.go`, `rules.go` | Graph input, rule catalogue, scoring, DFD elements, coverage notes |
| Attack paths | `attackpaths.go`, `backend/internal/posture/attack.go` (`QueryAttackPaths`, also serving `GET /posture/attack-paths`, which gains an additive `application_id` filter) | One threat per attack path |
| Generation | `generate.go` | Snapshot selection, loading, evidence references, finding links, merge (`apply`) |
| Store | `store.go` | Models, threats, elements, events, approvals, version copy |
| API | `service.go`, `threats.go`, `importexport.go` | Handlers, review workflow, diagram, import and export, feedback loop |
| Framework data | `backend/internal/threatmodel/frameworks` (`data/*.json`, `sources.json`), `backend/cmd/pathos-frameworks` | Bundled reference data and its updater |
| Web app | `frontend/src/features/threatmodels` | List, model page (diagram, threats, versions, approval), hub panel |

## 3. Rule catalogue

Severity starts at the rule's base; it is raised one level when the repository is internet-facing (a `crosses_boundary` edge into the internet boundary: published port, Ingress, LoadBalancer or NodePort Service, open security group, or an observed exposed workload; or the inventory's public exposure `yes`) and one level when an evidence node holds open critical or high findings; rules that fire on **absent** evidence are capped at high. Confidence starts at the rule's base; +0.10 when the internet exposure is observed at run time, −0.10 when the snapshot is partial; bounded to 0.10–0.99. The reasons are stored with each threat.

| Rule | Ver. | STRIDE | Element | Fires when | Base severity / confidence | ATT&CK · CAPEC · CWE · D3FEND |
|---|---|---|---|---|---|---|
| TM-S-001 | 1 | Spoofing | Process (route) | A route crossing an ingress boundary has no function named like authentication (auth, login, session, token, jwt, oauth, guard, principal, current user, …) on its handler chain (`calls`, 4 deep) and its file imports no authentication library. Public-by-design paths (health, readiness, metrics, static, sign-in, callbacks) are skipped and listed in the notes. Raised when the chain writes a data store; lowered for read-only methods | medium / 0.55 (absence) | T1190, T1078 · CAPEC-115 · CWE-306 · D3-TBA, D3-MFA |
| TM-E-001 | 1 | Elevation of privilege | Process (route) | A state-changing entry route (POST, PUT, PATCH, DELETE, or its chain writes a data store) with no authorization-check name on its chain. Raised when TM-S-001 also applies | medium / 0.50 (absence) | T1190 · CAPEC-122, CAPEC-1 · CWE-862 · D3-UAP, D3-WSAM |
| TM-T-001 | 1 | Tampering | Data store | A data store or queue written by code reachable from an entry route. Raised when a writing route lacks authentication evidence. SQL stores map to SQL injection | medium / 0.80 | T1565.001 · CAPEC-66 or CAPEC-153 · CWE-89 or CWE-20 · D3-DQSA or D3-CV |
| TM-R-001 | 1 | Repudiation | Process (route) | An entry route whose chain writes a data store with no audit-like function (audit, journal, history, activity, event log, track) on the chain and no audit data store written | low / 0.50 (absence) | — · CAPEC-268 · CWE-778 · D3-RAPA |
| TM-I-001 | 1 | Information disclosure | Data flow | A `calls` or `depends_on` flow to an external service that crosses a boundary, whose scheme or technology is not https, wss or tls | medium / 0.85 | T1040, T1557 · CAPEC-157, CAPEC-94 · CWE-319 · D3-ET, D3-MENCR |
| TM-I-003 | 1 | Information disclosure | Data store (secret reference) | A secret reference defined as a literal in code (name and location only, never the value) | high / 0.80 | T1552.001 · CAPEC-191 · CWE-798 · D3-CRO, D3-CH |
| TM-D-001 | 1 | Denial of service | Data store (queue) | A queue published to by code reachable from an entry route, with no rate-limit-like function on the chain (one threat per queue and route) | medium / 0.60 (absence) | T1499.003 · CAPEC-125 · CWE-770 · D3-ISVA |
| TM-D-002 | 1 | Denial of service | Trust boundary | An element crossing the internet boundary when the graph holds no WAF, network policy or rate-limit resource | medium / 0.60 (absence) | T1498, T1190 · CAPEC-125 · CWE-1327 · D3-ITF, D3-NTF |
| TM-E-002 | 1 | Elevation of privilege | Process (container) | A Dockerfile image without USER, or with USER root or 0 | medium / 0.75 | T1611 · CWE-250 · D3-EI |
| TM-AP-001 | 1 | from the finding | Process (the function or file holding the finding) | Each attack path of the application ([posture](../user-guide/posture.md#attack-paths): internet → tested target, internet-facing repository or observed exposed workload → open finding with risk ≥ 50). Category: secrets → information disclosure; dependencies, images, infrastructure → elevation of privilege; code by CWE. Evidence type observed for dynamic testing and runtime entries. Links: the finding (its remediation guidance), the attack paths page and the blast radius of its CVE | the finding's severity / 0.95 KEV, 0.90 exploit or observed, else 0.80 | T1190 · CAPEC exploiting the finding's CWE · the finding's CWE |

Open findings located in an evidence node (same file; for functions and classes the line within the node's span; for routes the same line) are linked to rule threats (up to 10 per threat) and their CWE ids become mappings with source `finding`.

A change of a rule's logic bumps its version. Generated threats are deterministic: the same snapshot gives the same threats (unit test).

## Data flow

1. A person creates a model (`POST /threat-models`, optionally `generate`) or a new snapshot arrives (feedback loop).
2. `compute` picks the newest ready or partial snapshot (rows storage) of each active repository of the application (or the model's repository), runs the rules per snapshot, fills the evidence references, links findings, and runs the attack-path query in the caller's `findings.read` scope (organization-wide for the feedback loop).
3. `apply` writes into a draft in one transaction: elements are upserted by key; each generated threat is matched by its **fingerprint** (`rule | repository | element`). A match keeps status and status reason, owner, a severity a person overrode, a mitigation a person edited and person-added mappings and finding links, and refreshes the rest (`change_state` `changed` when the evidence hash differs, ignoring snapshot-specific ids, else `unchanged`); unmatched new threats are `new`; previous generated threats not found again become `resolved` (kept, with their status). Manual and imported threats are never touched.
4. Review: `submit` (draft → in review; refused while an open or accepted threat has no mitigation, or a manual or imported threat is unverified and not marked not applicable); `approve` (in review → approved, the previous approved version becomes superseded) or `reject` (back to draft with a note). The approver is never the version's author or submitter (service check and database check).
5. Changing an approved model: `POST …/versions` or `generate` copies it into version N+1 (draft) with every threat, link, mapping and edit; the history of a threat continues across versions through `copied` events.

## Dependencies

CodeGraph (M4, flag `codegraph`) for snapshots; posture attack paths; findings (CWE, location); the bundled framework data. No external service at run time.

## 5. Framework data and licences

| Data | Release (pinned) | Source | Licence and notice |
|---|---|---|---|
| MITRE ATT&CK Enterprise | 20.1 (718 techniques and sub-techniques, not revoked) | `mitre-attack/attack-stix-data` `enterprise-attack-20.1.json` | [ATT&CK Terms of Use](https://attack.mitre.org/resources/legal-and-branding/terms-of-use/): non-exclusive, royalty-free licence for research, development and commercial use, provided MITRE's copyright designation and the licence are reproduced. Notice in `NOTICE`, the PATHOS export and the Markdown export |
| MITRE CAPEC | 3.9 (615 attack patterns) | `capec_v3.9.xml` | [CAPEC Terms of Use](https://capec.mitre.org/about/termsofuse.html), same form |
| MITRE CWE | 5.0 (984 weaknesses) | `cwec_v5.0.xml.zip` | [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html), same form; CWE is a MITRE trademark |
| MITRE D3FEND | 1.6.0 (272 countermeasures, `D3-` ids) | `d3fend.mitre.org/ontologies/d3fend/1.6.0/d3fend.json` | MIT License ([d3fend-ontology](https://github.com/d3fend/d3fend-ontology/blob/develop/LICENSE.md)) |
| LINDDUN | categories only | [linddun.org](https://linddun.org) | No licence is stated, so no LINDDUN text is bundled: the seven category names are cited, with PATHOS's own one-line descriptions |

Terms checked on 2026-11-20 (re-check when the data is updated). The bundled files keep, per entry, the id, name, a summary of at most 300 characters (first sentences, citations removed), the URL and a deprecated flag, plus relations from the sources (CAPEC → CWE exploited, CAPEC ↔ ATT&CK, CWE child-of). About 1 MB in total, embedded in the API binary (`go:embed`), so air-gapped installations need nothing else.

**Update.** `make threat-frameworks` runs `backend/cmd/pathos-frameworks`: it downloads each source of `frameworks/sources.json` (cache `~/.cache/pathos-frameworks`), refuses a file whose SHA-256 differs from the pin, and writes `frameworks/data/<framework>.json` with the release, source, SHA-256, licence and notice. To move to a new release: edit the release and URL in `sources.json`, run `go run ./cmd/pathos-frameworks -pin <framework>` (records the new SHA-256 for review), then `make threat-frameworks`, run the tests (`frameworks_test.go` checks that every rule mapping still exists) and commit the data with the pin.

## APIs

See the [API reference](../api-reference/threat-models.md). Summary: models (`/api/v1/threat-models`, list, create, get, patch, generate, versions, submit, approve, reject, diagram, export, import, settings), threats (`/api/v1/threat-models/{id}/threats`, `/api/v1/threats/{id}`), framework catalogue (`/api/v1/threat-frameworks`). `GET /api/v1/posture/attack-paths` gains the additive `application_id` filter.

## Protocols

JSON over HTTPS. Import formats: OWASP Threat Dragon v2 JSON (cells `process`, `store`, `actor`, `flow`, `trust-boundary-box`/`-curve` with `data.threats[]`; v1 `diagramJson` models are refused with a hint), PATHOS export (`pathos.threatmodel/v1`). Export formats: PATHOS JSON, Threat Dragon v2 JSON (PATHOS fields without a Threat Dragon place — rule, evidence label, confidence, accepted status, critical severity — are written into the threat description; critical is exported as High), a pytm model description (Python source: elements, boundaries and data flows; PATHOS threats as comments; strings are quoted literals, so text cannot become code), Markdown. Exports are stamped `Quditmind PATHOS v… · build … · generated …` (file and `X-PATHOS-Generated-By` header).

## Authentication

Session or API token. Permissions `threats.read`, `threats.manage` and `threats.approve` (separate from manage), added to `backend/internal/authz/catalog.go` and [RBAC_MATRIX.md](../RBAC_MATRIX.md): read for every system role (the read-only set), manage for security manager, security analyst, AppSec engineer and application owner, approve for security manager and independent reviewer. A model narrowed to a repository needs the permission on that repository; an application-wide model needs it on every active repository of the application (its evidence comes from all of them). Callers without access get 404.

## Security requirements

- Rule 4 and 5: no AI in generation; generated threats are `verified` or `observed` only (database check); manual and imported threats are "manual, unverified" / "imported, unverified" until linked to CodeGraph elements or findings that exist (checked against the latest snapshot and the application's findings).
- Separation of duties: approver ≠ author and ≠ submitter (service and `CHECK` on `threat_models`); approvals are append-only (trigger).
- Every change writes an audit entry (`threat_model.*`); severity and status changes require a reason (service and `CHECK` on `threat_events`).
- Secret references carry names and locations only; no secret value is read or exported.
- Imports are size-limited (10 MB, 2,000 elements, 5,000 threats) and parsed as data only; pytm is never executed.
- Tenant isolation: every table carries `organization_id` with the standard row-level security policy; the tenant isolation suite covers every route.

## Error handling

| Code | Meaning |
|---|---|
| PTH-TM-1001 | The status does not allow the action (409) |
| PTH-TM-1002 | No ready CodeGraph snapshot (409) |
| PTH-TM-1003 | Evidence reference not found (422) |
| PTH-TM-1004 | Submit refused: threats without mitigation (422) |
| PTH-TM-1005 | Approver is the author or submitter (409) |
| PTH-TM-1006 | Submit refused: unverified manual or imported threats (422) |
| PTH-TM-1007 | Severity or status change without a reason (422) |
| PTH-TM-1008 | A model already exists for the scope (409) |
| PTH-TM-1009 | Generated threats cannot be deleted (409) |
| PTH-TM-1010 | Generation could not be stored (500) |
| PTH-TM-1011 | Invalid request field (422) |
| PTH-TM-1101 | Import parse error, with the line or field (422) |
| PTH-TM-1102 | Import format not supported (415) |
| PTH-TM-1103 | Import too large (422) |

Generated pages: [docs/troubleshooting/tm.md](../troubleshooting/tm.md).

## Operations

Migrations 00052 (models, elements, threats, links, mappings), 00053 (approvals, threat events), 00054 (settings) are additive. The flag `threat_models` is off by default. `auto_update` (default on, `PUT /api/v1/threat-models/settings`) controls the feedback loop; its failures are logged with `PTH-TM-1010` and never affect the CodeGraph build. Data updates: see §5.

## Implementation status

Prototype behind the flag: engine, rules, attack paths, mappings, versions, review, regeneration, feedback loop, import and export, API, web pages and hub panel, unit and integration tests.

## Known limitations

- Absence rules (TM-S-001, TM-E-001, TM-R-001, TM-D-001, TM-D-002) rely on names: authentication in a gateway, a framework decorator or middleware registered outside the handler chain is not seen. Their confidence is lower and their severity is capped; set such threats not applicable with the reason.
- External calls record their scheme from the discovery engine version of this milestone on (`workers/graph`); older snapshots record `https` for every outbound call, so TM-I-001 fires only on newer snapshots.
- Threats cover what CodeGraph shows; frameworks and languages it does not parse produce no elements and no threats (the generation notes say so).
- The Threat Dragon round trip keeps titles, categories, severities (critical becomes High), statuses (accepted becomes Open), descriptions and mitigations; evidence does not survive a Threat Dragon round trip (re-link after import). PATHOS JSON keeps everything and re-links threats whose CodeGraph keys exist.
- Imported data flows without CodeGraph evidence are not drawn in the diagram (rule 5); the diagram response lists them as `unverified_flows`.

## Future improvements

AI-suggested threats behind review once the AI evidence record exists (M7); LINDDUN rules once CodeGraph can tag personal data; data-store TLS evidence; authentication middleware detection from framework routing (decorators, route groups); remediation items linked to threats (M8).
