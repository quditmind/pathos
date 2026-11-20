---
title: Threat models
section: api-reference
order: 9
version: "3.0"
updated: 2026-11-20
summary: Create, generate, edit, review, approve, import and export threat models of an application, built by the STRIDE rule engine on CodeGraph snapshots and the attack paths, with ATT&CK, CAPEC, CWE and D3FEND mappings. Behind the threat_models feature flag.
---
# Threat models

A **threat model** belongs to an application (optionally narrowed to one repository). PATHOS builds it from the application's latest ready [CodeGraph](codegraph.md) snapshots with a deterministic STRIDE rule engine and from the [attack paths](posture.md) of the application. People then edit it (add manual threats, change severity or status with a reason, write and link mitigations) and approve it (draft → in review → approved; the approver is never the author). The [user guide](../user-guide/threat-models.md) explains the workflow; the design and the rule catalogue are in [PATHOS_THREAT_MODELLING.md](../aspm/PATHOS_THREAT_MODELLING.md).

Every endpoint answers `404` with `PTH-PLAT-1007` (`feature_disabled`) while the organization's `threat_models` feature flag is off (Administration → Feature flags). Changes write an audit log entry (`threat_model.*`).

## Permissions

| Operation | Permission |
|---|---|
| List, read, versions, threats, diagram, export | `threats.read` |
| Create, generate, edit, add and delete threats, submit, new version, import | `threats.manage` |
| Approve, reject, request changes | `threats.approve` (separate from `threats.manage`; the approver must not be the version's author or submitter) |
| Read and change settings | `threats.read` / `threats.manage` organization-wide |
| Framework catalogue (`/threat-frameworks`) | any authenticated user |

Scope: a model narrowed to a repository needs the permission on that repository. An application-wide model needs it on **every** active repository of the application (organization-wide grants cover all), because its evidence comes from all of them. Callers without it get `404`.

## Objects

### Threat model (one version)

```json
{ "id": "0196…", "lineage_id": "0196…", "version": 2, "status": "draft",
  "application_id": "0196…", "application_name": "Payments", "repository_id": null, "repository_name": "",
  "title": "Payments threat model", "summary": "", "method": "stride", "imported_format": "",
  "codegraph_snapshot_ids": ["0196…"], "generated_at": "2026-11-20T10:00:00Z",
  "generation": { "engines": ["stride", "attack_paths"], "rules": [{ "id": "TM-S-001", "version": "1", "threats": 3 }],
                  "snapshots": [{ "id": "0196…", "repository_id": "0196…", "repository_name": "payments-api", "commit_sha": "…", "status": "ready" }],
                  "counts": { "new": 4, "changed": 1, "unchanged": 9, "resolved": 2 }, "notes": ["…"] },
  "created_by": { "id": "0196…", "name": "Ana" }, "created_at": "…", "updated_at": "…",
  "submitted_by": null, "submitted_at": null, "approved_by": null, "approved_at": null, "previous_version_id": "0196…",
  "counts": { "total": 14, "open": 10, "mitigated": 2, "accepted": 1, "not_applicable": 1,
              "by_severity": { "high": 3 }, "by_category": { "spoofing": 2 }, "unverified": 0, "without_mitigation": 0 },
  "can_edit": true, "can_approve": false }
```

| Field | Meaning |
|---|---|
| `lineage_id` | Shared by all versions of the same model |
| `status` | `draft` (editable), `in_review` (read-only, waiting for an approver), `approved`, `superseded` (an older approved version), `archived` |
| `method` | `stride` (generated), `manual`, `imported` |
| `generation` | What the last generation used and produced. `notes` say what the graph does not cover (for example "no routes found: entry-point rules produced nothing") |
| `can_edit`, `can_approve` | What the caller may do with this version now |

### Threat

```json
{ "id": "0196…", "threat_model_id": "0196…", "fingerprint": "TM-S-001|0196…|route:POST /api/orders",
  "title": "Unauthenticated entry point POST /api/orders", "description": "…",
  "category": "spoofing", "method": "rule", "rule_id": "TM-S-001", "rule_version": "1",
  "evidence_type": "verified", "label": "verified",
  "severity": "high", "severity_reason": "Base medium (rule TM-S-001); raised: internet-facing (Ingress shop, deploy/k8s/api.yaml:35)",
  "severity_overridden": false, "confidence": 0.6, "confidence_reason": "Absence of evidence: no authentication function found on the handler chain (depth 4)",
  "status": "open", "status_reason": "", "mitigation": "Require authentication …", "mitigation_edited": false,
  "change_state": "new", "owner": null,
  "evidence": { "snapshot_id": "0196…", "repository_id": "0196…", "rule": { "id": "TM-S-001", "version": "1", "logic": "…" },
                "nodes": [{ "id": "0196…", "key": "route:POST /api/orders", "type": "route", "label": "POST /api/orders", "file": "api/orders.go", "line": 24 }],
                "edges": [{ "id": "0196…", "key": "…", "source": "route:POST /api/orders", "target": "tb:http-ingress", "type": "crosses_boundary",
                            "evidence": "verified", "refs": [{ "kind": "file_line", "ref": "api/orders.go:24", "detail": "chi route POST /api/orders" }] }],
                "absent": ["no function matching authentication patterns on the handler chain"],
                "exposure": { "level": "internet", "reasons": ["Ingress shop crosses the internet boundary (deploy/k8s/api.yaml:35)"] },
                "runtime": [], "links": [{ "label": "Open in CodeGraph", "href": "/codegraph/0196…?snapshot=…&node=…" }] },
  "elements": [{ "id": "0196…", "kind": "process", "name": "POST /api/orders", "codegraph_key": "route:POST /api/orders", "node_type": "route", "repository_id": "0196…" }],
  "findings": [{ "id": "0196…", "title": "…", "severity": "high", "status": "open", "cwe": "CWE-89", "href": "/findings?finding=0196…" }],
  "mappings": [{ "framework": "attack", "id": "T1190", "name": "Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190", "source": "rule" }],
  "created_at": "…", "updated_at": "…" }
```

| Field | Meaning |
|---|---|
| `category` | STRIDE: `spoofing`, `tampering`, `repudiation`, `information_disclosure`, `denial_of_service`, `elevation_of_privilege`; LINDDUN (manual or imported only): `linking`, `identifying`, `non_repudiation`, `detecting`, `data_disclosure`, `unawareness`, `non_compliance` |
| `method` | `rule` (STRIDE rule engine), `attack_path` (an attack path of the application), `manual`, `imported`. `ai` is reserved: PATHOS has no AI threat suggestion endpoint yet |
| `rule_id`, `rule_version` | The rule (`TM-…`) and its version for `rule` and `attack_path` threats |
| `evidence_type`, `label` | `verified` (static CodeGraph evidence or a finding), `observed` (runtime evidence was used), `unverified` (a manual or imported threat not yet linked to evidence; label "manual, unverified" or "imported, unverified"). `ai_inferred` is reserved |
| `evidence` | CodeGraph nodes and edges with their evidence references, what the rule looked for and did not find (`absent`), exposure, runtime facts, the attack path, links |
| `severity_reason`, `confidence_reason` | How the engine derived them; a manual change records the person's reason instead |
| `severity_overridden`, `mitigation_edited` | A person changed it: regeneration keeps it |
| `change_state` | Against the previous generation: `new`, `changed` (evidence changed), `unchanged`, `resolved` (the rule no longer finds it in the new snapshot). Empty for manual and imported threats |
| `status` | `open`, `mitigated`, `accepted`, `not_applicable` |
| `mappings[].source` | `rule` (the rule's table), `finding` (CWE of a linked finding), `user`, `imported` |

## Endpoints

| Method and path | Permission | Request | Response | Errors |
|---|---|---|---|---|
| `GET /api/v1/threat-models` | `threats.read` | `?application_id=&status=` | `{items: [model]}` (latest version of each model in scope) | — |
| `POST /api/v1/threat-models` | `threats.manage` | `{application_id, repository_id?, title, summary?, generate?: true}` | Model v1, `draft` (`201`); generated at once when `generate` is true and a snapshot is ready | `409` `PTH-TM-1008` (a model exists for this application and repository); `409` `PTH-TM-1002` (generate without a ready snapshot); `422` |
| `GET /api/v1/threat-models/{id}` | `threats.read` | — | `{model, elements, versions}` | `404` |
| `PATCH /api/v1/threat-models/{id}` | `threats.manage` | `{title?, summary?}` | Model | `409` `PTH-TM-1001` (not a draft) |
| `POST /api/v1/threat-models/{id}/generate` | `threats.manage` | `{engines?: ["stride", "attack_paths"]}` | `{model, result: {new, changed, unchanged, resolved, created_version}}`. On a draft it regenerates in place; on an approved or in-review version it creates the next draft version first (`created_version: true`) | `409` `PTH-TM-1002` (no ready CodeGraph snapshot); `409` `PTH-TM-1001` (a newer draft exists: generate that one) |
| `POST /api/v1/threat-models/{id}/versions` | `threats.manage` | — | The next draft version, copied from this one with every human edit (`201`) | `409` `PTH-TM-1001` (a draft or in-review version exists) |
| `GET /api/v1/threat-models/{id}/versions` | `threats.read` | — | `{items: [model], approvals: [approval]}` for the whole lineage | `404` |
| `GET /api/v1/threat-models/{id}/threats` | `threats.read` | `?status=&category=&severity=&change_state=&method=` | `{items: [threat]}` | `404` |
| `POST /api/v1/threat-models/{id}/threats` | `threats.manage` | `{title, description?, category, severity, mitigation?, element_keys?: [{repository_id, key}], finding_ids?: [], mappings?: [{framework, id}]}` | Manual threat (`201`): `verified` with CodeGraph keys or findings that exist, else "manual, unverified" | `409` `PTH-TM-1001`; `422` `PTH-TM-1003` (a key or finding does not exist) |
| `GET /api/v1/threats/{id}` | `threats.read` | — | `{threat, events: [event]}` | `404` |
| `PATCH /api/v1/threats/{id}` | `threats.manage` | `{severity?, status?, reason?, mitigation?, owner_id?, title?, description?, link?: {element_keys?, finding_ids?}, unlink_findings?: [], mappings_add?: [{framework, id}], mappings_remove?: [{framework, id}]}` | Threat | `409` `PTH-TM-1001`; `422` `PTH-TM-1007` (severity or status changed without `reason`); `422` `PTH-TM-1003` (link to a key or finding that does not exist); `422` (unknown framework entry) |
| `DELETE /api/v1/threats/{id}` | `threats.manage` | — | `204`. Manual and imported threats only | `409` `PTH-TM-1009` (generated threat: set it `not_applicable` instead); `409` `PTH-TM-1001` |
| `POST /api/v1/threat-models/{id}/submit` | `threats.manage` | `{note?}` | Model `in_review` | `409` `PTH-TM-1001`; `422` `PTH-TM-1004` (an open or accepted threat has no mitigation); `422` `PTH-TM-1006` (a manual or imported threat is not linked to evidence and not `not_applicable`) |
| `POST /api/v1/threat-models/{id}/approve` | `threats.approve` | `{note?}` | Model `approved`; the previous approved version becomes `superseded` | `409` `PTH-TM-1005` (approver is the author or submitter); `409` `PTH-TM-1001` (not in review) |
| `POST /api/v1/threat-models/{id}/reject` | `threats.approve` | `{note, decision?: "rejected" \| "changes_requested"}` | Model back to `draft` | `409` `PTH-TM-1005`; `409` `PTH-TM-1001`; `422` (note required) |
| `GET /api/v1/threat-models/{id}/diagram` | `threats.read` | — | Graph data for the shared graph component: the model's elements as nodes (open threats by severity in `finding_counts`, `attrs.threats`, `attrs.dfd_kind`) and its data flows as edges with their evidence | `404` |
| `GET /api/v1/threat-models/{id}/export` | `threats.read` | `?format=pathos\|threat_dragon\|pytm\|markdown` | File download, stamped with the PATHOS version, build and time (`Quditmind PATHOS v… · build … · generated …`). Exports that contain framework names carry the MITRE notices | `400` (unknown format) |
| `POST /api/v1/threat-models/import` | `threats.manage` | `{application_id, repository_id?, format: "threat_dragon" \| "pathos", title?, document: {…}}` (max 10 MB) | Model v1 `draft`, method `imported` (`201`). Imported threats are "imported, unverified" until linked; a PATHOS export's threats whose CodeGraph keys exist in the application's latest snapshot are linked at once | `415` `PTH-TM-1102` (format not importable, e.g. `pytm`: PATHOS never runs Python); `422` `PTH-TM-1101` (parse error, with the JSON path); `422` `PTH-TM-1103` (too many elements or threats); `409` `PTH-TM-1008` |
| `GET`, `PUT /api/v1/threat-models/settings` | read / manage org-wide | `{auto_update: bool}` | Settings | — |
| `GET /api/v1/threat-frameworks` | Authenticated | — | `{frameworks: [release], rules: [rule], stride: [category], linddun: [category], notices: [text]}` | — |
| `GET /api/v1/threat-frameworks/{framework}/entries` | Authenticated | `?q=&limit=` (≤ 100) | `{framework, release, notice, items: [entry]}` | `404` (unknown framework) |

`framework` is `attack`, `capec`, `cwe`, `d3fend` or `linddun` (the seven category names only, cited, see [licences](../aspm/PATHOS_THREAT_MODELLING.md#5-framework-data-and-licences)).

### Approval and event

```json
{ "id": "0196…", "threat_model_id": "0196…", "version": 2, "decision": "approved", "actor": { "id": "0196…", "name": "Lee" }, "note": "", "decided_at": "…" }
{ "id": "0196…", "action": "severity_changed", "from": "high", "to": "medium", "reason": "Behind the VPN", "actor": { "id": "…", "name": "Ana" }, "at": "…" }
```

`decision` is `submitted`, `approved`, `rejected` or `changes_requested`. Event actions: `created`, `regenerated`, `severity_changed`, `status_changed`, `mitigation_changed`, `linked`, `unlinked`, `mapping_added`, `mapping_removed`, `edited`, `copied`.

## Regeneration and the architecture feedback loop

Each generated threat has a **fingerprint** (rule, repository, element). Regenerating matches fingerprints: a threat found again keeps its status, its reason, its owner, a severity a person changed and a mitigation a person wrote, and gets fresh evidence (`change_state` `changed` when the evidence differs, else `unchanged`); a threat not found again is kept with `change_state` `resolved`; a new one is `new`. Manual and imported threats are never touched.

When a new CodeGraph snapshot of an application becomes ready and `auto_update` is on (default), PATHOS regenerates each of the application's threat models in a draft: an existing draft in place, otherwise a new draft version after the approved one (an in-review version is left alone until it is decided). The audit log records `threat_model.auto_update`.

## Errors

| Code | HTTP | Meaning |
|---|---|---|
| `PTH-TM-1001` | 409 | The model's status does not allow this action (edit a non-draft, approve a version that is not in review, a newer draft exists) |
| `PTH-TM-1002` | 409 | No ready CodeGraph snapshot for the application (build one first) |
| `PTH-TM-1003` | 422 | Evidence reference that does not exist (CodeGraph key or finding) |
| `PTH-TM-1004` | 422 | Submit refused: open or accepted threats without a mitigation |
| `PTH-TM-1005` | 409 | The approver is the version's author or submitter |
| `PTH-TM-1006` | 422 | Submit refused: manual or imported threats not linked to evidence |
| `PTH-TM-1007` | 422 | Severity or status changed without a reason |
| `PTH-TM-1008` | 409 | A threat model already exists for this application and repository |
| `PTH-TM-1009` | 409 | Generated threats cannot be deleted; set them not applicable |
| `PTH-TM-1010` | 500 | Generation could not be stored |
| `PTH-TM-1011` | 422 | A request field is missing, too long or not allowed (short code `threat_model_invalid`) |
| `PTH-TM-1101` | 422 | The import file could not be parsed |
| `PTH-TM-1102` | 415 | The import format is not supported |
| `PTH-TM-1103` | 422 | The import file has too many elements or threats |

Troubleshooting pages: [docs/troubleshooting/tm.md](../troubleshooting/tm.md).
