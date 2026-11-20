---
title: Troubleshooting: Threat modelling
section: troubleshooting
order: 108
version: "1.0"
updated: 2026-11-20
summary: Threat models and attack paths (14 codes, PTH-TM-*)
---

# Troubleshooting: Threat modelling

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Threat models and attack paths.

| Code | Title | Severity |
|---|---|---|
| [PTH-TM-1001](#PTH-TM-1001) | The threat model's status does not allow this action | warning |
| [PTH-TM-1002](#PTH-TM-1002) | No ready CodeGraph snapshot for the application | warning |
| [PTH-TM-1003](#PTH-TM-1003) | Evidence reference not found | warning |
| [PTH-TM-1004](#PTH-TM-1004) | Threats without a mitigation | warning |
| [PTH-TM-1005](#PTH-TM-1005) | The approver is the author | warning |
| [PTH-TM-1006](#PTH-TM-1006) | Threats not linked to evidence | warning |
| [PTH-TM-1007](#PTH-TM-1007) | A reason is required | info |
| [PTH-TM-1008](#PTH-TM-1008) | A threat model already exists | info |
| [PTH-TM-1009](#PTH-TM-1009) | Generated threats cannot be deleted | info |
| [PTH-TM-1010](#PTH-TM-1010) | Threat generation could not be stored | error |
| [PTH-TM-1011](#PTH-TM-1011) | The threat-model request is invalid | info |
| [PTH-TM-1101](#PTH-TM-1101) | The import file could not be parsed | warning |
| [PTH-TM-1102](#PTH-TM-1102) | The import format is not supported | info |
| [PTH-TM-1103](#PTH-TM-1103) | The import file is too large | warning |

<a id="PTH-TM-1001"></a>

## PTH-TM-1001: The threat model's status does not allow this action

| | |
|---|---|
| Severity | warning |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `threat_model_state` |
| Raised in | internal/threatmodel/service.go |

**What it means.** Only a draft version can be edited or generated in place; only a version in review can be approved or rejected; a new version cannot be started while a draft or in-review version exists.

**Confirmed cause.** The version's status is not the one the action needs (the message names it). Confirmed automatically when this code is raised.

**Probable causes**

1. The version was submitted or approved meanwhile
2. Another person started a new draft version

**Impact.** Nothing was changed.

**How to fix**

1. Reload the model and open its latest version.
2. To change an approved model, start a new version (New version) and edit the draft.
3. To change a model in review, ask an approver to request changes, which returns it to draft.

**Verify**

1. The action succeeds on the draft version.


<a id="PTH-TM-1002"></a>

## PTH-TM-1002: No ready CodeGraph snapshot for the application

| | |
|---|---|
| Severity | warning |
| Category | dependency |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `no_codegraph_snapshot` |
| Raised in | internal/threatmodel/service.go |

**What it means.** Threats are generated from the application's CodeGraph snapshots, and none of its repositories (in the caller's scope) has a ready or partial snapshot.

**Confirmed cause.** No snapshot with status ready or partial exists for the application's repositories. Confirmed automatically when this code is raised.

**Probable causes**

1. CodeGraph was never built for the application
2. The last build failed or is still running
3. The codegraph feature flag is off

**Impact.** Nothing was generated; existing threats are unchanged.

**How to fix**

1. Open CodeGraph for the application and build it (the codegraph flag must be on and a worker-graph worker online).
2. Wait for the snapshot to reach ready, then generate again.

**Verify**

1. Generate answers 200 and the model lists generated threats.


<a id="PTH-TM-1003"></a>

## PTH-TM-1003: Evidence reference not found

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `threat_evidence_not_found` |
| Raised in | internal/threatmodel/service.go |

**What it means.** A manual threat or an evidence link names a CodeGraph element or a finding that does not exist in the application's latest snapshot or in the caller's findings.

**Confirmed cause.** The named CodeGraph key or finding id was not found (the message names it). Confirmed automatically when this code is raised.

**Probable causes**

1. The element was renamed or removed in the latest snapshot
2. The finding belongs to another application or is outside your scope
3. A typing error in the key

**Impact.** The threat was not created or linked.

**How to fix**

1. Copy the key from the CodeGraph inspector of the latest snapshot.
2. Check the finding is in a repository of this application.

**Verify**

1. The threat shows the evidence label verified.


<a id="PTH-TM-1004"></a>

## PTH-TM-1004: Threats without a mitigation

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `threat_without_mitigation`, `threat_model_empty` |
| Raised in | internal/threatmodel/service.go |

**What it means.** A threat model can be submitted for review only when every open or accepted threat has a mitigation.

**Confirmed cause.** At least one open or accepted threat has an empty mitigation (the message gives the count). Confirmed automatically when this code is raised.

**Probable causes**

1. Manual or imported threats added without a mitigation
2. A mitigation was cleared

**Impact.** The model stays a draft.

**How to fix**

1. Filter the threat table by "without mitigation" and write one for each, or set the threat to not applicable with a reason.
2. Submit again.

**Verify**

1. Submit moves the model to in review.


<a id="PTH-TM-1005"></a>

## PTH-TM-1005: The approver is the author

| | |
|---|---|
| Severity | warning |
| Category | permission |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `threat_model_self_approval` |
| Raised in | internal/threatmodel/service.go |

**What it means.** A threat model version must be approved or rejected by someone other than the person who created or submitted it (separation of duties).

**Confirmed cause.** The caller created or submitted this version. Confirmed automatically when this code is raised.

**Probable causes**

1. The author tried to approve their own model

**Impact.** The decision was not recorded.

**How to fix**

1. Ask another person with the threats.approve permission to review the model.

**Verify**

1. The other approver's decision appears in the Versions tab.


<a id="PTH-TM-1006"></a>

## PTH-TM-1006: Threats not linked to evidence

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `threat_unverified` |
| Raised in | internal/threatmodel/service.go |

**What it means.** Manual and imported threats are "unverified" until they are linked to CodeGraph elements or findings. A model can be submitted only when each of them is linked or set to not applicable.

**Confirmed cause.** At least one manual or imported threat is unverified and not marked not applicable (the message gives the count). Confirmed automatically when this code is raised.

**Probable causes**

1. A Threat Dragon import whose elements are not in CodeGraph
2. Manual threats added without evidence

**Impact.** The model stays a draft.

**How to fix**

1. Filter the threat table by the label "unverified".
2. Link each threat to a CodeGraph element or a finding (Link evidence), or set it to not applicable with a reason.

**Verify**

1. No threat shows the label unverified; submit succeeds.


<a id="PTH-TM-1007"></a>

## PTH-TM-1007: A reason is required

| | |
|---|---|
| Severity | info |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `threat_reason_required` |
| Raised in | internal/threatmodel/service.go |

**What it means.** Changing a threat's severity or status is recorded with the reason the person gives; a change without a reason is refused.

**Confirmed cause.** The request changes severity or status and its reason is empty. Confirmed automatically when this code is raised.

**Probable causes**

1. The reason field was left empty

**Impact.** Nothing was changed.

**How to fix**

1. Enter the reason (for example "behind the VPN, not reachable from the internet") and save again.

**Verify**

1. The threat's history shows the change and its reason.


<a id="PTH-TM-1008"></a>

## PTH-TM-1008: A threat model already exists

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `threat_model_exists` |
| Raised in | internal/threatmodel/service.go |

**What it means.** An application has one threat model per scope (the whole application, or one repository). New threats go into a new version of the existing model.

**Confirmed cause.** A model with the same application and repository scope exists. Confirmed automatically when this code is raised.

**Probable causes**

1. The model was created earlier, possibly by an import

**Impact.** No model was created.

**How to fix**

1. Open the existing model (Threat models list, filter by application).
2. Start a new version there, or create a model narrowed to one repository.

**Verify**

1. The list shows one model for the scope.


<a id="PTH-TM-1009"></a>

## PTH-TM-1009: Generated threats cannot be deleted

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `threat_generated` |
| Raised in | internal/threatmodel/service.go |

**What it means.** A threat generated by a rule or an attack path would come back at the next generation, so it is never deleted: it is set to not applicable with a reason, which regeneration keeps.

**Confirmed cause.** The threat's method is rule or attack_path. Confirmed automatically when this code is raised.

**Probable causes**

1. Delete was used on a generated threat

**Impact.** The threat is unchanged.

**How to fix**

1. Set the status to not applicable and give the reason.

**Verify**

1. The threat shows not applicable; a regeneration keeps that status.


<a id="PTH-TM-1010"></a>

## PTH-TM-1010: Threat generation could not be stored

| | |
|---|---|
| Severity | error |
| Category | internal |
| HTTP status | 500 |
| AI help | offered |
| Short codes | `threat_generation_failed` |
| Raised in | internal/threatmodel/generate.go |

**What it means.** The STRIDE engine or the attack-path query ran, but writing the result failed (database error or a constraint refused a threat).

**Confirmed cause.** The database refused the generation transaction (the API log has the request id and the error). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The database is unavailable or out of space
2. A very large graph exceeded a size limit
3. A PATHOS bug (a threat without its rule or evidence)

**Impact.** The model is unchanged (the transaction was rolled back).

**How to fix**

1. Retry the generation.
2. Check the API log for the request id and the database error.
3. If it repeats, report it with the request id.

**Verify**

1. Generate answers 200.


<a id="PTH-TM-1011"></a>

## PTH-TM-1011: The threat-model request is invalid

| | |
|---|---|
| Severity | info |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `threat_model_invalid` |
| Raised in | internal/threatmodel/service.go |

**What it means.** A field of the request is missing, too long or not one of its allowed values (title, summary, category, severity, status, confidence, owner, repository, framework entry, review note), or a generated threat's rule text was edited.

**Confirmed cause.** Validation of the request failed (the message names the field). Confirmed automatically when this code is raised.

**Probable causes**

1. A required field was left empty
2. A value outside the allowed list (for example a severity or a framework id that is not in the bundled data)
3. A generated threat's title or description was edited (only manual and imported threats can be renamed)

**Impact.** Nothing was changed.

**How to fix**

1. Correct the field the message names and send the request again.
2. Look up framework ids with GET /api/v1/threat-frameworks/{framework}/entries.

**Verify**

1. The request succeeds.


<a id="PTH-TM-1101"></a>

## PTH-TM-1101: The import file could not be parsed

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `threat_import_parse` |
| Raised in | internal/threatmodel/importexport.go |

**What it means.** The uploaded document is not valid JSON of the chosen format (OWASP Threat Dragon v2 or a PATHOS export), or a required field is missing.

**Confirmed cause.** Parsing failed at the position or field the message names. Confirmed automatically when this code is raised.

**Probable causes**

1. A Threat Dragon v1 model (convert it to v2 in Threat Dragon first)
2. The wrong format was chosen
3. The file was truncated

**Impact.** Nothing was imported.

**How to fix**

1. Open the file in Threat Dragon 2 and save it again, or export it again from PATHOS.
2. Choose the format that matches the file.

**Verify**

1. The import creates a draft model.


<a id="PTH-TM-1102"></a>

## PTH-TM-1102: The import format is not supported

| | |
|---|---|
| Severity | info |
| Category | validation |
| HTTP status | 415 |
| AI help | not offered |
| Short codes | `threat_import_format` |
| Raised in | internal/threatmodel/importexport.go |

**What it means.** PATHOS imports OWASP Threat Dragon v2 JSON and PATHOS threat-model exports. pytm models are Python programs, which PATHOS never runs, so they can be exported but not imported.

**Confirmed cause.** The format is not threat_dragon or pathos. Confirmed automatically when this code is raised.

**Probable causes**

1. A pytm or Threagile model was uploaded

**Impact.** Nothing was imported.

**How to fix**

1. Export the model from its tool as Threat Dragon v2 JSON if it can, or add the threats manually.

**Verify**

1. The import creates a draft model.


<a id="PTH-TM-1103"></a>

## PTH-TM-1103: The import file is too large

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `threat_import_too_large` |
| Raised in | internal/threatmodel/importexport.go |

**What it means.** An import may hold at most 2,000 diagram elements and 5,000 threats (and 10 MB).

**Confirmed cause.** The document exceeds a limit (the message names it). Confirmed automatically when this code is raised.

**Probable causes**

1. Several models were combined into one file

**Impact.** Nothing was imported.

**How to fix**

1. Split the model into several models (one per repository) and import each.

**Verify**

1. Each import creates a draft model.

