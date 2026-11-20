---
title: Troubleshooting: Reverse engineering
section: troubleshooting
order: 109
version: "1.0"
updated: 2026-11-20
summary: Binary and artifact reverse engineering (12 codes, PTH-REA-*)
---

# Troubleshooting: Reverse engineering

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Binary and artifact reverse engineering.

| Code | Title | Severity |
|---|---|---|
| [PTH-REA-1001](#PTH-REA-1001) | Artifact refused: not from your own builds | warning |
| [PTH-REA-1002](#PTH-REA-1002) | No reverse-engineering worker online | warning |
| [PTH-REA-1003](#PTH-REA-1003) | The analysis failed in the sandbox | error |
| [PTH-REA-1004](#PTH-REA-1004) | The analysis timed out | warning |
| [PTH-REA-1005](#PTH-REA-1005) | Invalid analysis document | error |
| [PTH-REA-1006](#PTH-REA-1006) | Not an analysable artifact | warning |
| [PTH-REA-1007](#PTH-REA-1007) | Authorisations are disabled by the input policy | warning |
| [PTH-REA-1008](#PTH-REA-1008) | No source snapshot for the artifact's commit | info |
| [PTH-REA-1009](#PTH-REA-1009) | The analysis could not be stored | error |
| [PTH-REA-1010](#PTH-REA-1010) | Decompiled code is withheld from this AI model | warning |
| [PTH-REA-1011](#PTH-REA-1011) | The analysis is not ready | info |
| [PTH-REA-1012](#PTH-REA-1012) | The artifact does not match its verification or authorisation | error |

<a id="PTH-REA-1001"></a>

## PTH-REA-1001: Artifact refused: not from your own builds

| | |
|---|---|
| Severity | warning |
| Category | permission |
| HTTP status | 403 |
| AI help | not offered |
| Short codes | `rea_untrusted_artifact` |
| Raised in | internal/rea/service.go |

**What it means.** By default PATHOS analyses only artifacts it can tie to the organization's own builds: a verified signature or a verified SLSA provenance attestation (cosign). This artifact has neither and no active "analyse untrusted artifact" authorisation.

**Confirmed cause.** The newest signature verification of the artifact is not verified, its provenance attestation is not verified, and no active authorisation exists for this artifact's SHA-256. Confirmed automatically when this code is raised.

**Probable causes**

1. The artifact was uploaded without a signature or provenance attestation
2. The target has no signature policy (key or keyless identity), so nothing was verified
3. The artifact was never scanned since its signature was attached, so no verification is recorded
4. The artifact comes from a third party

**Impact.** The artifact was not analysed; nothing was queued.

**How to fix**

1. Sign the artifact in your build (cosign sign-blob --bundle) or attest its provenance (cosign attest-blob --type slsaprovenance1 --bundle) and upload the bundle with it.
2. Set the target's signature policy (Scan targets → the artifact → Signature verification) and scan the target once so the verification is recorded.
3. For a third-party artifact, ask a user with rea.authorize to authorise this artifact with a reason (Binary analysis → Authorise untrusted artifact), if the input policy allows it.

**Verify**

1. Binary analysis shows the artifact as Trusted or Authorised, and Analyse queues an analysis.


<a id="PTH-REA-1002"></a>

## PTH-REA-1002: No reverse-engineering worker online

| | |
|---|---|
| Severity | warning |
| Category | dependency |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `rea_no_worker` |
| Raised in | internal/rea/service.go |

**What it means.** Analyses run only on worker-rea workers (their own queue lane, analyser in the sandbox runner). No such worker of the organization reported in recently.

**Confirmed cause.** No registered worker that advertises pathos-rea was seen within the online window. Confirmed automatically when this code is raised.

**Probable causes**

1. The rea Compose profile is not enabled (COMPOSE_PROFILES=rea)
2. worker-rea or worker-rea-sandbox is stopped or restarting
3. The worker cannot reach the API's worker listener

**Impact.** Nothing was queued: an artifact is never analysed by another worker.

**How to fix**

1. Start the reverse-engineering workers: COMPOSE_PROFILES=rea docker compose up -d worker-rea worker-rea-sandbox.
2. Check docker compose logs worker-rea for registration errors (PTH-WORK codes).
3. Open Configurations → Reverse engineering tools: the installed tools appear once the worker is online.

**Verify**

1. GET /api/v1/rea/tools answers worker_online: true and Analyse queues an analysis.


<a id="PTH-REA-1003"></a>

## PTH-REA-1003: The analysis failed in the sandbox

| | |
|---|---|
| Severity | error |
| Category | dependency |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/worker/rea.go |

**What it means.** pathos-rea runs only in the sandbox runner (no network, its own UID, no worker token). It was not available, exited with an error or was killed.

**Confirmed cause.** The worker reported the pathos-rea step as failed (the analysis error names the reason: no sandbox runner, exit code or signal). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. worker-rea runs without its sandbox runner (PATHOS_SANDBOX_DIR not shared with worker-rea-sandbox)
2. The runner hit its memory limit (killed by SIGKILL) on a large artifact
3. A parser crashed on a malformed artifact

**Impact.** No facts were stored for this analysis; earlier analyses are unchanged.

**How to fix**

1. Check that worker-rea-sandbox is running and shares the rea_sandbox volume with worker-rea.
2. For memory kills raise PATHOS_REA_MEMORY (container limit) and the memory limit in Configurations → Reverse engineering tools, or disable the decompiler for this run.
3. Re-run the analysis; if it fails again, open the execution log from History.

**Verify**

1. A new analysis reaches status ready or partial.


<a id="PTH-REA-1004"></a>

## PTH-REA-1004: The analysis timed out

| | |
|---|---|
| Severity | warning |
| Category | timeout |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/worker/rea.go |

**What it means.** The analysis did not finish within the time limit of the reverse-engineering settings; the sandbox runner stopped every process.

**Confirmed cause.** The pathos-rea step ended with status timed_out. Confirmed automatically when this code is raised.

**Probable causes**

1. A large binary with the decompiler enabled
2. The time limit is lower than the artifact needs
3. The runner's CPU limit is low

**Impact.** No facts were stored for this analysis.

**How to fix**

1. Raise the time limit in Configurations → Reverse engineering tools (at most 230 minutes; an execution is limited to 4 hours).
2. Disable the decompiler for very large artifacts (triage still lists functions, imports and strings).
3. Raise PATHOS_REA_CPUS for the sandbox runner.

**Verify**

1. The next analysis finishes as ready or partial.


<a id="PTH-REA-1005"></a>

## PTH-REA-1005: Invalid analysis document

| | |
|---|---|
| Severity | error |
| Category | validation |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/rea/service.go |

**What it means.** The worker uploaded a document that is not a valid pathos.rea/v1 document (schema, limits, duplicate or dangling references).

**Confirmed cause.** Validation of the uploaded document failed (the analysis error names the first problem). Confirmed automatically when this code is raised.

**Probable causes**

1. The worker-rea image and the API are different PATHOS versions
2. The document was truncated or corrupted

**Impact.** Nothing was stored for this analysis.

**How to fix**

1. Run the worker-rea image of the same PATHOS version as the API.
2. Re-run the analysis.

**Verify**

1. A new analysis reaches ready.


<a id="PTH-REA-1006"></a>

## PTH-REA-1006: Not an analysable artifact

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `rea_not_artifact` |
| Raised in | internal/rea/service.go |

**What it means.** Reverse engineering analyses uploaded build artifacts and mobile app packages (scan targets of kind artifact or mobile-app).

**Confirmed cause.** The target is not an artifact or mobile app target, or it is disabled, or its repository is archived. Confirmed automatically when this code is raised.

**Probable causes**

1. An image, URL, API or SBOM target was chosen
2. The target or its repository was disabled or archived

**Impact.** Nothing was queued.

**How to fix**

1. Upload the build artifact as an artifact target (Scan targets → Upload artifact) with its signature or provenance.
2. Enable the target and its repository.

**Verify**

1. The artifact appears in Binary analysis.


<a id="PTH-REA-1007"></a>

## PTH-REA-1007: Authorisations are disabled by the input policy

| | |
|---|---|
| Severity | warning |
| Category | permission |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `rea_authorization_disabled` |
| Raised in | internal/rea/service.go |

**What it means.** The organization's input policy is "own builds only": untrusted artifacts cannot be authorised for analysis.

**Confirmed cause.** rea_settings.input_policy is own_builds_only. Confirmed automatically when this code is raised.

**Probable causes**

1. An administrator chose the strict policy

**Impact.** No authorisation was recorded.

**How to fix**

1. Analyse a signed or attested artifact from your own build instead.
2. If third-party analysis is intended, an administrator with scanners.manage can switch the input policy in Configurations → Reverse engineering tools.

**Verify**

1. The Authorise action is available and records the authorisation.


<a id="PTH-REA-1008"></a>

## PTH-REA-1008: No source snapshot for the artifact's commit

| | |
|---|---|
| Severity | info |
| Category | dependency |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `rea_no_source_snapshot` |
| Raised in | internal/rea/service.go |

**What it means.** The source ↔ binary diff compares the binary with the CodeGraph snapshot of the commit the artifact was built from (from its provenance or build information). No ready source snapshot of that commit exists, or the chosen snapshot is not of the artifact's repository.

**Confirmed cause.** No ready CodeGraph source snapshot of the artifact's repository has the commit, or the requested snapshot belongs to another repository. Confirmed automatically when this code is raised.

**Probable causes**

1. CodeGraph was not built for that commit
2. The artifact has no provenance and no embedded build information, so the commit is unknown
3. The codegraph flag is off

**Impact.** The binary facts are available; the diff is not.

**How to fix**

1. Build CodeGraph for the artifact's repository at the commit (CodeGraph → Build), then recompute the diff.
2. Or choose a source snapshot for the diff (Source ↔ binary → Compare with snapshot); the diff is then labelled as chosen by a person.

**Verify**

1. Source ↔ binary shows matched, binary-only and source-only items.


<a id="PTH-REA-1009"></a>

## PTH-REA-1009: The analysis could not be stored

| | |
|---|---|
| Severity | error |
| Category | internal |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/rea/service.go |

**What it means.** Storing the binary graph, the code views or the diff failed in the database.

**Confirmed cause.** The store transaction failed (the server log has the database error with this code). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The database is unavailable or out of space
2. A very large graph exceeded a statement limit

**Impact.** The analysis is marked failed; earlier analyses are unchanged.

**How to fix**

1. Check the API log lines with error_code PTH-REA-1009.
2. Check database health and free space, then re-run the analysis.

**Verify**

1. A new analysis reaches ready.


<a id="PTH-REA-1010"></a>

## PTH-REA-1010: Decompiled code is withheld from this AI model

| | |
|---|---|
| Severity | warning |
| Category | permission |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `rea_code_withheld` |
| Raised in | internal/rea/service.go |

**What it means.** Decompiled code is source-equivalent. The reverse-engineering setting decides which AI model may see it: none (default), local (self-hosted providers only) or cloud, and cloud also needs the AI configuration to allow sending code (send code context).

**Confirmed cause.** The requested model or setting is not allowed by the decompiled-code policy (the message names the rule). Confirmed automatically when this code is raised.

**Probable causes**

1. The policy is none (the default)
2. The default AI configuration uses a cloud provider while the policy is local
3. Cloud was chosen while the AI configuration does not allow sending code

**Impact.** No decompiled code was sent to an AI model.

**How to fix**

1. Keep decompiled code away from AI (recommended for third-party code), or
2. Configure a self-hosted model and set the policy to local, or
3. Allow sending code in AI settings first, then choose cloud (an explicit, audited decision).

**Verify**

1. Configurations → Reverse engineering tools saves the chosen policy.


<a id="PTH-REA-1011"></a>

## PTH-REA-1011: The analysis is not ready

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `rea_not_ready` |
| Raised in | internal/rea/service.go |

**What it means.** The facts, graph and diff of an analysis can be read once it is ready or partial.

**Confirmed cause.** The analysis status is queued, running or failed. Confirmed automatically when this code is raised.

**Probable causes**

1. The analysis is still queued or running
2. The analysis failed (see its error)

**Impact.** Nothing to show yet.

**How to fix**

1. Wait for the analysis to finish (History shows its status).
2. For a failed analysis, fix the cause shown and run it again.

**Verify**

1. The analysis shows ready or partial.


<a id="PTH-REA-1012"></a>

## PTH-REA-1012: The artifact does not match its verification or authorisation

| | |
|---|---|
| Severity | error |
| Category | integrity |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `rea_artifact_mismatch` |
| Raised in | internal/rea/service.go |

**What it means.** A verification or authorisation applies to one artifact SHA-256. The provenance statement does not name this artifact, or the authorisation was given for another file.

**Confirmed cause.** The SHA-256 of the artifact differs from the attested subject or the authorised digest. Confirmed automatically when this code is raised.

**Probable causes**

1. The provenance attestation belongs to another build
2. The authorisation was recorded for an earlier upload

**Impact.** The artifact is treated as untrusted.

**How to fix**

1. Upload the provenance attestation produced for this exact artifact.
2. Authorise the current artifact again with a reason.

**Verify**

1. The artifact shows as Trusted or Authorised.

