---
title: Continuous monitoring and architecture drift
section: api-reference
order: 17
version: "3.0"
updated: 2026-11-20
summary: The continuous monitoring feed of the lifecycle feedback loops, architecture drift between CodeGraph snapshots, drift alert settings, and the version stamp of every export. Behind the continuous_monitoring flag.
---

# Continuous monitoring and architecture drift

Quditmind PATHOS · applies to v3.0 (unreleased) · status: Prototype (feature flag `continuous_monitoring`, off by default)

Every endpoint on this page answers `404 feature_disabled` (`PTH-PLAT-1007`) while the flag is off for the organization. Errors use the [standard envelope](index.md#errors) with the catalogue code in `error.error_code` ([troubleshooting: MON](../troubleshooting/mon.md)). Rows are limited to the caller's scope: an event or drift of a repository is visible with `findings.read` on that repository; an application-level event only when every active repository of the application is in scope.

## Feed

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/monitoring/types` | `findings.read` | `{ items: [{ type, label, loop, description }] }`: the event types (below) |
| `GET` | `/api/v1/monitoring/events` | `findings.read`; `findings.export` for CSV | Query: `application_id`, `repository_id`, `type` (comma list), `severity` (comma list of `critical,high,medium,low,info`), `loop` (1–7), `since`, `until` (RFC 3339), `cursor`, `limit` (1–200, default 50), `format=csv`. Returns `{ items, next_cursor }`, newest first (keyset on the time-ordered id). `format=csv` downloads at most 10,000 rows with the version stamp headers (audited `monitoring.export`) |
| `GET` | `/api/v1/monitoring/summary` | `findings.read` | Query: `application_id`, `days` (1–365, default 30). `{ days, total, by_type, by_severity, latest_at, drift: { total, with_changes, latest_at } }` |

**Event** fields: `id, type, type_label, loop (1–7 or null), severity, title, summary, evidence_label (verified|observed|ai_inferred), evidence (references: snapshot ids, commit, scan job, gate decision, verification, threat model, feeds), application_id, application_name, repository_id, repository_name, subject_type, subject_id, link (in-app path), details, created_at`. Events are never updated, except that the commit of drift-related evidence is filled in once the discovery execution reports it. They are kept for 365 days.

| Type | Loop | Recorded when |
|---|---|---|
| `rediscovery.queued` | 1 | A finished scan of a new commit (push, merge, schedule, manual) queued a CodeGraph rediscovery (codegraph flag, automatic rediscovery and its rate limit) |
| `dependency.changed` | 2 | A new snapshot's components differ from the previous snapshot's: component policies were re-evaluated, the repository's dependency findings marked for re-scoring; `details.not_in_scanned_sbom` counts components the next scan still has to assess |
| `architecture.drift` | 3 | A new snapshot changed routes, API operations, external services, datastores, queues, internet exposure, trust-boundary crossings or components |
| `threat_model.updated` | 3 | The threat model draft was regenerated from the new snapshot (an approved version is never changed: a new draft version is created) |
| `threat_model.review_needed` | 3 | The architecture changed and the model was not regenerated (automatic updates off, or a version in review) |
| `risk.rescored` | 4 | Vulnerability intelligence (EPSS, CISA KEV, OSV) changed the risk of previously scored findings: newly in KEV, risk band changed, or EPSS percentile moved by 10 points or more; one event per repository and run |
| `fix.verification_queued` | 5 | A targeted rescan was queued (fix pull request merged, item marked `fix_submitted`, manual, existing scan) |
| `fix.verified` | 5 | A verification finished (`fixed`, `still_present`, `regressed`, `inconclusive`) or could not run |
| `gate.failed` | 6 | A gate decision blocked or required approval under a policy (never without one); developers are notified (below) |
| `findings.new` | 7 | A repository scan (not a pull request scan) reported new findings |
| `ai.triage_queued` | 7 | New findings were queued for AI review (AI configured with automatic review) |
| `ai.triage_concluded` | 7 | The AI reviewed a new finding; `evidence.evidence_record_id` is its AI evidence record ([AI evidence](ai-evidence.md)). Labelled `ai_inferred`; the review waits for a person (`details.review_status` `pending_approval`) |

Errors: `400 invalid_filter` (`PTH-MON-1101`) for an unknown type or severity, a loop outside 1–7, a time that is not RFC 3339, `until` before `since`, a bad limit or cursor.

## Architecture drift

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/monitoring/drift` | `findings.read` | Query: `application_id`, `repository_id`, `changed_only` (default `true`), `cursor`, `limit`. `{ items, next_cursor }` |
| `GET` | `/api/v1/monitoring/drift/{id}` | `findings.read` | The drift with `items` (at most 500, `truncated`) |

Each new CodeGraph snapshot is compared with the previous ready snapshot of the same repository that is still stored in rows; the first snapshot is a baseline (`from_snapshot_id: null`, no changes).

**Drift** fields: `id, application_id, application_name, repository_id, repository_name, from_snapshot_id, to_snapshot_id, from_commit, to_commit, severity, has_changes, counts, created_at`. `counts` keys are `added_` / `removed_` + `routes`, `api_operations`, `external_services`, `datastores`, `queues`, `internet_exposure`, `boundary_crossings`, `components`, and `changed_components`. Severity: new internet exposure `high`; new boundary crossings, external services or datastores `medium`; new routes, operations, queues or component changes `low`; removals only `info`.

**Item** fields: `change (added|removed|changed), category (route|api_operation|external_service|datastore|queue|internet_exposure|boundary_crossing|component), key, label, detail (e.g. "version 5.0.8 → 5.0.9"), file, evidence_label, evidence [{ kind (file_line|sbom|scan|registry|runtime|ai_record), ref, detail, file, line }]`. Edge items carry up to five evidence rows of the CodeGraph edge (the evidence label is the edge's strongest); node items carry the source file; components their package URL.

## Settings

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/monitoring/settings` | `findings.read` | `{ drift_alerts, drift_alert_min_severity, updated_at, updated_by }` |
| `PUT` | `/api/v1/monitoring/settings` | `settings.manage` (organization) | `{ drift_alerts?, drift_alert_min_severity? (critical|high|medium|low) }`. Audited `monitoring.settings_update`. `422` `PTH-MON-1102` for another severity |

Drift alerts are **off by default**. When on, a drift at or above the minimum severity raises the notification event `architecture.drift` (in-app and e-mail rules — the seeded rule "Architecture drift alerts" sends to security managers and the application owners — and outbound webhooks subscribed to it).

## Developer feedback on gate failures

With the flag on, a gate decision that blocks or requires approval (by rule 7 always under a policy) raises the notification event `gate.failed` (seeded rule "Failed security gates": the requester and the application owners, in-app and e-mail; outbound webhooks subscribed to `gate.failed`; payload: stage, outcome, policy names and ids, commit, pull request, matching finding count, decision id). Pull requests additionally get the check result as before ([pull request checks](scans.md)).

## AI triage

With the flag on, automated AI reviews of new findings never apply a decision on their own: they wait for approval whatever the configuration's approval policy. Secret values are never sent (the review prompt omits code context for secret findings and redacts secret patterns).

## Version stamps of exports

Every server download sets `X-PATHOS-Generated-By` (`Quditmind PATHOS v{version} · build {commit} · generated {UTC time}`), `X-PATHOS-Version` and `X-PATHOS-Build`, from the same build metadata as `GET /api/v1/meta`. JSON, generated SBOM, VEX and Markdown documents also carry the stamp (a scanner's own SBOM file is served unchanged, stamped in the headers) in the document (`generated_by`, tool metadata or footer); CSV files keep their header row first, so their stamp is in the headers. Exports: findings reports CSV, monitoring CSV, compliance JSON/CSV, Human Eye CSV, CodeGraph JSON, threat model exports, SBOM (CycloneDX, SPDX), VEX, AI report Markdown, scanner artifacts, AI fix reports, review patches and evidence. Browser exports (table CSV, graph JSON) carry the version and build in the file name; graph JSON also in `generated_by`; printed pages show the stamp in a print-only footer.
