---
title: Troubleshooting: Monitoring
section: troubleshooting
order: 116
version: "1.0"
updated: 2026-11-20
summary: Runtime context, SLA detection and notification dispatch (8 codes, PTH-MON-*)
---

# Troubleshooting: Monitoring

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Runtime context, SLA detection and notification dispatch.

| Code | Title | Severity |
|---|---|---|
| [PTH-MON-1001](#PTH-MON-1001) | Runtime sync failed | error |
| [PTH-MON-1002](#PTH-MON-1002) | SLA breach detection failed | error |
| [PTH-MON-1003](#PTH-MON-1003) | Notification dispatch failed | error |
| [PTH-MON-1101](#PTH-MON-1101) | Invalid monitoring filter | info |
| [PTH-MON-1102](#PTH-MON-1102) | Invalid monitoring settings | info |
| [PTH-MON-1103](#PTH-MON-1103) | Architecture drift could not be computed | warning |
| [PTH-MON-1104](#PTH-MON-1104) | A feedback loop step failed | warning |
| [PTH-MON-1105](#PTH-MON-1105) | Monitoring event not recorded | warning |

<a id="PTH-MON-1001"></a>

## PTH-MON-1001: Runtime sync failed

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/runtimectx/sync.go |

**What it means.** Synchronising a Kubernetes cluster or container registry connection failed.

**Confirmed cause.** The sync ended with an error (stored as the connection's last error). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The service-account token expired
2. The API server or registry is unreachable
3. The role lacks list permission on a resource kind

**Impact.** Runtime facts (deployed, exposed, privileged) for this cluster are stale.

**How to fix**

1. Open Runtime → connections and read the last error.
2. Renew the token or fix the ClusterRole (deploy/kubernetes).

**Verify**

1. Sync now succeeds.


<a id="PTH-MON-1002"></a>

## PTH-MON-1002: SLA breach detection failed

| | |
|---|---|
| Severity | error |
| Category | internal |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/notify/dispatch.go |

**What it means.** The periodic SLA breach detection could not run.

**Confirmed cause.** SLA breach detection returned an error (see the jobs log). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A database error

**Impact.** SLA breach notifications are delayed until the next successful run.

**How to fix**

1. Check the jobs log for the error_code and the database health.

**Verify**

1. The next run logs no error.


<a id="PTH-MON-1003"></a>

## PTH-MON-1003: Notification dispatch failed

| | |
|---|---|
| Severity | error |
| Category | internal |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/notify/dispatch.go |

**What it means.** Turning events into notifications (in-app, e-mail, webhooks) failed in the jobs role.

**Confirmed cause.** The dispatcher returned an error (see the jobs log). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A database error
2. A template that fails to render

**Impact.** Notifications are delayed; they are processed on the next run.

**How to fix**

1. Check the jobs log; preview custom templates in Administration → Notifications.

**Verify**

1. Pending notifications are delivered.


<a id="PTH-MON-1101"></a>

## PTH-MON-1101: Invalid monitoring filter

| | |
|---|---|
| Severity | info |
| Category | validation |
| HTTP status | 400 |
| AI help | not offered |
| Short codes | `invalid_filter` |
| Raised in | internal/monitoring/api.go |

**What it means.** A filter of the monitoring feed or drift timeline is not valid (event type, severity, loop, time, limit or cursor).

**Confirmed cause.** The request carries a filter value PATHOS does not accept (named in the message). Confirmed automatically when this code is raised.

**Probable causes**

1. A bookmarked link with an old or edited filter
2. A script that sends a time without a time zone (RFC 3339 is required)

**Impact.** The feed was not returned.

**How to fix**

1. Clear the filters in Continuous monitoring and choose them again.
2. API clients: use the types from GET /api/v1/monitoring/types and RFC 3339 times.

**Verify**

1. The feed loads with the filters applied.


<a id="PTH-MON-1102"></a>

## PTH-MON-1102: Invalid monitoring settings

| | |
|---|---|
| Severity | info |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Raised in | internal/monitoring/api.go |

**What it means.** The drift alert settings were refused: the minimum severity must be critical, high, medium or low.

**Confirmed cause.** The submitted minimum severity is not one of critical, high, medium or low. Confirmed automatically when this code is raised.

**Probable causes**

1. An API client sent another value

**Impact.** The settings were not changed.

**How to fix**

1. Choose a minimum severity in Continuous monitoring → Drift alerts and save again.

**Verify**

1. The dialog shows the saved settings.


<a id="PTH-MON-1103"></a>

## PTH-MON-1103: Architecture drift could not be computed

| | |
|---|---|
| Severity | warning |
| Category | internal |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/codegraph/drift.go |

**What it means.** After a new CodeGraph snapshot was stored, comparing it with the previous snapshot of the repository failed, so no drift record or feed event was written for it.

**Confirmed cause.** The comparison or storing the drift record failed (see the API log line with this code). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A database error or timeout while loading the two snapshots
2. The previous snapshot was archived during the comparison

**Impact.** The drift timeline misses this snapshot; the snapshot itself and the threat model loop are not affected.

**How to fix**

1. Check the API log for the error_code and the database health.
2. Rebuild CodeGraph for the application: the next snapshot is compared again.

**Verify**

1. The next snapshot appears in the drift timeline.


<a id="PTH-MON-1104"></a>

## PTH-MON-1104: A feedback loop step failed

| | |
|---|---|
| Severity | warning |
| Category | internal |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/feedback/feedback.go |

**What it means.** A lifecycle feedback loop could not complete its target action: the threat model update, the dependency reassessment (component policies, re-scoring) or queuing a drift alert.

**Confirmed cause.** The step returned an error (see the log line with this code; the feed event says which part failed). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A database error
2. A threat model generation error (see PTH-TM codes)

**Impact.** The source event happened, but its follow-up did not run this time; the next event of the same kind runs it again.

**How to fix**

1. Read the log line for the failing step.
2. Run the step by hand: regenerate the threat model, or re-evaluate component policies (they also run hourly).

**Verify**

1. The next feed event of the loop shows the follow-up without the failure note.


<a id="PTH-MON-1105"></a>

## PTH-MON-1105: Monitoring event not recorded

| | |
|---|---|
| Severity | warning |
| Category | internal |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/monitoring, internal/codegraph, internal/feedback, cmd/pathos (jobs role) |

**What it means.** A module could not add an event to the monitoring feed, or the yearly feed retention failed.

**Confirmed cause.** Writing or pruning monitoring_events failed (see the log line with this code). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A database error
2. An event larger than the allowed details size

**Impact.** The feed misses this event; the action itself (rescan, gate, re-score) was done.

**How to fix**

1. Check the log for the error and the database health.

**Verify**

1. New events appear in Continuous monitoring.

