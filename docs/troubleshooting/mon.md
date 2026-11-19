---
title: Troubleshooting: Monitoring
section: troubleshooting
order: 116
version: "1.0"
updated: 2026-11-20
summary: Runtime context, SLA detection and notification dispatch (3 codes, PTH-MON-*)
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

