---
title: Troubleshooting: Reporting
section: troubleshooting
order: 115
version: "1.0"
updated: 2026-11-20
summary: Saved reports, exports, AI analyst reports and developer insights (5 codes, PTH-REP-*)
---

# Troubleshooting: Reporting

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Saved reports, exports, AI analyst reports and developer insights.

| Code | Title | Severity |
|---|---|---|
| [PTH-REP-1001](#PTH-REP-1001) | Export permission required | info |
| [PTH-REP-1002](#PTH-REP-1002) | AI narrative not generated | warning |
| [PTH-REP-1003](#PTH-REP-1003) | Developer attribution disabled | info |
| [PTH-REP-1004](#PTH-REP-1004) | Scheduled report could not be queued | error |
| [PTH-REP-1101](#PTH-REP-1101) | Unsupported export format | info |

<a id="PTH-REP-1001"></a>

## PTH-REP-1001: Export permission required

| | |
|---|---|
| Severity | info |
| Category | authorization |
| HTTP status | 403 |
| AI help | not offered |
| Raised in | internal/reporting/reports.go |

**What it means.** Exporting or scheduling report data needs the findings.export permission.

**Confirmed cause.** You lack findings.export. Confirmed automatically when this code is raised.

**Probable causes**

1. Your role can read findings but not export them

**Impact.** The export was not produced.

**How to fix**

1. Ask an administrator for a role with findings.export.

**Verify**

1. The CSV export downloads.


<a id="PTH-REP-1002"></a>

## PTH-REP-1002: AI narrative not generated

| | |
|---|---|
| Severity | warning |
| Category | provider |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/analyst/reports.go |

**What it means.** The AI analyst report was created with figures only, because the narrative could not be generated.

**Confirmed cause.** The narrative step failed or AI is not available (reason stored on the report). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. No AI provider is configured
2. The AI request failed
3. The requester lacks ai.review

**Impact.** The report has figures but no narrative.

**How to fix**

1. Fix the AI configuration (see PTH-AI codes) and create the report again.

**Verify**

1. A new report has a narrative.


<a id="PTH-REP-1003"></a>

## PTH-REP-1003: Developer attribution disabled

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `attribution_disabled` |
| Raised in | internal/insights/api.go |

**What it means.** Developer insights by person need attribution, which is off for the organization.

**Confirmed cause.** Attribution is disabled. Confirmed automatically when this code is raised.

**Probable causes**

1. Attribution is off by default (privacy)

**Impact.** Per-developer views and identity links are unavailable.

**How to fix**

1. An administrator enables attribution in Developer insights settings, if your policy allows.

**Verify**

1. The people view loads.


<a id="PTH-REP-1004"></a>

## PTH-REP-1004: Scheduled report could not be queued

| | |
|---|---|
| Severity | error |
| Category | internal |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/reporting/reports.go (RunDue) |

**What it means.** The scheduler could not create the notifications of due scheduled reports.

**Confirmed cause.** Queuing the due reports failed (see the scheduler log). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A database error in the scheduler

**Impact.** Recipients do not get this run's report notification.

**How to fix**

1. Check the scheduler log for the error_code and retry by running the report manually.

**Verify**

1. The next scheduled run is delivered.


<a id="PTH-REP-1101"></a>

## PTH-REP-1101: Unsupported export format

| | |
|---|---|
| Severity | info |
| Category | validation |
| HTTP status | 400 |
| AI help | not offered |
| Raised in | internal/compliance/service.go |

**What it means.** The compliance report export supports the formats json and csv only.

**Confirmed cause.** The format parameter is not json or csv. Confirmed automatically when this code is raised.

**Probable causes**

1. An edited link or an API client using another format

**Impact.** No file was produced.

**How to fix**

1. Use format=json or format=csv; print the page for a PDF.

**Verify**

1. The export downloads with the X-PATHOS-Generated-By header.

