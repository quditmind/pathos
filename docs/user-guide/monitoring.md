---
title: Continuous monitoring
section: user-guide
group: report
order: 23
version: "3.0"
updated: 2026-11-20
summary: One feed of what changed and what PATHOS did about it — the seven feedback loops from a new commit to verified fixes — plus architecture drift between CodeGraph snapshots and optional drift alerts.
---
# Continuous monitoring

Quditmind PATHOS · applies to v3.0 (unreleased) · status: Prototype (behind the `continuous_monitoring` feature flag)

## Purpose

**Report & monitor → Continuous monitoring** (`/monitoring`) shows, in one place, how PATHOS reacts to change: a new commit, a dependency change, a new architecture, new vulnerability intelligence, a merged fix, a failed gate or new findings. Every entry is a real event recorded by the platform, with its evidence label (*verified*, *observed* or *AI-inferred*) and references to the evidence (snapshots, commit, scan, gate decision, threat model). Nothing is simulated: an empty feed means nothing has happened yet.

The module is behind the feature flag `continuous_monitoring` (off by default). An administrator with `settings.manage` turns it on under **Administration → Feature flags**. While it is off, the sidebar item stays disabled, the page shows a "not enabled" notice and the API answers `404` with `PTH-PLAT-1007`.

The page has two tabs: **Feed** and **Architecture drift**. The application profile (**Applications → an application → Overview**) shows a **Monitoring** card with the application's latest five events and its latest drift, and a link that opens this page filtered to the application.

## The feed

The feed lists events newest first. Each event shows:

- its type (for example *Architecture drift* or *Fix verification queued*) and the **Loop N** chip of the feedback loop it belongs to;
- its severity and its evidence label;
- a title and a short summary;
- the application and repository;
- evidence references: the CodeGraph snapshots it compares (a link opens the CodeGraph comparison), the commit, the scan, the gate decision or the threat model;
- a link to the page where you act on it, when there is one.

Filter by **application**, **event type**, **severity** and **time range** (last 24 hours, 7 days, 30 days or a custom range). Filters are kept in the address, so a filtered view can be bookmarked or shared (for example `/monitoring?application_id=…`). The cards above the feed summarise the last 30 days: number of events, critical and high events, drift with changes and the latest drift.

**Export CSV** downloads the feed with the current filters (needs `findings.export`). The file name and the `X-PATHOS-Generated-By` header carry the PATHOS version and build.

## The seven feedback loops

| Loop | When | What PATHOS does |
|---|---|---|
| 1 | A new commit reaches a monitored branch | Queues a CodeGraph rediscovery of the repository |
| 2 | Dependencies change (lock or manifest files) | Reassesses the affected components and their vulnerabilities |
| 3 | The architecture changes between two CodeGraph snapshots | Records the drift and updates the threat model draft; an approved model is marked for review |
| 4 | New vulnerability intelligence arrives (for example a CVE added to the known-exploited list) | Re-scores the risk of the affected findings |
| 5 | A fix pull request merges, or an item is marked *fix submitted* | Queues a targeted verification rescan of the remediation item |
| 6 | A security gate fails | Gives the developer feedback through the pull request check, the outbound webhook and an in-app notification — only when a policy says the gate applies (no blocking without a policy) |
| 7 | New findings arrive | Adds them to the AI triage queue when an AI model is configured; AI conclusions are labelled *AI-inferred* and are never approved automatically |

A loop step that fails is recorded with `PTH-MON-1104`; the rest of the platform keeps working.

## Architecture drift

Each new CodeGraph snapshot of a repository is compared with the previous one. The **Architecture drift** tab shows the comparisons as a timeline, newest first, with the commits (*from → to*) and the counts per category: routes, external services, data stores, internet exposure, trust boundary crossings and components (`+` added, `−` removed, `~` changed). By default only comparisons with changes are listed; **Show snapshots without changes** lists the others too. The first snapshot of a repository is the *baseline*.

Select an entry to open its detail: every added, removed and changed item grouped by category, each with its evidence (kind, reference, file and line) and its evidence label. **Compare the snapshots in CodeGraph** opens the CodeGraph change-impact view of the same two snapshots.

## Drift alerts

Drift alerts are **off by default**. Someone with `settings.manage` opens **Drift alerts** on the page, turns on **Alert on architecture drift** and chooses the minimum severity (default *high*). Drift at or above that severity is then sent as the notification event `architecture.drift` through the existing channels — in-app and e-mail rules under **Administration → Notifications** and outbound webhooks. The change is written to the audit log.

## Permissions

| Permission | Allows |
|---|---|
| `findings.read` | See the feed, the drift timeline and the drift details (limited to the repositories and applications in your scope) |
| `findings.export` | Export the feed as CSV |
| `settings.manage` | Change the drift alert settings; turn the feature flag on or off |

## Troubleshooting

| Code | Meaning | Fix |
|---|---|---|
| `PTH-PLAT-1007` | The `continuous_monitoring` feature is not enabled | An administrator turns the flag on under Administration → Feature flags |
| `PTH-MON-1101` | A feed or drift filter is invalid (for example a malformed time, an unknown type or severity, or a loop outside 1–7) | Clear the filters, or pick the time range again; the API expects RFC 3339 times |
| `PTH-MON-1102` | The drift alert settings are invalid (unknown minimum severity) | Choose one of critical, high, medium, low or info and save again |
| `PTH-MON-1103` | The drift between two snapshots could not be computed (a snapshot is missing, failed or was deleted) | Rebuild the CodeGraph of the repository; the next finished snapshot is compared again |
| `PTH-MON-1104` | A feedback loop step failed (for example the rediscovery or the verification rescan could not be queued) | Check the workers under Configurations → Scanners & workers and the repository connection, then retry the action from the linked page |
| `PTH-MON-1105` | A feed event could not be recorded | The action itself still ran; check the server log and the database, then refresh the feed |
