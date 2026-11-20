---
title: "The PATHOS shell: brand header, version and navigation"
section: user-guide
group: home
order: 2
version: "3.0"
updated: 2026-11-20
summary: The top bar (brand, version, search, notifications, Help, theme, user menu), the sidebar grouped by the nine lifecycle phases, feature flags, and the shared page states.
---
# The PATHOS shell: brand header, version and navigation

Every page of PATHOS shares one frame: a **sidebar** on the left and a **top bar** above the page. This page explains both, and the states every page uses for loading, empty, partial, denied and failed data.

## Brand header and version

The top left of every page reads **Quditmind | PATHOS** with the version chip beside it, for example **v2.2.0 ▾**.

- The version is the version of the **PATHOS server** you are connected to, read from `GET /api/v1/meta`. It is never hard-coded in the web app.
- Select the chip to open **About PATHOS** (see [Help and troubleshooting](help-and-troubleshooting.md#about-pathos)).
- Development builds and release candidates show their real version (`dev`, `3.0.0-rc.1`) and a small **Pre-release** tag at the start of the top bar.
- When the sidebar is collapsed, only the logo shows; hover over it (or focus it) to see the version, and select it to open About.
- The sign-in page shows the same brand and the server version.

### "A newer PATHOS version is available"

The web app in your browser carries its own version. When an administrator upgrades the server while you have PATHOS open, the two differ and a banner appears at the top: **A newer PATHOS version is available. Reload to update.** Select **Reload** to load the new web app. The banner never blocks your work; you can dismiss it and reload later. Development builds (`dev`) are not compared.

## Top bar

From left to right: the **Pre-release** tag (pre-release builds only), **Search** (Ctrl+K or ⌘K, the command palette), the organization switcher (multi-tenant installations), **Notifications**, **Help (?)**, the light/dark **theme** toggle and the **user menu** (API tokens, sign-in security, sign out).

## Sidebar

The sidebar follows the application security lifecycle. Groups appear only when you can open at least one of their pages.

| Group | Pages |
|---|---|
| Home | Dashboard · Lifecycle overview *(flag `lifecycle_overview`)* |
| 1 · Connect | Connectors *(flag `connectors`)* · Add repositories · Import history · SCM connections · Integrations |
| 2 · Inventory | Applications · Repositories · Scan targets · Unmanaged assets · Coverage · Tags |
| 3 · Discover | CodeGraph *(flag `codegraph`)* · Context graph · Runtime · API & endpoints *(flag `codegraph`)* · SBOM inventory · Component portfolio |
| 4 · Threat model | Threat models *(flag `threat_models`)* · Attack paths · Blast radius |
| 5 · Reverse engineering | Binary analysis *(flag `reverse_engineering`)* |
| 6 · Assess | Scan overview · Scans · Scan schedules · Scan comparison · Import results · Findings |
| 7 · Validate & intelligence | AI Security Analyst · AI reviews · AI reports · AI evidence log *(flag `ai_intelligence`)* · Human Eye: overview, review queue, assessments, assignments, review reports |
| 8 · Remediate & gate | Remediation workspace *(flag `remediation_workspace`)* · Policies · Component policies · Pull request checks · Risk acceptances · Suppression rules · VEX statements |
| 9 · Report & monitor | Executive overview · Reports · Application posture · Benchmarking · Compliance · Developer insights · Continuous monitoring *(flag `continuous_monitoring`)* |
| Configurations | Scan profiles · Scanners & workers · Scan coverage · Custom rules · Asset settings · Risk & intelligence · Secret validation · Review configurations · AI settings · Reverse engineering tools *(flag `reverse_engineering`)* |
| Administration | Organizations *(multi-tenant installations, installation administrators only)* · Users · Organization · Developer attribution · Notifications · AI usage · MCP registry · Audit log · Feature flags |

Every page keeps its address from earlier versions; bookmarks and links keep working. Only the place in the menu changed. With the `connectors` flag on, **SCM connections** (`/admin/scm`) and **Integrations** (`/admin/integrations`) open inside [Connectors](connectors.md), which contains the same pages with every action; with the flag off they open as before.

### Modules behind a feature flag

Every lifecycle module is built. Items marked *(flag …)* open only while that feature flag is on for your organization; while it is off they are shown dimmed with an **Off** label and cannot be opened (hover over one to read "not enabled" and where an administrator turns it on). Nothing behind them is simulated.

### Feature flags

New modules are switched on per organization with **feature flags**, which are off by default. The web app reads the flags of your organization from `GET /api/v1/meta`. A page behind a flag that is off says so, names the flag and who can turn it on (an administrator with the `settings.manage` permission).

Administrators with `settings.manage` switch flags under **Administration › Feature flags**: each flag shows the module it gates, the roadmap milestone that delivers it and its last change. Every change is recorded in the audit log. Turning a flag on opens its module for the organization; while it is off, the module's menu item stays disabled with an **Off** label. For example, **Connectors** (`connectors`) opens [Connectors](connectors.md) while the flag is on.

## Page states

All pages use the same building blocks, so a state always looks the same:

| State | What you see |
|---|---|
| Loading | Grey placeholder blocks in the shape of the content |
| Empty | What will appear here and how to add the first item |
| Partial data | A yellow note naming the part that did not load |
| Permission denied | The name of the missing permission |
| Feature disabled | The feature flag and who can enable it |
| Error | An error panel with a code, cause and fixes (see [Help and troubleshooting](help-and-troubleshooting.md#error-panels)) |
| Success | A short message at the bottom right saying what happened |

## Accessibility

The shell can be used with the keyboard alone: Tab moves through the sidebar and top bar, menus open with Enter or Space and close with Esc, and focus is always visible. Menus, dialogs and the help drawer carry ARIA roles and names. Animations are turned off when your system asks for reduced motion. Both themes meet WCAG 2.2 AA contrast with the PATHOS colour tokens.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| The version chip shows `v?` | The web app could not read `GET /api/v1/meta`. Reload; if it persists, check **Help › System status** and the error code in the error panel of the failing page. |
| The banner "A newer PATHOS version is available" keeps coming back | Your browser or a proxy caches the old web app. Reload with the cache bypassed (Ctrl+Shift+R), or ask your administrator to check the cache headers of the proxy in front of PATHOS. |
| A menu item I used to have is gone | Pages only moved between groups. Search for it with Ctrl+K; if it is still missing, your role lacks the permission the page needs. |
| A menu item is disabled and shows **Off** | Its module's feature flag is off for your organization. An administrator turns it on under **Administration › Feature flags**. |
