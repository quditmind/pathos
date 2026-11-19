---
title: Help and troubleshooting
section: user-guide
group: home
order: 3
version: "3.0"
updated: 2026-11-20
summary: The Help (?) menu, help for the current page (F1), the Help Center, the Troubleshooting centre and error codes, error panels and AI troubleshooting, keyboard shortcuts, what's new, system status, reporting a problem, and About PATHOS.
---
# Help and troubleshooting

All help ships with PATHOS and works without an internet connection, including on air-gapped installations.

## The Help menu

Select **Help (?)** in the top bar to open the Help menu:

| Item | What it does |
|---|---|
| Help for this page | Opens a panel on the right with the guide for the page you are on. Shortcut: **F1** or **?** |
| Help centre | Opens the Help Center with every guide, grouped like the sidebar |
| Troubleshooting centre | Opens the searchable list of every PATHOS error code |
| Keyboard shortcuts | Lists every shortcut |
| What's new in v… | The release notes of the version you run |
| API reference | The REST API reference |
| System status | Health of the API, worker packs and AI providers |
| Report a problem | Downloads a redacted diagnostic file for your support request |
| About PATHOS | Version, build, licence and component versions |

## Help for this page

Press **F1** (or **?** when you are not typing in a field) on any page to open its guide in a panel on the right, scrolled to the relevant section. Links inside open the Help Center; **Open in the Help Center** shows the full page. Press **Esc** to close the panel and return to where you were.

Every page of PATHOS has a guide; an automated test fails the build when a new page has none.

## The Help Center

The Help Center (`/help`) groups the user guide like the sidebar (Home, the nine lifecycle phases, Configurations, Administration), then lists the troubleshooting articles and the API reference. Use the search box to search every page.

## Troubleshooting centre

The Troubleshooting centre (`/help/troubleshooting`) lists every PATHOS error code, grouped by area (for example *Connections* `PTH-CONN`, *Scan execution* `PTH-SCAN`, *Workers* `PTH-WORK`). Search by code, by words from the message, or by symptom. Open a code to read:

- what it means,
- the cause when it is confirmed, and the probable causes when it is not,
- the impact,
- numbered steps to fix it,
- how to verify the fix,
- a link to the full article.

The list comes from the server's error catalogue. If the server cannot be reached, the centre shows the codes bundled with your version and says so.

### Error codes

Codes have the form `PTH-<AREA>-<NNNN>`, for example `PTH-CONN-1004`. The areas are PLAT (platform), AUTH (sign-in and authorization), CONN (connections), SYNC (source sync), ONB (onboarding), DISC (discovery), GRAPH (CodeGraph), TM (threat modelling), REA (reverse engineering), SCAN (scan execution), WORK (workers), AI (AI models), GATE (security gates), REM (remediation), REP (reports) and MON (monitoring).

## Error panels

When an action or a page fails with a catalogued error, PATHOS shows an **error panel** instead of a one-line message:

- the **title** and the server's message;
- the **code** and the **request ID**, each with a copy button (give both to your administrator or support);
- the **confirmed cause**, marked *Confirmed*, or the **probable causes**, marked *not confirmed*;
- the **impact**;
- numbered **fixes**, with links to the screen where you make the fix;
- **Verify**, which runs the failed check again;
- **Read the docs** and **Troubleshooting centre**.

Errors from older PATHOS components without a code still show their message as before.

### Troubleshoot with AI

**Troubleshoot with AI** asks the AI model configured for troubleshooting (the local model when one is set up) to explain the error. PATHOS sends only the error code, the request ID, the page address without identifiers, and the error message with anything secret-shaped removed. It never sends credentials, tokens, source code or finding contents, and it never asks you to paste a secret.

The answer has the same structure as the panel. It is labelled **AI-inferred: check before acting**. When AI is turned off or unavailable, the answer comes from the error catalogue and is labelled **From the error catalogue (AI not used)**; troubleshooting never depends on AI.

## Keyboard shortcuts

| Keys | Action |
|---|---|
| Ctrl+K (⌘K on a Mac) | Search and the command palette |
| F1 or ? | Help for this page |
| Esc | Close a dialog, panel or menu |
| Tab / Shift+Tab | Next / previous control |
| ↑ ↓ | Move through menus, the palette and lists |
| Enter | Open the selected row or result |

**Help › Keyboard shortcuts** lists them all, including the shortcuts of single pages.

## What's new

**Help › What's new in v…** shows the release notes of the version the server runs, taken from the change log bundled with the web app. Pre-release builds show the changes not yet released.

## System status

**Help › System status** shows, with the time of the last check:

- **API**: whether the PATHOS API answers;
- **Worker packs**: for each pack, how many workers are online and when they were last seen (needs `scans.read`);
- **AI providers**: the result of each provider's last connection test (needs `ai.review` or `ai.configure`).

Database, queue, object storage and connector health have no endpoint the browser can reach, so they show **Not available** rather than a guess. Operators check them with `GET /readyz` on the API container (see the operations guide). Select **Check again** to refresh.

## Report a problem

**Help › Report a problem** downloads a file named `pathos-diagnostics-<time>.json` to attach to your support request. It contains:

- the server and web app versions, commit and build date;
- your browser, language, time zone and window size;
- the page you are on, without its query string and with identifiers replaced by `:id`;
- the last 50 API calls of this browser tab: method, address (identifiers masked), status, request ID and error code;
- your organization's feature flags.

It never contains passwords, tokens, cookies, secrets, source code or finding contents. Anything secret-shaped is replaced with `[REDACTED]` before the file is written. The file is created in your browser; nothing is uploaded.

## About PATHOS

**About PATHOS** (also the version chip) shows the product and vendor, the server version, commit and build date, the API version, the web app version, the licence (Apache License 2.0), the third-party notice (`NOTICE`), and the version of each scanner pack with its registered workers. Individual scanner versions are listed under **Configurations › Scanners & workers**.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| F1 opens the browser's own help | Some browsers or extensions reserve F1. Use **?** or **Help › Help for this page**. |
| **?** does nothing | The cursor is in a text field, where **?** types a question mark. Click outside the field first, or press F1. |
| The Troubleshooting centre says the live catalogue is not reachable | The server did not answer `GET /api/v1/diagnostics/codes`. The bundled codes are shown instead; check **System status**. |
| **Troubleshoot with AI** answers "From the error catalogue" | AI is off for troubleshooting or the model did not answer. The catalogue steps apply; an administrator can configure a model under **Configurations › AI settings**. |
| System status shows a worker pack with 0 workers online | No worker of that pack has contacted PATHOS recently; scans that need it wait. See [Security scanning](security-scanning.md) and the `PTH-WORK` codes in the Troubleshooting centre. |
