---
title: Troubleshooting codes
section: troubleshooting
order: 100
version: "1.0"
updated: 2026-11-20
summary: Every PATHOS error code (PTH-<AREA>-<NNNN>) by area, with its cause, impact, fix and how to verify it.
---

# Troubleshooting codes

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Every error PATHOS reports carries a code of the form `PTH-<AREA>-<NNNN>` and a request ID. API errors return them in `error.error_code` and `error.request_id` (see the API reference, "Errors"); the server log lines of the same error carry `error_code` and `request_id`. Search for the code below, or open **Help → Troubleshooting centre**.

| Area | Page | Codes |
|---|---|---|
| `PLAT` | [Platform](plat.md) | 23 |
| `AUTH` | [Authentication and access](auth.md) | 18 |
| `CONN` | [Connections](conn.md) | 60 |
| `SYNC` | [Synchronisation](sync.md) | 7 |
| `ONB` | [Onboarding and imports](onb.md) | 12 |
| `DISC` | [Discovery](disc.md) | 7 |
| `GRAPH` | [CodeGraph](graph.md) | 5 |
| `SCAN` | [Scanning](scan.md) | 10 |
| `WORK` | [Workers](work.md) | 6 |
| `AI` | [AI](ai.md) | 11 |
| `GATE` | [Security gates](gate.md) | 2 |
| `REM` | [Remediation](rem.md) | 5 |
| `REP` | [Reporting](rep.md) | 4 |
| `MON` | [Monitoring](mon.md) | 3 |

Areas without codes yet: `TM` (Threat modelling), `REA` (Reverse engineering). Their modules are planned; codes are added with them.

## Confirmed and probable causes

A cause is **confirmed** when the check that raised the error proves it (for example a rejected API token). Otherwise PATHOS lists **probable causes**, most likely first; work through them in order. **Troubleshoot with AI** is offered for codes marked "AI help: offered"; it sends only the code, the redacted message and non-secret context, and the catalogue steps below always remain available.
