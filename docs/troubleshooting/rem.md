---
title: Troubleshooting: Remediation
section: troubleshooting
order: 114
version: "1.0"
updated: 2026-11-20
summary: Fix pull requests and verified AI fixes (5 codes, PTH-REM-*)
---

# Troubleshooting: Remediation

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Fix pull requests and verified AI fixes.

| Code | Title | Severity |
|---|---|---|
| [PTH-REM-1001](#PTH-REM-1001) | Fix pull request not available | info |
| [PTH-REM-1002](#PTH-REM-1002) | Verified AI fix not available | info |
| [PTH-REM-1003](#PTH-REM-1003) | AI fix not verified | warning |
| [PTH-REM-1004](#PTH-REM-1004) | Fix pull request could not be created | error |
| [PTH-REM-1005](#PTH-REM-1005) | Source not available for the fix | warning |

<a id="PTH-REM-1001"></a>

## PTH-REM-1001: Fix pull request not available

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `fix_pr_not_available` |
| Raised in | internal/scans/fixprs.go, internal/scans/aifixes.go |

**What it means.** A fix pull request cannot be opened for this item: no applicable fix, the repository's provider cannot open pull requests, or fix PRs are off for the repository.

**Confirmed cause.** The item does not qualify for an automated fix pull request (see the message). Confirmed automatically when this code is raised.

**Probable causes**

1. No fixed version or verified patch exists
2. The repository is an upload without a provider
3. Fix PRs are disabled in the repository settings

**Impact.** Fix manually or with the suggested patch.

**How to fix**

1. Read the message for the missing condition.
2. Enable fix PRs in the repository's settings if appropriate.

**Verify**

1. The "Open fix PR" action becomes available.


<a id="PTH-REM-1002"></a>

## PTH-REM-1002: Verified AI fix not available

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `ai_fix_not_available` |
| Raised in | internal/scans/aifixes.go |

**What it means.** Verified AI fixes are not available for this finding (category, settings or missing source).

**Confirmed cause.** The finding does not qualify for a verified AI fix. Confirmed automatically when this code is raised.

**Probable causes**

1. AI fixes are disabled for the repository
2. The finding's category is not supported

**Impact.** No AI fix can be requested.

**How to fix**

1. Check the repository's AI fix settings.

**Verify**

1. The request is accepted.


<a id="PTH-REM-1003"></a>

## PTH-REM-1003: AI fix not verified

| | |
|---|---|
| Severity | warning |
| Category | integrity |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `not_verified`, `invalid_fix` |
| Raised in | internal/scans/aifixes.go |

**What it means.** Only a fix whose verification passed (tests and re-scan in the worker sandbox) can be turned into a pull request.

**Confirmed cause.** The fix's verification did not pass. Confirmed automatically when this code is raised.

**Probable causes**

1. Tests failed with the fix
2. The re-scan still reports the finding

**Impact.** No pull request is opened.

**How to fix**

1. Open the before/after reports, then request a new fix or fix it manually.

**Verify**

1. A new fix shows status verified.


<a id="PTH-REM-1004"></a>

## PTH-REM-1004: Fix pull request could not be created

| | |
|---|---|
| Severity | error |
| Category | provider |
| HTTP status | 502 |
| AI help | offered |
| Raised in | internal/scans/fixprs.go, internal/scm/pullrequest.go (ErrConflict) |

**What it means.** Creating the branch, commit or pull request at the provider failed.

**Confirmed cause.** The provider refused or failed the pull request (see the message). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The token lacks write permission
2. The branch already exists or the base changed
3. Branch protection blocks the push

**Impact.** The fix is not proposed; nothing was merged.

**How to fix**

1. Give the connection write access (contents and pull requests).
2. Delete a stale fix branch and retry.

**Verify**

1. The fix PR link appears on the finding.


<a id="PTH-REM-1005"></a>

## PTH-REM-1005: Source not available for the fix

| | |
|---|---|
| Severity | warning |
| Category | availability |
| HTTP status | 502 |
| AI help | not offered |
| Short codes | `source_unavailable` |
| Raised in | internal/scans/aifixes.go |

**What it means.** The source file needed for the AI fix could not be read from the provider or snapshot.

**Confirmed cause.** Reading the source for the fix failed. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The file moved or the commit is gone
2. The connection cannot read the repository

**Impact.** No fix is generated.

**How to fix**

1. Re-scan the repository so the finding points at current code, then request the fix again.

**Verify**

1. The fix request is accepted.

