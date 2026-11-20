---
title: Troubleshooting: Remediation
section: troubleshooting
order: 114
version: "1.0"
updated: 2026-11-20
summary: Fix pull requests and verified AI fixes (11 codes, PTH-REM-*)
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
| [PTH-REM-1101](#PTH-REM-1101) | Remediation status change not allowed | info |
| [PTH-REM-1102](#PTH-REM-1102) | Fix cannot be verified | info |
| [PTH-REM-1103](#PTH-REM-1103) | Finding already in an open remediation item | info |
| [PTH-REM-1104](#PTH-REM-1104) | Verification already running | info |
| [PTH-REM-1105](#PTH-REM-1105) | Fix verification failed in the worker | warning |
| [PTH-REM-1106](#PTH-REM-1106) | Rescan inconclusive | info |

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


<a id="PTH-REM-1101"></a>

## PTH-REM-1101: Remediation status change not allowed

| | |
|---|---|
| Severity | info |
| Category | workflow |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `invalid_transition` |
| Raised in | internal/remediation/items.go |

**What it means.** The requested status change of a remediation item is not allowed. An item closes only when a verification proves the fix; while a verification runs the status cannot be changed by hand.

**Confirmed cause.** The transition is not in the allowed set (closed is set only by a verification that proved the fix). Confirmed automatically when this code is raised.

**Probable causes**

1. Someone tried to close the item by hand
2. A verification of the item is queued or running

**Impact.** The item keeps its status.

**How to fix**

1. Use Verify fix on the item; it closes when the rescan proves the findings are gone.
2. Mark it Won't fix if the risk is accepted another way.
3. Wait for a running verification to finish.

**Verify**

1. The item shows the new status, or Closed after a successful verification.


<a id="PTH-REM-1102"></a>

## PTH-REM-1102: Fix cannot be verified

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `fix_not_verifiable` |
| Raised in | internal/remediation/verify.go |

**What it means.** PATHOS cannot verify this item's fix: a targeted rescan needs a finding with a file, a scanner a worker can re-run, a recorded commit and an SCM connection; a verification with an existing scan needs a succeeded scan of the scan branch.

**Confirmed cause.** A precondition of the verification is missing (named in the message). Confirmed automatically when this code is raised.

**Probable causes**

1. The finding comes only from an imported report
2. The repository is an upload without an SCM connection
3. The finding has no file location
4. The given scan did not succeed or is a pull request scan

**Impact.** The item stays open; nothing is rescanned.

**How to fix**

1. Run a full scan of the repository and verify with that scan (scan_job_id).
2. Connect the repository to its SCM provider.
3. Close the risk another way (risk acceptance) if the finding cannot be re-checked.

**Verify**

1. Verify fix is enabled on the item page.


<a id="PTH-REM-1103"></a>

## PTH-REM-1103: Finding already in an open remediation item

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `finding_already_tracked` |
| Raised in | internal/remediation/items.go |

**What it means.** Each finding belongs to at most one active remediation item.

**Confirmed cause.** One of the findings is linked to an item that is not closed or won't fix. Confirmed automatically when this code is raised.

**Probable causes**

1. The item was created earlier from the Findings page or by a colleague

**Impact.** No item was created.

**How to fix**

1. Open the existing item from the Remediation workspace (search by file or title).
2. Leave the finding out of the new item.

**Verify**

1. The finding appears in exactly one active item.


<a id="PTH-REM-1104"></a>

## PTH-REM-1104: Verification already running

| | |
|---|---|
| Severity | info |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `verification_running` |
| Raised in | internal/remediation/verify.go |

**What it means.** A verification of this item is queued or running; one runs at a time.

**Confirmed cause.** The item has a verification with status queued or running. Confirmed automatically when this code is raised.

**Probable causes**

1. Verify fix was pressed twice
2. A merged fix pull request queued a verification automatically

**Impact.** No second verification was queued.

**How to fix**

1. Wait for the running verification; its result appears on the item.

**Verify**

1. The verification shows completed or failed.


<a id="PTH-REM-1105"></a>

## PTH-REM-1105: Fix verification failed in the worker

| | |
|---|---|
| Severity | warning |
| Category | worker |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/remediation/verify.go, internal/worker/remediation.go |

**What it means.** The targeted rescan could not run: cloning, the scanner or the result upload failed, or the worker lease expired three times.

**Confirmed cause.** The verification ended with status failed (reason recorded on it). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. No worker has the finding's scanner
2. The clone credential lacks read access or expired
3. The scan branch no longer exists
4. The scanner failed on the files

**Impact.** The item returns to In progress; nothing is closed.

**How to fix**

1. Read the failure reason on the item's verification history.
2. Check workers in Configurations › Scanners & workers.
3. Check the SCM connection in Connectors.
4. Run Verify fix again.

**Verify**

1. A new verification completes.


<a id="PTH-REM-1106"></a>

## PTH-REM-1106: Rescan inconclusive

| | |
|---|---|
| Severity | info |
| Category | evidence |
| HTTP status | none (background work and logs) |
| AI help | not offered |
| Raised in | internal/remediation/verify.go |

**What it means.** The scanner did not report the finding on the code before the fix, so its absence afterwards proves nothing; the item is not closed.

**Confirmed cause.** The verification result is inconclusive: a finding was not reproduced on the before commit. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The scanner version or rules changed since the finding was reported
2. The finding depends on files outside the affected files (for example a lockfile next to a manifest)

**Impact.** The item stays open.

**How to fix**

1. Run a full scan of the scan branch and verify the item with that scan.
2. Check the scanner configuration in the repository's scan profile.

**Verify**

1. A verification with result fixed closes the item.

