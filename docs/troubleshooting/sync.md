---
title: Troubleshooting: Synchronisation
section: troubleshooting
order: 104
version: "1.0"
updated: 2026-11-20
summary: Repository inventory, metadata re-sync, intelligence feeds and outbound deliveries (6 codes, PTH-SYNC-*)
---

# Troubleshooting: Synchronisation

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Repository inventory, metadata re-sync, intelligence feeds and outbound deliveries.

| Code | Title | Severity |
|---|---|---|
| [PTH-SYNC-1002](#PTH-SYNC-1002) | Repository no longer visible to the connection | warning |
| [PTH-SYNC-1003](#PTH-SYNC-1003) | Page token invalid or expired | info |
| [PTH-SYNC-1005](#PTH-SYNC-1005) | Outbound delivery failed after all retries | error |
| [PTH-SYNC-1011](#PTH-SYNC-1011) | Repository inventory refresh failed | error |
| [PTH-SYNC-1020](#PTH-SYNC-1020) | Intelligence feed download failed | warning |
| [PTH-SYNC-1021](#PTH-SYNC-1021) | Feed file format not recognised | warning |

<a id="PTH-SYNC-1002"></a>

## PTH-SYNC-1002: Repository no longer visible to the connection

| | |
|---|---|
| Severity | warning |
| Category | data |
| HTTP status | 502 |
| AI help | not offered |
| Raised in | internal/repos/resync.go |

**What it means.** During re-sync the provider no longer shows the repository: it was deleted, moved, archived or the credential lost access.

**Confirmed cause.** The provider no longer returns this repository for the connection's credential. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The repository was deleted or transferred
2. Access was removed from the token or app

**Impact.** The repository is not re-synced or scanned from the provider; existing findings remain.

**How to fix**

1. Check the repository at the provider.
2. Restore access, or archive the repository in PATHOS.

**Verify**

1. Re-sync the repository; its metadata updates.


<a id="PTH-SYNC-1003"></a>

## PTH-SYNC-1003: Page token invalid or expired

| | |
|---|---|
| Severity | info |
| Category | validation |
| HTTP status | 400 |
| AI help | not offered |
| Raised in | internal/scm/pagetoken.go (ErrInvalidPageToken) |

**What it means.** A paginated listing was continued with a page token that is invalid or expired.

**Confirmed cause.** The page token could not be decoded or is expired. Confirmed automatically when this code is raised.

**Probable causes**

1. The listing was left open too long
2. The filter changed between pages

**Impact.** The listing must restart from the first page.

**How to fix**

1. Reload the listing from the first page.

**Verify**

1. The listing loads.


<a id="PTH-SYNC-1005"></a>

## PTH-SYNC-1005: Outbound delivery failed after all retries

| | |
|---|---|
| Severity | error |
| Category | connectivity |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/notify/webhooks.go, internal/notify/dispatch.go |

**What it means.** An outbound webhook (JSON, Slack or Teams) delivery failed on every retry.

**Confirmed cause.** The receiving endpoint did not accept the delivery after the last retry. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The receiver URL was removed or changed
2. The receiver rejects the signature or payload
3. The receiver is down

**Impact.** The event was not delivered to this endpoint.

**How to fix**

1. Open the webhook's deliveries to see the response status.
2. Fix the URL or receiver and send a test delivery.

**Verify**

1. A test delivery shows status delivered.


<a id="PTH-SYNC-1011"></a>

## PTH-SYNC-1011: Repository inventory refresh failed

| | |
|---|---|
| Severity | error |
| Category | provider |
| HTTP status | 502 |
| AI help | offered |
| Short codes | `inventory_failed` |
| Raised in | internal/repos/inventory.go |

**What it means.** Listing the connection's repositories for the inventory failed.

**Confirmed cause.** The inventory run ended with an error (see the run's message). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The connection's credential failed (see PTH-CONN-1007 to 1010)
2. The provider is unreachable

**Impact.** The inventory shows the previous state; new repositories do not appear.

**How to fix**

1. Test the connection and fix the reported problem.
2. Refresh the inventory again.

**Verify**

1. The inventory run succeeds and lists new repositories.


<a id="PTH-SYNC-1020"></a>

## PTH-SYNC-1020: Intelligence feed download failed

| | |
|---|---|
| Severity | warning |
| Category | connectivity |
| HTTP status | 502 |
| AI help | offered |
| Short codes | `feed_failed` |
| Raised in | internal/intel/service.go (recordFailure) |

**What it means.** Downloading a vulnerability intelligence feed (EPSS, CISA KEV) failed; the run is recorded as failed.

**Confirmed cause.** The feed download failed (see the run's error). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. No internet access from the jobs container
2. The feed URL changed
3. The feed exceeded 64 MiB

**Impact.** Risk scores use the previous feed data until the next successful run.

**How to fix**

1. Check egress to the feed host.
2. In air-gapped installs, import the feed file instead (docs/AIRGAP.md).

**Verify**

1. Run the feed now; the run shows succeeded.


<a id="PTH-SYNC-1021"></a>

## PTH-SYNC-1021: Feed file format not recognised

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `invalid_feed` |
| Raised in | internal/intel/service.go |

**What it means.** An imported intelligence feed file could not be parsed as the expected format.

**Confirmed cause.** The uploaded file is not a valid file of this feed. Confirmed automatically when this code is raised.

**Probable causes**

1. The file of another feed was uploaded
2. The file is truncated or still compressed differently

**Impact.** The feed was not updated.

**How to fix**

1. Download the feed again from its official source and upload the unmodified file.

**Verify**

1. The import run shows succeeded.

