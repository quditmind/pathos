---
title: Troubleshooting: Scanning
section: troubleshooting
order: 110
version: "1.0"
updated: 2026-11-20
summary: Scan execution, result and SBOM imports, artifacts and custom rules (10 codes, PTH-SCAN-*)
---

# Troubleshooting: Scanning

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Scan execution, result and SBOM imports, artifacts and custom rules.

| Code | Title | Severity |
|---|---|---|
| [PTH-SCAN-1001](#PTH-SCAN-1001) | Clone credential could not be obtained | error |
| [PTH-SCAN-1002](#PTH-SCAN-1002) | Scan failed: worker lease expired repeatedly | error |
| [PTH-SCAN-1003](#PTH-SCAN-1003) | Scan result could not be ingested | error |
| [PTH-SCAN-1004](#PTH-SCAN-1004) | Imported report not recognised | warning |
| [PTH-SCAN-1005](#PTH-SCAN-1005) | SBOM not recognised | warning |
| [PTH-SCAN-1006](#PTH-SCAN-1006) | Malware detected in the upload | critical |
| [PTH-SCAN-1007](#PTH-SCAN-1007) | Malware scanner unavailable | error |
| [PTH-SCAN-1008](#PTH-SCAN-1008) | Source snapshot not available | warning |
| [PTH-SCAN-1009](#PTH-SCAN-1009) | Custom rules invalid | warning |
| [PTH-SCAN-1010](#PTH-SCAN-1010) | No SBOM or component inventory yet | info |

<a id="PTH-SCAN-1001"></a>

## PTH-SCAN-1001: Clone credential could not be obtained

| | |
|---|---|
| Severity | error |
| Category | authentication |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/scans/worker_api.go (lease → failJob) |

**What it means.** When a worker leased the scan, the API could not produce a clone credential for the repository, so the scan failed.

**Confirmed cause.** The repository's connection could not provide a clone credential. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The connection's token expired or was revoked
2. The connection was deleted
3. The stored credential cannot be decrypted

**Impact.** The scan failed without running any tool.

**How to fix**

1. Test the repository's SCM connection and fix it (see PTH-CONN codes).
2. Start the scan again.

**Verify**

1. The new scan reaches "running".


<a id="PTH-SCAN-1002"></a>

## PTH-SCAN-1002: Scan failed: worker lease expired repeatedly

| | |
|---|---|
| Severity | error |
| Category | availability |
| HTTP status | none (background work and logs) |
| AI help | offered |
| Raised in | internal/scans/worker_api.go (requeueExpired) |

**What it means.** The worker running the scan stopped sending heartbeats on every attempt, so the scan was failed after its maximum attempts.

**Confirmed cause.** The scan's worker lease expired on every attempt. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The worker container restarts (out of memory on a large repository)
2. The worker lost its network connection to the API
3. A tool hangs beyond the scan timeout

**Impact.** The scan failed; earlier results are kept.

**How to fix**

1. Check Configurations → Scanners & workers for offline workers.
2. Check the worker log and memory limits.
3. Start the scan again.

**Verify**

1. The scan completes.


<a id="PTH-SCAN-1003"></a>

## PTH-SCAN-1003: Scan result could not be ingested

| | |
|---|---|
| Severity | error |
| Category | internal |
| HTTP status | 500 |
| AI help | offered |
| Raised in | internal/scans/worker_api.go (result upload) |

**What it means.** A worker uploaded a tool result that the API could not parse or store.

**Confirmed cause.** Storing the tool's result failed (see the API log for the job and scanner). Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The tool produced output in an unexpected format (new tool version)
2. A database or object storage error

**Impact.** Findings of this tool are missing from the scan; the scan may end as partial.

**How to fix**

1. Download the tool's artifact from the scan page to inspect it.
2. Report the problem with the request ID if the format is new.

**Verify**

1. A new scan shows the tool's results.


<a id="PTH-SCAN-1004"></a>

## PTH-SCAN-1004: Imported report not recognised

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `invalid_report` |
| Raised in | internal/scans/imports.go |

**What it means.** An imported scanner report could not be parsed as the named or detected format.

**Confirmed cause.** The report does not match the format's parser (the message names the problem). Confirmed automatically when this code is raised.

**Probable causes**

1. The wrong --format was given
2. The file is a different report type of the same tool
3. The file is truncated

**Impact.** Nothing was imported; the import record shows the error.

**How to fix**

1. Run `GET /api/v1/import-formats` to pick the right format.
2. Import the unmodified report again.

**Verify**

1. The import shows the number of imported findings.


<a id="PTH-SCAN-1005"></a>

## PTH-SCAN-1005: SBOM not recognised

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `invalid_sbom` |
| Raised in | internal/scans/imports.go, internal/scans/targets.go |

**What it means.** The SBOM is not valid CycloneDX or SPDX JSON, or has no components.

**Confirmed cause.** The SBOM could not be parsed. Confirmed automatically when this code is raised.

**Probable causes**

1. An XML or tag-value SBOM (only JSON is accepted)
2. A truncated file

**Impact.** No components were imported.

**How to fix**

1. Export the SBOM as CycloneDX JSON or SPDX JSON and import it again.

**Verify**

1. The repository's SBOM tab lists components.


<a id="PTH-SCAN-1006"></a>

## PTH-SCAN-1006: Malware detected in the upload

| | |
|---|---|
| Severity | critical |
| Category | integrity |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `malware_detected`, `import:malware_detected` |
| Raised in | internal/scans/targets.go, internal/repos/import_worker.go |

**What it means.** ClamAV reported malware in an uploaded artifact or source archive; the upload was rejected.

**Confirmed cause.** The malware scanner reported a detection (signature in the message). Confirmed automatically when this code is raised.

**Probable causes**

1. The artifact is infected
2. A test file with a known signature (EICAR)

**Impact.** The upload was not stored or scanned.

**How to fix**

1. Do not use the artifact; investigate where it came from.
2. Upload a clean build.

**Verify**

1. A clean upload is accepted.


<a id="PTH-SCAN-1007"></a>

## PTH-SCAN-1007: Malware scanner unavailable

| | |
|---|---|
| Severity | error |
| Category | availability |
| HTTP status | 503 |
| AI help | offered |
| Short codes | `malware_scanner_unavailable`, `import:malware_scan_too_large` |
| Raised in | internal/scans/targets.go, internal/repos/import_worker.go |

**What it means.** Uploads must be scanned by ClamAV (PATHOS_CLAMAV_REQUIRED) but the scanner did not answer, or the upload is too large for it.

**Confirmed cause.** The required malware scan could not run. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The clamav container is starting (signature download) or stopped
2. PATHOS_CLAMAV_ADDRESS is wrong
3. The file exceeds ClamAV's stream limit

**Impact.** Uploads are refused while the scanner is unavailable.

**How to fix**

1. Check `docker compose ps clamav` and its log.
2. Raise ClamAV's StreamMaxLength for large artifacts.

**Verify**

1. The upload is accepted.


<a id="PTH-SCAN-1008"></a>

## PTH-SCAN-1008: Source snapshot not available

| | |
|---|---|
| Severity | warning |
| Category | not-found |
| HTTP status | 404 |
| AI help | not offered |
| Short codes | `no_snapshot` |
| Raised in | internal/scans/worker_api.go |

**What it means.** The scan needs a stored source snapshot (uploaded source) that does not exist anymore.

**Confirmed cause.** No stored snapshot exists for this scan. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The snapshot was removed by retention
2. The upload never completed

**Impact.** The scan cannot run on uploaded source.

**How to fix**

1. Upload the source again and start a new scan.

**Verify**

1. The new scan runs.


<a id="PTH-SCAN-1009"></a>

## PTH-SCAN-1009: Custom rules invalid

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `invalid_rules` |
| Raised in | internal/scans/rules.go |

**What it means.** The custom Opengrep rule file failed validation.

**Confirmed cause.** The rule content does not validate (details in the message). Confirmed automatically when this code is raised.

**Probable causes**

1. YAML syntax error
2. A missing id, message, languages or severity field

**Impact.** The rule version was not saved; scans keep the previous version.

**How to fix**

1. Fix the reported line and save again.

**Verify**

1. The rule saves and appears in the next scan's configuration.


<a id="PTH-SCAN-1010"></a>

## PTH-SCAN-1010: No SBOM or component inventory yet

| | |
|---|---|
| Severity | info |
| Category | not-found |
| HTTP status | 404 |
| AI help | not offered |
| Short codes | `no_sbom` |
| Raised in | internal/vuln/sbom.go |

**What it means.** The repository has no scan SBOM and no component inventory to export.

**Confirmed cause.** No components are known for this repository. Confirmed automatically when this code is raised.

**Probable causes**

1. No scan with an SBOM tool has completed
2. No SBOM was imported

**Impact.** SBOM export is unavailable for this repository.

**How to fix**

1. Run a scan with a profile that includes Syft, or import an SBOM.

**Verify**

1. The SBOM export downloads.

