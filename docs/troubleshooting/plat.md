---
title: Troubleshooting: Platform
section: troubleshooting
order: 101
version: "1.0"
updated: 2026-11-20
summary: Database, queue, object storage, uploads, request handling and the generic API errors (23 codes, PTH-PLAT-*)
---

# Troubleshooting: Platform

Quditmind PATHOS · status: Production-ready

> Generated from the PATHOS error catalogue (`backend/internal/platform/diag`) by `make docs-errors`. Do not edit by hand; change the catalogue and regenerate.

Database, queue, object storage, uploads, request handling and the generic API errors.

| Code | Title | Severity |
|---|---|---|
| [PTH-PLAT-0001](#PTH-PLAT-0001) | Unexpected internal error | error |
| [PTH-PLAT-0002](#PTH-PLAT-0002) | Invalid request | warning |
| [PTH-PLAT-0003](#PTH-PLAT-0003) | Validation failed | warning |
| [PTH-PLAT-0004](#PTH-PLAT-0004) | Resource not found | info |
| [PTH-PLAT-0005](#PTH-PLAT-0005) | Conflict with the current state | warning |
| [PTH-PLAT-0006](#PTH-PLAT-0006) | Unsupported content type | warning |
| [PTH-PLAT-0007](#PTH-PLAT-0007) | Request or file too large | warning |
| [PTH-PLAT-0008](#PTH-PLAT-0008) | Too many requests | warning |
| [PTH-PLAT-0009](#PTH-PLAT-0009) | Service temporarily unavailable | error |
| [PTH-PLAT-0010](#PTH-PLAT-0010) | Item no longer available | info |
| [PTH-PLAT-1001](#PTH-PLAT-1001) | Database unreachable | critical |
| [PTH-PLAT-1002](#PTH-PLAT-1002) | Database migrations pending | critical |
| [PTH-PLAT-1003](#PTH-PLAT-1003) | Queue and session store unreachable | critical |
| [PTH-PLAT-1004](#PTH-PLAT-1004) | Object storage error | error |
| [PTH-PLAT-1005](#PTH-PLAT-1005) | Uploads are not configured | warning |
| [PTH-PLAT-1006](#PTH-PLAT-1006) | Secret storage unavailable | error |
| [PTH-PLAT-1007](#PTH-PLAT-1007) | Feature not enabled | info |
| [PTH-PLAT-1008](#PTH-PLAT-1008) | Multi-tenancy is not enabled | info |
| [PTH-PLAT-1009](#PTH-PLAT-1009) | The default organization cannot be changed this way | warning |
| [PTH-PLAT-1010](#PTH-PLAT-1010) | Organization must be suspended first | warning |
| [PTH-PLAT-1011](#PTH-PLAT-1011) | Too many uploads in progress | warning |
| [PTH-PLAT-1012](#PTH-PLAT-1012) | Upload checksum mismatch | error |
| [PTH-PLAT-1013](#PTH-PLAT-1013) | Stored credential could not be decrypted | critical |

<a id="PTH-PLAT-0001"></a>

## PTH-PLAT-0001: Unexpected internal error

| | |
|---|---|
| Severity | error |
| Category | internal |
| HTTP status | 500 |
| AI help | offered |
| Short codes | `internal` |
| Raised in | internal/platform/httpx/httpx.go (WriteError, panic recovery) |

**What it means.** The server hit an error it does not classify. The details are logged on the server with the request ID; they are never sent to the client.

**Confirmed cause.** An unclassified server-side error. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A database or storage call failed transiently
2. A defect in PATHOS for this request

**Impact.** The request did not complete. Nothing was changed unless the response said otherwise.

**How to fix**

1. Retry the action once.
2. If it fails again, look up the request ID in the API log (`docker compose logs api | grep <request_id>`).
3. Report the problem with the request ID and error code (Help → Report a problem).

**Verify**

1. Repeat the action; it completes without an error.


<a id="PTH-PLAT-0002"></a>

## PTH-PLAT-0002: Invalid request

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 400 |
| AI help | not offered |
| Short codes | `invalid_request`, `method_not_allowed` |
| Raised in | internal/platform/httpx/httpx.go (BadRequest, DecodeJSON) |

**What it means.** The request body, query or path failed validation (malformed JSON, unknown field, missing or out-of-range value).

**Confirmed cause.** The request did not pass validation; the message names the field or rule. Confirmed automatically when this code is raised.

**Probable causes**

1. A required field is missing or has the wrong type
2. A client or script built for another PATHOS version

**Impact.** Nothing was changed.

**How to fix**

1. Correct the value named in the message.
2. For scripts, compare the request with the API reference of this version.

**Verify**

1. Send the corrected request; it succeeds.


<a id="PTH-PLAT-0003"></a>

## PTH-PLAT-0003: Validation failed

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `validation_failed`, `invalid_items` |
| Raised in | internal/review/decide.go, internal/repos/metadata.go, internal/repos/imports.go |

**What it means.** The request was well-formed but one or more values break a business rule. Per-field messages are in error.fields.

**Confirmed cause.** One or more fields break a validation rule (listed in error.fields). Confirmed automatically when this code is raised.

**Probable causes**

1. A value outside the allowed range or list
2. A referenced item was deleted or changed meanwhile

**Impact.** Nothing was changed.

**How to fix**

1. Fix each field listed in the form or in error.fields.
2. Reload the page if a referenced item may have changed.

**Verify**

1. Save again; the form is accepted.


<a id="PTH-PLAT-0004"></a>

## PTH-PLAT-0004: Resource not found

| | |
|---|---|
| Severity | info |
| Category | not-found |
| HTTP status | 404 |
| AI help | not offered |
| Short codes | `not_found`, `no_target_file` |
| Raised in | internal/platform/httpx/httpx.go (ErrNotFound) and every service's fail() |

**What it means.** The item does not exist, was deleted, or is outside what the caller may see (PATHOS answers 404 instead of 403 so it does not reveal other teams' or organizations' items).

**Confirmed cause.** No item with this identifier is visible to you. Confirmed automatically when this code is raised.

**Probable causes**

1. The item was deleted or archived
2. The link belongs to another organization or business unit
3. A mistyped identifier

**Impact.** Nothing was read or changed.

**How to fix**

1. Open the list page and search for the item.
2. Switch organization if the link came from another one.
3. Ask an administrator for access if you should see it.

**Verify**

1. The item opens from its list page.


<a id="PTH-PLAT-0005"></a>

## PTH-PLAT-0005: Conflict with the current state

| | |
|---|---|
| Severity | warning |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `conflict` |
| Raised in | internal/platform/httpx/httpx.go (Conflict), database unique constraints |

**What it means.** The change conflicts with existing data: a duplicate name, an operation already running, or a state that does not allow it.

**Confirmed cause.** The item already exists or is in a state that does not allow this change (see the message). Confirmed automatically when this code is raised.

**Probable causes**

1. An item with the same name already exists
2. The same operation is already running
3. Someone else changed the item

**Impact.** Nothing was changed.

**How to fix**

1. Reload the page to see the current state.
2. Choose another name, or wait for the running operation to finish.

**Verify**

1. Retry after reloading; the change is accepted.


<a id="PTH-PLAT-0006"></a>

## PTH-PLAT-0006: Unsupported content type

| | |
|---|---|
| Severity | warning |
| Category | validation |
| HTTP status | 415 |
| AI help | not offered |
| Short codes | `unsupported_media_type` |
| Raised in | internal/platform/httpx/httpx.go (DecodeJSON), internal/scans/imports.go, internal/repos/importer.go |

**What it means.** The request's Content-Type is not one the endpoint accepts (JSON endpoints need application/json; uploads name their own types).

**Confirmed cause.** The Content-Type header does not match what the endpoint accepts. Confirmed automatically when this code is raised.

**Probable causes**

1. A script sends form data or text instead of JSON
2. A file upload with the wrong media type

**Impact.** Nothing was changed.

**How to fix**

1. Send the Content-Type named in the message (for JSON: application/json).

**Verify**

1. Repeat the request with the right header; it is accepted.


<a id="PTH-PLAT-0007"></a>

## PTH-PLAT-0007: Request or file too large

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | 413 |
| AI help | not offered |
| Short codes | `too_large` |
| Raised in | internal/repos/uploads.go, internal/repos/webhooks.go, internal/scans/imports.go, internal/scans/worker_api.go, internal/review/evidence.go |

**What it means.** The body, upload, webhook payload or decompressed output exceeds the configured limit.

**Confirmed cause.** The payload exceeds the limit named in the message. Confirmed automatically when this code is raised.

**Probable causes**

1. A very large report, SBOM or archive
2. The size limit of this installation is lower than needed

**Impact.** The upload or request was rejected; nothing was stored.

**How to fix**

1. Split the upload or compress it where the endpoint accepts gzip.
2. An administrator can raise the limit (PATHOS_UPLOAD_MAX_BYTES and related settings in docs/OPERATIONS.md).

**Verify**

1. Upload again; the request succeeds.


<a id="PTH-PLAT-0008"></a>

## PTH-PLAT-0008: Too many requests

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | 429 |
| AI help | not offered |
| Short codes | `rate_limited` |
| Raised in | internal/platform/ratelimit/middleware.go |

**What it means.** The API rate limiter refused the request (per user, token or address, configured by PATHOS_RATE_LIMIT_*).

**Confirmed cause.** Your requests exceeded the API rate limit. Confirmed automatically when this code is raised.

**Probable causes**

1. A script polls too often
2. Many people share one address behind a proxy

**Impact.** The request was not processed. Retrying after the Retry-After delay succeeds.

**How to fix**

1. Wait for the Retry-After delay, then retry.
2. Reduce polling in scripts (the CLI already backs off).
3. An administrator can tune PATHOS_RATE_LIMIT_SCALE.

**Verify**

1. The next request after the delay succeeds.


<a id="PTH-PLAT-0009"></a>

## PTH-PLAT-0009: Service temporarily unavailable

| | |
|---|---|
| Severity | error |
| Category | availability |
| HTTP status | 503 |
| AI help | offered |
| Short codes | `unavailable` |
| Raised in | internal/review/evidence.go, internal/scans/fixprs.go, internal/scans/aifixes.go |

**What it means.** A dependency needed for this request is not available right now (an upstream service, the evidence store, or a background component).

**Confirmed cause.** A dependency of this request is unavailable. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. A container is restarting
2. The dependency named in the message is not configured

**Impact.** The request did not complete.

**How to fix**

1. Retry in a minute.
2. Check Help → System status.
3. An administrator checks `docker compose ps` and the API log for the request ID.

**Verify**

1. Retry; the request succeeds and System status is healthy.


<a id="PTH-PLAT-0010"></a>

## PTH-PLAT-0010: Item no longer available

| | |
|---|---|
| Severity | info |
| Category | not-found |
| HTTP status | 410 |
| AI help | not offered |
| Short codes | `gone` |
| Raised in | internal/review/evidence.go |

**What it means.** The item existed but its content was removed (for example review evidence deleted by retention).

**Confirmed cause.** The content was removed and cannot be served. Confirmed automatically when this code is raised.

**Probable causes**

1. Retention removed it
2. Someone deleted it

**Impact.** The content cannot be downloaded; metadata and audit records remain.

**How to fix**

1. Upload the evidence again if it is still needed.

**Verify**

1. The new item downloads.


<a id="PTH-PLAT-1001"></a>

## PTH-PLAT-1001: Database unreachable

| | |
|---|---|
| Severity | critical |
| Category | availability |
| HTTP status | 503 |
| AI help | offered |
| Raised in | internal/server/server.go (readiness), cmd/pathos/main.go (healthcheck) |

**What it means.** PostgreSQL did not answer the readiness ping (GET /readyz) or a health check.

**Confirmed cause.** The API cannot reach PostgreSQL. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The postgres container is stopped or restarting
2. Wrong PATHOS_DATABASE_URL credentials or host
3. The database ran out of disk or connections

**Impact.** No page or API call that reads data works; scans and jobs stop.

**How to fix**

1. Check `docker compose ps postgres` and `docker compose logs postgres`.
2. Check free disk space on the database volume.
3. Check PATHOS_DATABASE_URL in .env and restart api, jobs and scheduler.

**Verify**

1. `curl -s https://<host>/readyz` shows postgres "ok".


<a id="PTH-PLAT-1002"></a>

## PTH-PLAT-1002: Database migrations pending

| | |
|---|---|
| Severity | critical |
| Category | configuration |
| HTTP status | 503 |
| AI help | offered |
| Raised in | internal/server/server.go (readiness) |

**What it means.** The schema version is lower than the version this API build expects (GET /readyz).

**Confirmed cause.** Migrations newer than the database schema are not applied. Confirmed automatically when this code is raised.

**Probable causes**

1. The upgrade ran without the migrate step
2. The migrate container failed

**Impact.** The API reports not ready; features that use new tables fail.

**How to fix**

1. Run `docker compose run --rm migrate` (or deploy/scripts/upgrade.sh).
2. Read the migrate log if it fails.

**Verify**

1. `pathosctl migrate-status` shows current = latest and /readyz is ready.


<a id="PTH-PLAT-1003"></a>

## PTH-PLAT-1003: Queue and session store unreachable

| | |
|---|---|
| Severity | critical |
| Category | availability |
| HTTP status | 503 |
| AI help | offered |
| Raised in | internal/server/server.go (readiness) |

**What it means.** Redis (sessions, rate limits, login flows) did not answer the readiness ping.

**Confirmed cause.** The API cannot reach Redis. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The redis container is stopped or restarting
2. Wrong PATHOS_REDIS_URL or password

**Impact.** Sign-in and sessions fail; rate limiting is unavailable.

**How to fix**

1. Check `docker compose ps redis` and its log.
2. Check PATHOS_REDIS_URL in .env and restart the API.

**Verify**

1. /readyz shows redis "ok" and sign-in works.


<a id="PTH-PLAT-1004"></a>

## PTH-PLAT-1004: Object storage error

| | |
|---|---|
| Severity | error |
| Category | availability |
| HTTP status | 502 |
| AI help | offered |
| Short codes | `object_storage_error` |
| Raised in | internal/tenancy/http.go, internal/platform/objstore |

**What it means.** Reading or deleting a stored object (scan artifacts, snapshots, evidence) in the S3-compatible store failed.

**Confirmed cause.** The object store refused or failed the request. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. The bucket is unreachable or the endpoint changed
2. The access key was rotated or lacks permission
3. The object was removed outside PATHOS

**Impact.** Artifacts cannot be downloaded or deleted; organization deletion stops before removing data.

**How to fix**

1. Check PATHOS_S3_* settings and that the bucket exists.
2. Check the store's own log for denied requests.
3. Retry the operation.

**Verify**

1. Download a scan artifact; it succeeds.


<a id="PTH-PLAT-1005"></a>

## PTH-PLAT-1005: Uploads are not configured

| | |
|---|---|
| Severity | warning |
| Category | configuration |
| HTTP status | 503 |
| AI help | not offered |
| Short codes | `uploads_unavailable`, `import:uploads_unavailable` |
| Raised in | internal/repos/uploads.go, internal/repos/imports.go |

**What it means.** Local source uploads need the encrypted source store, which is not configured on this server.

**Confirmed cause.** This server has no source store for uploads. Confirmed automatically when this code is raised.

**Probable causes**

1. PATHOS_SOURCE_STORE_DIR (or its volume) is not set

**Impact.** Archive and folder uploads are unavailable; SCM imports still work.

**How to fix**

1. An administrator configures the source store (docs/OPERATIONS.md) and restarts the API.

**Verify**

1. Start an upload; it is accepted.


<a id="PTH-PLAT-1006"></a>

## PTH-PLAT-1006: Secret storage unavailable

| | |
|---|---|
| Severity | error |
| Category | configuration |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `secrets_unavailable` |
| Raised in | internal/notify/webhooks.go |

**What it means.** Saving a credential needs the master key (PATHOS_MASTER_KEY); the secret store is not available.

**Confirmed cause.** The encrypted secret store is not configured on this server. Confirmed automatically when this code is raised.

**Probable causes**

1. PATHOS_MASTER_KEY is missing from the environment of this service

**Impact.** Webhook signing secrets and other credentials cannot be stored.

**How to fix**

1. Set PATHOS_MASTER_KEY (generate with `pathosctl gen-key`) and restart.

**Verify**

1. Save the webhook again; it is accepted.


<a id="PTH-PLAT-1007"></a>

## PTH-PLAT-1007: Feature not enabled

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 404 |
| AI help | not offered |
| Short codes | `feature_disabled` |
| Raised in | internal/featureflags/flags.go |

**What it means.** The module is behind a feature flag that is off for this organization (feature flags are off by default until the module is approved).

**Confirmed cause.** The feature flag named in the message is off for your organization. Confirmed automatically when this code is raised.

**Probable causes**

1. The module has not been enabled by an administrator

**Impact.** The module's pages and API answer as unavailable.

**How to fix**

1. An administrator with settings.manage enables the flag (Administration → Feature flags, or PUT /api/v1/admin/feature-flags).

**Verify**

1. GET /api/v1/meta lists the flag as true and the page opens.


<a id="PTH-PLAT-1008"></a>

## PTH-PLAT-1008: Multi-tenancy is not enabled

| | |
|---|---|
| Severity | info |
| Category | configuration |
| HTTP status | 404 |
| AI help | not offered |
| Short codes | `multi_tenancy_disabled` |
| Raised in | internal/tenancy/http.go |

**What it means.** Installation administration (organizations) is available only when multi-tenancy is enabled.

**Confirmed cause.** This installation runs as a single organization. Confirmed automatically when this code is raised.

**Probable causes**

1. `pathosctl multi-tenancy enable` was not run

**Impact.** Organizations cannot be created or managed.

**How to fix**

1. Follow docs/MULTI_TENANCY.md: run `pathosctl multi-tenancy enable` and restart api, jobs and scheduler.

**Verify**

1. `pathosctl multi-tenancy status` reports enabled.


<a id="PTH-PLAT-1009"></a>

## PTH-PLAT-1009: The default organization cannot be changed this way

| | |
|---|---|
| Severity | warning |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `default_organization` |
| Raised in | internal/tenancy/http.go |

**What it means.** The default organization (PATHOS_ORG_SLUG) cannot be suspended or deleted.

**Confirmed cause.** The target is the installation's default organization. Confirmed automatically when this code is raised.

**Probable causes**

1. The default organization was selected by mistake

**Impact.** Nothing was changed.

**How to fix**

1. Select another organization, or change PATHOS_ORG_SLUG first.

**Verify**

1. The intended organization shows the new status.


<a id="PTH-PLAT-1010"></a>

## PTH-PLAT-1010: Organization must be suspended first

| | |
|---|---|
| Severity | warning |
| Category | conflict |
| HTTP status | 409 |
| AI help | not offered |
| Short codes | `not_suspended` |
| Raised in | internal/tenancy/http.go |

**What it means.** An organization is deleted only after it is suspended.

**Confirmed cause.** The organization is active. Confirmed automatically when this code is raised.

**Probable causes**

1. The suspend step was skipped

**Impact.** Nothing was deleted.

**How to fix**

1. Suspend the organization, then delete it with its slug as confirmation.

**Verify**

1. The organization is listed as deleted in the installation audit log.


<a id="PTH-PLAT-1011"></a>

## PTH-PLAT-1011: Too many uploads in progress

| | |
|---|---|
| Severity | warning |
| Category | capacity |
| HTTP status | 429 |
| AI help | not offered |
| Short codes | `too_many_uploads` |
| Raised in | internal/repos/uploads.go |

**What it means.** A user may have a limited number of unfinished chunked uploads.

**Confirmed cause.** You reached the limit of unfinished uploads. Confirmed automatically when this code is raised.

**Probable causes**

1. Earlier uploads were abandoned before completion

**Impact.** New uploads are refused until older ones finish or expire.

**How to fix**

1. Finish or cancel the open uploads, or wait for them to expire.

**Verify**

1. Start the upload again; it is accepted.


<a id="PTH-PLAT-1012"></a>

## PTH-PLAT-1012: Upload checksum mismatch

| | |
|---|---|
| Severity | error |
| Category | integrity |
| HTTP status | 422 |
| AI help | not offered |
| Short codes | `checksum_mismatch`, `import:checksum_mismatch` |
| Raised in | internal/repos/uploads.go |

**What it means.** The SHA-256 of the received upload differs from the checksum the client declared.

**Confirmed cause.** The uploaded bytes do not match the declared SHA-256. Confirmed automatically when this code is raised.

**Probable causes**

1. The upload was corrupted or truncated in transit
2. The client computed the checksum of another file

**Impact.** The upload was discarded.

**How to fix**

1. Upload the file again.
2. Check the file's sha256sum before uploading.

**Verify**

1. The upload completes and the import starts.


<a id="PTH-PLAT-1013"></a>

## PTH-PLAT-1013: Stored credential could not be decrypted

| | |
|---|---|
| Severity | critical |
| Category | integrity |
| HTTP status | 500 |
| AI help | offered |
| Raised in | internal/platform/crypto/envelope.go (ErrDecrypt), internal/secrets |

**What it means.** A secret's envelope encryption check failed (wrong master key, or the ciphertext was moved or altered).

**Confirmed cause.** Decryption of a stored credential failed. Shown as confirmed only when the failing check proves it; otherwise use the probable causes.

**Probable causes**

1. PATHOS_MASTER_KEY changed without `pathosctl rotate-master-key`
2. The database was restored with another installation's key

**Impact.** Every connection that uses the credential fails until it is re-entered or the right key is restored.

**How to fix**

1. Restore the previous PATHOS_MASTER_KEY (keep both keys during rotation).
2. Otherwise re-enter the credential on the connection.

**Verify**

1. Test the connection; it succeeds.

