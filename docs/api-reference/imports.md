---
title: Imports and uploads
section: api-reference
order: 5
version: "1.0"
updated: 2026-11-19
summary: Register new repositories through asynchronous import jobs from SCM connections or uploaded archives, using resumable chunked uploads.
---

# Imports and uploads

Imports are how new repositories (assets) are created. An import job holds one or more items. Each item is a remote repository of an SCM connection or an uploaded source archive. The API validates the job when it is created, then background workers process the items, register the repositories and, if requested, queue an onboarding scan.

Typical flows:

- **Git or Azure DevOps:** browse the connection with the [discovery endpoints](integrations.md#list-remote-repositories), optionally [validate](#validate-an-import), then [start an import](#start-an-import) and poll [Get an import job](#get-an-import-job).
- **Local upload:** [create an upload session](#create-an-upload-session), [send the parts](#upload-a-part), [complete the upload](#complete-an-upload), then [start an import](#start-an-import) with `source: "upload"`.

All endpoints are under `/api/v1` and accept a browser session (with `X-CSRF-Token` on mutations) or a REST API token. See [Authentication](index.md#authentication).

## Upload sessions

Uploads are resumable. The client declares the file name, size and SHA-256 of the whole archive, then sends fixed-size parts with a per-part SHA-256. Uploads are private to the user who created them, expire 24 hours after they were created (sending parts does not extend this; see `expires_at`), and are removed by an hourly cleanup.

Limits:

| Limit | Value |
|---|---|
| Part size (`chunk_size`) | 8 MiB (8,388,608 bytes); the last part holds the remainder |
| Formats | `.zip`, `.tar`, `.tar.gz`, `.tgz` (format `zip`, `tar` or `tar.gz`) |
| Maximum archive size | `PATHOS_UPLOAD_MAX_BYTES`, default 2 GiB. Shown as `upload.max_bytes` in [Get asset settings](assets.md#get-asset-settings) |
| Open sessions per user | 50 (`uploading` or `complete`, not expired) |
| Staged bytes per user | 4 × the maximum archive size |
| Session lifetime | 24 hours |

During processing, archives are also bounded by `PATHOS_IMPORT_MAX_FILES` (default 200,000), `PATHOS_IMPORT_MAX_EXTRACTED_BYTES` (default 8 GiB), `PATHOS_IMPORT_MAX_FILE_BYTES` (default 1 GiB) and `PATHOS_IMPORT_TIMEOUT` (default 30 minutes per item). `PATHOS_IMPORT_CONCURRENCY` (default 2) sets how many items are processed in parallel and `PATHOS_IMPORT_WORK_DIR` (default `/tmp/pathos-import`) where archives are unpacked. Uploaded archives are checked by ClamAV when `PATHOS_CLAMAV_ADDRESS` is set; `PATHOS_CLAMAV_REQUIRED` makes the check mandatory.

Upload `status` values:

| Status | Meaning |
|---|---|
| `uploading` | Accepting parts. |
| `complete` | All parts received; ready to import. |
| `consumed` | Imported into a repository; parts were replaced by a snapshot. |
| `expired` | Not imported within 24 hours (also shown for `uploading` or `complete` sessions past `expires_at`). |
| `cancelled` | Deleted by the user, or rejected by the malware scanner. |

All upload endpoints return `503 uploads_unavailable` when the server has no source store configured.

### Create an upload session

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/source-uploads` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` at any scope |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

| Field | Type | Required | Description |
|---|---|---|---|
| `filename` | string | yes | File name (path components are stripped), max 255 characters. Its extension selects the format. |
| `size` | integer | yes | Archive size in bytes, 1 to the configured maximum. |
| `sha256` | string | yes | Lower- or upper-case hex SHA-256 of the whole file (64 characters). |

```json
{
  "filename": "billing-batch-2026.11.zip",
  "size": 20971520,
  "sha256": "3b1f0c9e8d7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c"
}
```

Response `201 Created`:

```json
{
  "id": "0190c0de-9999-7000-8000-000000000001",
  "filename": "billing-batch-2026.11.zip",
  "format": "zip",
  "size": 20971520,
  "sha256": "3b1f0c9e8d7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c",
  "chunk_size": 8388608,
  "status": "uploading",
  "received_parts": [],
  "received_bytes": 0,
  "expires_at": "2026-11-18T08:30:00Z"
}
```

This archive has 3 parts: 0 and 1 of 8,388,608 bytes, and 2 of 4,194,304 bytes.

| Status | Meaning |
|---|---|
| 201 | Session created. |
| 400 `invalid_request` | Invalid file name, unsupported extension ("only .zip, .tar, .tar.gz and .tgz archives are accepted"), invalid `sha256`, malformed JSON. |
| 403 `forbidden` | No `repos.manage` anywhere. |
| 413 `too_large` | "archives must be between 1 byte and 2048 MB". |
| 415 `unsupported_media_type` | Wrong `Content-Type`. |
| 429 `too_many_uploads` | "finish, import or cancel your open uploads first". |
| 503 `uploads_unavailable` | Uploads are not configured. |

Database entities: `source_uploads`.

### Get an upload session

Returns the session, including which parts were received, so an interrupted upload can resume by sending the missing parts.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/source-uploads/{id}` |
| Authentication | Session or API token |
| Permission | Only the user who created the upload; anyone else gets `404 not_found` |
| Request headers | `Cookie` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Upload ID. |

Response `200 OK`: the upload object, for example with `"received_parts": [0, 2]` and `"received_bytes": 12582912`.

| Status | Meaning |
|---|---|
| 200 | Returned. |
| 404 `not_found` | Unknown upload, or created by another user. |
| 503 `uploads_unavailable` | Uploads are not configured. |

Database entities: `source_uploads`, `source_upload_parts`.

### Upload a part

Stores one part. Parts can be sent in any order and in parallel. Sending a part again replaces it.

| Property | Value |
|---|---|
| Method | `PUT` |
| Path | `/api/v1/source-uploads/{id}/parts/{n}` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Only the user who created the upload |
| Request headers | `Cookie`, `X-CSRF-Token`, `X-Content-SHA256` (hex SHA-256 of this part), `Content-Type: application/octet-stream` (not checked) |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Upload ID. |
| `n` | integer | yes | Zero-based part number, `0` to `ceil(size / chunk_size) - 1`. |

Body: the raw bytes of the part, exactly `chunk_size` bytes (the last part: the remainder).

```bash
curl -X PUT "https://pathos.example.com/api/v1/source-uploads/0190c0de-9999-7000-8000-000000000001/parts/0" \
  -H "Cookie: __Host-pathos_session=<session-cookie>" \
  -H "X-CSRF-Token: <csrf-token>" \
  -H "Content-Type: application/octet-stream" \
  -H "X-Content-SHA256: 5d41402abc4b2a76b9719d911017c5925d41402abc4b2a76b9719d911017c592" \
  --data-binary @part-000
```

Response `200 OK`:

```json
{ "part": 0, "size": 8388608 }
```

| Status | Meaning |
|---|---|
| 200 | Part stored. |
| 400 `invalid_request` | Part number out of range, missing or malformed `X-Content-SHA256`, body shorter than the expected part size. |
| 404 `not_found` | Unknown upload or not the creator. |
| 409 `conflict` | The upload is no longer `uploading` ("the upload is complete", "... expired", ...). |
| 413 `too_large` | Body longer than the expected part size. |
| 422 `checksum_mismatch` | "the part does not match its SHA-256; resend it". |
| 503 `uploads_unavailable` | Uploads are not configured. |

```json
{
  "error": { "code": "checksum_mismatch", "message": "the part does not match its SHA-256; resend it" },
  "request_id": "d24a6f3e5c7b8a9f0e1d2c3b"
}
```

Database entities: `source_upload_parts` (the bytes go to the encrypted source store).

### Complete an upload

Marks the upload `complete` when every part was received. Calling it again on a complete upload returns the upload unchanged. The SHA-256 of the whole archive is verified when the import processes it.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/source-uploads/{id}/complete` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Only the user who created the upload |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response `200 OK`: the upload object with `"status": "complete"`.

| Status | Meaning |
|---|---|
| 200 | Complete. |
| 404 `not_found` | Unknown upload or not the creator. |
| 409 `conflict` | Parts are missing (see below), or the upload is `consumed`, `expired` or `cancelled`. |
| 503 `uploads_unavailable` | Uploads are not configured. |

```json
{
  "error": {
    "code": "conflict",
    "message": "1 of 3 parts are missing",
    "details": { "missing_parts": [1] }
  },
  "request_id": "e35b7a4f6d8c9b0a1f2e3d4c"
}
```

Database entities: `source_uploads`, `audit_logs` (`source_upload.complete`).

### Delete an upload

Cancels an upload that was not imported and deletes its stored parts.

| Property | Value |
|---|---|
| Method | `DELETE` |
| Path | `/api/v1/source-uploads/{id}` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | Only the user who created the upload |
| Request headers | `Cookie`, `X-CSRF-Token` |

Response: `204 No Content`.

| Status | Meaning |
|---|---|
| 204 | Cancelled. |
| 404 `not_found` | Unknown upload or not the creator. |
| 409 `conflict` | "the upload was already imported", or "the upload is being imported; cancel the import first". |
| 503 `uploads_unavailable` | Uploads are not configured. |

Database entities: `source_uploads`, `source_upload_parts`.

## Import jobs

### The import request

[Validate an import](#validate-an-import) and [Start an import](#start-an-import) take the same body (frontend type `CreateImportRequest`).

| Field | Type | Required | Description |
|---|---|---|---|
| `source` | string | yes | `git` (GitHub, GitHub Enterprise, GitLab, Bitbucket connections), `devops` (Azure DevOps connections) or `upload`. |
| `scm_connection_id` | UUID | for `git` and `devops` | Must not be set for `upload`. The connection's category must match `source`. |
| `idempotency_key` | string | for start | 8–100 characters, random per submission. Alternatively send the `Idempotency-Key` header. |
| `metadata` | object | yes | Asset metadata shared by all items: the fields of [Update a repository](repositories.md#update-a-repository) except the scan settings (`scan_enabled`, `scan_branch`, `technologies`, `full_history`). |
| `items` | array | yes | 1–200 items. |
| `start_scan` | boolean | no | Queue an onboarding scan for each registered repository. Honoured only while `scan_on_import` is enabled in [asset settings](assets.md#get-asset-settings). |

Item fields (`ImportItemRequest`):

| Field | Type | Applies to | Description |
|---|---|---|---|
| `ref` | object | `git`, `devops` | `{ "external_id", "full_name", "organization", "project" }` as returned by [discovery](integrations.md#list-remote-repositories). `external_id` or `full_name` is required; each value max 300 characters. |
| `upload_id` | UUID | `upload` | A `complete` upload of the caller. |
| `target_repository_id` | UUID | `upload` | Adds the archive as a new snapshot of an existing uploaded repository instead of creating one. See [version uploads](#upload-a-new-version-of-an-uploaded-repository). |
| `branch` | string | `git`, `devops` | Branch to track and scan; `""` = default branch. Max 255 characters. |
| `full_history` | boolean | `git`, `devops` | Clone full history for scans. |
| `display_name` | string | all | Per-item display name; default: the repository full name or the archive name without extension. Max 200 characters. |
| `asset_name` | string | all | Per-item asset name; unique among active repositories and within the job. Max 200 characters. |
| `allow_duplicate` | boolean | all | Register even if the same archive (SHA-256) or the same clone URL is already registered. |

Metadata rules for new repositories: the same field rules as [Update a repository](repositories.md#update-a-repository), with every required field enforced:

- Always required: `business_owner_id`, `business_unit_id`, `business_region_id`, `public_exposure`, plus the organization's `required_fields`. A new organization's `required_fields` are business owner, technical owner, business unit, business region, criticality, data classification and environment, so `technical_owner_id` and `data_classification` are needed too unless an administrator relaxes them ([asset settings](assets.md#get-asset-settings)).
- `criticality` and `environment` must be sent (no default is applied in imports).
- Defaults when absent: `internet_exposure: "unknown"`, `lifecycle_status: "active"`.
- Authorization: `repos.manage` at the placement (the business unit; without one, the region of the country; else the organization).
- `new_application` creates the application once per job; later items of the same job reuse it.

### Validate an import

Checks an import request without creating anything. Use it to show field and item problems before submitting.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repository-imports/validate` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` at any scope; `repos.manage` at the placement (otherwise `403`) |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` |

Body: [the import request](#the-import-request) (`idempotency_key` is ignored).

Response `200 OK`. Field errors and item problems are part of the response body, not error statuses:

```json
{
  "valid": false,
  "fields": {
    "business_owner_id": "required",
    "production_url": "enter an absolute http:// or https:// URL"
  },
  "items": [
    { "index": 0, "code": "already_imported", "message": "already imported; it will be skipped", "repository_id": "0190c0de-5555-7000-8000-000000000042" },
    { "index": 1, "code": "invalid_branch", "message": "invalid branch name" }
  ]
}
```

`valid` is `false` when there is any field error or any blocking item problem. `repository_id` is included only when the caller can read that repository.

Item problem codes:

| Code | Blocking | Meaning |
|---|:-:|---|
| `invalid_item` | yes | Missing `ref` / `upload_id`, mixed item kinds, or an over-long reference. |
| `invalid_branch` | yes | Not a valid branch name. |
| `invalid_upload` | yes | Unknown upload, upload not `complete`, target repository missing or not uploaded, or no `repos.manage` on the target. |
| `duplicate` | yes, unless `allow_duplicate` | An identical archive was already imported. |
| `duplicate_item` | yes | The same repository or upload appears twice in the request. |
| `already_imported` | no | The repository is already registered through this connection; the item is skipped (result `already_imported`). |
| `invalid_name` | yes | Display name or asset name longer than 200 characters. |
| `name_clash` | yes | Asset name used twice in the job, or by another active asset. |

| Status | Meaning |
|---|---|
| 200 | Validation result. |
| 400 `invalid_request` | Bad `source`, missing or unexpected `scm_connection_id`, "unknown SCM connection", wrong connection category, "country does not exist" (a `country_id` that does not exist when no business unit is set), 0 or more than 200 items, metadata sent with a version-only upload, malformed JSON. |
| 403 `forbidden` | No `repos.manage` anywhere or at the placement. |
| 404 `not_found` | The placement (business unit) does not exist. |
| 415 `unsupported_media_type` | Wrong `Content-Type`. |
| 503 `uploads_unavailable` | `source: "upload"` without upload support. |

Database entities: read-only checks on `repositories`, `source_uploads`, `source_snapshots`, `applications`, `asset_settings`, `asset_classifications`.

### Start an import

Validates the request and creates an import job with its items. Processing is asynchronous.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repository-imports` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | `repos.manage` at any scope, and `repos.manage` at the placement (or on each `target_repository_id` for version uploads) |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json`, optional `Idempotency-Key` |

Idempotency: a job is identified by (organization, requesting user, idempotency key). Sending the same key again returns the existing job with `200 OK` and does not compare the bodies. Use a new random key for every new submission.

Example: two GitHub repositories.

```json
{
  "source": "git",
  "scm_connection_id": "0190c0de-6666-7000-8000-000000000001",
  "idempotency_key": "wizard-3f9a1c7e-5b2d-4e8f",
  "start_scan": true,
  "metadata": {
    "description": "Payment services",
    "application_id": "0190c0de-4444-7000-8000-000000000001",
    "business_owner_id": "0190c0de-2222-7000-8000-000000000001",
    "technical_owner_id": "0190c0de-2222-7000-8000-000000000002",
    "responsible_team_id": "0190c0de-3333-7000-8000-000000000001",
    "business_unit_id": "0190c0de-1111-7000-8000-000000000101",
    "business_region_id": "0190c0de-1111-7000-8000-000000000201",
    "country_id": "0190c0de-1111-7000-8000-000000000301",
    "criticality": "high",
    "environment": "production",
    "data_classification": "confidential",
    "internet_exposure": "public",
    "compliance_scopes": ["pci_dss"],
    "tag_ids": ["0190c0de-7777-7000-8000-000000000011"],
    "production_url": "https://payments.example.com",
    "public_exposure": "yes",
    "public_domains": ["payments.example.com"]
  },
  "items": [
    {
      "ref": { "external_id": "812345678", "full_name": "example-org/payments-api", "organization": "example-org", "project": "" },
      "branch": "main",
      "display_name": "Payments API",
      "asset_name": "payments-api-prod"
    },
    {
      "ref": { "external_id": "812345679", "full_name": "example-org/payments-worker", "organization": "example-org", "project": "" }
    }
  ]
}
```

Example: an uploaded archive (after [completing the upload](#complete-an-upload)).

```json
{
  "source": "upload",
  "idempotency_key": "upload-8c2e6a1b-77d4-4f0e",
  "metadata": {
    "business_owner_id": "0190c0de-2222-7000-8000-000000000001",
    "technical_owner_id": "0190c0de-2222-7000-8000-000000000002",
    "business_unit_id": "0190c0de-1111-7000-8000-000000000101",
    "business_region_id": "0190c0de-1111-7000-8000-000000000201",
    "criticality": "medium",
    "data_classification": "internal",
    "environment": "production",
    "public_exposure": "no",
    "new_application": { "name": "Billing Batch", "external_ref": "APP-0193" }
  },
  "items": [{ "upload_id": "0190c0de-9999-7000-8000-000000000001", "display_name": "Billing Batch" }]
}
```

Response `202 Accepted` (or `200 OK` for a repeated idempotency key): the [import job](#the-import-job-object) with its items.

| Status | Meaning |
|---|---|
| 202 | Job created and queued. |
| 200 | Job with this idempotency key already exists; it is returned. |
| 400 `invalid_request` | Missing or invalid `idempotency_key` ("idempotency_key (8-100 characters) is required"), and the reasons listed for [Validate an import](#validate-an-import). |
| 403 `forbidden` | No `repos.manage` anywhere or at the placement. |
| 404 `not_found` | The placement does not exist. |
| 409 `conflict` | "an upload is already being imported by another job". |
| 415 `unsupported_media_type` | Wrong `Content-Type`. |
| 422 `validation_failed` | Metadata field errors in `fields`. |
| 422 `invalid_items` | Blocking item problems in `details.items`. |
| 503 `uploads_unavailable` | Uploads are not configured. |

```json
{
  "error": {
    "code": "invalid_items",
    "message": "item 2: the same repository is listed twice",
    "details": {
      "items": [
        { "index": 1, "code": "duplicate_item", "message": "the same repository is listed twice" }
      ]
    }
  },
  "request_id": "f46c8b5a7e9d0c1b2a3f4e5d"
}
```

```json
{
  "error": {
    "code": "validation_failed",
    "message": "check the highlighted fields: business_region_id, environment",
    "fields": { "business_region_id": "required", "environment": "required" }
  },
  "request_id": "0a57d9c6b8f1e2d3c4b5a697"
}
```

Database entities: `repository_import_jobs`, `repository_import_items`, `audit_logs` (`repository_import.create`; while the job runs: `repository_import.item_failed`, `repository.import` and `repository.snapshot_add` for uploaded archives, `source_upload.malware_detected`).

### Upload a new version of an uploaded repository

There is no separate endpoint. Send an import with `source: "upload"` where **every** item has `target_repository_id`:

```json
{
  "source": "upload",
  "idempotency_key": "version-1d3b5f7a-9c2e-4a6b",
  "metadata": {},
  "items": [
    { "upload_id": "0190c0de-9999-7000-8000-000000000002", "target_repository_id": "0190c0de-5555-7000-8000-000000000057" }
  ]
}
```

- `metadata` must be empty (`{}`); otherwise `400 invalid_request` "metadata cannot be changed when uploading a new version; edit the repository instead". Item `display_name` and `asset_name` are ignored.
- The target must be an active repository with `source_type: "upload"`, and the caller needs `repos.manage` on it.
- The item result is `snapshot_added` and the repository's `current_snapshot` moves to the new snapshot.

If only some items have `target_repository_id`, the job is treated as a normal import and the metadata rules apply.

### The import job object

Returned by start, get, cancel and retry (Go `ImportJobView`, frontend type `ImportJob`). The list endpoint omits `items`.

```json
{
  "id": "0190c0de-8888-7000-8000-000000000001",
  "source_type": "git",
  "scm_connection_id": "0190c0de-6666-7000-8000-000000000001",
  "scm_connection_name": "GitHub Example Org",
  "status": "importing",
  "requested_by": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" },
  "total_items": 2,
  "completed_items": 1,
  "failed_items": 0,
  "attention_items": 0,
  "start_scan": true,
  "created_at": "2026-11-17T09:00:00Z",
  "started_at": "2026-11-17T09:00:02Z",
  "completed_at": null,
  "items": [
    {
      "id": "0190c0de-8888-7000-8000-000000000011",
      "position": 0,
      "display_name": "Payments API",
      "status": "completed",
      "stage": "completed",
      "result": "imported",
      "progress": 100,
      "progress_message": "Completed",
      "error_code": "",
      "error_message": "",
      "attempts": 1,
      "max_attempts": 3,
      "repository_id": "0190c0de-5555-7000-8000-000000000042",
      "snapshot_id": null,
      "started_at": "2026-11-17T09:00:02Z",
      "completed_at": "2026-11-17T09:00:09Z",
      "can_retry": false
    },
    {
      "id": "0190c0de-8888-7000-8000-000000000012",
      "position": 1,
      "display_name": "example-org/payments-worker",
      "status": "importing",
      "stage": "importing",
      "result": "",
      "progress": 55,
      "progress_message": "Detecting languages",
      "error_code": "",
      "error_message": "",
      "attempts": 1,
      "max_attempts": 3,
      "repository_id": null,
      "snapshot_id": null,
      "started_at": "2026-11-17T09:00:09Z",
      "completed_at": null,
      "can_retry": false
    }
  ],
  "can_cancel": true,
  "can_retry": false
}
```

`start_scan` is stored as `start_scan && scan_on_import` at creation. `can_cancel` and `can_retry` are only `true` for the requester or a user with organization-wide `repos.manage`.

Job and item `status`:

| Status | Meaning |
|---|---|
| `queued` | Waiting for a worker (also after a temporary error, until the retry time). |
| `validating` | A worker claimed the item and is checking it. |
| `importing` | Reading the provider (branch, commit, languages) or verifying, scanning and normalizing the archive. |
| `registering` | Re-checking metadata and permissions and creating the repository. |
| `completed` | Done; see `result`. |
| `failed` | Stopped with a permanent error, or temporary errors exceeded `max_attempts`. |
| `needs_attention` | Stopped with a problem the user can fix (for example a duplicate, expired authorization, or changed permissions). Can be retried. |
| `cancelled` | Cancelled before completion. |

`draft` and `pending` are reserved in the schema and count as active, but the API does not create them. A job's status is derived from its items: any running item gives the running stage; else any waiting item gives `queued`; else any `failed` item gives `failed`; else any `needs_attention` gives `needs_attention`; else all `cancelled` gives `cancelled`; otherwise `completed`.

Item `stage` (the last stage reached, showing where a stopped item ended): `queued`, `validating`, `importing`, `registering`, `completed`.

Item `result` (for `completed` items):

| Result | Meaning |
|---|---|
| `imported` | A new repository was registered. |
| `already_imported` | The repository already existed for this connection; nothing was changed. |
| `snapshot_added` | A new snapshot was added to `target_repository_id`. |

Item `error_code` values:

| Code | Outcome | Meaning |
|---|---|---|
| `invalid_item` | failed | The item has no connection or no upload. |
| `connection_unavailable` | failed | The SCM connection was deleted. |
| `repository_not_found` | failed | The repository does not exist or the connection cannot see it. |
| `permission_denied` | failed / needs_attention | The credential lacks read permission (failed), or the requesting user no longer has `repos.manage` for the placement or target (needs attention). |
| `authentication_failed` | failed | The provider rejected the credential. |
| `token_expired` | needs_attention | The connection's OAuth authorization expired; reconnect it, then retry. |
| `blocked_address` | failed | The provider address is blocked by the outbound network policy. |
| `untrusted_clone_url` | failed | The provider returned a clone URL that does not match the connection. |
| `invalid_branch` | failed | The requested branch does not exist. |
| `duplicate` | needs_attention | Same clone URL registered through another connection, or identical archive already imported. Retry with `allow_duplicate`. |
| `name_clash` | failed | Another asset already uses the asset name. |
| `validation_failed` | needs_attention | Metadata became invalid since the job was created (for example a deleted owner, team, unit, region or tag). |
| `requester_unavailable` | needs_attention | The requesting user is no longer active. |
| `uploads_unavailable` | failed | Uploads are not configured. |
| `upload_missing` | failed | The upload no longer exists. |
| `upload_incomplete` | failed | The upload is not complete or parts are missing. |
| `upload_consumed` | failed | The upload was already imported. |
| `upload_corrupt` | failed | Stored upload data failed its integrity check. |
| `checksum_mismatch` | failed | A part or the whole archive does not match its SHA-256. |
| `malware_detected` | failed | The malware scanner rejected the archive; the upload is discarded. |
| `malware_scan_too_large` | failed | The archive exceeds the scanner's size limit. |
| `malware_scanner_unavailable` | retried, then failed | The malware scanner is required (`PATHOS_CLAMAV_REQUIRED`) but unreachable. |
| `archive_rejected` | failed | Unsupported or unsafe archive. The message contains the reason (it starts with it, except "unsupported or corrupt archive: …" when the format cannot be detected): `path_traversal`, `absolute_path`, `invalid_path`, `duplicate_path`, `too_many_files`, `too_large`, `file_too_large`, `compression_ratio`, `encrypted_entry`, `unsupported_format` or `corrupt_archive`. |
| `storage_unavailable` | retried, then failed | The source store could not be read or written. |
| `timeout` | retried, then failed | The provider did not answer in time. An item that exceeds `PATHOS_IMPORT_TIMEOUT` fails at once with this code and is not retried. |
| `provider_unavailable` | retried, then failed | Temporary provider error. |
| `provider_error` | retried, then failed | Other provider error. |
| `cancelled` | cancelled | Cancelled while running. |
| `worker_lost` | failed | The worker stopped while processing and no attempts remain. |
| `internal_error` | failed | Unexpected server error (see the server log). |

Temporary errors are retried automatically after 15 s × 2^attempts, up to `max_attempts` (3). While waiting, the item is `queued` and keeps the last `error_code`.

After an item completes with result `imported` or `snapshot_added`, an onboarding scan is queued if the job has `start_scan` and `scan_on_import` is still enabled. When a job finishes with `failed` or `needs_attention`, an `import.failed` notification event is raised.

### List import jobs

Returns import jobs, newest first, 25 per page.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/repository-imports` |
| Authentication | Session or API token |
| Permission | `repos.manage` at any scope, or `repos.read` organization-wide. Users without organization-wide `repos.manage` or `repos.read` see only their own jobs. |
| Request headers | `Cookie` |

| Query parameter | Type | Required | Description |
|---|---|---|---|
| `mine` | string | no | `true`: only the caller's jobs. |
| `status` | string | no | `all` (default), `active` (draft, pending, queued, validating, importing, registering), `finished` (everything else), or one status value. |
| `cursor` | string | no | `next_cursor` of the previous page. |

The page size is fixed at 25; there is no `limit` parameter.

Response `200 OK`:

```json
{
  "items": [
    {
      "id": "0190c0de-8888-7000-8000-000000000001",
      "source_type": "git",
      "scm_connection_id": "0190c0de-6666-7000-8000-000000000001",
      "scm_connection_name": "GitHub Example Org",
      "status": "completed",
      "requested_by": { "id": "0190c0de-2222-7000-8000-000000000001", "name": "Dana Owner", "email": "dana.owner@example.com" },
      "total_items": 2,
      "completed_items": 2,
      "failed_items": 0,
      "attention_items": 0,
      "start_scan": true,
      "created_at": "2026-11-17T09:00:00Z",
      "started_at": "2026-11-17T09:00:02Z",
      "completed_at": "2026-11-17T09:00:15Z",
      "can_cancel": false,
      "can_retry": false
    }
  ],
  "next_cursor": null
}
```

| Status | Meaning |
|---|---|
| 200 | Page returned. |
| 400 `invalid_request` | "invalid status" or "invalid cursor". |
| 403 `forbidden` | Neither `repos.manage` anywhere nor organization-wide `repos.read`. |

Database entities: `repository_import_jobs`, `repository_import_items`, `scm_connections`, `users`.

### Get an import job

Returns one job with all items. Poll it to follow progress.

| Property | Value |
|---|---|
| Method | `GET` |
| Path | `/api/v1/repository-imports/{id}` |
| Authentication | Session or API token |
| Permission | The requester, or organization-wide `repos.manage` or `repos.read`. Others get `404 not_found`. |
| Request headers | `Cookie` |

| Path parameter | Type | Required | Description |
|---|---|---|---|
| `id` | UUID | yes | Import job ID. |

Response `200 OK`: the [import job object](#the-import-job-object).

| Status | Meaning |
|---|---|
| 200 | Returned. |
| 404 `not_found` | Unknown job or not visible to the caller. |

Database entities: `repository_import_jobs`, `repository_import_items`.

### Cancel an import job

Requests cancellation. Waiting items (`queued`) and items in `needs_attention` are cancelled immediately; running items stop at their next stage boundary.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repository-imports/{id}/cancel` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | The requester, or organization-wide `repos.manage` |
| Request headers | `Cookie`, `X-CSRF-Token` (no body) |

Response `200 OK`: the updated [import job object](#the-import-job-object).

| Status | Meaning |
|---|---|
| 200 | Cancellation recorded. |
| 403 `forbidden` | Visible, but the caller is neither the requester nor an organization-wide manager. |
| 404 `not_found` | Unknown job or not visible. |
| 409 `conflict` | "nothing to cancel". |

Database entities: `repository_import_jobs.cancel_requested_at`, `repository_import_items`, `audit_logs` (`repository_import.cancel`).

### Retry an import job

Re-queues items in `failed`, `needs_attention` or `cancelled`, resetting their attempts and errors.

| Property | Value |
|---|---|
| Method | `POST` |
| Path | `/api/v1/repository-imports/{id}/retry` |
| Authentication | Session with `X-CSRF-Token`, or API token with `api:write` |
| Permission | The requester, or organization-wide `repos.manage` |
| Request headers | `Cookie`, `X-CSRF-Token`, `Content-Type: application/json` when a body is sent |

Body (optional; an empty body retries every retryable item):

| Field | Type | Required | Description |
|---|---|---|---|
| `item_ids` | UUID array | no | Retry only these items. Empty or absent: all retryable items. |
| `allow_duplicate` | boolean | no | Set `allow_duplicate` on the retried items ("import anyway"). |

```json
{ "item_ids": ["0190c0de-8888-7000-8000-000000000012"], "allow_duplicate": true }
```

Response `200 OK`: the updated [import job object](#the-import-job-object), now `queued`.

| Status | Meaning |
|---|---|
| 200 | Items re-queued. |
| 400 `invalid_request` | Malformed JSON. |
| 403 `forbidden` | Not the requester or an organization-wide manager. |
| 404 `not_found` | Unknown job or not visible. |
| 409 `conflict` | "no failed, cancelled or attention items to retry", or "an upload in this job is already being imported by another job". |
| 415 `unsupported_media_type` | A body was sent without `application/json`. |

Database entities: `repository_import_items`, `repository_import_jobs`, `audit_logs` (`repository_import.retry`).
