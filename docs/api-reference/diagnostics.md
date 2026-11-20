---
title: Product metadata, diagnostics and feature flags
section: api-reference
order: 54
version: "1.0"
updated: 2026-11-20
summary: GET /api/v1/meta (product, version, build, feature flags, workers), the error catalogue, AI troubleshooting with catalogue fallback, and feature flag administration.
---

# Product metadata, diagnostics and feature flags

Quditmind PATHOS · status: Production-ready

All endpoints are under `/api/v1` and follow the [common conventions](index.md#authentication). Errors use the [error envelope](index.md#errors), whose `error.error_code` is a code of the catalogue below.

## Product metadata

### Get product metadata

`GET /api/v1/meta` — **no authentication required** for the public part.

Without a session or token, only the product, vendor and backend version are returned:

```json
{ "product": "PATHOS", "vendor": "Quditmind", "version": "2.2.0" }
```

With a session or API token (any role), the response adds the build, the API version, the organization's feature flags and the live worker registry:

```json
{
  "product": "PATHOS",
  "vendor": "Quditmind",
  "version": "2.2.0",
  "commit": "f3c5efd0123456789abcdef0123456789abcdef0",
  "build_date": "2026-11-20T10:00:00Z",
  "api_version": "v1",
  "feature_flags": { "connectors": false, "onboarding": false, "codegraph": false, "threat_models": false,
                     "reverse_engineering": false, "remediation_workspace": false, "continuous_monitoring": false, "lifecycle_overview": false, "scan_profile_tiers": false },
  "workers": [
    { "name": "worker-core-1", "family": "core", "version": "2.2.0", "scanners": { "opengrep": "1.12.1", "trivy": "0.67.2" }, "online": true }
  ],
  "scanner_packs": [ { "family": "core", "version": "2.2.0" } ]
}
```

| Member | Description |
|---|---|
| `version`, `commit`, `build_date` | Build metadata of the API server (`dev` / `unknown` for local builds without build arguments; see `docs/OPERATIONS.md`, "Build metadata"). |
| `api_version` | Version of this REST API (`v1`). |
| `feature_flags` | Every known flag of the caller's organization; `false` unless an administrator enabled it. |
| `workers` | Registered, not revoked workers of the organization: name, family, the worker's own version, the scanners it advertises with their versions, and whether it sent a heartbeat in the last two minutes. |
| `scanner_packs` | Per worker family, the version of the most recently seen worker. |

No credential, token, secret or internal address is returned. An invalid bearer token is rejected with 401 (`PTH-AUTH-1004`) rather than treated as anonymous.

## Error catalogue

### List the error catalogue

`GET /api/v1/diagnostics/codes` — any authenticated user.

Returns `areas` (the areas that have codes: `key`, `slug`, `title`, `summary`) and `items`, one per code:

| Member | Description |
|---|---|
| `code` | `PTH-<AREA>-<NNNN>`. |
| `area`, `category`, `severity` | Area key; category (`authentication`, `connectivity`, `validation`, ...); `info`, `warning`, `error` or `critical`. |
| `title`, `description` | Short title and technical description. |
| `confirmed_cause`, `proven` | The cause text, and whether raising the code proves it. |
| `probable_causes`, `impact`, `actions`, `verify` | As in the error envelope. |
| `ai_help` | Whether AI troubleshooting is offered. |
| `http_status` | Status of API responses with the code (absent for codes raised only in background work and logs). |
| `legacy_codes` | The short codes the entry covers: API `error.code` values, sign-in redirect reasons (`login:<reason>`) and repository import item codes (`import:<code>`). |
| `source` | Where in the backend the error is raised. |
| `docs_slug`, `docs_url` | `<area>#<code>` and the in-app help link. |

The same catalogue is published as `docs/troubleshooting/<area>.md`, generated with `make docs-errors`, and bundled into the Help Center so it works offline.

Other places that carry codes: the sign-in page redirect (`/login?error=<reason>&code=PTH-AUTH-…`), scan executions (`error_code` next to `error`), the security gate (`error_code` when `passed` is false: `PTH-GATE-1001` or `PTH-GATE-1002`) and repository import items (`error_diag_code` next to `error_code`).

## Troubleshoot an error

`POST /api/v1/diagnostics/troubleshoot` — any authenticated user.

```json
{
  "code": "PTH-CONN-1004",
  "request_id": "qjxkbtnmwpzrfhdcylvsageo",
  "message": "x509: certificate signed by unknown authority",
  "context": { "connection_kind": "github", "http_status": "502" }
}
```

| Field | Description |
|---|---|
| `code` | Required. A catalogue code (`error.error_code`); short codes such as `not_found` are refused with 422. |
| `request_id` | Optional, echoed in the answer (at most 64 characters). |
| `message` | Optional error message the user saw (at most 1,000 characters are kept). |
| `context` | Optional non-secret metadata, at most 20 entries with lower-case keys; values are cut to 2,000 characters. |

The answer has the diagnostic members of the error envelope (`error_code`, `title`, `cause`, `probable_causes`, `impact`, `actions`, `verify`, `docs_url`, `ai_help`, `request_id`) plus `message`, and:

| Member | Description |
|---|---|
| `source` | `ai` (the steps were written by the AI model) or `catalogue`. |
| `model` | The model that answered (source `ai`). |
| `ai_unavailable` | Why the catalogue answered: AI not configured, AI failed (with its `PTH-AI-…` code), or AI help not offered for the code. |

How it works:

1. The code must be in the catalogue. If the code does not offer AI help, or AI is not configured or fails, the catalogue steps are returned with `source: "catalogue"`. Troubleshooting never depends on AI.
2. The model is the organization's configuration on a **self-hosted (local) model** when one exists, otherwise the default AI configuration.
3. Before anything is sent, fenced code blocks are removed from `message` and `context`, and both are redacted with the platform's secret patterns, then again with the configuration's redaction patterns. Only the code, the catalogue entry, the redacted message and the redacted context are sent, fenced as untrusted data. PATHOS never asks the user for a secret or source code.
4. AI answers are AI-inferred: `cause.confirmed` is always `false` for `source: "ai"`.

Errors: 401 `PTH-AUTH-1001`; 400 `PTH-PLAT-0002` (malformed body, too many context entries); 422 `PTH-PLAT-0003` (unknown code).

## Feature flags

Every module added in PATHOS 3.0 is behind a per-organization flag that is **off by default** until its milestone is approved. Known flags: `connectors`, `onboarding`, `codegraph`, `threat_models`, `reverse_engineering`, `remediation_workspace`, `continuous_monitoring`, `lifecycle_overview`, `scan_profile_tiers` (M6: the Quick, Standard and Comprehensive scan profiles). A module whose flag is off answers 404 with `feature_disabled` (`PTH-PLAT-1007`).

### List feature flags

`GET /api/v1/admin/feature-flags` — `settings.manage` (org-wide).

```json
{ "items": [ { "name": "connectors", "description": "Connectors hub (/connectors): …", "milestone": "M2",
               "enabled": true, "updated_at": "2026-11-20T10:00:00Z", "updated_by": "admin@example.com" } ] }
```

`updated_at` and `updated_by` are `null` for a flag never changed.

### Change feature flags

`PUT /api/v1/admin/feature-flags` — `settings.manage` (org-wide).

```json
{ "flags": { "connectors": true, "codegraph": false } }
```

Flags not named keep their value. Each flag whose value changes writes an audit entry `feature_flag.update` (target `feature_flag`, the flag name; metadata `enabled`, `was_enabled`). The response is the full list, as for `GET`.

Errors: 400 `PTH-PLAT-0002` (empty or malformed body); 403 `PTH-AUTH-1002`; 422 `PTH-PLAT-0003` with `fields` naming each unknown flag.
