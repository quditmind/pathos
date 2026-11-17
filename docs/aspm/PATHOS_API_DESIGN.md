# PATHOS ASPM API design

Planned API additions. They follow the existing conventions (`docs/api-reference/index.md`):

- `/api/v1`, session plus CSRF
- JSON errors `{error: {code, message, fields}}`
- server-side filtering
- scoped RBAC enforced in SQL
- audit on every change
- **No existing endpoint changes its contract**; new response fields are additive.

## Phase 1

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/findings` | New filters: `kev`, `epss_min`, `risk_min`, `confidence`, `reachability`, `presentation_status` (D2); new sort `risk`. New response fields: `cvss_version`, `cvss_vector`, `confidence`, `epss`, `kev`, `reachability`, `risk_score`, `presentation_status` |
| `GET` | `/api/v1/findings/{id}/risk` | Score with factor breakdown and model version |
| `GET`, `PUT` | `/api/v1/risk-model` | Weights (`settings.manage`), versioned |
| `GET` | `/api/v1/intel/cves/{id}` | CVE record with EPSS and KEV |
| `GET`, `POST` | `/api/v1/intel/feeds` | Feed status; `POST /intel/feeds/{feed}/run` (online) or `POST /intel/feeds/{feed}/import` (multipart file, offline) |
| `GET`, `PATCH` | `/api/v1/applications/{id}` | Adds `application_key`, technical owner, lifecycle, environment, aggregated exposure, last scan, posture |

## Phase 2

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/v1/imports/results` | Multipart SARIF or JSON (format, tool name, repository or application, commit). Validated, size-limited, asynchronous; returns the job |
| `POST` | `/api/v1/imports/sbom` | CycloneDX or SPDX |
| `GET` | `/api/v1/imports/results/{id}` | Job status and counts |
| `GET`, `POST`, `PATCH`, `DELETE` | `/api/v1/scan-targets` | URL, API spec, image and artifact targets (scope rules, credentials by secret reference) |
| `GET`, `POST`, `PUT` | `/api/v1/custom-rules` | Upload, validate (dry run on samples), version, enable per profile |

## Phase 3

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/aspm/applications/{id}/posture` | Risk rollup, coverage, top risks, owners, exposure |
| `GET` | `/api/v1/aspm/coverage` | Matrix of applications/repositories × categories |
| `GET` | `/api/v1/aspm/unmanaged` | Shadow and unowned assets |
| `GET` | `/api/v1/aspm/graph` | `?root=application:{id}\|component:{purl}\|finding:{id}&depth=` nodes and edges (bounded) |
| `GET` | `/api/v1/aspm/benchmarks` | Grouped by application, business unit or team |

## Phase 4

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/v1/findings/{id}/correlations` | `POST` confirm or reject |
| `GET`, `POST`, `DELETE` | `/api/v1/suppression-rules` | With expiry |
| `GET` | `/api/v1/findings/{id}/attack-paths` | Paths from internet-exposed entry points |

## Phases 6–9

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/v1/ai/analyst/sessions` | Analyst conversation over scoped data (tool calls = the MCP tool set, read-only) |
| `GET` | `/api/v1/ai/usage` | Tokens and executions by provider, model and feature |
| `POST` | `/api/v1/ai/reports` | Technical or executive report draft (marked AI-generated, requires approval to publish) |
| `GET`, `POST`, `PUT` | `/api/v1/policies` | Versioned; `POST /policies/{id}/simulate` |
| `GET` | `/api/v1/compliance/frameworks/{id}/status` | Controls with mapped findings |
| `GET`, `POST`, `PUT` | `/api/v1/reports/definitions` | `POST /reports/definitions/{id}/run`, schedules |
| `GET`, `POST`, `PUT`, `DELETE` | `/api/v1/connectors` | `POST /connectors/{id}/test`; `POST /findings/{id}/tickets` creates a linked issue |
| `POST` | `/api/v1/scm/pull-requests/{id}/checks` | Internal: PR scan result posted back to the provider (status or check run) |

## Outbound webhook contract (phase 9)

```
POST <configured URL>
X-PATHOS-Event: finding.created
X-PATHOS-Delivery: <uuid>
X-PATHOS-Signature: sha256=<HMAC-SHA256(body, secret)>

{ "event": "finding.created", "occurred_at": "…", "organization": "…", "data": { … } }
```

Deliveries are retried with exponential backoff (at most 24 hours). Events: `finding.created`, `finding.status_changed`, `finding.risk_changed`, `scan.completed`, `scan.failed`, `review.completed`, `policy.violated`.

## Authentication for automation

Personal and service API tokens (existing `api_tokens`, extended scopes such as `findings:read` and `imports:write`) are accepted with `Authorization: Bearer` on the endpoints marked automation-capable (imports, findings read, scans). Session and CSRF behaviour for browsers is unchanged.
