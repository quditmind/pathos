# PATHOS ASPM API design (historical)

> **Status: historical design, written in phase 0 (2026-11-17).** All ten ASPM phases are now built, and several endpoints were built under different paths than planned. This page keeps the plan and maps every planned endpoint to what exists today. For the current API, use the [API reference](../api-reference/index.md). It is the canonical description of paths, permissions, request and response bodies.

The plan kept the existing conventions, and the as-built API follows them:

- everything under `/api/v1`, with a browser session plus CSRF token, or a personal API token (see below)
- JSON errors `{error: {code, message, fields}}`
- server-side filtering
- scoped RBAC enforced in SQL
- an audit entry for every change
- **no existing endpoint changes its contract**; new response fields are additive

## Planned endpoints and what was built

### Phase 1: unified data model

| Planned | As built |
|---|---|
| `GET /findings` with new filters and fields | Built. Filters `lifecycle` (the planned `presentation_status`), `kev`, `epss_min`, `risk_min`, `confidence`, `reachability`, `application_id`; sort by risk. See [Risk intelligence](../api-reference/risk-intelligence.md) |
| `GET /findings/{id}/risk` | Built as planned |
| `GET`, `PUT /risk-model` | Built, plus `GET /risk-model/history` |
| `GET /intel/cves/{id}` | Built (OSV record with EPSS and KEV). See [Vulnerability intelligence](../api-reference/vulnerability-intelligence.md) |
| `GET`, `POST /intel/feeds` | `GET /intel/feeds`, `PUT /intel/feeds/{feed}` (enable, URL, interval), `POST /intel/feeds/{feed}/run` (online), `POST /intel/feeds/{feed}/import` (file) |
| `GET`, `PATCH /applications/{id}` | `PATCH /applications/{id}` with the new fields; read through `GET /applications` and `GET /posture/applications`. See [Applications](../api-reference/applications.md) |

### Phase 2: ingestion and engines

| Planned | As built |
|---|---|
| `POST /imports/results` | Built as planned. See [Result imports](../api-reference/result-imports.md) |
| `POST /imports/sbom` | Built as planned |
| `GET /imports/results/{id}` | Not built. Each import is a scan execution (`GET /scans/{id}`); the list is `GET /imports/history` |
| `/scan-targets` (`GET`, `POST`, `PATCH`, `DELETE`) | `GET`, `POST /scan-targets`, `GET`, `PUT`, `DELETE /scan-targets/{id}`, `POST /scan-targets/{id}/scan`, `POST /scan-targets/sbom`, `POST /scan-targets/artifact`. See [Scan targets](../api-reference/scan-targets.md) |
| `/custom-rules` (`GET`, `POST`, `PUT`) | `GET`, `POST /custom-rules`, `GET`, `PUT`, `DELETE /custom-rules/{id}`, `GET /custom-rules/{id}/versions`, `POST /custom-rules/validate` |

### Phase 3: ASPM inventory

The planned `/aspm/*` prefix became `/posture/*`. See [Posture](../api-reference/posture.md).

| Planned | As built |
|---|---|
| `GET /aspm/applications/{id}/posture` | `GET /posture/applications` (every application with its rollup) and `GET /posture/aggregate` |
| `GET /aspm/coverage` | `GET /posture/coverage` |
| `GET /aspm/unmanaged` | `GET /posture/unmanaged` |
| `GET /aspm/graph` | `GET /posture/context-graph` |
| `GET /aspm/benchmarks` | `GET /posture/benchmark` |
| (not planned) | `GET /posture/blast-radius`, `GET /repositories/{id}/dependencies`, `GET /repositories/{id}/dependencies/paths`, `GET /findings/{id}/dependency-paths` |

### Phase 4: vulnerability intelligence

| Planned | As built |
|---|---|
| `GET`, `POST /findings/{id}/correlations` | `GET /findings/{id}/related`. Correlation is computed on request; there is no confirm or reject |
| `GET`, `POST`, `DELETE /suppression-rules` | `GET`, `POST /suppression-rules`, `POST /suppression-rules/preview`, `POST /suppression-rules/{id}/{action}` (approve, reject, revoke). Rules are revoked, not deleted |
| `GET /findings/{id}/attack-paths` | `GET /posture/attack-paths` |

### Phases 6 to 9: AI, governance, reporting, integrations

| Planned | As built |
|---|---|
| `POST /ai/analyst/sessions` | `/ai/analyst/conversations`: `GET`, `POST`, `GET`, `DELETE /{id}`, `POST /{id}/messages`. See [AI analyst](../api-reference/ai-analyst.md) |
| `GET /ai/usage` | Built as planned |
| `POST /ai/reports` | Built, plus `GET /ai/reports`, `GET /ai/reports/{id}`, `GET /ai/reports/{id}/markdown`. Reports are marked AI-generated; there is no approval step before others can read them |
| `/policies` with `POST /policies/{id}/simulate` | `/security-policies`: `GET`, `POST`, `GET`, `PUT`, `DELETE /{id}`, `GET /{id}/violations`, `POST /security-policies/preview` (dry run), `POST /security-policies/evaluate`; `GET /findings/{id}/policies`. See [Governance](../api-reference/governance.md) |
| `GET /compliance/frameworks/{id}/status` | `GET /compliance/frameworks` and `GET /compliance/frameworks/{key}` |
| `/reports/definitions` with `POST /{id}/run` | `/reports`: `GET`, `POST`, `GET`, `PUT`, `DELETE /{id}`, `GET /reports/{id}/run`, `POST /reports/preview`; executive overview `GET /executive`. See [Integrations and reporting](../api-reference/integrations-reporting.md) |
| `/connectors` with `POST /{id}/test` | Split by kind: outbound webhooks under `/notifications/webhooks` (with `/{id}/test` and `/{id}/deliveries`), Jira and ServiceNow under `/ticket-connections` (with `/{id}/test`) |
| `POST /findings/{id}/tickets` | Built as planned, plus `GET /findings/{id}/tickets` |
| `POST /scm/pull-requests/{id}/checks` (internal) | No endpoint. PATHOS posts the commit status to the provider itself. Results are read with `GET /pr-checks` and `GET /pr-checks/{id}`, re-posted with `POST /pr-checks/{id}/repost`, and configured per repository with `GET`, `PUT /repositories/{id}/pr-settings` |

## Outbound webhook contract

As built (see [Integrations and reporting](../api-reference/integrations-reporting.md) for the payload):

- Headers (generic JSON format; Slack and Teams receive their own payload without them): `X-PATHOS-Event`, `X-PATHOS-Delivery` (delivery UUID), `X-PATHOS-Timestamp`, and, when a signing secret is set, `X-PATHOS-Signature: sha256=<hex>`. The signature is HMAC-SHA256 over `<timestamp>.<body>`, so the timestamp is covered as well as the body. The plan signed the body only.
- Formats: generic JSON, Slack and Microsoft Teams (Adaptive Card).
- Events: any notification event, chosen per endpoint. The plan had a fixed list of seven.
- Retries: 1 minute, 5 minutes, 30 minutes, 2 hours and 6 hours after the first attempt (six attempts, about 9 hours in total). A 4xx response other than 408 or 429 is not retried. The plan said "at most 24 hours".

## Authentication for automation

As built: personal API tokens (`api_tokens`) carry the scopes `mcp`, `api:read` or `api:write`. A token with an `api:*` scope is accepted as `Authorization: Bearer` on every `/api/` endpoint except token management, sign-in, recovery codes and MFA, not only on the few endpoints the plan marked as automation-capable. It acts with the owner's current permissions. `api:read` allows safe methods only. Tokens do not use CSRF. See [API reference: authentication](../api-reference/index.md#authentication) and [SECURITY.md](../SECURITY.md#api-tokens-and-mcp).
