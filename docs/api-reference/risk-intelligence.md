---
title: Risk and vulnerability intelligence
section: api-reference
order: 10
version: "1.0"
updated: 2026-11-17
summary: Contextual risk scores, the risk model, EPSS and CISA KEV feeds, CVE lookups, the unified lifecycle status and the new finding fields and filters.
---
# Risk and vulnerability intelligence

## Finding fields and filters

`GET /api/v1/findings` and `GET /api/v1/findings/{id}` return these additional fields. Existing fields and stored statuses are unchanged.

| Field | Description |
|---|---|
| `lifecycle_status` | Unified status, derived (see below): `new`, `open`, `in_progress`, `under_review`, `confirmed`, `false_positive`, `accepted_risk`, `resolved`, `reopened` |
| `risk_score` | Contextual risk 0–100 (`null` until scored) |
| `cvss_version`, `cvss_vector` | As reported by the scanner (Trivy, Grype) |
| `confidence` | `high`, `medium`, `low`, `unknown` |
| `epss`, `epss_percentile` | FIRST EPSS probability and percentile for the CVE |
| `kev`, `kev_due_date` | Listed in the CISA KEV catalog, with its due date |
| `exploit_available` | Known exploitation (KEV) |
| `reachability` | `reachable`, `not_reachable`, `unknown` (`unknown` until reachability analysis exists) |
| `application_id`, `application_name` | The repository's application |

| Lifecycle | Derived from |
|---|---|
| `resolved` | status `fixed` |
| `false_positive`, `accepted_risk` | the same status |
| `under_review` | status `needs_review`, or a Human Eye review is open |
| `confirmed` | a Human Eye reviewer confirmed the finding (still open) |
| `in_progress` | status `in_progress` |
| `reopened` | open again after a fix (recurrence) |
| `new` | first seen by the latest scan; not assigned, triaged or reviewed |
| `open` | any other open finding |

New query parameters:

| Parameter | Description |
|---|---|
| `lifecycle` | Comma-separated lifecycle statuses (spans every stored status) |
| `kev` | `true` or `false` |
| `epss_min` | Minimum EPSS percentile (0–1) |
| `risk_min` | Minimum risk score (0–100) |
| `confidence`, `reachability`, `application_id` | Exact match |
| `sort` | `severity` (default) or `risk` (keyset cursor; pass `next_cursor` back unchanged) |

## Risk explanation

`GET /api/v1/findings/{id}/risk` (`findings.read`):

```json
{
  "risk_score": 86.37, "band": "critical", "pending": false, "scored_at": "…",
  "explanation": { "score": 86.37, "base": 9.8, "model_version": 0, "factors": [
    { "key": "base", "label": "CVSS base score", "value": "9.8", "weight": 9.8 },
    { "key": "likelihood", "label": "Exploit likelihood", "value": "EPSS percentile 98%", "weight": 1.48 },
    { "key": "exposure", "label": "Internet exposure", "value": "unknown", "weight": 1.1 } ] },
  "cve": "CVE-2022-29078", "epss": 0.33, "epss_percentile": 0.98, "kev": false, "confidence": "high", "reachability": "unknown",
  "cvss_version": "3.1", "cvss_vector": "CVSS:3.1/…"
}
```

The score is `clamp(10 × base × (0.5 + likelihood) × context ÷ 1.75, 0, 100)`:

- **base**: the human-assessed severity, else CVSS, else the severity table.
- **likelihood**: the maximum of the EPSS percentile, KEV and public-exploit signals, or a neutral value when no signal exists.
- **context**: the product of criticality, exposure, reachability, confidence, human confirmation, compensating controls and fix availability.

Fixed, false-positive and accepted-risk findings score 0. Bands: critical ≥ 75, high ≥ 50, medium ≥ 25.

## Risk model

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/risk-model` | `findings.read` | `{ model, defaults, pending_recompute }` |
| `PUT` | `/api/v1/risk-model` | `settings.manage` | `{ weights, change_note }` creates a new version and re-scores every finding in the background. Weights are validated (ranges, known keys) |
| `GET` | `/api/v1/risk-model/history` | `findings.read` | Versions with author and note |

Scores are recomputed in the background (jobs role) whenever an input changes: ingest, status, severity, Human Eye outcome, repository or application criticality and exposure, a feed update, or a model change.

## Feeds

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/intel/feeds` | `findings.read` | EPSS and KEV feeds: enabled, URL, interval, record count, last run, last success, next due |
| `PUT` | `/api/v1/intel/feeds/{epss\|kev}` | `settings.manage` | `{ enabled, url (https), interval_hours (1–720) }` |
| `POST` | `/api/v1/intel/feeds/{feed}/run` | `settings.manage` | Download now (`409` while a run is in progress, `502 feed_failed` on download errors) |
| `POST` | `/api/v1/intel/feeds/{feed}/import` | `settings.manage` | Offline import: multipart field `file` (EPSS CSV or CSV.gz, KEV JSON; at most 64 MiB). `422 invalid_feed` with the reason when the file cannot be parsed |
| `GET` | `/api/v1/intel/cves/{cve}` | `findings.read` | EPSS, KEV entry and the number of open findings for a CVE |

Online updates are on by default (daily). The jobs role downloads each enabled feed when its interval has passed, and retries an hour after a failure. Each import replaces the feed's data atomically and is recorded in `intel_feed_runs` and the audit log. For air-gapped installations, turn online updates off and import the files.
