---
title: Risk scoring and intelligence feeds
section: api-reference
order: 27
version: "1.0"
updated: 2026-11-19
summary: Contextual risk scores and their explanation, the versioned risk model, the EPSS, KEV, OSV and deps.dev intelligence feeds, and CVE lookups.
---
# Risk scoring and intelligence feeds

Every open finding gets a contextual risk score from 0 to 100. The finding fields that carry risk and intelligence data (`risk_score`, `epss`, `kev`, `confidence`, `reachability`, …) and the matching list filters are described with the [finding object](findings.md#the-finding-object).

## Risk explanation

`GET /api/v1/findings/{id}/risk` (`findings.read` on the finding's repository):

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
| `PUT` | `/api/v1/risk-model` | `settings.manage` (organization-wide) | `{ weights, change_note }` creates a new version and re-scores every finding in the background. Weights are validated (ranges, known keys) |
| `GET` | `/api/v1/risk-model/history` | `findings.read` | Versions with author and note |

Scores are recomputed in the background (jobs role) whenever an input changes: ingest, status, severity, Human Eye outcome, repository or application criticality and exposure, a feed update, or a model change.

## Feeds

| Feed | Data | Default |
|---|---|---|
| `epss` | FIRST EPSS scores and percentiles | On, daily |
| `kev` | CISA Known Exploited Vulnerabilities catalog | On, daily |
| `osv` | OSV vulnerability records (descriptions, references, vendor CVSS, fixed versions) | On, daily; see [OSV feed](#osv-feed) |
| `depsdev` | deps.dev package health; see [package health](supply-chain.md#package-health) | **Off**: it sends package names to `api.deps.dev` |
| `endoflife` | endoflife.date release cycles and end-of-life dates; see [endoflife.date feed](#endoflifedate-feed) | **Off**: an administrator opts in (it sends nothing but the download request) |

| Method | Path | Permission | Description |
|---|---|---|---|
| `GET` | `/api/v1/intel/feeds` | `findings.read` | Every feed: enabled, URL, interval, record count, last run, last success, next due |
| `PUT` | `/api/v1/intel/feeds/{feed}` | `settings.manage` (organization-wide) | `{ enabled, url (https), interval_hours (1–720) }`; each field optional |
| `POST` | `/api/v1/intel/feeds/{feed}/run` | `settings.manage` (organization-wide) | Download now (`409` while a run is in progress, `502 feed_failed` on download errors) |
| `POST` | `/api/v1/intel/feeds/{feed}/import` | `settings.manage` (organization-wide) | Offline import: multipart field `file`, at most 64 MiB (EPSS CSV or CSV.gz, KEV JSON, OSV JSON or zip, endoflife.date API v1 JSON). `422 invalid_feed` with the reason when the file cannot be parsed; `409` while a run is in progress |

An unknown `{feed}` returns `404`. The jobs role downloads each enabled feed when its interval has passed, and retries an hour after a failure. Each import replaces the feed's data atomically and is recorded in `intel_feed_runs` and the audit log. With `PATHOS_OFFLINE=true` nothing is downloaded; import the files instead.

### endoflife.date feed

Feed key `endoflife`, default URL `https://endoflife.date/api/v1/products/full` (the API v1 document with every product and its release cycles), daily, **disabled by default**. The file import accepts the same document (or a single-product document from `/api/v1/products/{name}`). After each successful load every repository's [end-of-life status](supply-chain.md#end-of-life) is recomputed. `records` is the number of products.

### OSV feed

The feed URL is the OSV API base, `https://api.osv.dev/v1/vulns/` by default.

- **Online:** each run looks up at most 300 identifiers of open findings (their `cve`, and `GHSA-` rule IDs) without a record from the last 7 days, with 4 lookups at a time. Identifiers OSV does not know are remembered for the same period.
- **Offline import:** OSV JSON (one record or an array) or a zip of record files (OSV's `all.zip` exports).

Loading a record:

- fills `cvss_vector`, `cvss_version` and the 3.x base score of findings without a vector (3.1 preferred over 4.0)
- marks those findings for re-scoring

`EVIDENCE` references count as exploit evidence in the risk score.

## CVE lookup

`GET /api/v1/intel/cves/{id}` (`findings.read` at any scope) accepts CVE and GHSA identifiers (`400` otherwise):

| Field | Description |
|---|---|
| `id` | Normalized identifier |
| `epss`, `epss_percentile`, `epss_as_of` | EPSS data, `null` when unknown |
| `kev` | KEV entry (`vendor`, `product`, `name`, `description`, `required_action`, `added_on`, `due_date`, `known_ransomware`) or `null` |
| `open_findings` | Open findings with this CVE; counted only for callers with organization-wide `findings.read` (otherwise `0`) |
| `osv` | OSV record or `null`: `id`, `aliases`, `summary`, `details`, `published`, `modified`, `withdrawn`, `cvss_vectors`, `cwes`, `references[]{type,url}`, `exploit_references`, `affected[]{ecosystem,package,fixed[]}`, `source`, `fetched_at` |
