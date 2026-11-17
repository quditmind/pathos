# PATHOS ASPM database design

Planned schema changes for the roadmap phases. Every change is an **additive** goose migration with a Down migration and a `pathos_apply_app_grants()` update. Existing columns, values and fingerprints are unchanged. Current schema: `docs/DATABASE.md`.

## Phase 1: unified finding and application model

**`findings` (new nullable or defaulted columns)**

| Column | Type | Source |
|---|---|---|
| `cvss_version` | text (`2.0`, `3.0`, `3.1`, `4.0`) | Scanner, CVE feed |
| `cvss_vector` | text | Scanner, CVE feed |
| `confidence` | text (`high`, `medium`, `low`, `unknown`) default `unknown` | SARIF `rank` and precision, tool defaults |
| `epss_score`, `epss_percentile` | numeric(6,5) | EPSS feed |
| `kev` | boolean default false; `kev_due_date` date | KEV feed |
| `exploit_available` | boolean | CVE references, KEV |
| `reachability` | text (`reachable`, `not_reachable`, `unknown`) default `unknown` | Phase 4 analysers |
| `risk_score` | numeric(5,2); `risk_factors` jsonb; `risk_scored_at` timestamptz | Risk engine |

Index: `(organization_id, risk_score DESC)` WHERE the finding is open.

**`applications`**

- `application_key` (`QD-APP-000001`, trigger-assigned from a sequence, immutable, like Repository IDs)
- `technical_owner_user_id`
- `lifecycle`, `environment`
- `internet_exposure` (derived view over repositories, plus an optional override)

**Intel tables (organization-independent reference data, read-only for the app role except through the feed job)**

| Table | Key | Columns |
|---|---|---|
| `intel_cves` | cve_id | description, published, modified, cvss_v3_vector, cvss_v4_vector, base scores, cwe[], references jsonb, source |
| `intel_epss` | cve_id | score, percentile, as_of |
| `intel_kev` | cve_id | vendor, product, added_on, due_date, known_ransomware |
| `intel_feed_runs` | id | feed, started, finished, records, error, mode (`online` or `file`) |

**`risk_models`** (versioned per organization): `weights` jsonb, `version`, `created_by`. Findings record the model version in `risk_factors`.

## Phase 2: ingestion

- `import_jobs`: kind (`sarif`, `json`, `cyclonedx`, `spdx`), repository or application target, uploader, file SHA-256, status, counts, error.
- Imported results become `scan_results` with `scanner_key` = `import:<tool>`.
- `scan_targets`: type (`repository`, `url`, `api_spec`, `image`, `artifact`), reference, credentials secret, scope rules. `scan_jobs.target_id` is nullable; repositories keep working unchanged.
- `custom_rules`: engine, name, content (validated), version, enabled, profile links.

## Phase 3 and 7: components and graph

- `components` (organization, purl, name, version, type, licences, latest_version, eol, deprecated, malicious, scorecard_score) de-duplicated by purl.
- `repository_components` (repository, component, scan, direct boolean, scope).
- `component_dependencies` (parent component, child component, repository). Built from CycloneDX `dependencies`.
- The existing `sbom_components` stays and is backfilled into the new tables; it is dropped only in a later major version.
- Graph traversal: recursive CTE views `v_component_paths` and `v_application_exposure`.

## Phase 4: correlation, suppression

- `finding_correlations` (finding_a, finding_b, kind: `same_location`, `same_cve_package`, `ai_suggested`, confidence, confirmed_by). Correlation links findings; it never merges them.
- `suppression_rules` (match on fingerprint, rule, path glob or package; reason; expires_at; created_by). Matched findings get status `false_positive` through the lifecycle trigger, with `source=rule`.

## Phase 8 and 9: governance and integrations

- `policies` (versioned): condition jsonb over finding and context attributes, actions (gate, require_review, sla_days, notify), scope.
- `compliance_frameworks`, `compliance_controls`, `control_mappings` (control ↔ CWE, category or rule).
- `report_definitions` (filters, grouping, columns, schedule, recipients) and `report_runs`.
- `connectors` (kind: `webhook`, `jira`, `servicenow`, `slack`, `teams`; config jsonb; secret_id; enabled).
- `connector_links` (finding or review ↔ external key and URL, last sync).
- `outbound_deliveries` (signed payload, attempts, status).
- `api_tokens.scopes` extended for REST use.

## Conventions kept

- `organization_id` on every tenant table, with composite foreign keys.
- Permanent keys come from database sequences and triggers (`SECURITY DEFINER`).
- History and audit tables are append-only, enforced by grants.
- Large reference data is loaded in batches by the jobs role.
