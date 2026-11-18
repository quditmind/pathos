# PATHOS ASPM database design (historical)

> **Status: historical design, written in phase 0 (2026-11-17).** All ten ASPM phases are built (migrations `00013` to `00023`). Some planned tables were built under other names or replaced by a simpler design. This page keeps the plan and maps each part to what exists today. The current schema is described in [DATABASE.md](../DATABASE.md), which is canonical.

The plan's rules hold for every ASPM migration:

- each change is an **additive** goose migration with a Down migration and an updated `pathos_apply_app_grants()`
- existing columns, values and fingerprints are unchanged

## Planned and as built

| Planned (phase) | As built |
|---|---|
| `findings` intelligence columns: `cvss_version`, `cvss_vector`, `confidence`, `epss_score`, `epss_percentile`, `kev`, `kev_due_date`, `exploit_available`, `reachability`, `risk_score`, `risk_factors`, `risk_scored_at` (1) | Built in `00013`, plus `risk_dirty` and the re-scoring triggers. `reachability_basis` came in `00017`, `malicious` in `00020` |
| `applications`: `application_key`, `technical_owner_user_id`, `lifecycle`, `environment` (1) | Built in `00013`. Internet exposure is derived from the application's repositories in the posture queries; there is no override column |
| `intel_cves` (1) | Not built. CVE and GHSA details come from OSV and are stored in `intel_vulns` (`00017`) |
| `intel_epss`, `intel_kev`, `intel_feed_runs` (1) | Built in `00013`, plus `intel_feeds` (feed configuration). The `osv` feed came in `00017`, `depsdev` in `00020` |
| `risk_models` (1) | Built in `00013` |
| `import_jobs` (2) | Built in `00014`. Imported results use scanner keys `import-<category>-<tool>` (registered through `pathos_register_import_tool()`), not `import:<tool>` |
| `scan_targets` with types `repository`, `url`, `api_spec`, `image`, `artifact` (2) | Built in `00015` with kinds `image`, `url`, `api`, `sbom`; `artifact` was added in `00020`. Repositories are not targets: `scan_jobs.target_kind` is `repository` for source scans |
| `custom_rules` (2) | Built in `00014`, plus `custom_rule_versions` |
| `components`, `repository_components`, `component_dependencies`, views `v_component_paths`, `v_application_exposure` (3, 7) | Not built. `sbom_components` gained `bom_ref` and `depth`, and `sbom_dependencies` holds the edges (`00016`). Package health is kept per package in `package_health` (`00020`). Paths are computed by the posture service |
| `finding_correlations` (4) | Not built. Related findings are computed on request (`GET /findings/{id}/related`) and never stored or merged |
| `suppression_rules` (4) | Built in `00017`, plus `findings.suppression_rule_id`. Matched findings get status `false_positive` through the lifecycle trigger |
| `policies` (8) | Built as `security_policies` and `policy_violations` (`00021`) |
| `compliance_frameworks`, `compliance_controls`, `control_mappings` (8) | Not tables. The five frameworks and their control mappings are a catalog in code (`backend/internal/compliance`) |
| `report_definitions`, `report_runs` (9) | Built as `saved_reports` (`00022`). Runs are not stored; scheduled runs deliver a link through the notification rules |
| `connectors` (9) | Split by kind: `outbound_webhooks` (JSON, Slack, Teams) and `ticket_connections` (Jira, ServiceNow) (`00022`) |
| `connector_links` (9) | Built as `finding_tickets` (`00022`) |
| `outbound_deliveries` (9) | Built as `outbound_webhook_deliveries` (`00022`) |
| `api_tokens.scopes` extended (9) | No migration needed: the existing `scopes` column takes the new values `api:read` and `api:write` |
| (not planned) | `pr_checks`, `pr_findings` (`00020`); AI analyst tables `ai_conversations`, `ai_messages`, `ai_reports` (`00019`); Human Eye approval levels and patch decisions (`00018`); `pathos_register_plugin_scanner()` (`00023`) |

## Conventions kept

- `organization_id` on every tenant table, with composite foreign keys.
- Permanent keys come from database sequences and triggers (`SECURITY DEFINER`).
- History and audit tables are append-only, enforced by grants.
- Large reference data is loaded in batches by the jobs role.
