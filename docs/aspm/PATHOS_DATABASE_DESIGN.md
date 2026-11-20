Quditmind PATHOS · applies to v2.2.0 · status: Proposed

# PATHOS ASPM database design (historical) and lifecycle release data model

The first part of this page is the historical ASPM plan (status: Existing, as built). The last section, [Lifecycle release data model (M0, proposed)](#lifecycle-release-data-model-m0-proposed), is a proposal for the lifecycle release. Nothing in that section exists yet.

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

## Lifecycle release data model (M0, proposed)

**Status: Proposed.** Nothing in this section is built. Every table and column below needs owner approval at the gate of its milestone (see [PATHOS_IMPLEMENTATION_ROADMAP.md](PATHOS_IMPLEMENTATION_ROADMAP.md#17-lifecycle-release-plan-m0m11-proposed)). The decisions behind the design are in [PATHOS_ARCHITECTURE_DECISION_RECORDS.md](PATHOS_ARCHITECTURE_DECISION_RECORDS.md). The schema checked for this proposal is migrations `00001` to `00042` on `main` at PATHOS 2.2.0.

### What the proposal builds on (Existing, verified in code)

| Convention | Where it is today |
|---|---|
| Goose migrations, each with a Down section, additive only | `backend/migrations/*.sql`. The numbers `00030`, `00036`, `00037` and `00039` are unused. New migrations start at **`00043`** and never fill the gaps, because goose refuses a migration older than the current version unless it runs with out-of-order support |
| `id uuid PRIMARY KEY`, generated by the application as UUIDv7 | [DATABASE.md](../DATABASE.md). Exception found: `notification_events`, `notifications` and `material_changes` default to `gen_random_uuid()` (UUIDv4) (`00006_schedules_notifications.sql:103`, `00028_developer_context.sql:29`). New tables use application-generated UUIDv7 only |
| `organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE` and `UNIQUE (organization_id, id)` on parent tables | For example `tag_categories` (`00002_repositories.sql:92`) |
| Composite foreign keys `(organization_id, x_id) → parent(organization_id, id)` | `00002`, and 86 more added by `00042_same_org_references.sql`, so the database rejects a reference to another organization's row |
| Row-level security policy on every table with `organization_id` | `pathos_enable_tenant_rls()` (`00041_row_level_security.sql:72`) creates the policy `tenant_isolation` on any table with an `organization_id` column that has no policy yet. It runs from `pathos_apply_app_grants()` (`00041_row_level_security.sql:192`), which every migration calls last. Row-level security itself is switched on only when `installation_settings.multi_tenant` is true ([MULTI_TENANCY.md](../MULTI_TENANCY.md#22-database-layer-row-level-security)) |
| Global tables (no `organization_id`) must be classified | The list `global` in `backend/test/integration/zz_tenant_isolation_test.go:1067`. A new global table fails the test until it is added there and to [MULTI_TENANCY.md §1.1](../MULTI_TENANCY.md#11-tables) |
| Append-only tables | `REVOKE UPDATE, DELETE, TRUNCATE … FROM pathos_app` inside `pathos_apply_app_grants()`. The function is replaced as a whole (`CREATE OR REPLACE`), so a migration that adds an append-only table repeats the full current body and adds its line |
| Column grants for the one mutable part of an otherwise immutable row | `GRANT UPDATE (patch_status, …) ON human_review_recommendations` (`00041_row_level_security.sql:226`) |
| Enumerations as `text` with `CHECK` | [DATABASE.md](../DATABASE.md#conventions) |
| JSONB only for schemaless data | [DATABASE.md](../DATABASE.md#conventions) |
| Secrets only through `secrets` (envelope-encrypted), referenced by `secret_id` | `00001_foundation.sql` |
| Large objects in object storage with organization-prefixed keys (`artifacts/<org>/…`, `evidence/<org>/…`) | [MULTI_TENANCY.md §1.2](../MULTI_TENANCY.md#12-query-paths) |
| Bulk inserts | `COPY FROM` is rejected under row-level security. With multi-tenancy enabled the seven existing bulk inserts switch to multi-row `INSERT` ([MULTI_TENANCY.md §2.2](../MULTI_TENANCY.md#22-database-layer-row-level-security)). The CodeGraph loader must do the same |
| Permissions | Defined in Go (`backend/internal/authz/catalog.go`) and synced into `permissions` at start-up (`backend/internal/org/bootstrap.go:53`). New permissions need no migration, only catalog entries and system-role mappings |

### Rules for every new table in this proposal

1. Every new table carries `organization_id`, including child tables. This avoids hand-written `EXISTS` policies like the seven existing child tables need. The only exceptions are the global reference tables in [threat modelling](#threat-modelling-m5), which are classified as global.
2. Parents get `UNIQUE (organization_id, id)`. Children reference them with composite foreign keys.
3. The migration ends with `SELECT pathos_apply_app_grants();`. That creates the `tenant_isolation` policy automatically. No table is created with `FORCE ROW LEVEL SECURITY`, which matches the existing tables.
4. Every migration has a Down section that drops only what it added, in reverse order.
5. No existing column changes type, meaning or default. New columns on existing tables are `NOT NULL DEFAULT <neutral>` or nullable.
6. Each table maps to one milestone and one feature flag ([ADR-003](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-003-feature-flag-framework)). A table can exist while its flag is off. It stays empty.

### Feature flags (M1)

**Flag definitions live in code**, in a Go catalogue (for example `backend/internal/platform/flags`): key, milestone, description, depends-on keys, default (always off). Only the per-organization state is stored.

```sql
CREATE TABLE organization_feature_flags (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    flag_key        text NOT NULL CHECK (flag_key ~ '^[a-z][a-z0-9_.]{2,62}$'),
    enabled         boolean NOT NULL DEFAULT false,
    note            text NOT NULL DEFAULT '' CHECK (length(note) <= 500),
    changed_by      uuid,
    changed_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, flag_key),
    FOREIGN KEY (organization_id, changed_by) REFERENCES users(organization_id, id)
);
```

- A missing row means "off". A row for a key that is no longer in the catalogue is ignored and reported once in the log.
- Changes are recorded in the existing `audit_logs`; no separate history table.
- An installation-wide setting (environment variable, for example `PATHOS_FEATURES_DISABLED`) can force a flag off for every organization. It cannot force a flag on.

### Error catalogue (M1): code, not a table

The catalogue `PTH-<AREA>-<NNNN>` is a Go package (proposed `backend/internal/platform/diag`), not a table. Reasons:

- It must match the binary that raises the codes. A table could drift from the code after an upgrade or a rollback (`pathosctl migrate-down`).
- The docs in `docs/troubleshooting/*.md` are generated from it at build time (`make docs-errors`), and the help bundle must work offline. Neither needs the database.
- Nothing in it is per organization.

Stored records refer to codes as plain text. Proposed additive columns, all `text NOT NULL DEFAULT ''` with `CHECK (error_code = '' OR error_code ~ '^PTH-[A-Z]{2,5}-[0-9]{4}$')`:

| Table | Column | Milestone | Why |
|---|---|---|---|
| `scan_job_events` | `error_code` | M1 | Scan failure stages shown in the scan page |
| `repository_sync_runs`, `runtime_sync_runs` | `error_code` | M2 | Source sync and runtime sync failures on the Health tab |
| `outbound_webhook_deliveries` | `error_code` | M2 | Webhook delivery failures |
| `repository_import_items` | (none) | — | Already has `error_code text` (`00009_asset_onboarding.sql:305`) with legacy values. M3 maps legacy values to catalogue codes in the API response instead of rewriting stored rows |

The "Report a problem" bundle (last 50 request IDs and error codes) is kept in the browser's memory only. No table.

### Connectors and health checks (M2)

**Existing (Partial).** Connections are stored per kind, each with its own table and service: `scm_connections` (`00002`, extended in `00009`), `ticket_connections` and `outbound_webhooks` (`00022`), `runtime_clusters` and `registry_connections` (`00035`), `ai_providers` (`00004`), `smtp_settings` (`00006`, one row per organization). Each has a different status shape (for example `runtime_clusters.last_status`, `scm_connections.status`).

**Proposed:** a registry table that points at the existing rows, plus new kinds stored in the registry itself. The existing tables, services and pages stay unchanged (rule 1).

```sql
CREATE TABLE connectors (
    id                     uuid PRIMARY KEY,
    organization_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind                   text NOT NULL CHECK (kind IN (
        -- existing kinds (row lives in the legacy table)
        'scm', 'ticketing', 'outbound_webhook', 'kubernetes', 'container_registry', 'ai_provider', 'smtp',
        -- new kinds (row lives here), added per milestone by later migrations
        'cloud_aws', 'cloud_azure', 'cloud_gcp', 'siem', 'vault', 'cloud_secret_manager', 'api_spec')),
    category               text NOT NULL CHECK (category IN ('scm_ide', 'cicd', 'cloud', 'containers', 'security',
                                                             'iam_secrets', 'apis', 'databases', 'monitoring')),
    name                   text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    -- exactly one of these for an existing kind, none for a new kind
    scm_connection_id      uuid,
    ticket_connection_id   uuid,
    outbound_webhook_id    uuid,
    runtime_cluster_id     uuid,
    registry_connection_id uuid,
    ai_provider_id         uuid,
    -- new kinds only: non-secret settings, validated per kind in Go
    config                 jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(config) = 'object' AND pg_column_size(config) <= 65536),
    secret_id              uuid,
    enabled                boolean NOT NULL DEFAULT true,
    health                 text NOT NULL DEFAULT 'unknown' CHECK (health IN ('unknown', 'healthy', 'degraded', 'failing', 'disabled')),
    last_checked_at        timestamptz,
    last_ok_at             timestamptz,
    last_error_code        text NOT NULL DEFAULT '',
    credential_expires_at  timestamptz,
    created_by             uuid,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    CHECK (num_nonnulls(scm_connection_id, ticket_connection_id, outbound_webhook_id, runtime_cluster_id,
                        registry_connection_id, ai_provider_id)
           = CASE WHEN kind IN ('scm', 'ticketing', 'outbound_webhook', 'kubernetes', 'container_registry', 'ai_provider') THEN 1 ELSE 0 END),
    FOREIGN KEY (organization_id, scm_connection_id)      REFERENCES scm_connections(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, ticket_connection_id)   REFERENCES ticket_connections(organization_id, id) ON DELETE CASCADE,
    -- … one composite key per legacy table; a legacy table without UNIQUE (organization_id, id) gets it in the same migration
    FOREIGN KEY (organization_id, secret_id)              REFERENCES secrets(organization_id, id)
);
CREATE UNIQUE INDEX connectors_scm_uq ON connectors (scm_connection_id) WHERE scm_connection_id IS NOT NULL;
-- … one partial unique index per legacy reference
CREATE INDEX connectors_list_idx ON connectors (organization_id, category, health);
```

- The migration backfills one row per existing connection. `AFTER INSERT` triggers on the six legacy tables (`SECURITY DEFINER`, like the key-assignment triggers) add the registry row when an old page creates a connection, so old pages need no code change before parity. Deletes cascade from the legacy row. `smtp` has no reference column: it is matched by `organization_id`.
- **Alternative rejected:** moving all connection data into one table. It would rewrite six services and their tests and break the parity rule before the new page exists.
- Credentials for new kinds use `secrets` (write-only, envelope-encrypted, never returned), as today.
- Composite keys need `UNIQUE (organization_id, id)` on each legacy table. `00042` added that constraint dynamically to every table it referenced (`00042_same_org_references.sql:46-47`); a table it did not reference gets it in the same migration.

```sql
CREATE TABLE connector_health_checks (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    connector_id    uuid NOT NULL,
    check_kind      text NOT NULL CHECK (check_kind IN ('dns', 'reachability', 'tls', 'authentication', 'scopes',
                                                        'api_version', 'rate_limit', 'webhook', 'credential_expiry', 'egress_policy')),
    status          text NOT NULL CHECK (status IN ('pass', 'warn', 'fail', 'skipped')),
    error_code      text NOT NULL DEFAULT '',
    detail          text NOT NULL DEFAULT '' CHECK (length(detail) <= 2000),  -- redacted before insert
    observed        jsonb NOT NULL DEFAULT '{}' CHECK (pg_column_size(observed) <= 16384), -- granted scopes, API version, rate-limit remaining; never secrets
    duration_ms     integer NOT NULL DEFAULT 0,
    trigger         text NOT NULL CHECK (trigger IN ('schedule', 'user', 'verify', 'event')),
    triggered_by    uuid,
    checked_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, connector_id) REFERENCES connectors(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, triggered_by) REFERENCES users(organization_id, id)
);
CREATE INDEX connector_health_checks_recent_idx ON connector_health_checks (connector_id, checked_at DESC);
```

Retention: the jobs service keeps 30 days or the last 200 checks per connector, whichever is more. The table is therefore not append-only by grants. Connector changes are audited in `audit_logs`.

### Onboarding drafts, classification and tags (M3)

**Existing (Partial):**

- `repository_import_jobs.status` and `repository_import_items.status` already allow `draft` (`00009_asset_onboarding.sql:262`, `:290`). That covers imports, not a hand-entered application or target.
- Required asset fields per organization: `asset_settings.required_fields` (`00009_asset_onboarding.sql:31`).
- Classification catalogues: `asset_classifications` with kinds `criticality`, `data_classification`, `environment`, `application_type`, `internet_exposure`, `compliance`, `hosting_region`, `lifecycle_status` (`00009_asset_onboarding.sql:11`).
- Repositories carry the full set of business, technical, geography and environment fields (`00009_asset_onboarding.sql:177-210`). Applications carry fewer: `criticality`, `business_unit_id`, owners, `lifecycle`, `environment`, `external_ref` (`00002`, `00009`, `00013`).
- Tags: `tag_categories.is_mandatory` and `allow_multiple` exist (`00002_repositories.sql:97-98`). Tags attach to repositories only (`repository_tags`). There is no tag history.

**Proposed:**

```sql
CREATE TABLE asset_drafts (
    id                     uuid PRIMARY KEY,
    organization_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind                   text NOT NULL CHECK (kind IN ('application', 'repository', 'scan_target')),
    status                 text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'incomplete', 'ready', 'registered', 'discarded')),
    form                   jsonb NOT NULL DEFAULT '{}' CHECK (pg_column_size(form) <= 65536), -- partly filled form: schemaless by nature
    missing_fields         text[] NOT NULL DEFAULT '{}',
    connector_id           uuid,
    registered_application_id uuid,
    registered_repository_id  uuid,
    registered_target_id      uuid,
    created_by             uuid NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, connector_id) REFERENCES connectors(organization_id, id) ON DELETE SET NULL,
    FOREIGN KEY (organization_id, registered_application_id) REFERENCES applications(organization_id, id),
    FOREIGN KEY (organization_id, registered_repository_id)  REFERENCES repositories(organization_id, id),
    FOREIGN KEY (organization_id, registered_target_id)      REFERENCES scan_targets(organization_id, id),
    FOREIGN KEY (organization_id, created_by)                REFERENCES users(organization_id, id)
);
```

- `ON DELETE SET NULL` on a composite key would also null `organization_id`. The migration uses `ON DELETE SET NULL (connector_id)` (PostgreSQL 15 and later; the stack runs PostgreSQL 18, `docker-compose.yml:257`).
- Registered assets that still miss required fields get a status column instead of a draft: `repositories.registration_status` and `applications.registration_status`, `text NOT NULL DEFAULT 'complete' CHECK (registration_status IN ('complete', 'incomplete'))`. Existing rows stay `complete`, so nothing changes for them.
- Duplicate detection reuses the existing repository identity rules (clone URL, `repository_key`) and adds a normalized-name index on applications. No new table.

Classification: add to `applications` the fields repositories already have, so an application can be classified without a repository: `data_classification`, `internet_exposure`, `hosting_region`, `business_region_id`, `business_purpose`, all `NOT NULL DEFAULT ''` (or nullable for the region reference), validated against `asset_classifications` in Go as for repositories. The prompt's "security" group (for example a security tier) needs a new `asset_classifications.kind` value; the kind `CHECK` is replaced by a wider one. **Open question for the owner:** the exact list of security classification fields.

Tag framework:

```sql
ALTER TABLE tag_categories ADD COLUMN applies_to text[] NOT NULL DEFAULT '{repository}'
    CHECK (applies_to <@ ARRAY['repository', 'application', 'scan_target']::text[] AND cardinality(applies_to) >= 1);

CREATE TABLE application_tags (
    organization_id uuid NOT NULL,
    application_id  uuid NOT NULL,
    tag_id          uuid NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id, tag_id),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, tag_id) REFERENCES tags(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE tag_assignment_history (   -- append-only
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    tag_id          uuid,                 -- kept when the tag is later deleted
    tag_label       text NOT NULL,        -- category and tag name at the time
    subject_kind    text NOT NULL CHECK (subject_kind IN ('repository', 'application', 'scan_target')),
    subject_id      uuid NOT NULL,
    action          text NOT NULL CHECK (action IN ('added', 'removed')),
    source          text NOT NULL CHECK (source IN ('user', 'bulk', 'import', 'connector', 'rule')),
    actor_id        uuid,
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tag_assignment_history_subject_idx ON tag_assignment_history (organization_id, subject_kind, subject_id, created_at DESC);
```

`tag_assignment_history` gets `REVOKE UPDATE, DELETE, TRUNCATE` in `pathos_apply_app_grants()`. It has no foreign key to the subject so that history survives deletes. The organization delete function `pathos_delete_organization` covers it without change: it finds every table with an `organization_id` column at run time (`00040_multi_tenancy.sql:70-75`) and runs as the owner, so the revoked `DELETE` does not stop it.

### CodeGraph (M4)

**Existing (Partial):** the context graph (`backend/internal/posture/graph.go:557`) builds an ownership graph on request from relational tables (business unit, owner, team, application, repository, target, finding, component). Node IDs are `<type>:<uuid>`; edges have a `kind`; the result is capped at 5,000 component nodes (`maxGraphNodes`, `graph.go:55`). Function-level call sites to external modules exist for JavaScript/TypeScript, Python and Java (`pathos-reach`, stored as JSON in `repository_reach_reports`, `00032_function_reachability.sql:26`). Dependency edges exist in `sbom_dependencies` (`00016`). Endpoints declared by users exist in `repository_public_endpoints` (`00010`), with verification results in `endpoint_verifications` (`00025`). No code-level graph is stored.

**Proposed:** a stored graph per repository and commit, in PostgreSQL ([ADR-004](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-004-graph-store-postgresql-versus-a-graph-database)).

```sql
CREATE TABLE codegraph_snapshots (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id   uuid NOT NULL,
    source          text NOT NULL DEFAULT 'source' CHECK (source IN ('source', 'binary')),  -- binary: M10
    commit_sha      text NOT NULL DEFAULT '' CHECK (length(commit_sha) <= 64),
    scan_job_id     uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
    status          text NOT NULL DEFAULT 'building' CHECK (status IN ('building', 'ready', 'partial', 'failed', 'archived')),
    storage         text NOT NULL DEFAULT 'rows' CHECK (storage IN ('rows', 'object')),  -- object: only the archived file remains
    engines         jsonb NOT NULL DEFAULT '{}',   -- engine key → version, for reproducibility
    node_count      integer NOT NULL DEFAULT 0,
    edge_count      integer NOT NULL DEFAULT 0,
    object_key      text,                          -- gzip JSON of the whole graph: graphs/<org>/<snapshot>.json.gz
    error_code      text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX codegraph_snapshots_repo_idx ON codegraph_snapshots (repository_id, created_at DESC);

CREATE TABLE codegraph_nodes (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    snapshot_id     uuid NOT NULL,
    node_key        text NOT NULL CHECK (length(node_key) BETWEEN 1 AND 300),  -- stable across snapshots: hash of kind + qualified name + path
    kind            text NOT NULL CHECK (kind IN ('service', 'module', 'package', 'file', 'class', 'function', 'route',
                       'api_operation', 'data_store', 'db_table', 'queue', 'external_service', 'component',
                       'config', 'secret_reference', 'trust_boundary', 'deployment', 'binary_section', 'binary_symbol')),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 500),
    qualified_name  text NOT NULL DEFAULT '' CHECK (length(qualified_name) <= 2000),
    parent_id       uuid,                          -- containment tree, used for aggregation
    depth           smallint NOT NULL DEFAULT 0,
    language        text NOT NULL DEFAULT '',
    technology      text NOT NULL DEFAULT '',      -- framework, database engine, protocol
    file_path       text NOT NULL DEFAULT '' CHECK (length(file_path) <= 1000),
    start_line      integer,
    end_line        integer,
    security_tags   text[] NOT NULL DEFAULT '{}',  -- authn, authz, crypto, pii, entry_point, …
    open_findings   integer NOT NULL DEFAULT 0,    -- denormalised at snapshot time for filters
    attrs           jsonb NOT NULL DEFAULT '{}' CHECK (pg_column_size(attrs) <= 8192),
    UNIQUE (organization_id, id),
    UNIQUE (snapshot_id, node_key),
    FOREIGN KEY (organization_id, snapshot_id) REFERENCES codegraph_snapshots(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, parent_id)   REFERENCES codegraph_nodes(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX codegraph_nodes_parent_idx ON codegraph_nodes (snapshot_id, parent_id);
CREATE INDEX codegraph_nodes_kind_idx ON codegraph_nodes (snapshot_id, kind);

CREATE TABLE codegraph_edges (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    snapshot_id     uuid NOT NULL,
    edge_key        text NOT NULL,                 -- from node_key + kind + to node_key, for diffs
    from_node_id    uuid NOT NULL,
    to_node_id      uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('contains', 'imports', 'calls', 'depends_on', 'routes_to', 'handles',
                       'reads', 'writes', 'publishes', 'consumes', 'authenticates_with', 'calls_external',
                       'deploys_to', 'exposes', 'data_flow', 'crosses_boundary')),
    evidence_type   text NOT NULL CHECK (evidence_type IN ('verified', 'observed', 'ai_inferred')), -- strongest evidence held
    confidence      numeric(4,3) NOT NULL DEFAULT 1 CHECK (confidence BETWEEN 0 AND 1),
    UNIQUE (organization_id, id),
    UNIQUE (snapshot_id, edge_key),
    FOREIGN KEY (organization_id, snapshot_id)  REFERENCES codegraph_snapshots(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, from_node_id) REFERENCES codegraph_nodes(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, to_node_id)   REFERENCES codegraph_nodes(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX codegraph_edges_out_idx ON codegraph_edges (snapshot_id, from_node_id, kind);
CREATE INDEX codegraph_edges_in_idx  ON codegraph_edges (snapshot_id, to_node_id, kind);

CREATE TABLE codegraph_edge_evidence (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    edge_id         uuid NOT NULL,
    evidence_type   text NOT NULL CHECK (evidence_type IN ('verified', 'observed', 'ai_inferred')),
    engine          text NOT NULL,                 -- engine key; kept in the API for audit, hidden in the UI (ADR-011)
    file_path       text NOT NULL DEFAULT '',
    start_line      integer,
    commit_sha      text NOT NULL DEFAULT '',
    runtime_ref     jsonb,                         -- observed: cluster, workload, time window
    ai_evidence_id  uuid,                          -- required for ai_inferred
    FOREIGN KEY (organization_id, edge_id) REFERENCES codegraph_edges(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, ai_evidence_id) REFERENCES ai_evidence_records(organization_id, id),
    CHECK (evidence_type <> 'ai_inferred' OR ai_evidence_id IS NOT NULL),
    CHECK (evidence_type <> 'verified' OR file_path <> '' OR engine LIKE 'sbom%')
);
CREATE INDEX codegraph_edge_evidence_edge_idx ON codegraph_edge_evidence (edge_id);
```

- Every edge has at least one evidence row (rule 5). The loader writes both in one transaction and a test asserts `NOT EXISTS (edge without evidence)` for every built snapshot (the M4 "done when").
- `ai_evidence_records` is created in M4 (first user: AI-inferred edges), not M7. M7 extends it.
- **Server-side aggregation** reads the containment tree (`parent_id`) and groups edges by the ancestors at the requested level. To keep the first view fast, the snapshot finalizer stores the group edges per level:

```sql
CREATE TABLE codegraph_group_edges (
    organization_id uuid NOT NULL,
    snapshot_id     uuid NOT NULL,
    level           text NOT NULL CHECK (level IN ('service', 'module', 'package', 'file')),
    from_group_id   uuid NOT NULL,
    to_group_id     uuid NOT NULL,
    kind            text NOT NULL,
    edge_count      integer NOT NULL,
    evidence_types  text[] NOT NULL,
    PRIMARY KEY (snapshot_id, level, from_group_id, to_group_id, kind),
    FOREIGN KEY (organization_id, snapshot_id) REFERENCES codegraph_snapshots(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE codegraph_diffs (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL,
    repository_id     uuid NOT NULL,
    base_snapshot_id  uuid NOT NULL,
    head_snapshot_id  uuid NOT NULL,
    status            text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'ready', 'failed')),
    summary           jsonb NOT NULL DEFAULT '{}',   -- counts of added, removed and changed nodes and edges by kind
    object_key        text,                          -- full diff
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (base_snapshot_id, head_snapshot_id),
    FOREIGN KEY (organization_id, repository_id)    REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, base_snapshot_id) REFERENCES codegraph_snapshots(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, head_snapshot_id) REFERENCES codegraph_snapshots(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE graph_saved_views (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    owner_id        uuid NOT NULL,
    graph           text NOT NULL CHECK (graph IN ('codegraph', 'threat_model', 'reverse_engineering', 'context')),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    snapshot_id     uuid,                          -- null: always the latest snapshot
    state           jsonb NOT NULL CHECK (pg_column_size(state) <= 32768), -- filters, layers, expanded groups, viewport
    shared          boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, owner_id) REFERENCES users(organization_id, id) ON DELETE CASCADE
);
```

**Volume and retention.** A large repository can give hundreds of thousands of edges per snapshot. Keeping every snapshot as rows would grow without bound. Proposed: only the latest `ready` snapshot per repository, plus snapshots referenced by an application version (`application_versions`, `00027`), stay as rows. Older snapshots are archived: the rows are deleted, `storage` becomes `object`, and the gzip file and diffs stay. Compare against an archived snapshot reads the file. Loading uses multi-row `INSERT` in batches (no `COPY` with multi-tenancy enabled). **To measure in M4:** load time and table size for the PATHOS repository and for one large public repository.

### Threat modelling (M5)

**Existing (Partial):** attack paths and blast radius are computed on request (`backend/internal/posture/attack.go:49`, `GET /api/v1/posture/attack-paths`); findings carry CWE identifiers (`pr_findings.cwe`, `00021`; finding CWE fields); compliance frameworks are a code catalogue (`backend/internal/compliance`). No threat model is stored.

```sql
CREATE TABLE threat_models (
    id                  uuid PRIMARY KEY,
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id      uuid NOT NULL,
    repository_id       uuid,                              -- optional narrower scope
    codegraph_snapshot_id uuid,
    version             integer NOT NULL DEFAULT 1,
    status              text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'in_review', 'approved', 'superseded', 'archived')),
    method              text NOT NULL CHECK (method IN ('stride', 'linddun', 'stride_linddun', 'manual', 'imported')),
    imported_format     text NOT NULL DEFAULT '' CHECK (imported_format IN ('', 'threat_dragon', 'pytm', 'threagile', 'pathos')),
    title               text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    summary             text NOT NULL DEFAULT '' CHECK (length(summary) <= 8000),
    created_by          uuid NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    UNIQUE (application_id, version),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id)  REFERENCES repositories(organization_id, id),
    FOREIGN KEY (organization_id, codegraph_snapshot_id) REFERENCES codegraph_snapshots(organization_id, id) ON DELETE SET NULL (codegraph_snapshot_id),
    FOREIGN KEY (organization_id, created_by) REFERENCES users(organization_id, id)
);

CREATE TABLE threat_model_elements (       -- diagram elements; linked to CodeGraph where they come from it
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    threat_model_id uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('process', 'data_store', 'external_entity', 'data_flow', 'trust_boundary')),
    name            text NOT NULL,
    codegraph_node_key text NOT NULL DEFAULT '',
    attrs           jsonb NOT NULL DEFAULT '{}',
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, threat_model_id) REFERENCES threat_models(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE threats (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    threat_model_id uuid NOT NULL,
    element_id      uuid,
    title           text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 8000),
    category        text NOT NULL CHECK (category IN ('spoofing', 'tampering', 'repudiation', 'information_disclosure',
                       'denial_of_service', 'elevation_of_privilege',          -- STRIDE
                       'linking', 'identifying', 'non_repudiation', 'detecting',
                       'data_disclosure', 'unawareness', 'non_compliance')),   -- LINDDUN
    method          text NOT NULL CHECK (method IN ('rule', 'attack_path', 'ai', 'manual', 'imported')),
    evidence_type   text NOT NULL CHECK (evidence_type IN ('verified', 'observed', 'ai_inferred')),
    evidence        jsonb NOT NULL DEFAULT '{}',   -- CodeGraph node and edge keys, finding ids, attack path reference, rule id
    ai_evidence_id  uuid,
    severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    likelihood      text NOT NULL DEFAULT 'unknown' CHECK (likelihood IN ('high', 'medium', 'low', 'unknown')),
    confidence      numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    status          text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'mitigated', 'accepted', 'not_applicable', 'transferred')),
    mitigation      text NOT NULL DEFAULT '' CHECK (length(mitigation) <= 8000),
    owner_id        uuid,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, threat_model_id) REFERENCES threat_models(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, element_id)      REFERENCES threat_model_elements(organization_id, id) ON DELETE SET NULL (element_id),
    FOREIGN KEY (organization_id, ai_evidence_id)  REFERENCES ai_evidence_records(organization_id, id),
    FOREIGN KEY (organization_id, owner_id)        REFERENCES users(organization_id, id),
    CHECK (evidence_type <> 'ai_inferred' OR ai_evidence_id IS NOT NULL)
);

CREATE TABLE threat_findings (
    organization_id uuid NOT NULL,
    threat_id       uuid NOT NULL,
    finding_id      uuid NOT NULL,
    PRIMARY KEY (threat_id, finding_id),
    FOREIGN KEY (organization_id, threat_id)  REFERENCES threats(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE threat_framework_mappings (
    organization_id uuid NOT NULL,
    threat_id       uuid NOT NULL,
    framework       text NOT NULL CHECK (framework IN ('attack', 'capec', 'cwe', 'd3fend', 'linddun')),
    entry_id        text NOT NULL CHECK (length(entry_id) BETWEEN 1 AND 50),   -- T1190, CAPEC-66, CWE-89, D3-…
    source          text NOT NULL CHECK (source IN ('rule', 'ai', 'user', 'imported')),
    ai_evidence_id  uuid,
    PRIMARY KEY (threat_id, framework, entry_id),
    FOREIGN KEY (organization_id, threat_id) REFERENCES threats(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE threat_model_approvals (     -- append-only
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    threat_model_id uuid NOT NULL,
    version         integer NOT NULL,
    decision        text NOT NULL CHECK (decision IN ('approved', 'rejected', 'changes_requested')),
    approver_id     uuid NOT NULL,
    note            text NOT NULL DEFAULT '' CHECK (length(note) <= 4000),
    decided_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, threat_model_id) REFERENCES threat_models(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, approver_id)     REFERENCES users(organization_id, id)
);
```

- Every threat has evidence, method, severity, confidence and a mitigation field (the M5 "done when"). An empty mitigation is allowed only while the model is a draft; submit for review refuses it (application check, error `PTH-TM-…`).
- The approver must differ from the model's author, as in Human Eye. Enforced in the service, recorded in the approval row.

**Global reference data** (no `organization_id`; classified in `zz_tenant_isolation_test.go` and `MULTI_TENANCY.md §1.1`; written by the jobs role only, like `intel_*`):

```sql
CREATE TABLE framework_entries (
    framework       text NOT NULL CHECK (framework IN ('attack', 'capec', 'cwe', 'd3fend')),
    entry_id        text NOT NULL,
    name            text NOT NULL,
    summary         text NOT NULL DEFAULT '' CHECK (length(summary) <= 4000),
    url             text NOT NULL DEFAULT '',
    release         text NOT NULL,                 -- the framework release the row came from
    deprecated      boolean NOT NULL DEFAULT false,
    PRIMARY KEY (framework, entry_id)
);
CREATE TABLE framework_relations (
    framework_a text NOT NULL, entry_a text NOT NULL,
    framework_b text NOT NULL, entry_b text NOT NULL,
    relation    text NOT NULL CHECK (relation IN ('related', 'child_of', 'mitigates', 'detects', 'exploits')),
    PRIMARY KEY (framework_a, entry_a, framework_b, entry_b, relation)
);
```

The data ships with the build or in the offline bundle (`scripts/offline-bundle.sh`) and is loaded in batches. LINDDUN categories are a code catalogue (seven fixed categories), not rows. Licence notices: [ADR-007](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-007-threat-model-engine-and-framework-mappings).

### AI evidence records (M4 table, M7 full use)

**Existing (Partial):** AI reviews (`ai_reviews`, `00004_ai_mcp.sql:67`) and AI fixes (`ai_fix_proposals`, `00033_verified_ai_fixes.sql:13`) store provider, model, configuration version, token counts and the **SHA-256** of exactly what was sent (`transmitted_sha256`), not the prompt or the raw response. One default AI configuration per organization (`ai_configurations_default_uq`, `00004_ai_mcp.sql:37`); there is no model per task.

```sql
CREATE TABLE ai_evidence_records (
    id                    uuid PRIMARY KEY,
    organization_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    task                  text NOT NULL CHECK (task IN ('finding_validation', 'troubleshooting', 'graph_inference',
                             'threat_suggestion', 'correlation', 'fix_proposal', 'report', 'analyst')),
    subject_kind          text NOT NULL CHECK (subject_kind IN ('finding', 'codegraph_edge', 'threat', 'connector',
                             'error', 'remediation_item', 'report', 'conversation')),
    subject_id            uuid,
    config_version_id     uuid,
    provider              text NOT NULL,
    model                 text NOT NULL,
    model_digest          text NOT NULL DEFAULT '',    -- local models: the model file digest (for example Ollama's)
    prompt_template       text NOT NULL,               -- template key and version, for example finding_validation@3
    parameters            jsonb NOT NULL DEFAULT '{}', -- temperature, seed, max tokens
    inputs                jsonb NOT NULL DEFAULT '{}', -- references only: finding ids, node keys, check ids
    input_sha256          text NOT NULL,
    prompt_object_key     text,                        -- redacted prompt, encrypted store: evidence/<org>/ai/<id>/prompt
    response_object_key   text,
    response_sha256       text NOT NULL DEFAULT '',
    steps                 jsonb NOT NULL DEFAULT '[]', -- reasoning steps as returned and schema-validated
    conclusion            text NOT NULL DEFAULT '' CHECK (length(conclusion) <= 8000),
    confidence            numeric(4,3) CHECK (confidence BETWEEN 0 AND 1),
    status                text NOT NULL CHECK (status IN ('succeeded', 'invalid_output', 'failed', 'disabled')),
    error_code            text NOT NULL DEFAULT '',
    input_tokens          bigint NOT NULL DEFAULT 0,
    output_tokens         bigint NOT NULL DEFAULT 0,
    review_decision       text NOT NULL DEFAULT 'pending' CHECK (review_decision IN ('pending', 'accepted', 'rejected', 'not_required')),
    reviewer_id           uuid,
    reviewed_at           timestamptz,
    replay_of             uuid,                        -- set when the record re-runs another record
    created_at            timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, config_version_id) REFERENCES ai_configuration_versions(organization_id, id),
    FOREIGN KEY (organization_id, reviewer_id)       REFERENCES users(organization_id, id)
);
CREATE INDEX ai_evidence_subject_idx ON ai_evidence_records (organization_id, subject_kind, subject_id, created_at DESC);
```

- Immutable except the review: `REVOKE UPDATE, DELETE, TRUNCATE` plus `GRANT UPDATE (review_decision, reviewer_id, reviewed_at)`, the same pattern as `human_review_recommendations`.
- The prompt and response are stored only after redaction, in the encrypted source store with the organization prefix. Secrets are never sent and never stored (rule 6).
- **Open question for the owner:** storing the redacted prompt (which can contain up to ±5 lines of code today, [ARCHITECTURE.md §6](../ARCHITECTURE.md#6-ai-review-architecture)) is needed to make a decision reproducible, but it keeps code fragments longer than today. Proposed: on by default for `finding_validation`, `graph_inference` and `threat_suggestion`; retention follows the scan artifact retention.
- Additive link columns: `ai_reviews.evidence_record_id`, `ai_fix_proposals.evidence_record_id`, `ai_messages.evidence_record_id` (nullable). Old rows stay as they are.
- Model per task (M7):

```sql
CREATE TABLE ai_task_assignments (
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    task             text NOT NULL,                  -- same values as ai_evidence_records.task
    configuration_id uuid NOT NULL,
    updated_by       uuid,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, task),
    FOREIGN KEY (organization_id, configuration_id) REFERENCES ai_configurations(organization_id, id)
);
```

A task without a row uses the organization's default configuration (today's behaviour). The proposed seed for new organizations points code-related tasks at a local provider when one is configured ([ADR-008](PATHOS_ARCHITECTURE_DECISION_RECORDS.md#adr-008-ai-evidence-record-and-reproducibility)).

### Remediation items and gate decisions (M8)

**Existing (Partial):** fix pull requests for dependencies and verified AI fixes (`fix_pull_requests`, `fix_pull_request_findings`, `00027`; `ai_fix_proposals`, `00033`); security policies with a `block` action (`security_policies`, `policy_violations`, `00021`; `backend/internal/policy/policy.go:47`); the scan security gate (`scan_jobs.gate_failed`, computed in `backend/internal/scans/ingest.go:499`); pull request checks (`pr_checks`, `00020`); the CI gate endpoint `GET /api/v1/scans/{id}/gate` (`backend/internal/scans/gate.go`). Today the gate fails for four reasons, two of them without a policy object (see the conflict below).

```sql
CREATE TABLE remediation_items (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id   uuid,
    repository_id    uuid,
    title            text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    kind             text NOT NULL CHECK (kind IN ('code_fix', 'dependency_upgrade', 'configuration', 'threat_mitigation', 'design_change')),
    status           text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'planned', 'in_progress', 'fix_submitted',
                        'verifying', 'verified', 'closed', 'wont_fix')),
    priority         text NOT NULL DEFAULT 'medium' CHECK (priority IN ('critical', 'high', 'medium', 'low')),
    owner_id         uuid,
    team_id          uuid,
    due_at           timestamptz,
    fix_pull_request_id uuid,
    ai_fix_id        uuid,
    created_by       uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    CHECK (application_id IS NOT NULL OR repository_id IS NOT NULL),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id)  REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, owner_id)       REFERENCES users(organization_id, id),
    FOREIGN KEY (organization_id, team_id)        REFERENCES teams(organization_id, id)
    -- fix_pull_request_id, ai_fix_id: composite keys once the referenced tables have UNIQUE (organization_id, id)
);
CREATE TABLE remediation_item_findings (organization_id uuid NOT NULL, item_id uuid NOT NULL, finding_id uuid NOT NULL,
    PRIMARY KEY (item_id, finding_id),
    FOREIGN KEY (organization_id, item_id)    REFERENCES remediation_items(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE);
CREATE TABLE remediation_item_threats (organization_id uuid NOT NULL, item_id uuid NOT NULL, threat_id uuid NOT NULL,
    PRIMARY KEY (item_id, threat_id),
    FOREIGN KEY (organization_id, item_id)   REFERENCES remediation_items(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, threat_id) REFERENCES threats(organization_id, id) ON DELETE CASCADE);

CREATE TABLE remediation_verifications (   -- append-only: before-and-after evidence
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL,
    item_id            uuid NOT NULL,
    before_scan_job_id uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
    after_scan_job_id  uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
    result             text NOT NULL CHECK (result IN ('fixed', 'still_present', 'regressed', 'inconclusive')),
    evidence           jsonb NOT NULL,       -- fingerprints before and after, counts, scanner versions
    verified_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, item_id) REFERENCES remediation_items(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE security_gates (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    stage           text NOT NULL CHECK (stage IN ('ide', 'pre_commit', 'pull_request', 'ci', 'release', 'deploy')),
    policy_id       uuid NOT NULL,                     -- a gate cannot exist without a policy (rule 7)
    mode            text NOT NULL CHECK (mode IN ('block', 'warn', 'require_approval')),
    allow_exceptions boolean NOT NULL DEFAULT true,
    application_id  uuid,                              -- null: every application in scope
    enabled         boolean NOT NULL DEFAULT true,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, policy_id)      REFERENCES security_policies(organization_id, id),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE
);

CREATE TABLE gate_decisions (               -- append-only
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stage            text NOT NULL,
    repository_id    uuid,
    application_version_id uuid,
    scan_job_id      uuid,
    commit_sha       text NOT NULL DEFAULT '',
    pull_request     integer,
    outcome          text NOT NULL CHECK (outcome IN ('pass', 'warn', 'block', 'approval_required', 'exception_applied')),
    gate_ids         uuid[] NOT NULL DEFAULT '{}',
    policy_ids       uuid[] NOT NULL DEFAULT '{}',
    policy_versions  integer[] NOT NULL DEFAULT '{}',
    reasons          jsonb NOT NULL DEFAULT '[]',
    request_id       text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (outcome NOT IN ('block', 'approval_required') OR cardinality(policy_ids) > 0)
);
CREATE INDEX gate_decisions_repo_idx ON gate_decisions (organization_id, repository_id, created_at DESC);

CREATE TABLE gate_exceptions (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    gate_id          uuid NOT NULL,
    decision_id      uuid,
    scope            jsonb NOT NULL,                 -- repository, commit, pull request or application version
    reason           text NOT NULL CHECK (length(reason) BETWEEN 1 AND 4000),
    status           text NOT NULL DEFAULT 'requested' CHECK (status IN ('requested', 'approved', 'rejected', 'expired', 'revoked')),
    requested_by     uuid NOT NULL,
    decided_by       uuid,
    expires_at       timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    decided_at       timestamptz,
    CHECK (decided_by IS NULL OR decided_by <> requested_by),
    FOREIGN KEY (organization_id, gate_id) REFERENCES security_gates(organization_id, id) ON DELETE CASCADE
);
```

The `CHECK` on `gate_decisions` makes rule 7 a database constraint: a blocking decision without at least one policy cannot be stored. `security_policies` is declared with `UNIQUE (organization_id, name)` (`00021_governance.sql:19`). The composite key also needs `UNIQUE (organization_id, id)`; `00042` adds it to referenced tables, and the M8 migration adds it if it is still missing.

**Conflict found (rule 7, needs owner decision).** Today a scan or pull request can fail without a `security_policies` row:

| Gate today | Where | Default |
|---|---|---|
| Scan profile "fail on critical" | `scan_profile_versions.fail_on_critical` (`00003_scanning.sql:48`), applied in `scans/ingest.go:499` | Off |
| Target requires a verified signature | `signatureGateFailed`, `scans/ingest.go:507` | Off (per target) |
| Pull request check severity | `repositories.pr_gate_severity` (`00020_supply_chain.sql:50`), applied in `scans/prchecks.go:45` | `high`, but only when `pr_checks_enabled` (default false) |
| CI gate threshold | `fail_on` query parameter of `GET /scans/{id}/gate` (`scans/gate.go:45`) | `none`; the caller chooses |

Each is an explicit, opt-in setting, but none is a policy object. Options: (a) treat these settings as policies and document them so; (b) migrate them into generated `security_policies` rows (one per profile or repository that uses them), keeping behaviour identical; (c) keep them and record them as `legacy_setting` reasons in `gate_decisions` with a synthetic policy reference. Recommended: (b) in M8, behind the M8 flag, with a parity test. The M8 test "no gate blocks without a policy" depends on this choice.

**Implemented in M8 (migrations 00055–00057), differences from the design above:** `remediation_items.status` has no separate `verified` (a successful verification sets `closed`, and a CHECK requires the proving `closed_by_verification_id`); `team_id` and `remediation_item_threats` are not built (M8 was built before the M5 threat models were merged; linking items to threats is a follow-up); verifications carry `trigger`, a worker lease, `scanner_keys` and immutable evidence; `security_gates` adds `repository_id` and `managed`; `gate_decisions` adds `application_id`, `pr_check_id`, `gates`, `evidence` and `requested_by` (the planned `application_version_id` is left out: no endpoint takes it yet); `gate_exceptions` adds `kind` (exception or approval), `repository_id`/`application_id` and `decision_note`. The legacy-threshold conflict was resolved by decision C6 (see ADR-010). See [DATABASE.md](../DATABASE.md#remediation-and-security-gates-migrations-0005500057).

### Monitoring feed (M9)

**Existing (Partial):** `notification_events` (`00006`) is a delivery queue (`processed_at`), not a readable feed. Material changes (`material_changes`, `00028`), runtime facts (`00035`), feed runs (`intel_feed_runs`) and policy violations each record their own events.

```sql
CREATE TABLE monitoring_events (
    id              uuid NOT NULL,
    organization_id uuid NOT NULL,
    occurred_at     timestamptz NOT NULL DEFAULT now(),
    kind            text NOT NULL CHECK (kind IN ('new_critical_finding', 'kev_added', 'epss_jump', 'architecture_drift',
                       'new_entry_point', 'threat_model_stale', 'connector_failing', 'gate_blocked', 'sla_breached',
                       'runtime_exposure', 'material_change', 'scan_failed', 'remediation_verified')),
    severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    application_id  uuid,
    repository_id   uuid,
    subject_kind    text NOT NULL,
    subject_id      uuid,
    summary         text NOT NULL CHECK (length(summary) <= 1000),
    evidence_type   text NOT NULL DEFAULT 'verified' CHECK (evidence_type IN ('verified', 'observed', 'ai_inferred')),
    dedup_key       text NOT NULL,
    payload         jsonb NOT NULL DEFAULT '{}' CHECK (pg_column_size(payload) <= 16384),
    acknowledged_by uuid,
    acknowledged_at timestamptz,
    PRIMARY KEY (id, occurred_at),
    UNIQUE (organization_id, dedup_key, occurred_at)
) PARTITION BY RANGE (occurred_at);
CREATE INDEX monitoring_events_feed_idx ON monitoring_events (organization_id, occurred_at DESC);
```

- Partitioned by month like `audit_logs`, with a partition-maintenance function granted to the application (pattern: `pathos_ensure_audit_partitions`). The application uses the parent table only; partitions get no grants, so the parent's `tenant_isolation` policy applies (as for `audit_logs`).
- Only `acknowledged_by` and `acknowledged_at` are updatable (column grant).
- Architecture drift is not a table: it is a `codegraph_diffs` row whose summary crosses a threshold, published as a `monitoring_events` row.

### Reverse-engineering analyses (M10)

**Existing (Partial):** build artifact targets (`scan_targets` kind `artifact`, `00020`) with malware scanning and signature verification (`signature_verifications`, `00025`); the binary worker family (CVE Binary Tool, capa, YARA-X; `workers/binary/Dockerfile`).

```sql
CREATE TABLE rea_analyses (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scan_target_id   uuid NOT NULL,                  -- an artifact target
    application_version_id uuid,
    artifact_sha256  text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    origin           text NOT NULL CHECK (origin IN ('own_build', 'third_party')),
    origin_evidence  jsonb NOT NULL DEFAULT '{}',    -- signature or provenance verification that proves own_build
    tier             text NOT NULL DEFAULT 'static' CHECK (tier = 'static'),  -- the sandbox tier (M11) needs its own migration and approval
    status           text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled')),
    engines          jsonb NOT NULL DEFAULT '{}',
    codegraph_snapshot_id uuid,                      -- binary graph (codegraph_snapshots.source = 'binary')
    object_key       text,
    summary          jsonb NOT NULL DEFAULT '{}',
    error_code       text NOT NULL DEFAULT '',
    requested_by     uuid NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    started_at       timestamptz,
    finished_at      timestamptz,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, scan_target_id) REFERENCES scan_targets(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, requested_by)   REFERENCES users(organization_id, id)
);

CREATE TABLE rea_source_diffs (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL,
    analysis_id       uuid NOT NULL,
    repository_id     uuid NOT NULL,
    commit_sha        text NOT NULL,
    status            text NOT NULL CHECK (status IN ('queued', 'ready', 'failed')),
    summary           jsonb NOT NULL DEFAULT '{}',    -- symbols only in the binary, embedded strings and URLs not in source, unmatched components
    object_key        text,
    created_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, analysis_id)   REFERENCES rea_analyses(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
```

Findings from the static tier go into the existing `findings` table through the existing ingest path, with existing categories. Analysing a `third_party` artifact needs an organization setting that is off by default (M10 "done when").

### Table-to-milestone map

| Milestone | Tables and columns (all proposed) | Feature flag (proposed key) |
|---|---|---|
| M1 | `organization_feature_flags`; `scan_job_events.error_code` | `shell.v2`, `diagnostics` (flags themselves are not flagged) |
| M2 | `connectors`, `connector_health_checks`; `error_code` on `repository_sync_runs`, `runtime_sync_runs`, `outbound_webhook_deliveries` | `connectors` |
| M3 | `asset_drafts`, `application_tags`, `tag_assignment_history`; `tag_categories.applies_to`; `registration_status` on `repositories` and `applications`; classification columns on `applications` | `onboarding.v2` |
| M4 | `codegraph_snapshots`, `codegraph_nodes`, `codegraph_edges`, `codegraph_edge_evidence`, `codegraph_group_edges`, `codegraph_diffs`, `graph_saved_views`, `ai_evidence_records` | `codegraph` |
| M5 | `threat_models`, `threat_model_elements`, `threats`, `threat_findings`, `threat_framework_mappings`, `threat_model_approvals`; global `framework_entries`, `framework_relations` | `threat_models` |
| M6 | None expected. Scan profiles and the catalogue exist (`scan_profiles`, `scanner_catalog`; `findings.scanner_keys` already holds the agreeing engines) | `scan_profiles.v2` |
| M7 | `ai_task_assignments`; `evidence_record_id` on `ai_reviews`, `ai_fix_proposals`, `ai_messages` | `ai.evidence` |
| M8 | `remediation_items`, `remediation_item_findings`, `remediation_item_threats`, `remediation_verifications`, `security_gates`, `gate_decisions`, `gate_exceptions` | `remediation`, `gates` |
| M9 | `monitoring_events` (partitioned) | `monitoring` |
| M10 | `rea_analyses`, `rea_source_diffs`; `codegraph_snapshots.source = 'binary'` | `reverse_engineering` |
| M11 | Not designed. Needs separate approval | — |

### Tests each migration adds

- The existing migration rollback test rolls back through every new migration and re-applies it.
- `zz_tenant_isolation_test.go` probes every new route with another organization's ids (it discovers routes by AST scan, so new routes are covered automatically) and checks that every new table has a policy. Global tables must be added to its `global` list.
- One integration test per `CHECK` that carries a rule: edge without evidence, AI-inferred edge or threat without an evidence record, blocking gate decision without a policy, gate without a policy, self-approved exception or threat model.
- The organization delete test (`zz_tenant_lifecycle_test.go`) asserts that no row of a deleted organization is left in any new table and that stored objects (graph files, AI prompts, REA results) are deleted.
