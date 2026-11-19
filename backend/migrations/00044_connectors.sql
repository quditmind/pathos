-- +goose Up
-- PATHOS 3.0 M2: Connectors (docs/api-reference/connectors.md,
-- docs/aspm/PATHOS_DATABASE_DESIGN.md "Connectors and health checks").
--
-- connectors is a registry that points at the existing connection tables
-- (scm_connections, ticket_connections, outbound_webhooks, runtime_clusters,
-- registry_connections, ai_providers, smtp_settings, intel_feeds,
-- secret_validation_settings) and at installation services (object storage,
-- egress proxy). Those tables stay the source of truth: a registry row holds
-- only the source key, the health state and the check request, never a copy
-- of the connection's settings or credential. The connectors service keeps
-- the registry in step with the sources (rows are added and removed by
-- reconciliation, not by triggers, so the legacy services need no change).
--
-- Kinds added in M2 that have no legacy table store their non-secret
-- settings in config and their credential in secrets (secret_id), as every
-- other connection does. The kind is validated in Go against the kinds
-- catalogue (internal/connectors/kinds.go), so a new kind needs no migration.
CREATE TABLE connectors (
    id                  uuid PRIMARY KEY,
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind                text NOT NULL CHECK (kind ~ '^[a-z][a-z0-9_]{1,62}$'),
    -- Legacy rows: the table and key of the source row ('' key for the
    -- per-organization singletons such as smtp_settings). NULL for kinds
    -- stored here.
    source_table        text CHECK (source_table IS NULL OR source_table ~ '^[a-z][a-z0-9_]{1,62}$'),
    source_key          text CHECK (source_key IS NULL OR length(source_key) <= 200),
    -- Kinds stored here only.
    name                text NOT NULL DEFAULT '' CHECK (length(name) <= 200),
    config              jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(config) = 'object' AND pg_column_size(config) <= 65536),
    secret_id           uuid,
    enabled             boolean NOT NULL DEFAULT true,
    -- Health: the last check's outcome. 'unknown' until a check ran.
    status              text NOT NULL DEFAULT 'unknown' CHECK (status IN ('unknown', 'healthy', 'degraded', 'failing', 'disabled')),
    last_check_at       timestamptz,
    last_ok_at          timestamptz,
    last_error_code     text NOT NULL DEFAULT '' CHECK (last_error_code = '' OR last_error_code ~ '^PTH-[A-Z]{2,5}-[0-9]{4}$'),
    -- "Check now" for kinds checked by the jobs service (the API server
    -- never calls Kubernetes clusters, registries or the egress proxy).
    check_requested_at  timestamptz,
    check_requested_by  uuid,
    created_by          uuid,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    CHECK ((source_table IS NULL) = (source_key IS NULL)),
    CHECK (source_table IS NOT NULL OR length(name) BETWEEN 1 AND 200),
    FOREIGN KEY (organization_id, secret_id) REFERENCES secrets (organization_id, id)
);
CREATE UNIQUE INDEX connectors_source_uq ON connectors (organization_id, source_table, source_key) WHERE source_table IS NOT NULL;
CREATE UNIQUE INDEX connectors_name_uq ON connectors (organization_id, lower(name)) WHERE source_table IS NULL;
CREATE INDEX connectors_due_idx ON connectors (last_check_at NULLS FIRST);
CREATE INDEX connectors_requested_idx ON connectors (check_requested_at) WHERE check_requested_at IS NOT NULL;

-- Health check history. Kept 30 days, and at least the last 200 checks of
-- each connector (pruned by the jobs service). Messages are redacted before
-- they are stored; observed holds non-secret facts only (API version,
-- remaining rate limit, granted scopes).
CREATE TABLE connector_health_checks (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    connector_id    uuid NOT NULL,
    status          text NOT NULL CHECK (status IN ('unknown', 'healthy', 'degraded', 'failing', 'disabled')),
    trigger         text NOT NULL CHECK (trigger IN ('schedule', 'user', 'verify')),
    triggered_by    uuid,
    checked_at      timestamptz NOT NULL DEFAULT now(),
    duration_ms     integer NOT NULL DEFAULT 0 CHECK (duration_ms >= 0),
    error_code      text NOT NULL DEFAULT '' CHECK (error_code = '' OR error_code ~ '^PTH-[A-Z]{2,5}-[0-9]{4}$'),
    message         text NOT NULL DEFAULT '' CHECK (length(message) <= 2000),
    -- [{check, status: pass|warn|fail|skipped, error_code, detail}]
    steps           jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(steps) = 'array' AND pg_column_size(steps) <= 16384),
    observed        jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(observed) = 'object' AND pg_column_size(observed) <= 16384),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, connector_id) REFERENCES connectors (organization_id, id) ON DELETE CASCADE
);
CREATE INDEX connector_health_checks_recent_idx ON connector_health_checks (connector_id, checked_at DESC);

-- GitLab webhook signing token (Standard Webhooks HMAC, GitLab 19.0+). The
-- token is generated by GitLab and pasted into PATHOS; when it is set,
-- deliveries must carry a valid webhook-signature and the legacy
-- X-Gitlab-Token alone is no longer accepted.
ALTER TABLE scm_connections ADD COLUMN webhook_signing_secret_id uuid;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_webhook_signing_fk
    FOREIGN KEY (organization_id, webhook_signing_secret_id) REFERENCES secrets (organization_id, id);

-- Microsoft Teams Workflows trigger authentication: a Microsoft Entra app
-- (client credentials) whose token PATHOS sends as a bearer token to
-- triggers restricted to "Any user in my tenant" or "Specific users in my
-- tenant". trigger_auth holds the non-secret part ({tenant_id, client_id,
-- audience}); the client secret is in secrets.
ALTER TABLE outbound_webhooks ADD COLUMN trigger_auth jsonb NOT NULL DEFAULT '{}'
    CHECK (jsonb_typeof(trigger_auth) = 'object' AND pg_column_size(trigger_auth) <= 4096);
ALTER TABLE outbound_webhooks ADD COLUMN trigger_auth_secret_id uuid;
ALTER TABLE outbound_webhooks ADD CONSTRAINT outbound_webhooks_trigger_auth_fk
    FOREIGN KEY (organization_id, trigger_auth_secret_id) REFERENCES secrets (organization_id, id);

SELECT pathos_apply_app_grants();

-- +goose Down
ALTER TABLE outbound_webhooks DROP CONSTRAINT IF EXISTS outbound_webhooks_trigger_auth_fk;
ALTER TABLE outbound_webhooks DROP COLUMN IF EXISTS trigger_auth_secret_id;
ALTER TABLE outbound_webhooks DROP COLUMN IF EXISTS trigger_auth;
ALTER TABLE scm_connections DROP CONSTRAINT IF EXISTS scm_connections_webhook_signing_fk;
ALTER TABLE scm_connections DROP COLUMN IF EXISTS webhook_signing_secret_id;
DROP TABLE IF EXISTS connector_health_checks;
DROP TABLE IF EXISTS connectors;
