-- +goose Up
-- ASPM phase 9: outbound webhooks (generic signed JSON, Slack, Microsoft
-- Teams) and ticketing connectors (Jira, ServiceNow). All optional: nothing
-- is sent anywhere until an administrator configures it.

ALTER TABLE secrets DROP CONSTRAINT secrets_kind_check;
ALTER TABLE secrets ADD CONSTRAINT secrets_kind_check CHECK (kind IN ('scm', 'ai', 'mcp', 'smtp', 'webhook', 'worker', 'scan_target', 'integration'));

CREATE TABLE outbound_webhooks (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    format          text NOT NULL CHECK (format IN ('json', 'slack', 'teams')),
    -- The URL is kept encrypted (Slack and Teams URLs are credentials);
    -- url_host is shown in the UI.
    url_secret_id   uuid NOT NULL REFERENCES secrets(id),
    url_host        text NOT NULL,
    signing_secret_id uuid REFERENCES secrets(id),
    events          text[] NOT NULL CHECK (cardinality(events) BETWEEN 1 AND 50),
    min_severity    text CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    allow_private   boolean NOT NULL DEFAULT false,
    enabled         boolean NOT NULL DEFAULT true,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TABLE outbound_webhook_deliveries (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    endpoint_id     uuid NOT NULL REFERENCES outbound_webhooks(id) ON DELETE CASCADE,
    event_id        uuid REFERENCES notification_events(id) ON DELETE SET NULL,
    event_key       text NOT NULL,
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'succeeded', 'failed')),
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    response_status integer,
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 1000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    UNIQUE (endpoint_id, event_id)
);
CREATE INDEX outbound_webhook_deliveries_due_idx ON outbound_webhook_deliveries (next_attempt_at) WHERE status = 'pending';
CREATE INDEX outbound_webhook_deliveries_endpoint_idx ON outbound_webhook_deliveries (endpoint_id, created_at DESC);

CREATE TABLE ticket_connections (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('jira', 'servicenow')),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    base_url        text NOT NULL CHECK (length(base_url) <= 500),
    -- jira: basic (e-mail + API token, Jira Cloud) or bearer (personal
    -- access token, Data Center); servicenow: basic or bearer (OAuth token).
    auth_type       text NOT NULL CHECK (auth_type IN ('basic', 'bearer')),
    username        text NOT NULL DEFAULT '' CHECK (length(username) <= 200),
    secret_id       uuid NOT NULL REFERENCES secrets(id),
    -- jira: {project_key, issue_type, labels[]}; servicenow: {table,
    -- assignment_group, caller_id}.
    config          jsonb NOT NULL DEFAULT '{}',
    allow_private   boolean NOT NULL DEFAULT false,
    enabled         boolean NOT NULL DEFAULT true,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name)
);

CREATE TABLE finding_tickets (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    finding_id      uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    connection_id   uuid NOT NULL REFERENCES ticket_connections(id) ON DELETE CASCADE,
    external_key    text NOT NULL CHECK (length(external_key) <= 100),
    external_id     text NOT NULL DEFAULT '' CHECK (length(external_id) <= 100),
    url             text NOT NULL CHECK (length(url) <= 1000),
    remote_status   text NOT NULL DEFAULT '' CHECK (length(remote_status) <= 100),
    remote_done     boolean NOT NULL DEFAULT false,
    sync_error      text NOT NULL DEFAULT '' CHECK (length(sync_error) <= 500),
    synced_at       timestamptz,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (finding_id, connection_id)
);
CREATE INDEX finding_tickets_sync_idx ON finding_tickets (synced_at NULLS FIRST) WHERE NOT remote_done;

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS finding_tickets;
DROP TABLE IF EXISTS ticket_connections;
DROP TABLE IF EXISTS outbound_webhook_deliveries;
DROP TABLE IF EXISTS outbound_webhooks;
DELETE FROM secrets WHERE kind = 'integration';
ALTER TABLE secrets DROP CONSTRAINT secrets_kind_check;
ALTER TABLE secrets ADD CONSTRAINT secrets_kind_check CHECK (kind IN ('scm', 'ai', 'mcp', 'smtp', 'webhook', 'worker', 'scan_target'));
