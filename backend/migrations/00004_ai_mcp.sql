-- +goose Up
-- Phase 5: AI review providers and configurations, reviews and approval
-- queue, personal API tokens, MCP server registry.

-- Redacted code context captured by workers (SAST / IaC), used as AI evidence.
ALTER TABLE findings ADD COLUMN snippet text NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN snippet_start_line int;
ALTER TABLE findings ADD COLUMN ai_status text NOT NULL DEFAULT 'none'
    CHECK (ai_status IN ('none', 'queued', 'pending_approval', 'reviewed', 'failed', 'skipped'));

CREATE TABLE ai_providers (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    kind            text NOT NULL CHECK (kind IN ('anthropic', 'openai', 'xai')),
    base_url        text NOT NULL DEFAULT '',
    secret_id       uuid NOT NULL REFERENCES secrets(id),
    status          text NOT NULL DEFAULT 'untested' CHECK (status IN ('untested', 'ok', 'error')),
    status_message  text NOT NULL DEFAULT '',
    created_by      uuid,
    archived_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);

CREATE TABLE ai_configurations (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    is_default         boolean NOT NULL DEFAULT false,
    current_version_id uuid,
    archived_at        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX ai_configurations_default_uq ON ai_configurations (organization_id) WHERE is_default AND archived_at IS NULL;

-- Immutable; every review records the version it ran with.
CREATE TABLE ai_configuration_versions (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL,
    configuration_id  uuid NOT NULL,
    version           int NOT NULL,
    provider_id       uuid NOT NULL,
    model             text NOT NULL,
    effort            text NOT NULL DEFAULT 'medium' CHECK (effort IN ('low', 'medium', 'high')),
    instructions      text NOT NULL DEFAULT '' CHECK (length(instructions) <= 8000),
    auto_review       boolean NOT NULL DEFAULT false,
    categories        text[] NOT NULL DEFAULT '{sast,sca,iac}',
    min_severity      text NOT NULL DEFAULT 'medium' CHECK (min_severity IN ('info', 'low', 'medium', 'high', 'critical')),
    approval_policy   text NOT NULL DEFAULT 'always' CHECK (approval_policy IN ('always', 'false_positives', 'never')),
    daily_limit       int NOT NULL DEFAULT 200 CHECK (daily_limit BETWEEN 1 AND 100000),
    send_code_context boolean NOT NULL DEFAULT true,
    redaction_patterns text[] NOT NULL DEFAULT '{}',
    change_note       text NOT NULL DEFAULT '',
    created_by        uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (configuration_id, version),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, configuration_id) REFERENCES ai_configurations(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, provider_id) REFERENCES ai_providers(organization_id, id)
);
ALTER TABLE ai_configurations ADD CONSTRAINT ai_configurations_version_fk
    FOREIGN KEY (organization_id, current_version_id) REFERENCES ai_configuration_versions(organization_id, id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE ai_reviews (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL,
    finding_id         uuid NOT NULL,
    config_version_id  uuid,
    source             text NOT NULL CHECK (source IN ('automated', 'interactive_mcp')),
    provider           text NOT NULL DEFAULT '',
    model              text NOT NULL DEFAULT '',
    verdict            text NOT NULL CHECK (verdict IN ('true_positive', 'false_positive', 'needs_review')),
    confidence         numeric(4,3) NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    suggested_severity text NOT NULL DEFAULT '' CHECK (suggested_severity IN ('', 'critical', 'high', 'medium', 'low', 'info')),
    rationale          text NOT NULL,
    remediation        text NOT NULL DEFAULT '',
    output             jsonb NOT NULL DEFAULT '{}'::jsonb,
    transmitted_sha256 text NOT NULL DEFAULT '',
    input_tokens       bigint NOT NULL DEFAULT 0,
    output_tokens      bigint NOT NULL DEFAULT 0,
    status             text NOT NULL CHECK (status IN ('pending_approval', 'applied', 'rejected', 'superseded')),
    reviewed_by        uuid,          -- human author for interactive MCP reviews
    decided_by         uuid,          -- approver / rejecter
    decided_at         timestamptz,
    decision_note      text NOT NULL DEFAULT '',
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX ai_reviews_finding_idx ON ai_reviews (finding_id, created_at DESC);
CREATE INDEX ai_reviews_pending_idx ON ai_reviews (organization_id, created_at) WHERE status = 'pending_approval';

CREATE TABLE ai_review_queue (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL,
    finding_id        uuid NOT NULL,
    config_version_id uuid NOT NULL,
    requested_by      uuid,
    status            text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed', 'skipped')),
    attempts          int NOT NULL DEFAULT 0,
    error             text NOT NULL DEFAULT '',
    lease_expires_at  timestamptz,
    not_before        timestamptz NOT NULL DEFAULT now(),
    enqueued_at       timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz,
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX ai_review_queue_active_uq ON ai_review_queue (finding_id) WHERE status IN ('queued', 'running');
CREATE INDEX ai_review_queue_ready_idx ON ai_review_queue (not_before) WHERE status = 'queued';

-- Personal API tokens (used by the PATHOS MCP server).
CREATE TABLE api_tokens (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    user_id         uuid NOT NULL,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    prefix          text NOT NULL,
    token_sha256    text NOT NULL UNIQUE,
    scopes          text[] NOT NULL,
    expires_at      timestamptz NOT NULL,
    last_used_at    timestamptz,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, user_id) REFERENCES users(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX api_tokens_user_idx ON api_tokens (user_id);

-- Registry of MCP servers approved for use with PATHOS data.
CREATE TABLE mcp_servers (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description     text NOT NULL DEFAULT '',
    transport       text NOT NULL CHECK (transport IN ('stdio', 'streamable_http')),
    endpoint        text NOT NULL,             -- URL or command
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'disabled')),
    data_access     text NOT NULL DEFAULT 'none' CHECK (data_access IN ('none', 'findings_redacted', 'findings_full')),
    requested_by    uuid,
    decided_by      uuid,
    decided_at      timestamptz,
    decision_note   text NOT NULL DEFAULT '',
    built_in        boolean NOT NULL DEFAULT false,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX mcp_servers_name_uq ON mcp_servers (organization_id, lower(name));

CREATE TABLE mcp_tool_permissions (
    organization_id uuid NOT NULL,
    server_id       uuid NOT NULL,
    tool            text NOT NULL CHECK (length(tool) BETWEEN 1 AND 200),
    access          text NOT NULL CHECK (access IN ('read', 'write')),
    allowed         boolean NOT NULL DEFAULT false,
    PRIMARY KEY (server_id, tool),
    FOREIGN KEY (organization_id, server_id) REFERENCES mcp_servers(organization_id, id) ON DELETE CASCADE
);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS mcp_tool_permissions;
DROP TABLE IF EXISTS mcp_servers;
DROP TABLE IF EXISTS api_tokens;
DROP TABLE IF EXISTS ai_review_queue;
DROP TABLE IF EXISTS ai_reviews;
ALTER TABLE ai_configurations DROP CONSTRAINT IF EXISTS ai_configurations_version_fk;
DROP TABLE IF EXISTS ai_configuration_versions;
DROP TABLE IF EXISTS ai_configurations;
DROP TABLE IF EXISTS ai_providers;
ALTER TABLE findings DROP COLUMN IF EXISTS ai_status;
ALTER TABLE findings DROP COLUMN IF EXISTS snippet_start_line;
ALTER TABLE findings DROP COLUMN IF EXISTS snippet;
