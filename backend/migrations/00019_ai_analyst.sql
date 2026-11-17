-- +goose Up
-- ASPM phase 6: AI Security Analyst workspace and AI reports.

-- Conversations of a user with the AI Security Analyst. Answers are
-- grounded in PATHOS data the user may read; each message records what was
-- sent (SHA-256), the model and the tokens.
CREATE TABLE ai_conversations (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL,
    title           text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, user_id) REFERENCES users(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX ai_conversations_user_idx ON ai_conversations (user_id, updated_at DESC);

CREATE TABLE ai_messages (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    conversation_id  uuid NOT NULL REFERENCES ai_conversations(id) ON DELETE CASCADE,
    role             text NOT NULL CHECK (role IN ('user', 'assistant')),
    content          text NOT NULL CHECK (length(content) <= 20000),
    -- Findings the answer cites (only ones that were in its context).
    citations        uuid[] NOT NULL DEFAULT '{}',
    follow_ups       text[] NOT NULL DEFAULT '{}',
    context_sha256   text NOT NULL DEFAULT '',
    context_findings integer NOT NULL DEFAULT 0,
    provider         text NOT NULL DEFAULT '',
    model            text NOT NULL DEFAULT '',
    input_tokens     bigint NOT NULL DEFAULT 0,
    output_tokens    bigint NOT NULL DEFAULT 0,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ai_messages_conversation_idx ON ai_messages (conversation_id, created_at);
CREATE INDEX ai_messages_org_idx ON ai_messages (organization_id, created_at) WHERE role = 'assistant';

-- Technical and executive reports: facts computed by PATHOS, narrative
-- written by AI from those facts only (or none when AI is not configured).
CREATE TABLE ai_reports (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('technical', 'executive')),
    scope_type      text NOT NULL CHECK (scope_type IN ('organization', 'application', 'repository')),
    scope_id        uuid,
    title           text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    facts           jsonb NOT NULL,
    narrative       jsonb,
    provider        text NOT NULL DEFAULT '',
    model           text NOT NULL DEFAULT '',
    input_tokens    bigint NOT NULL DEFAULT 0,
    output_tokens   bigint NOT NULL DEFAULT 0,
    narrative_error text NOT NULL DEFAULT '' CHECK (length(narrative_error) <= 500),
    created_by      uuid NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (scope_type = 'organization' OR scope_id IS NOT NULL)
);
CREATE INDEX ai_reports_org_idx ON ai_reports (organization_id, created_at DESC);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS ai_reports;
DROP TABLE IF EXISTS ai_messages;
DROP TABLE IF EXISTS ai_conversations;
