-- +goose Up
-- PATHOS 3.0 M7: AI evidence records (ADR-008, docs/aspm/PATHOS_AI_SECURITY_INTELLIGENCE.md).
-- One row per AI decision or conclusion PATHOS stores: AI reviews, Human Eye
-- suggestions, analyst answers and report narratives, fix proposals,
-- troubleshooting answers, threat suggestions and correlation
-- explanations. A record holds what is needed to show and replay the
-- decision: the subject, related CodeGraph nodes and edges, the model,
-- provider and parameters, the template, hashes of exactly what was sent
-- and received, the reasoning steps, the conclusion, the confidence and the
-- reviewer's decision. The redacted prompt and response are kept
-- envelope-encrypted in ai_evidence_payloads until the organization's
-- retention (default 180 days, assessment §8.6) and then purged; the record
-- itself is deleted with its finding. Every table carries organization_id,
-- so pathos_apply_app_grants() gives each the standard tenant policy
-- (docs/MULTI_TENANCY.md).

CREATE TABLE ai_evidence_records (
    id                  uuid PRIMARY KEY,
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- The model-per-task assignment the call used.
    task                text NOT NULL CHECK (task IN ('finding_validation', 'fix_proposal', 'troubleshooting', 'threat_suggestion',
                           'correlation', 'analyst', 'report', 'graph_inference')),
    -- What produced it, finer than the task (ai_review, interactive_mcp,
    -- assist:<kind>, analyst_answer, report_narrative, fix_proposal,
    -- troubleshoot, threat_suggestion, threat_suggestion_item,
    -- correlation_explain, replay).
    operation           text NOT NULL CHECK (length(operation) BETWEEN 1 AND 64),
    subject_kind        text NOT NULL CHECK (subject_kind IN ('finding', 'threat', 'threat_model', 'codegraph_edge', 'error',
                           'conversation', 'report', 'human_review')),
    subject_id          uuid,
    -- Set when the subject is (or belongs to) a finding: the record is
    -- deleted with the finding.
    finding_id          uuid,
    -- References only (ids and keys), never content: findings, CodeGraph
    -- nodes and edges ({snapshot_id, key}), threats, components.
    related             jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(related) = 'object' AND pg_column_size(related) <= 65536),
    -- A threat-suggestion item points at the record of the call that
    -- produced it (whose payload it shares).
    parent_id           uuid,
    config_version_id   uuid,
    -- anthropic, openai, xai, self_hosted; mcp for a review a person
    -- produced with their own assistant through the MCP server.
    provider            text NOT NULL CHECK (length(provider) BETWEEN 1 AND 32),
    -- local (self-hosted), cloud, or user (outside PATHOS).
    provider_location   text NOT NULL CHECK (provider_location IN ('local', 'cloud', 'user')),
    model               text NOT NULL CHECK (length(model) <= 200),
    -- The model version the provider reported for this call.
    model_reported      text NOT NULL DEFAULT '' CHECK (length(model_reported) <= 200),
    model_digest        text NOT NULL DEFAULT '' CHECK (length(model_digest) <= 200),
    prompt_template     text NOT NULL CHECK (length(prompt_template) BETWEEN 1 AND 100),
    parameters          jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(parameters) = 'object' AND pg_column_size(parameters) <= 8192),
    -- Whether the provider can repeat the answer for the same prompt
    -- (temperature 0 and a seed); hosted models cannot promise it.
    deterministic       boolean NOT NULL DEFAULT false,
    -- Whether source code was part of what was sent.
    sent_code           boolean NOT NULL DEFAULT false,
    input_sha256        text NOT NULL DEFAULT '' CHECK (input_sha256 = '' OR input_sha256 ~ '^[0-9a-f]{64}$'),
    response_sha256     text NOT NULL DEFAULT '' CHECK (response_sha256 = '' OR response_sha256 ~ '^[0-9a-f]{64}$'),
    -- Reasoning steps as returned and validated (strings).
    steps               jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(steps) = 'array' AND pg_column_size(steps) <= 65536),
    conclusion          text NOT NULL DEFAULT '' CHECK (length(conclusion) <= 8000),
    -- Machine-readable conclusion where the task has one (true_positive,
    -- false_positive, needs_review, not_exploitable, exploitable,
    -- suggested, answered, proposed).
    verdict             text NOT NULL DEFAULT '' CHECK (length(verdict) <= 32),
    confidence          numeric(4,3) CHECK (confidence BETWEEN 0 AND 1),
    status              text NOT NULL CHECK (status IN ('succeeded', 'invalid_output', 'failed', 'disabled')),
    error_code          text NOT NULL DEFAULT '' CHECK (error_code = '' OR error_code ~ '^PTH-[A-Z]+-[0-9]{4}$'),
    error               text NOT NULL DEFAULT '' CHECK (length(error) <= 1000),
    input_tokens        bigint NOT NULL DEFAULT 0,
    output_tokens       bigint NOT NULL DEFAULT 0,
    -- pending until a person accepts or rejects the conclusion;
    -- not_required for records that propose nothing (a replay, a failed
    -- call, the parent of threat-suggestion items).
    review_decision     text NOT NULL DEFAULT 'pending' CHECK (review_decision IN ('pending', 'accepted', 'rejected', 'not_required')),
    reviewer_id         uuid,
    reviewed_at         timestamptz,
    review_note         text NOT NULL DEFAULT '' CHECK (length(review_note) <= 2000),
    replay_of           uuid,
    -- Set on a replay: {same_conclusion, identical_response, ...}.
    comparison          jsonb CHECK (comparison IS NULL OR (jsonb_typeof(comparison) = 'object' AND pg_column_size(comparison) <= 32768)),
    -- The redacted prompt and response are kept until this time.
    payload_expires_at  timestamptz,
    payload_purged_at   timestamptz,
    requested_by        uuid,
    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    CHECK (review_decision IN ('pending', 'not_required') OR reviewed_at IS NOT NULL),
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, parent_id) REFERENCES ai_evidence_records(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, replay_of) REFERENCES ai_evidence_records(organization_id, id) ON DELETE SET NULL (replay_of),
    FOREIGN KEY (organization_id, config_version_id) REFERENCES ai_configuration_versions(organization_id, id),
    FOREIGN KEY (organization_id, reviewer_id) REFERENCES users(organization_id, id) ON DELETE SET NULL (reviewer_id),
    FOREIGN KEY (organization_id, requested_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (requested_by)
);
CREATE INDEX ai_evidence_subject_idx ON ai_evidence_records (organization_id, subject_kind, subject_id, created_at DESC);
CREATE INDEX ai_evidence_created_idx ON ai_evidence_records (organization_id, created_at DESC, id DESC);
CREATE INDEX ai_evidence_finding_idx ON ai_evidence_records (finding_id) WHERE finding_id IS NOT NULL;
CREATE INDEX ai_evidence_parent_idx ON ai_evidence_records (parent_id) WHERE parent_id IS NOT NULL;
CREATE INDEX ai_evidence_payload_exp_idx ON ai_evidence_records (payload_expires_at) WHERE payload_purged_at IS NULL;

-- A record is immutable: only the review and the payload purge are
-- recorded on it (ADR-008).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_ai_evidence_immutable() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Only the review and the purge change; ON DELETE SET NULL of the
    -- requester or the replayed record (deleted user or record) is allowed.
    IF (to_jsonb(NEW) - ARRAY['review_decision', 'reviewer_id', 'reviewed_at', 'review_note', 'payload_purged_at', 'requested_by', 'replay_of'])
       IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['review_decision', 'reviewer_id', 'reviewed_at', 'review_note', 'payload_purged_at', 'requested_by', 'replay_of'])
       OR (NEW.requested_by IS NOT NULL AND NEW.requested_by IS DISTINCT FROM OLD.requested_by)
       OR (NEW.replay_of IS NOT NULL AND NEW.replay_of IS DISTINCT FROM OLD.replay_of) THEN
        RAISE EXCEPTION 'ai_evidence_records are immutable except the review' USING ERRCODE = '42501';
    END IF;
    IF OLD.review_decision IN ('accepted', 'rejected') AND NEW.review_decision IS DISTINCT FROM OLD.review_decision THEN
        RAISE EXCEPTION 'the review of an AI evidence record cannot be changed once decided' USING ERRCODE = '42501';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER ai_evidence_immutable BEFORE UPDATE ON ai_evidence_records
    FOR EACH ROW EXECUTE FUNCTION pathos_ai_evidence_immutable();

-- The redacted prompt (system and user parts), the response and the
-- output schema, as one envelope-encrypted JSON document (the master key
-- of the secrets store; AAD binds it to the record). Deleted when the
-- retention ends.
CREATE TABLE ai_evidence_payloads (
    record_id       uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    ciphertext      bytea NOT NULL,
    wrapped_dek     bytea NOT NULL,
    key_version     integer NOT NULL,
    size_bytes      integer NOT NULL DEFAULT 0 CHECK (size_bytes >= 0),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, record_id) REFERENCES ai_evidence_records(organization_id, id) ON DELETE CASCADE
);

-- Retention per organization (without a row: 180 days, prompts stored).
CREATE TABLE ai_evidence_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    retention_days  integer NOT NULL DEFAULT 180 CHECK (retention_days BETWEEN 1 AND 3650),
    -- Off: only hashes are kept (the record cannot be replayed).
    store_payloads  boolean NOT NULL DEFAULT true,
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS ai_evidence_settings;
DROP TABLE IF EXISTS ai_evidence_payloads;
DROP TRIGGER IF EXISTS ai_evidence_immutable ON ai_evidence_records;
DROP TABLE IF EXISTS ai_evidence_records;
DROP FUNCTION IF EXISTS pathos_ai_evidence_immutable();
