-- +goose Up
-- ASPM phase 5: Human Eye extras.

-- Multi-level approval: decisions matching these severities or
-- dispositions (and needing independent review) also need a final approval
-- by a third person. Empty lists keep the two-level flow.
ALTER TABLE human_review_settings ADD COLUMN final_approval_severities text[] NOT NULL DEFAULT '{}',
                                  ADD COLUMN final_approval_dispositions text[] NOT NULL DEFAULT '{}';
ALTER TABLE human_review_approvals ADD COLUMN level smallint NOT NULL DEFAULT 1 CHECK (level IN (1, 2));
CREATE UNIQUE INDEX human_review_approvals_level_uq ON human_review_approvals (decision_id, level);
CREATE UNIQUE INDEX human_review_approvals_person_uq ON human_review_approvals (decision_id, reviewer_id);

-- AI suggestions: patch proposals (with a human decision), risk score
-- explanations and duplicate candidates.
ALTER TABLE human_review_recommendations DROP CONSTRAINT human_review_recommendations_kind_check;
ALTER TABLE human_review_recommendations ADD CONSTRAINT human_review_recommendations_kind_check CHECK (kind IN ('explanation', 'code_summary',
    'code_paths', 'investigation_questions', 'false_positive_indicators', 'evidence_suggestions', 'remediation', 'secure_code', 'references',
    'assessment_summary', 'patch', 'risk_explanation', 'duplicate_candidates'));
ALTER TABLE human_review_recommendations ADD COLUMN patch_status text CHECK (patch_status IN ('proposed', 'approved', 'rejected')),
                                         ADD COLUMN patch_decided_by uuid,
                                         ADD COLUMN patch_decided_at timestamptz,
                                         ADD COLUMN patch_note text NOT NULL DEFAULT '' CHECK (length(patch_note) <= 2000);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_apply_app_grants() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    t text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pathos_app') THEN
        RETURN;
    END IF;
    GRANT USAGE ON SCHEMA public TO pathos_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pathos_app;
    FOR t IN
        SELECT c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
        WHERE c.relname = 'audit_logs'
           OR c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'public.audit_logs'::regclass)
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM pathos_app', t);
    END LOOP;
    REVOKE UPDATE, DELETE, TRUNCATE ON finding_status_history FROM pathos_app;
    REVOKE DELETE, TRUNCATE ON notifications FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON permissions FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON scanner_catalog FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON goose_db_version FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_history FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_decisions FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_approvals FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_comments FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_recommendations FROM pathos_app;
    -- AI suggestions stay immutable; only a patch proposal's human decision
    -- is recorded on it.
    GRANT UPDATE (patch_status, patch_decided_by, patch_decided_at, patch_note) ON human_review_recommendations TO pathos_app;
    REVOKE DELETE, TRUNCATE ON human_review_evidence FROM pathos_app;
    GRANT EXECUTE ON FUNCTION pathos_ensure_audit_partitions(int) TO pathos_app;
END;
$$;
-- +goose StatementEnd
SELECT pathos_apply_app_grants();

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_apply_app_grants() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    t text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pathos_app') THEN
        RETURN;
    END IF;
    GRANT USAGE ON SCHEMA public TO pathos_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pathos_app;
    FOR t IN
        SELECT c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
        WHERE c.relname = 'audit_logs'
           OR c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'public.audit_logs'::regclass)
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM pathos_app', t);
    END LOOP;
    REVOKE UPDATE, DELETE, TRUNCATE ON finding_status_history FROM pathos_app;
    REVOKE DELETE, TRUNCATE ON notifications FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON permissions FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON scanner_catalog FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON goose_db_version FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_history FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_decisions FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_approvals FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_comments FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_recommendations FROM pathos_app;
    REVOKE DELETE, TRUNCATE ON human_review_evidence FROM pathos_app;
    GRANT EXECUTE ON FUNCTION pathos_ensure_audit_partitions(int) TO pathos_app;
END;
$$;
-- +goose StatementEnd
ALTER TABLE human_review_recommendations DROP COLUMN IF EXISTS patch_note, DROP COLUMN IF EXISTS patch_decided_at,
    DROP COLUMN IF EXISTS patch_decided_by, DROP COLUMN IF EXISTS patch_status;
DELETE FROM human_review_recommendations WHERE kind IN ('patch', 'risk_explanation', 'duplicate_candidates');
ALTER TABLE human_review_recommendations DROP CONSTRAINT human_review_recommendations_kind_check;
ALTER TABLE human_review_recommendations ADD CONSTRAINT human_review_recommendations_kind_check CHECK (kind IN ('explanation', 'code_summary',
    'code_paths', 'investigation_questions', 'false_positive_indicators', 'evidence_suggestions', 'remediation', 'secure_code', 'references',
    'assessment_summary'));
DROP INDEX IF EXISTS human_review_approvals_person_uq;
DROP INDEX IF EXISTS human_review_approvals_level_uq;
ALTER TABLE human_review_approvals DROP COLUMN IF EXISTS level;
ALTER TABLE human_review_settings DROP COLUMN IF EXISTS final_approval_dispositions, DROP COLUMN IF EXISTS final_approval_severities;
SELECT pathos_apply_app_grants();
