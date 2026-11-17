-- +goose Up
-- Human Review (docs/HUMAN_REVIEW.md): manual security assessment of
-- findings. A review references an existing finding (never a copy of it);
-- the scanner's data stays on the finding and the human decisions live in
-- the tables below. Review status, final disposition and remediation status
-- are three separate fields.

CREATE SEQUENCE human_review_key_seq AS bigint START 1;
CREATE SEQUENCE human_review_evidence_key_seq AS bigint START 1;

-- One row per organization; every workflow rule is configurable.
CREATE TABLE human_review_settings (
    organization_id              uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    -- Automatic queue creation.
    auto_queue                   boolean NOT NULL DEFAULT true,
    -- Which signals put a finding in the queue: needs_review (status set by
    -- automated triage or a person), ai_needs_review (AI verdict),
    -- ai_false_positive (AI says false positive: a human confirms) and
    -- new_findings (every new finding matching the filters below).
    auto_triggers                text[] NOT NULL DEFAULT '{needs_review,ai_needs_review,ai_false_positive}'
        CHECK (auto_triggers <@ ARRAY['needs_review', 'ai_needs_review', 'ai_false_positive', 'new_findings']::text[]),
    -- Empty = every scanner may send findings.
    auto_scanners                text[] NOT NULL DEFAULT '{}',
    auto_categories              text[] NOT NULL DEFAULT '{sast,sca,secrets,iac,container}'
        CHECK (auto_categories <@ ARRAY['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'other']::text[]),
    auto_min_severity            text NOT NULL DEFAULT 'medium' CHECK (auto_min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    -- Severity-based rules: review priority and review SLA (days) per
    -- severity, e.g. {"critical": "p1"} and {"critical": 2}.
    priority_by_severity         jsonb NOT NULL DEFAULT '{"critical": "p1", "high": "p2", "medium": "p3", "low": "p4", "info": "p4"}'::jsonb,
    sla_days                     jsonb NOT NULL DEFAULT '{"critical": 2, "high": 5, "medium": 10, "low": 20, "info": 30}'::jsonb,
    -- Assignment rules.
    assignment_strategy          text NOT NULL DEFAULT 'manual' CHECK (assignment_strategy IN ('manual', 'round_robin', 'least_loaded')),
    assignment_pool              uuid[] NOT NULL DEFAULT '{}',
    allow_self_assign            boolean NOT NULL DEFAULT true,
    -- Independent (second-level) review.
    independent_review_severities text[] NOT NULL DEFAULT '{critical,high}'
        CHECK (independent_review_severities <@ ARRAY['critical', 'high', 'medium', 'low', 'info']::text[]),
    independent_review_dispositions text[] NOT NULL DEFAULT '{accepted_risk}'
        CHECK (independent_review_dispositions <@ ARRAY['confirmed', 'false_positive', 'duplicate', 'not_exploitable', 'accepted_risk', 'mitigated', 'out_of_scope']::text[]),
    -- Required evidence: at least one evidence item for these dispositions
    -- and severities.
    evidence_required_dispositions text[] NOT NULL DEFAULT '{}'
        CHECK (evidence_required_dispositions <@ ARRAY['confirmed', 'false_positive', 'duplicate', 'not_exploitable', 'accepted_risk', 'mitigated', 'out_of_scope']::text[]),
    evidence_required_severities text[] NOT NULL DEFAULT '{}'
        CHECK (evidence_required_severities <@ ARRAY['critical', 'high', 'medium', 'low', 'info']::text[]),
    -- Assessment fields that must be filled before a decision (question
    -- keys and text fields, see internal/review/catalog.go).
    required_fields              text[] NOT NULL DEFAULT '{reachable,attacker_controlled,exploitable}',
    -- Notifications.
    notify_assignment            boolean NOT NULL DEFAULT true,
    notify_independent_review    boolean NOT NULL DEFAULT true,
    notify_overdue               boolean NOT NULL DEFAULT true,
    -- AI assistance.
    ai_assist                    boolean NOT NULL DEFAULT true,
    ai_send_code                 boolean NOT NULL DEFAULT true,
    -- Evidence uploads.
    evidence_max_mb              int NOT NULL DEFAULT 20 CHECK (evidence_max_mb BETWEEN 1 AND 100),
    -- Review permissions: whether reviewers who are not assigned may work
    -- on a review (otherwise only the assignee or a review manager).
    unassigned_can_assess        boolean NOT NULL DEFAULT false,
    updated_by                   uuid,
    updated_at                   timestamptz NOT NULL DEFAULT now(),
    CHECK (jsonb_typeof(priority_by_severity) = 'object' AND jsonb_typeof(sla_days) = 'object')
);

CREATE TABLE human_reviews (
    id                      uuid PRIMARY KEY,
    organization_id         uuid NOT NULL,
    review_key              text NOT NULL,
    finding_id              uuid NOT NULL,
    repository_id           uuid NOT NULL,
    -- Exactly what was scanned when the review was created: the source
    -- viewer reads this commit/snapshot, never the branch head.
    scan_job_id             uuid,
    commit_sha              text NOT NULL DEFAULT '',
    branch                  text NOT NULL DEFAULT '',
    snapshot_id             uuid,
    scanner_key             text NOT NULL DEFAULT '',
    file_path               text NOT NULL DEFAULT '',
    start_line              int,
    -- The scanner's assessment at creation, preserved independently of the
    -- finding (whose severity a later scan may raise).
    original_severity       text NOT NULL CHECK (original_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    original_cvss           numeric(3,1),
    original_cvss_vector    text NOT NULL DEFAULT '',
    -- The scanner's own record (redacted SARIF result / Grype match) and
    -- code flows, captured from the raw report before retention prunes it.
    original_output         jsonb,
    original_rule           jsonb,
    original_flows          jsonb,
    original_related        jsonb,
    original_captured_at    timestamptz,
    original_capture_error  text NOT NULL DEFAULT '',
    -- Workflow.
    status                  text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'assigned', 'in_progress', 'awaiting_information',
                                'awaiting_independent_review', 'completed', 'reopened')),
    disposition             text CHECK (disposition IN ('confirmed', 'false_positive', 'duplicate', 'not_exploitable', 'accepted_risk',
                                'mitigated', 'needs_more_information', 'out_of_scope')),
    remediation_status      text CHECK (remediation_status IN ('not_required', 'open', 'in_progress', 'fixed', 'pending_verification',
                                'verified', 'reopened')),
    priority                text NOT NULL DEFAULT 'p3' CHECK (priority IN ('p1', 'p2', 'p3', 'p4')),
    reviewer_id             uuid,
    independent_reviewer_id uuid,
    due_at                  timestamptz,
    round                   int NOT NULL DEFAULT 1 CHECK (round > 0),
    source                  text NOT NULL CHECK (source IN ('automatic', 'manual')),
    source_reason           text NOT NULL DEFAULT '' CHECK (length(source_reason) <= 2000),
    created_by              uuid,
    -- Human-assessed severity, kept apart from the scanner's.
    assessed_severity       text CHECK (assessed_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    assessed_cvss           numeric(3,1) CHECK (assessed_cvss IS NULL OR assessed_cvss BETWEEN 0 AND 10),
    assessed_cvss_vector    text NOT NULL DEFAULT '' CHECK (length(assessed_cvss_vector) <= 300),
    severity_justification  text NOT NULL DEFAULT '' CHECK (length(severity_justification) <= 4000),
    -- Remediation tracking for confirmed findings.
    remediation_owner_id    uuid,
    remediation_due_at      timestamptz,
    remediation_priority    text CHECK (remediation_priority IN ('p1', 'p2', 'p3', 'p4')),
    remediation_link        text NOT NULL DEFAULT '' CHECK (length(remediation_link) <= 1000),
    risk_acceptance_id      uuid,
    started_at              timestamptz,
    submitted_at            timestamptz,
    completed_at            timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    -- One review per finding: importing a finding again never duplicates
    -- it; re-reviews are new rounds of the same review.
    UNIQUE (finding_id),
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, scan_job_id) REFERENCES scan_jobs(organization_id, id) ON DELETE SET NULL (scan_job_id),
    FOREIGN KEY (organization_id, reviewer_id) REFERENCES users(organization_id, id),
    FOREIGN KEY (organization_id, independent_reviewer_id) REFERENCES users(organization_id, id),
    FOREIGN KEY (organization_id, remediation_owner_id) REFERENCES users(organization_id, id),
    FOREIGN KEY (organization_id, created_by) REFERENCES users(organization_id, id),
    FOREIGN KEY (risk_acceptance_id) REFERENCES risk_acceptances(id) ON DELETE SET NULL,
    CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
    CHECK (status <> 'completed' OR disposition IS NOT NULL)
);
CREATE UNIQUE INDEX human_reviews_key_uq ON human_reviews (review_key);
CREATE INDEX human_reviews_org_status_idx ON human_reviews (organization_id, status, priority, due_at);
CREATE INDEX human_reviews_repo_idx ON human_reviews (repository_id, status);
CREATE INDEX human_reviews_reviewer_idx ON human_reviews (reviewer_id, status) WHERE reviewer_id IS NOT NULL;
CREATE INDEX human_reviews_independent_idx ON human_reviews (independent_reviewer_id) WHERE independent_reviewer_id IS NOT NULL;
CREATE INDEX human_reviews_severity_idx ON human_reviews (organization_id, original_severity);
CREATE INDEX human_reviews_disposition_idx ON human_reviews (organization_id, disposition) WHERE disposition IS NOT NULL;
CREATE INDEX human_reviews_due_idx ON human_reviews (organization_id, due_at) WHERE status <> 'completed';
CREATE INDEX human_reviews_created_idx ON human_reviews (organization_id, created_at DESC);
CREATE INDEX human_reviews_completed_idx ON human_reviews (organization_id, completed_at DESC) WHERE completed_at IS NOT NULL;
CREATE INDEX human_reviews_capture_idx ON human_reviews (created_at) WHERE original_captured_at IS NULL;

-- +goose StatementBegin
CREATE FUNCTION pathos_assign_review_key() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    n bigint;
BEGIN
    n := nextval('human_review_key_seq');
    NEW.review_key := 'QD-HR-' || lpad(n::text, greatest(6, length(n::text)), '0');
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER human_reviews_assign_key BEFORE INSERT ON human_reviews FOR EACH ROW EXECUTE FUNCTION pathos_assign_review_key();

-- +goose StatementBegin
CREATE FUNCTION pathos_protect_human_review() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.review_key IS DISTINCT FROM OLD.review_key OR NEW.finding_id IS DISTINCT FROM OLD.finding_id THEN
        RAISE EXCEPTION 'a review''s key and finding are permanent' USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.original_severity IS DISTINCT FROM OLD.original_severity OR NEW.original_cvss IS DISTINCT FROM OLD.original_cvss
       OR NEW.original_cvss_vector IS DISTINCT FROM OLD.original_cvss_vector
       OR (OLD.original_captured_at IS NOT NULL AND (NEW.original_output IS DISTINCT FROM OLD.original_output
           OR NEW.original_flows IS DISTINCT FROM OLD.original_flows OR NEW.original_captured_at IS DISTINCT FROM OLD.original_captured_at)) THEN
        RAISE EXCEPTION 'the original scanner assessment of a review is immutable' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER human_reviews_protect BEFORE UPDATE ON human_reviews FOR EACH ROW EXECUTE FUNCTION pathos_protect_human_review();

-- The analyst's structured assessment, one version per review round.
CREATE TABLE human_review_assessments (
    review_id        uuid NOT NULL REFERENCES human_reviews(id) ON DELETE CASCADE,
    round            int NOT NULL,
    organization_id  uuid NOT NULL,
    -- Exploitability questions: {"reproducible": "yes"|"no"|"unknown"|"not_applicable", ...}
    answers          jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(answers) = 'object'),
    -- Free-text fields: attack_scenario, attack_complexity, ...
    fields           jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(fields) = 'object'),
    -- Reproduction template: preconditions, environment, steps, ...
    reproduction     jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(reproduction) = 'object'),
    -- CVSS metric selections and contextual risk factors.
    risk             jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(risk) = 'object'),
    -- Remediation guidance written by the reviewer.
    remediation      jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(remediation) = 'object'),
    -- Reviewer annotations of data flow steps (validation, sanitization...).
    dataflow_notes   jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(dataflow_notes) = 'object'),
    updated_by       uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (review_id, round),
    CHECK (pg_column_size(answers) + pg_column_size(fields) + pg_column_size(reproduction) + pg_column_size(risk)
           + pg_column_size(remediation) + pg_column_size(dataflow_notes) <= 262144)
);

-- Decisions are append-only: each submission is a new row, so the first
-- reviewer's decision is never overwritten by the independent reviewer.
CREATE TABLE human_review_decisions (
    id                      uuid PRIMARY KEY,
    organization_id         uuid NOT NULL,
    review_id               uuid NOT NULL REFERENCES human_reviews(id) ON DELETE CASCADE,
    round                   int NOT NULL,
    disposition             text NOT NULL CHECK (disposition IN ('confirmed', 'false_positive', 'duplicate', 'not_exploitable', 'accepted_risk',
                                'mitigated', 'needs_more_information', 'out_of_scope')),
    reason                  text NOT NULL CHECK (length(reason) BETWEEN 10 AND 8000),
    duplicate_of            uuid,
    risk_owner_id           uuid,
    risk_expires_at         timestamptz,
    assessed_severity       text,
    requires_independent    boolean NOT NULL DEFAULT false,
    -- final: completed the review; pending_approval: awaits an independent
    -- reviewer (their outcome is in human_review_approvals); open: the
    -- review stays open (needs more information).
    outcome                 text NOT NULL CHECK (outcome IN ('final', 'pending_approval', 'open')),
    decided_by              uuid NOT NULL,
    created_at              timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, duplicate_of) REFERENCES findings(organization_id, id) ON DELETE SET NULL (duplicate_of),
    FOREIGN KEY (organization_id, risk_owner_id) REFERENCES users(organization_id, id),
    FOREIGN KEY (organization_id, decided_by) REFERENCES users(organization_id, id),
    CHECK (disposition <> 'accepted_risk' OR (risk_owner_id IS NOT NULL AND risk_expires_at IS NOT NULL))
);
CREATE INDEX human_review_decisions_review_idx ON human_review_decisions (review_id, created_at);

-- Independent (second-level) review outcomes, separate from decisions.
CREATE TABLE human_review_approvals (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    review_id        uuid NOT NULL REFERENCES human_reviews(id) ON DELETE CASCADE,
    decision_id      uuid NOT NULL REFERENCES human_review_decisions(id) ON DELETE CASCADE,
    reviewer_id      uuid NOT NULL,
    outcome          text NOT NULL CHECK (outcome IN ('approved', 'rejected', 'information_requested')),
    comments         text NOT NULL CHECK (length(comments) BETWEEN 1 AND 8000),
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, reviewer_id) REFERENCES users(organization_id, id)
);
CREATE INDEX human_review_approvals_review_idx ON human_review_approvals (review_id, created_at);

-- +goose StatementBegin
-- Four eyes: the independent reviewer is never the author of the decision.
CREATE FUNCTION pathos_check_review_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF EXISTS (SELECT 1 FROM human_review_decisions d WHERE d.id = NEW.decision_id AND d.decided_by = NEW.reviewer_id) THEN
        RAISE EXCEPTION 'the independent reviewer must not be the author of the decision' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER human_review_approvals_four_eyes BEFORE INSERT ON human_review_approvals FOR EACH ROW EXECUTE FUNCTION pathos_check_review_approval();

-- Evidence: files live encrypted in the source store; text evidence
-- (HTTP requests, snippets, command output) is stored inline.
CREATE TABLE human_review_evidence (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    evidence_key     text NOT NULL,
    review_id        uuid NOT NULL REFERENCES human_reviews(id) ON DELETE CASCADE,
    finding_id       uuid NOT NULL,
    round            int NOT NULL,
    evidence_type    text NOT NULL CHECK (evidence_type IN ('screenshot', 'code_snippet', 'http_request', 'http_response', 'command_output',
                         'application_log', 'security_log', 'reproduction_result', 'document', 'other')),
    classification   text NOT NULL DEFAULT 'confidential' CHECK (classification IN ('internal', 'confidential', 'restricted')),
    description      text NOT NULL CHECK (length(description) BETWEEN 1 AND 2000),
    comments         text NOT NULL DEFAULT '' CHECK (length(comments) <= 4000),
    file_name        text NOT NULL DEFAULT '' CHECK (length(file_name) <= 255),
    content_type     text NOT NULL DEFAULT '',
    size_bytes       bigint NOT NULL DEFAULT 0,
    sha256           text NOT NULL DEFAULT '',
    object_key       text,
    text_content     text CHECK (length(text_content) <= 200000),
    uploaded_by      uuid NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    deleted_at       timestamptz,
    deleted_by       uuid,
    delete_reason    text NOT NULL DEFAULT '',
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, uploaded_by) REFERENCES users(organization_id, id),
    -- Exactly one content form while the evidence exists; deletion removes
    -- the content and keeps the record.
    CHECK (deleted_at IS NOT NULL OR (object_key IS NULL) <> (text_content IS NULL))
);
CREATE UNIQUE INDEX human_review_evidence_key_uq ON human_review_evidence (evidence_key);
CREATE INDEX human_review_evidence_review_idx ON human_review_evidence (review_id, created_at);

-- +goose StatementBegin
CREATE FUNCTION pathos_assign_evidence_key() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    n bigint;
BEGIN
    n := nextval('human_review_evidence_key_seq');
    NEW.evidence_key := 'QD-EV-' || lpad(n::text, greatest(6, length(n::text)), '0');
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER human_review_evidence_assign_key BEFORE INSERT ON human_review_evidence FOR EACH ROW EXECUTE FUNCTION pathos_assign_evidence_key();

-- Comments (collaboration, assignment notes, independent reviewer notes).
CREATE TABLE human_review_comments (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL,
    review_id        uuid NOT NULL REFERENCES human_reviews(id) ON DELETE CASCADE,
    author_id        uuid NOT NULL,
    kind             text NOT NULL DEFAULT 'comment' CHECK (kind IN ('comment', 'assignment', 'independent', 'information_request')),
    body             text NOT NULL CHECK (length(body) BETWEEN 1 AND 8000),
    created_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, author_id) REFERENCES users(organization_id, id)
);
CREATE INDEX human_review_comments_review_idx ON human_review_comments (review_id, created_at);

-- AI suggestions, kept for traceability. They never change a review.
CREATE TABLE human_review_recommendations (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL,
    review_id          uuid NOT NULL REFERENCES human_reviews(id) ON DELETE CASCADE,
    kind               text NOT NULL CHECK (kind IN ('explanation', 'code_summary', 'code_paths', 'investigation_questions',
                           'false_positive_indicators', 'evidence_suggestions', 'remediation', 'secure_code', 'references', 'assessment_summary')),
    provider           text NOT NULL DEFAULT '',
    model              text NOT NULL DEFAULT '',
    config_version_id  uuid,
    content            jsonb NOT NULL,
    transmitted_sha256 text NOT NULL DEFAULT '',
    input_tokens       bigint NOT NULL DEFAULT 0,
    output_tokens      bigint NOT NULL DEFAULT 0,
    requested_by       uuid NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX human_review_recommendations_review_idx ON human_review_recommendations (review_id, created_at DESC);

-- Append-only activity and audit history of a review.
CREATE TABLE human_review_history (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  uuid NOT NULL,
    review_id        uuid NOT NULL REFERENCES human_reviews(id) ON DELETE CASCADE,
    finding_id       uuid NOT NULL,
    round            int NOT NULL DEFAULT 1,
    actor_id         uuid,          -- NULL = PATHOS (ingestion, scanner)
    action           text NOT NULL,
    field            text NOT NULL DEFAULT '',
    old_value        jsonb,
    new_value        jsonb,
    note             text NOT NULL DEFAULT '' CHECK (length(note) <= 8000),
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX human_review_history_review_idx ON human_review_history (review_id, created_at, id);
CREATE INDEX human_review_history_org_idx ON human_review_history (organization_id, created_at DESC);

-- Human outcome on the finding itself, for finding views and remediation.
ALTER TABLE findings
    ADD COLUMN human_review_id   uuid,
    ADD COLUMN human_disposition text CHECK (human_disposition IN ('confirmed', 'false_positive', 'duplicate', 'not_exploitable', 'accepted_risk',
                                    'mitigated', 'needs_more_information', 'out_of_scope')),
    ADD COLUMN human_severity    text CHECK (human_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    ADD COLUMN human_reviewed_at timestamptz;
CREATE INDEX findings_human_disposition_idx ON findings (organization_id, human_disposition) WHERE human_disposition IS NOT NULL;

-- +goose StatementBegin
-- Keeps a confirmed finding's remediation status in step with scans: a fix
-- detected by a scan awaits the reviewer's verification, and a finding
-- detected again after a fix is reopened.
CREATE FUNCTION pathos_review_remediation_sync() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target text;
    allowed text[];
BEGIN
    IF NEW.status = 'fixed' AND OLD.status <> 'fixed' THEN
        target := 'pending_verification';
        allowed := ARRAY['open', 'in_progress', 'reopened'];
    ELSIF OLD.status = 'fixed' AND NEW.status = 'open' THEN
        target := 'reopened';
        allowed := ARRAY['fixed', 'pending_verification', 'verified'];
    ELSE
        RETURN NULL;
    END IF;
    WITH prev AS (
        SELECT id, remediation_status FROM human_reviews WHERE finding_id = NEW.id AND remediation_status = ANY(allowed) FOR UPDATE
    ), upd AS (
        UPDATE human_reviews h SET remediation_status = target, updated_at = now() FROM prev WHERE h.id = prev.id
        RETURNING h.id, h.organization_id, h.finding_id, h.round, prev.remediation_status AS before
    )
    INSERT INTO human_review_history (organization_id, review_id, finding_id, round, action, field, old_value, new_value, note)
    SELECT organization_id, id, finding_id, round, 'remediation.status', 'remediation_status', to_jsonb(before), to_jsonb(target),
           CASE WHEN target = 'reopened' THEN 'detected again by a scan after being fixed' ELSE 'no longer detected by a scan' END
    FROM upd;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER findings_review_remediation AFTER UPDATE OF status ON findings FOR EACH ROW EXECUTE FUNCTION pathos_review_remediation_sync();

INSERT INTO human_review_settings (organization_id) SELECT id FROM organizations ON CONFLICT DO NOTHING;

-- History, decisions, approvals and comments are append-only for the
-- application (like the audit log).
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
    GRANT EXECUTE ON FUNCTION pathos_ensure_audit_partitions(int) TO pathos_app;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER IF EXISTS findings_review_remediation ON findings;
DROP FUNCTION IF EXISTS pathos_review_remediation_sync();
DROP INDEX IF EXISTS findings_human_disposition_idx;
ALTER TABLE findings DROP COLUMN IF EXISTS human_reviewed_at, DROP COLUMN IF EXISTS human_severity,
    DROP COLUMN IF EXISTS human_disposition, DROP COLUMN IF EXISTS human_review_id;
DROP TABLE IF EXISTS human_review_history;
DROP TABLE IF EXISTS human_review_recommendations;
DROP TABLE IF EXISTS human_review_comments;
DROP TABLE IF EXISTS human_review_evidence;
DROP FUNCTION IF EXISTS pathos_assign_evidence_key();
DROP TABLE IF EXISTS human_review_approvals;
DROP FUNCTION IF EXISTS pathos_check_review_approval();
DROP TABLE IF EXISTS human_review_decisions;
DROP TABLE IF EXISTS human_review_assessments;
DROP TABLE IF EXISTS human_reviews;
DROP FUNCTION IF EXISTS pathos_protect_human_review();
DROP FUNCTION IF EXISTS pathos_assign_review_key();
DROP TABLE IF EXISTS human_review_settings;
DROP SEQUENCE IF EXISTS human_review_evidence_key_seq;
DROP SEQUENCE IF EXISTS human_review_key_seq;
SELECT pathos_apply_app_grants();
