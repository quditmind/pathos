-- +goose Up
-- Phase 6: finding lifecycle history, assignment, SLA policies, accepted
-- risk with expiry, recurrence, SBOM inventory, license policy.

ALTER TABLE findings ADD COLUMN assignee_id uuid;
ALTER TABLE findings ADD CONSTRAINT findings_assignee_fk FOREIGN KEY (organization_id, assignee_id) REFERENCES users(organization_id, id);
ALTER TABLE findings ADD COLUMN sla_due_at timestamptz;
ALTER TABLE findings ADD COLUMN recurrence_count int NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN accepted_until timestamptz;
ALTER TABLE findings ADD COLUMN status_changed_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX findings_assignee_idx ON findings (assignee_id) WHERE assignee_id IS NOT NULL;
CREATE INDEX findings_sla_idx ON findings (organization_id, sla_due_at) WHERE status IN ('open', 'in_progress', 'needs_review');

CREATE TABLE sla_policies (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    days            int CHECK (days IS NULL OR days BETWEEN 1 AND 3650), -- NULL = no SLA
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, severity)
);

CREATE TABLE finding_status_history (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    finding_id      uuid NOT NULL,
    from_status     text,
    to_status       text NOT NULL,
    actor_id        uuid,            -- NULL = PATHOS (scanner, AI policy, expiry)
    source          text NOT NULL DEFAULT 'system',
    reason          text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX finding_status_history_idx ON finding_status_history (finding_id, created_at);

-- Every status change, from any code path, is recorded. Callers attribute
-- changes with: SELECT set_config('pathos.actor', <user id>, true),
-- set_config('pathos.source', 'user'|'scanner'|'ai'|'expiry', true),
-- set_config('pathos.reason', <text>, true).
-- +goose StatementBegin
CREATE FUNCTION pathos_finding_lifecycle() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    actor uuid := NULLIF(current_setting('pathos.actor', true), '')::uuid;
    src   text := COALESCE(NULLIF(current_setting('pathos.source', true), ''), 'system');
    why   text := COALESCE(current_setting('pathos.reason', true), '');
    d     int;
BEGIN
    IF TG_OP = 'INSERT' THEN
        SELECT days INTO d FROM sla_policies WHERE organization_id = NEW.organization_id AND severity = NEW.severity;
        IF d IS NOT NULL AND NEW.sla_due_at IS NULL THEN
            NEW.sla_due_at := NEW.first_seen_at + make_interval(days => d);
        END IF;
        RETURN NEW;
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        NEW.status_changed_at := now();
        IF OLD.status = 'fixed' AND NEW.status = 'open' THEN
            NEW.recurrence_count := OLD.recurrence_count + 1;
            src := 'scanner';
            why := 'detected again after being fixed';
        END IF;
        IF NEW.status <> 'accepted_risk' THEN
            NEW.accepted_until := NULL;
        END IF;
        IF NEW.status IN ('open', 'in_progress', 'needs_review') THEN
            NEW.resolved_at := NULL;
        ELSIF NEW.resolved_at IS NULL THEN
            NEW.resolved_at := now();
        END IF;
        INSERT INTO finding_status_history (organization_id, finding_id, from_status, to_status, actor_id, source, reason)
        VALUES (NEW.organization_id, NEW.id, OLD.status, NEW.status, actor, src, left(why, 2000));
    END IF;
    IF NEW.severity IS DISTINCT FROM OLD.severity THEN
        SELECT days INTO d FROM sla_policies WHERE organization_id = NEW.organization_id AND severity = NEW.severity;
        NEW.sla_due_at := CASE WHEN d IS NULL THEN NULL ELSE NEW.first_seen_at + make_interval(days => d) END;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER findings_lifecycle_ins BEFORE INSERT ON findings FOR EACH ROW EXECUTE FUNCTION pathos_finding_lifecycle();
CREATE TRIGGER findings_lifecycle_upd BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION pathos_finding_lifecycle();

-- Initial history entry for findings that already exist.
INSERT INTO finding_status_history (organization_id, finding_id, from_status, to_status, source, reason, created_at)
SELECT organization_id, id, NULL, status, 'system', 'history started', first_seen_at FROM findings;

CREATE TABLE risk_acceptances (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    finding_id      uuid NOT NULL,
    requested_by    uuid NOT NULL,
    justification   text NOT NULL CHECK (length(justification) BETWEEN 10 AND 4000),
    expires_at      timestamptz NOT NULL,
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'expired', 'revoked', 'withdrawn')),
    decided_by      uuid,
    decided_at      timestamptz,
    decision_note   text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE,
    CHECK (decided_by IS NULL OR decided_by <> requested_by)
);
CREATE UNIQUE INDEX risk_acceptances_active_uq ON risk_acceptances (finding_id) WHERE status IN ('pending', 'approved');

CREATE TABLE sbom_components (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    scan_job_id     uuid NOT NULL,
    name            text NOT NULL,
    version         text NOT NULL DEFAULT '',
    purl            text NOT NULL DEFAULT '',
    type            text NOT NULL DEFAULT '',
    licenses        text[] NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX sbom_components_repo_idx ON sbom_components (repository_id);
CREATE INDEX sbom_components_name_idx ON sbom_components (organization_id, lower(name));
CREATE INDEX sbom_components_purl_idx ON sbom_components (organization_id, purl);

CREATE TABLE license_policies (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    spdx_id         text NOT NULL CHECK (length(spdx_id) BETWEEN 1 AND 100),
    decision        text NOT NULL CHECK (decision IN ('deny', 'review')),
    PRIMARY KEY (organization_id, spdx_id)
);

-- History, like the audit log, is append-only for the application; fold
-- that into the grant function so later migrations keep it.
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
    REVOKE INSERT, UPDATE, DELETE ON permissions FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON scanner_catalog FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON goose_db_version FROM pathos_app;
    GRANT EXECUTE ON FUNCTION pathos_ensure_audit_partitions(int) TO pathos_app;
END;
$$;
-- +goose StatementEnd
SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS license_policies;
DROP TABLE IF EXISTS sbom_components;
DROP TABLE IF EXISTS risk_acceptances;
DROP TRIGGER IF EXISTS findings_lifecycle_upd ON findings;
DROP TRIGGER IF EXISTS findings_lifecycle_ins ON findings;
DROP FUNCTION IF EXISTS pathos_finding_lifecycle();
DROP TABLE IF EXISTS finding_status_history;
DROP TABLE IF EXISTS sla_policies;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_assignee_fk;
ALTER TABLE findings DROP COLUMN IF EXISTS status_changed_at;
ALTER TABLE findings DROP COLUMN IF EXISTS accepted_until;
ALTER TABLE findings DROP COLUMN IF EXISTS recurrence_count;
ALTER TABLE findings DROP COLUMN IF EXISTS sla_due_at;
ALTER TABLE findings DROP COLUMN IF EXISTS assignee_id;
