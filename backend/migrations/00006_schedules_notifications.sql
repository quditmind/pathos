-- Phase 7: scan scheduling and notifications.
--
-- Scheduling: cron schedules targeting the organization, a region, a business
-- unit, a repository or every repository using a scan profile. A leader-
-- elected scheduler (pg advisory lock) turns due schedules into scan jobs.
--
-- Notifications: an outbox (notification_events) written by triggers and
-- background detectors, rules that match events to recipients, templates,
-- SMTP settings and a delivery history that doubles as the in-app inbox.

-- +goose Up

CREATE TABLE scan_schedules (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    enabled         boolean NOT NULL DEFAULT true,
    cron            text NOT NULL CHECK (length(cron) BETWEEN 1 AND 120),
    timezone        text NOT NULL DEFAULT 'UTC',
    target_type     text NOT NULL CHECK (target_type IN ('organization', 'region', 'business_unit', 'repository', 'profile')),
    target_id       uuid,
    priority        int NOT NULL DEFAULT 30 CHECK (priority BETWEEN 0 AND 90),
    next_run_at     timestamptz,
    last_run_at     timestamptz,
    last_status     text NOT NULL DEFAULT '',
    last_queued     int NOT NULL DEFAULT 0,
    missed_runs     int NOT NULL DEFAULT 0,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    CHECK ((target_type = 'organization') = (target_id IS NULL))
);
CREATE INDEX scan_schedules_due_idx ON scan_schedules (next_run_at) WHERE enabled;

ALTER TABLE scan_jobs ADD COLUMN schedule_id uuid REFERENCES scan_schedules(id) ON DELETE SET NULL;
CREATE INDEX scan_jobs_schedule_idx ON scan_jobs (schedule_id, queued_at DESC) WHERE schedule_id IS NOT NULL;

-- Visibility for the scheduler leader (one row per process role).
CREATE TABLE scheduler_state (
    name         text PRIMARY KEY,
    holder       text NOT NULL,
    started_at   timestamptz NOT NULL DEFAULT now(),
    heartbeat_at timestamptz NOT NULL DEFAULT now(),
    stats        jsonb NOT NULL DEFAULT '{}'::jsonb
);

ALTER TABLE workers ADD COLUMN offline_notified_at timestamptz;
ALTER TABLE scm_connections ADD COLUMN last_synced_at timestamptz;
ALTER TABLE findings ADD COLUMN sla_breach_notified_at timestamptz;

-- ---------------------------------------------------------------- notify

CREATE TABLE smtp_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    enabled         boolean NOT NULL DEFAULT false,
    host            text NOT NULL DEFAULT '',
    port            int NOT NULL DEFAULT 587 CHECK (port BETWEEN 1 AND 65535),
    tls_mode        text NOT NULL DEFAULT 'starttls' CHECK (tls_mode IN ('starttls', 'tls', 'none')),
    username        text NOT NULL DEFAULT '',
    secret_id       uuid REFERENCES secrets(id) ON DELETE SET NULL,
    from_address    text NOT NULL DEFAULT '',
    from_name       text NOT NULL DEFAULT 'PATHOS',
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE notification_templates (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_key       text NOT NULL,
    subject         text NOT NULL CHECK (length(subject) BETWEEN 1 AND 300),
    body            text NOT NULL CHECK (length(body) BETWEEN 1 AND 20000),
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, event_key)
);

CREATE TABLE notification_rules (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
    enabled         boolean NOT NULL DEFAULT true,
    event_key       text NOT NULL,
    min_severity    text CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    scope_type      text NOT NULL DEFAULT 'organization' CHECK (scope_type IN ('organization', 'region', 'business_unit', 'repository')),
    scope_id        uuid,
    -- {"roles": [...], "users": [uuid...], "emails": [...], "dynamic": ["assignee", "requester", "owners"]}
    recipients      jsonb NOT NULL DEFAULT '{}'::jsonb,
    email           boolean NOT NULL DEFAULT true,
    in_app          boolean NOT NULL DEFAULT true,
    system_key      text,                       -- seeded defaults (editable, not deletable)
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, system_key),
    CHECK ((scope_type = 'organization') = (scope_id IS NULL))
);
CREATE INDEX notification_rules_event_idx ON notification_rules (organization_id, event_key) WHERE enabled;

-- Outbox. Rows are produced by triggers and detectors in the same transaction
-- as the change, and consumed by the dispatcher in the jobs role.
CREATE TABLE notification_events (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_key       text NOT NULL,
    repository_id   uuid,
    severity        text,
    subject_id      uuid,
    payload         jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL DEFAULT now(),
    processed_at    timestamptz,
    error           text NOT NULL DEFAULT ''
);
CREATE INDEX notification_events_pending_idx ON notification_events (created_at) WHERE processed_at IS NULL;

CREATE TABLE notifications (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    event_id        uuid REFERENCES notification_events(id) ON DELETE SET NULL,
    rule_id         uuid REFERENCES notification_rules(id) ON DELETE SET NULL,
    event_key       text NOT NULL,
    channel         text NOT NULL CHECK (channel IN ('email', 'in_app')),
    user_id         uuid REFERENCES users(id) ON DELETE CASCADE,
    email           text NOT NULL DEFAULT '',
    subject         text NOT NULL,
    body            text NOT NULL,
    link            text NOT NULL DEFAULT '',
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sent', 'failed', 'suppressed')),
    attempts        int NOT NULL DEFAULT 0,
    last_error      text NOT NULL DEFAULT '',
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz,
    read_at         timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CHECK (channel = 'email' OR user_id IS NOT NULL)
);
-- One delivery per event, recipient and channel even if several rules match.
-- Deliveries without an event (test emails) are never deduplicated.
CREATE UNIQUE INDEX notifications_dedupe_uq ON notifications (event_id, channel, lower(email), user_id) NULLS NOT DISTINCT
    WHERE event_id IS NOT NULL;
CREATE INDEX notifications_outbox_idx ON notifications (next_attempt_at) WHERE status = 'pending' AND channel = 'email';
CREATE INDEX notifications_inbox_idx ON notifications (user_id, created_at DESC) WHERE channel = 'in_app';
CREATE INDEX notifications_history_idx ON notifications (organization_id, created_at DESC);

-- ------------------------------------------------------- event triggers

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_scan_job_events() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF NEW.status = 'failed' THEN
            INSERT INTO notification_events (organization_id, event_key, repository_id, subject_id, payload)
            VALUES (NEW.organization_id, 'scan.failed', NEW.repository_id, NEW.id,
                    jsonb_build_object('error', left(NEW.error, 500), 'trigger', NEW.trigger, 'attempts', NEW.attempts));
        ELSIF NEW.status IN ('succeeded', 'partial') AND NEW.findings_new > 0 THEN
            INSERT INTO notification_events (organization_id, event_key, repository_id, subject_id, severity, payload)
            SELECT NEW.organization_id, 'findings.new', NEW.repository_id, NEW.id,
                   (SELECT f.severity FROM findings f
                     WHERE f.repository_id = NEW.repository_id AND f.first_seen_at >= COALESCE(NEW.started_at, NEW.queued_at)
                     ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END
                     LIMIT 1),
                   jsonb_build_object('new', NEW.findings_new, 'fixed', NEW.findings_fixed, 'gate_failed', NEW.gate_failed);
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER scan_jobs_events AFTER UPDATE OF status ON scan_jobs
    FOR EACH ROW EXECUTE FUNCTION pathos_scan_job_events();

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_risk_events() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    repo uuid;
    sev  text;
BEGIN
    SELECT repository_id, severity INTO repo, sev FROM findings WHERE id = NEW.finding_id;
    IF TG_OP = 'INSERT' THEN
        INSERT INTO notification_events (organization_id, event_key, repository_id, severity, subject_id, payload)
        VALUES (NEW.organization_id, 'risk.requested', repo, sev, NEW.id,
                jsonb_build_object('finding_id', NEW.finding_id, 'requested_by', NEW.requested_by));
    ELSIF NEW.status IS DISTINCT FROM OLD.status AND NEW.status IN ('approved', 'rejected', 'revoked', 'expired') THEN
        INSERT INTO notification_events (organization_id, event_key, repository_id, severity, subject_id, payload)
        VALUES (NEW.organization_id, 'risk.decided', repo, sev, NEW.id,
                jsonb_build_object('finding_id', NEW.finding_id, 'requested_by', NEW.requested_by, 'status', NEW.status));
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER risk_acceptances_events AFTER INSERT OR UPDATE OF status ON risk_acceptances
    FOR EACH ROW EXECUTE FUNCTION pathos_risk_events();

-- Assignment by someone else notifies the new assignee.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_assign_events() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    actor uuid := NULLIF(current_setting('pathos.actor', true), '')::uuid;
BEGIN
    IF NEW.assignee_id IS NOT NULL AND NEW.assignee_id IS DISTINCT FROM OLD.assignee_id
       AND NEW.assignee_id IS DISTINCT FROM actor THEN
        INSERT INTO notification_events (organization_id, event_key, repository_id, severity, subject_id, payload)
        VALUES (NEW.organization_id, 'finding.assigned', NEW.repository_id, NEW.severity, NEW.id,
                jsonb_build_object('assignee_id', NEW.assignee_id, 'actor', actor));
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER findings_assign_events AFTER UPDATE OF assignee_id ON findings
    FOR EACH ROW EXECUTE FUNCTION pathos_assign_events();

-- notifications are delivery history: the app may update delivery state
-- (status, attempts, read_at) but never delete it.
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
SELECT pathos_apply_app_grants();

-- +goose Down
DROP TRIGGER IF EXISTS findings_assign_events ON findings;
DROP FUNCTION IF EXISTS pathos_assign_events();
DROP TRIGGER IF EXISTS risk_acceptances_events ON risk_acceptances;
DROP FUNCTION IF EXISTS pathos_risk_events();
DROP TRIGGER IF EXISTS scan_jobs_events ON scan_jobs;
DROP FUNCTION IF EXISTS pathos_scan_job_events();
DROP TABLE IF EXISTS notifications;
DROP TABLE IF EXISTS notification_events;
DROP TABLE IF EXISTS notification_rules;
DROP TABLE IF EXISTS notification_templates;
DROP TABLE IF EXISTS smtp_settings;
ALTER TABLE findings DROP COLUMN IF EXISTS sla_breach_notified_at;
ALTER TABLE scm_connections DROP COLUMN IF EXISTS last_synced_at;
ALTER TABLE workers DROP COLUMN IF EXISTS offline_notified_at;
DROP TABLE IF EXISTS scheduler_state;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS schedule_id;
DROP TABLE IF EXISTS scan_schedules;
