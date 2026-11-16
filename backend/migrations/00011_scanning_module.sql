-- +goose Up
-- Scanning module (docs/SCANNING_MODULE.md): permanent Scan IDs, progress,
-- stages and logs, immutable configuration snapshots, retries, schedule
-- execution plans and run history.

-- ---------------------------------------------------------------------------
-- Scan executions
-- ---------------------------------------------------------------------------

CREATE SEQUENCE scan_key_seq AS bigint START 1;

ALTER TABLE scan_jobs
    ADD COLUMN scan_key        text,
    ADD COLUMN name            text NOT NULL DEFAULT '' CHECK (length(name) <= 200),
    ADD COLUMN progress        int NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    ADD COLUMN stage           text NOT NULL DEFAULT 'queued',
    -- Effective configuration at enqueue time: profile version settings,
    -- scanners and their configuration, exclusions, limits. Immutable.
    ADD COLUMN config_snapshot jsonb,
    ADD COLUMN retry_of        uuid,
    ADD COLUMN retry_count     int NOT NULL DEFAULT 0,
    ADD COLUMN schedule_run_id uuid,
    ADD COLUMN cancel_reason   text NOT NULL DEFAULT '';

-- Existing executions: numbered in queue order, snapshot from their version.
WITH ordered AS (SELECT id, row_number() OVER (ORDER BY queued_at, id) AS n FROM scan_jobs)
UPDATE scan_jobs j SET scan_key = 'QD-SCAN-' || lpad(o.n::text, greatest(6, length(o.n::text)), '0')
FROM ordered o WHERE o.id = j.id;
SELECT setval('scan_key_seq', GREATEST((SELECT count(*) FROM scan_jobs), 1), (SELECT count(*) FROM scan_jobs) > 0);
UPDATE scan_jobs j SET progress = CASE WHEN j.status IN ('succeeded', 'partial', 'failed', 'cancelled') THEN 100 ELSE 0 END,
    stage = CASE j.status WHEN 'queued' THEN 'queued' WHEN 'running' THEN 'scanning' ELSE 'finished' END;

ALTER TABLE scan_jobs ALTER COLUMN scan_key SET NOT NULL;
CREATE UNIQUE INDEX scan_jobs_key_uq ON scan_jobs (scan_key);
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_retry_fk FOREIGN KEY (organization_id, retry_of) REFERENCES scan_jobs(organization_id, id) ON DELETE SET NULL (retry_of);
CREATE INDEX scan_jobs_retry_idx ON scan_jobs (retry_of) WHERE retry_of IS NOT NULL;
CREATE INDEX scan_jobs_finished_idx ON scan_jobs (organization_id, finished_at DESC) WHERE finished_at IS NOT NULL;
CREATE INDEX scan_jobs_status_idx ON scan_jobs (organization_id, status, queued_at DESC);
-- Findings observed by one execution (comparison, severity distribution).
CREATE INDEX finding_occurrences_result_idx ON finding_occurrences (scan_result_id, finding_id);

-- One queued execution per repository AND profile version (previously per
-- repository), so a repository can be queued for several profiles. Only one
-- execution per repository runs at a time (scan_jobs_running_uq).
DROP INDEX scan_jobs_queued_uq;
CREATE UNIQUE INDEX scan_jobs_queued_uq ON scan_jobs (repository_id, profile_version_id) WHERE status = 'queued';

-- +goose StatementBegin
CREATE FUNCTION pathos_assign_scan_key() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    n bigint;
BEGIN
    n := nextval('scan_key_seq');
    NEW.scan_key := 'QD-SCAN-' || lpad(n::text, greatest(6, length(n::text)), '0');
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION pathos_protect_scan_job() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.scan_key IS DISTINCT FROM OLD.scan_key THEN
        RAISE EXCEPTION 'scan_key is permanent and cannot be changed' USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.config_snapshot IS NOT NULL AND NEW.config_snapshot IS DISTINCT FROM OLD.config_snapshot THEN
        RAISE EXCEPTION 'the configuration snapshot of a scan is immutable' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER scan_jobs_assign_key BEFORE INSERT ON scan_jobs FOR EACH ROW EXECUTE FUNCTION pathos_assign_scan_key();
CREATE TRIGGER scan_jobs_protect BEFORE UPDATE OF scan_key, config_snapshot ON scan_jobs FOR EACH ROW EXECUTE FUNCTION pathos_protect_scan_job();

-- Stage and engine events (platform and worker).
CREATE TABLE scan_job_events (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid NOT NULL,
    scan_job_id     uuid NOT NULL,
    stage           text NOT NULL CHECK (stage IN ('queued', 'leased', 'source', 'scanner', 'ingest', 'finalize', 'cancel', 'retry')),
    scanner_key     text NOT NULL DEFAULT '',
    status          text NOT NULL CHECK (status IN ('started', 'succeeded', 'failed', 'skipped', 'timed_out', 'info')),
    message         text NOT NULL DEFAULT '' CHECK (length(message) <= 2000),
    at              timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, scan_job_id) REFERENCES scan_jobs(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX scan_job_events_job_idx ON scan_job_events (scan_job_id, at, id);
CREATE INDEX scan_job_events_time_idx ON scan_job_events (at);

-- Timestamped execution log (redacted, capped per job).
CREATE TABLE scan_job_logs (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    organization_id uuid NOT NULL,
    scan_job_id     uuid NOT NULL,
    at              timestamptz NOT NULL,
    level           text NOT NULL CHECK (level IN ('debug', 'info', 'warn', 'error')),
    source          text NOT NULL CHECK (length(source) BETWEEN 1 AND 50),
    message         text NOT NULL CHECK (length(message) <= 2000),
    FOREIGN KEY (organization_id, scan_job_id) REFERENCES scan_jobs(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX scan_job_logs_job_idx ON scan_job_logs (scan_job_id, id);
CREATE INDEX scan_job_logs_time_idx ON scan_job_logs (at);

-- ---------------------------------------------------------------------------
-- Schedules: execution plans, kinds, windows, retries, concurrency
-- ---------------------------------------------------------------------------

ALTER TABLE scan_schedules DROP CONSTRAINT scan_schedules_cron_check;
ALTER TABLE scan_schedules
    ADD COLUMN kind                text NOT NULL DEFAULT 'cron' CHECK (kind IN ('cron', 'once', 'interval')),
    ADD COLUMN run_at              timestamptz,
    ADD COLUMN interval_minutes    int CHECK (interval_minutes IS NULL OR interval_minutes BETWEEN 60 AND 525600),
    ADD COLUMN window_start        time,
    ADD COLUMN window_end          time,
    ADD COLUMN window_days         int[] NOT NULL DEFAULT '{}',
    ADD COLUMN retry_max           int NOT NULL DEFAULT 0 CHECK (retry_max BETWEEN 0 AND 5),
    ADD COLUMN retry_delay_minutes int NOT NULL DEFAULT 30 CHECK (retry_delay_minutes BETWEEN 5 AND 1440),
    ADD COLUMN max_concurrent      int NOT NULL DEFAULT 0 CHECK (max_concurrent BETWEEN 0 AND 1000),
    ADD COLUMN notify_on           text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT scan_schedules_cron_check CHECK (length(cron) <= 120 AND (kind <> 'cron' OR length(cron) >= 1)),
    ADD CONSTRAINT scan_schedules_kind_ck CHECK ((kind <> 'once' OR run_at IS NOT NULL) AND (kind <> 'interval' OR interval_minutes IS NOT NULL)),
    ADD CONSTRAINT scan_schedules_window_ck CHECK ((window_start IS NULL) = (window_end IS NULL)),
    ADD CONSTRAINT scan_schedules_notify_ck CHECK (notify_on <@ ARRAY['completed', 'failed']::text[]);

-- Execution plan: which assets run with which profile. A NULL profile uses
-- each repository's own (or the default) profile.
CREATE TABLE scan_schedule_targets (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    schedule_id     uuid NOT NULL REFERENCES scan_schedules(id) ON DELETE CASCADE,
    position        int NOT NULL DEFAULT 0,
    target_type     text NOT NULL CHECK (target_type IN ('organization', 'region', 'business_unit', 'repository')),
    target_id       uuid,
    profile_id      uuid,
    CHECK ((target_type = 'organization') = (target_id IS NULL)),
    FOREIGN KEY (organization_id, profile_id) REFERENCES scan_profiles(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX scan_schedule_targets_schedule_idx ON scan_schedule_targets (schedule_id, position);
-- Existing schedules become one-row plans ('profile' targets: repositories
-- assigned to that profile, scanned with it).
INSERT INTO scan_schedule_targets (id, organization_id, schedule_id, target_type, target_id, profile_id)
SELECT gen_random_uuid(), organization_id, id,
       CASE WHEN target_type = 'profile' THEN 'organization' ELSE target_type END,
       CASE WHEN target_type = 'profile' THEN NULL ELSE target_id END,
       CASE WHEN target_type = 'profile' THEN target_id END
FROM scan_schedules;

-- One row per activation; (schedule_id, due_at) is unique so a retried or
-- recovered scheduler pass never runs an activation twice.
CREATE TABLE scan_schedule_runs (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    schedule_id     uuid NOT NULL REFERENCES scan_schedules(id) ON DELETE CASCADE,
    due_at          timestamptz NOT NULL,
    trigger         text NOT NULL DEFAULT 'schedule' CHECK (trigger IN ('schedule', 'manual', 'catch_up')),
    status          text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'waiting', 'completed', 'partial', 'failed')),
    queued          int NOT NULL DEFAULT 0,
    skipped         int NOT NULL DEFAULT 0,
    failed          int NOT NULL DEFAULT 0,
    -- Plan entries not yet queued (concurrency limit or scan window).
    pending         jsonb NOT NULL DEFAULT '[]'::jsonb,
    message         text NOT NULL DEFAULT '',
    requested_by    uuid,
    started_at      timestamptz NOT NULL DEFAULT now(),
    finished_at     timestamptz,
    UNIQUE (schedule_id, due_at),
    UNIQUE (organization_id, id)
);
CREATE INDEX scan_schedule_runs_open_idx ON scan_schedule_runs (status) WHERE status IN ('running', 'waiting');
CREATE INDEX scan_schedule_runs_schedule_idx ON scan_schedule_runs (schedule_id, started_at DESC);

ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_schedule_run_fk
    FOREIGN KEY (organization_id, schedule_run_id) REFERENCES scan_schedule_runs(organization_id, id) ON DELETE SET NULL (schedule_run_id);
-- A run creates at most one execution per repository and profile version.
CREATE UNIQUE INDEX scan_jobs_run_dedupe_uq ON scan_jobs (schedule_run_id, repository_id, profile_version_id)
    WHERE schedule_run_id IS NOT NULL AND retry_of IS NULL;

INSERT INTO permissions (key, category, description, org_only, sort_order) VALUES
    ('scans.compare', 'Scanning', 'Compare scan executions and view scan history', false, 0)
ON CONFLICT (key) DO NOTHING;
INSERT INTO role_permissions (role_id, permission_key)
SELECT DISTINCT rp.role_id, 'scans.compare' FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
WHERE rp.permission_key = 'scans.read' AND NOT r.is_system
ON CONFLICT DO NOTHING;

SELECT pathos_apply_app_grants();

-- +goose Down
DELETE FROM role_permissions WHERE permission_key = 'scans.compare';
DELETE FROM permissions WHERE key = 'scans.compare';
DROP INDEX IF EXISTS scan_jobs_run_dedupe_uq;
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_schedule_run_fk;
DROP TABLE IF EXISTS scan_schedule_runs;
DROP TABLE IF EXISTS scan_schedule_targets;
ALTER TABLE scan_schedules DROP CONSTRAINT IF EXISTS scan_schedules_notify_ck, DROP CONSTRAINT IF EXISTS scan_schedules_window_ck,
    DROP CONSTRAINT IF EXISTS scan_schedules_kind_ck, DROP CONSTRAINT IF EXISTS scan_schedules_cron_check;
DELETE FROM scan_schedules WHERE kind <> 'cron';
ALTER TABLE scan_schedules DROP COLUMN IF EXISTS kind, DROP COLUMN IF EXISTS run_at, DROP COLUMN IF EXISTS interval_minutes,
    DROP COLUMN IF EXISTS window_start, DROP COLUMN IF EXISTS window_end, DROP COLUMN IF EXISTS window_days,
    DROP COLUMN IF EXISTS retry_max, DROP COLUMN IF EXISTS retry_delay_minutes, DROP COLUMN IF EXISTS max_concurrent,
    DROP COLUMN IF EXISTS notify_on;
ALTER TABLE scan_schedules ADD CONSTRAINT scan_schedules_cron_check CHECK (length(cron) BETWEEN 1 AND 120);
DROP TABLE IF EXISTS scan_job_logs;
DROP TABLE IF EXISTS scan_job_events;
DROP TRIGGER IF EXISTS scan_jobs_protect ON scan_jobs;
DROP TRIGGER IF EXISTS scan_jobs_assign_key ON scan_jobs;
DROP FUNCTION IF EXISTS pathos_protect_scan_job();
DROP FUNCTION IF EXISTS pathos_assign_scan_key();
DROP INDEX IF EXISTS scan_jobs_queued_uq;
-- Keep the newest queued execution per repository (older ones are cancelled).
UPDATE scan_jobs j SET status = 'cancelled', finished_at = now()
WHERE j.status = 'queued' AND EXISTS (SELECT 1 FROM scan_jobs k WHERE k.repository_id = j.repository_id AND k.status = 'queued'
    AND (k.queued_at, k.id) > (j.queued_at, j.id));
CREATE UNIQUE INDEX scan_jobs_queued_uq ON scan_jobs (repository_id) WHERE status = 'queued';
DROP INDEX IF EXISTS scan_jobs_status_idx;
DROP INDEX IF EXISTS finding_occurrences_result_idx;
DROP INDEX IF EXISTS scan_jobs_finished_idx;
DROP INDEX IF EXISTS scan_jobs_retry_idx;
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_retry_fk;
DROP INDEX IF EXISTS scan_jobs_key_uq;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS cancel_reason, DROP COLUMN IF EXISTS schedule_run_id, DROP COLUMN IF EXISTS retry_count,
    DROP COLUMN IF EXISTS retry_of, DROP COLUMN IF EXISTS config_snapshot, DROP COLUMN IF EXISTS stage,
    DROP COLUMN IF EXISTS progress, DROP COLUMN IF EXISTS name, DROP COLUMN IF EXISTS scan_key;
DROP SEQUENCE IF EXISTS scan_key_seq;
