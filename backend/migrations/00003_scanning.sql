-- +goose Up
-- Phase 4: scanner catalog, scan profiles, workers, scan jobs, results,
-- raw artifacts and normalized findings.

CREATE TABLE scanner_catalog (
    key               text PRIMARY KEY CHECK (key ~ '^[a-z0-9-]{2,40}$'),
    name              text NOT NULL,
    category          text NOT NULL,
    license_spdx      text NOT NULL,
    decision          text NOT NULL CHECK (decision IN ('use', 'optional', 'restricted')),
    worker_family     text NOT NULL,
    requires_build    boolean NOT NULL DEFAULT false,
    mandatory         boolean NOT NULL DEFAULT false,
    adapter_available boolean NOT NULL DEFAULT false,
    default_enabled   boolean NOT NULL DEFAULT false,
    output_format     text NOT NULL DEFAULT 'sarif',
    homepage          text NOT NULL DEFAULT '',
    notes             text NOT NULL DEFAULT '',
    sort_order        int NOT NULL DEFAULT 0
);

CREATE TABLE scan_profiles (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description        text NOT NULL DEFAULT '',
    is_default         boolean NOT NULL DEFAULT false,
    current_version_id uuid,
    archived_at        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX scan_profiles_name_uq ON scan_profiles (organization_id, lower(name)) WHERE archived_at IS NULL;
CREATE UNIQUE INDEX scan_profiles_default_uq ON scan_profiles (organization_id) WHERE is_default AND archived_at IS NULL;

-- Immutable: an edit creates a new version, which gives change history and
-- lets every scan job reference exactly the settings it ran with.
CREATE TABLE scan_profile_versions (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL,
    profile_id         uuid NOT NULL,
    version            int NOT NULL CHECK (version > 0),
    severity_threshold text NOT NULL DEFAULT 'info' CHECK (severity_threshold IN ('info', 'low', 'medium', 'high', 'critical')),
    exclusions         text[] NOT NULL DEFAULT '{}',
    timeout_seconds    int NOT NULL DEFAULT 1800 CHECK (timeout_seconds BETWEEN 60 AND 14400),
    sbom               boolean NOT NULL DEFAULT true,
    fail_on_critical   boolean NOT NULL DEFAULT false,
    retention_days     int NOT NULL DEFAULT 90 CHECK (retention_days BETWEEN 7 AND 3650),
    change_note        text NOT NULL DEFAULT '',
    created_by         uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (profile_id, version),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, profile_id) REFERENCES scan_profiles(organization_id, id) ON DELETE CASCADE
);
ALTER TABLE scan_profiles ADD CONSTRAINT scan_profiles_current_version_fk
    FOREIGN KEY (organization_id, current_version_id) REFERENCES scan_profile_versions(organization_id, id) DEFERRABLE INITIALLY DEFERRED;

CREATE TABLE profile_scanners (
    profile_version_id uuid NOT NULL REFERENCES scan_profile_versions(id) ON DELETE CASCADE,
    scanner_key        text NOT NULL REFERENCES scanner_catalog(key),
    config             jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (pg_column_size(config) <= 8192),
    PRIMARY KEY (profile_version_id, scanner_key)
);

-- Mandatory scanners (Gitleaks) cannot be left out of any profile version.
-- +goose StatementBegin
CREATE FUNCTION pathos_check_mandatory_scanners() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    missing text;
BEGIN
    SELECT string_agg(c.key, ', ') INTO missing
    FROM scanner_catalog c
    WHERE c.mandatory AND NOT EXISTS (
        SELECT 1 FROM profile_scanners ps WHERE ps.profile_version_id = NEW.id AND ps.scanner_key = c.key);
    IF missing IS NOT NULL THEN
        RAISE EXCEPTION 'scan profile version % must enable mandatory scanners: %', NEW.version, missing
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER scan_profile_versions_mandatory
    AFTER INSERT ON scan_profile_versions DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION pathos_check_mandatory_scanners();

ALTER TABLE repositories ADD COLUMN scan_profile_id uuid;
ALTER TABLE repositories ADD CONSTRAINT repositories_scan_profile_fk
    FOREIGN KEY (organization_id, scan_profile_id) REFERENCES scan_profiles(organization_id, id);

CREATE TABLE workers (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (name ~ '^[A-Za-z0-9._-]{1,100}$'),
    family          text NOT NULL,
    version         text NOT NULL DEFAULT '',
    token_sha256    text NOT NULL,
    scanners        jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_seen_at    timestamptz,
    revoked_at      timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    UNIQUE (token_sha256)
);

CREATE TABLE scan_jobs (
    id                  uuid PRIMARY KEY,
    organization_id     uuid NOT NULL,
    repository_id       uuid NOT NULL,
    profile_version_id  uuid NOT NULL,
    trigger             text NOT NULL CHECK (trigger IN ('manual', 'schedule', 'push', 'pull_request', 'merge', 'onboarding', 'emergency')),
    priority            int NOT NULL DEFAULT 50 CHECK (priority BETWEEN 0 AND 100),
    status              text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'succeeded', 'partial', 'failed', 'cancelled')),
    ref                 text NOT NULL,
    commit_sha          text NOT NULL DEFAULT '',
    attempts            int NOT NULL DEFAULT 0,
    max_attempts        int NOT NULL DEFAULT 3,
    leased_by           uuid REFERENCES workers(id) ON DELETE SET NULL,
    lease_expires_at    timestamptz,
    requested_by        uuid,
    error               text NOT NULL DEFAULT '',
    findings_new        int NOT NULL DEFAULT 0,
    findings_fixed      int NOT NULL DEFAULT 0,
    gate_failed         boolean NOT NULL DEFAULT false,
    queued_at           timestamptz NOT NULL DEFAULT now(),
    started_at          timestamptz,
    finished_at         timestamptz,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, profile_version_id) REFERENCES scan_profile_versions(organization_id, id)
);
-- Per repository at most one queued job (new triggers coalesce into it)
-- and one running job.
CREATE UNIQUE INDEX scan_jobs_queued_uq ON scan_jobs (repository_id) WHERE status = 'queued';
CREATE UNIQUE INDEX scan_jobs_running_uq ON scan_jobs (repository_id) WHERE status = 'running';
CREATE INDEX scan_jobs_queue_idx ON scan_jobs (priority DESC, queued_at) WHERE status = 'queued';
CREATE INDEX scan_jobs_repo_idx ON scan_jobs (repository_id, queued_at DESC);
CREATE INDEX scan_jobs_org_idx ON scan_jobs (organization_id, queued_at DESC);

CREATE TABLE scan_results (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    scan_job_id     uuid NOT NULL,
    scanner_key     text NOT NULL REFERENCES scanner_catalog(key),
    scanner_version text NOT NULL DEFAULT '',
    status          text NOT NULL CHECK (status IN ('succeeded', 'failed', 'skipped', 'timed_out')),
    duration_ms     int NOT NULL DEFAULT 0,
    findings_count  int NOT NULL DEFAULT 0,
    error           text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (scan_job_id, scanner_key),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, scan_job_id) REFERENCES scan_jobs(organization_id, id) ON DELETE CASCADE
);

-- Raw reports and SBOMs (gzip). Object storage replaces this in Phase 8;
-- callers use the internal/artifacts interface.
CREATE TABLE scan_artifacts (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    scan_result_id  uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('raw', 'sbom')),
    content_type    text NOT NULL,
    sha256          text NOT NULL,
    size_bytes      bigint NOT NULL,
    data_gzip       bytea NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, scan_result_id) REFERENCES scan_results(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX scan_artifacts_result_idx ON scan_artifacts (scan_result_id);
CREATE INDEX scan_artifacts_created_idx ON scan_artifacts (created_at);

CREATE TABLE findings (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL,
    repository_id      uuid NOT NULL,
    fingerprint        text NOT NULL,
    category           text NOT NULL CHECK (category IN ('secrets', 'sast', 'sca', 'iac', 'container', 'license', 'other')),
    scanner_keys       text[] NOT NULL,
    rule_id            text NOT NULL,
    title              text NOT NULL,
    description        text NOT NULL DEFAULT '',
    severity           text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cwe                text[] NOT NULL DEFAULT '{}',
    cve                text NOT NULL DEFAULT '',
    cvss               numeric(3,1),
    package_name       text NOT NULL DEFAULT '',
    package_version    text NOT NULL DEFAULT '',
    fixed_version      text NOT NULL DEFAULT '',
    file_path          text NOT NULL DEFAULT '',
    start_line         int,
    end_line           int,
    status             text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'false_positive', 'accepted_risk', 'in_progress', 'needs_review')),
    first_seen_at      timestamptz NOT NULL DEFAULT now(),
    last_seen_at       timestamptz NOT NULL DEFAULT now(),
    first_scan_job_id  uuid,
    last_scan_job_id   uuid,
    resolved_at        timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repository_id, fingerprint),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX findings_org_status_idx ON findings (organization_id, status, severity);
CREATE INDEX findings_repo_status_idx ON findings (repository_id, status);

-- Append-only history of where a finding was seen.
CREATE TABLE finding_occurrences (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    finding_id      uuid NOT NULL,
    scan_result_id  uuid NOT NULL,
    commit_sha      text NOT NULL DEFAULT '',
    file_path       text NOT NULL DEFAULT '',
    start_line      int,
    end_line        int,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, scan_result_id) REFERENCES scan_results(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX finding_occurrences_finding_idx ON finding_occurrences (finding_id, created_at DESC);

-- The scanner catalog, like the permission catalog, is owned by migrations.
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
    REVOKE INSERT, UPDATE, DELETE ON permissions FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON scanner_catalog FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON goose_db_version FROM pathos_app;
    GRANT EXECUTE ON FUNCTION pathos_ensure_audit_partitions(int) TO pathos_app;
END;
$$;
-- +goose StatementEnd
SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS finding_occurrences;
DROP TABLE IF EXISTS findings;
DROP TABLE IF EXISTS scan_artifacts;
DROP TABLE IF EXISTS scan_results;
DROP TABLE IF EXISTS scan_jobs;
DROP TABLE IF EXISTS workers;
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_scan_profile_fk;
ALTER TABLE repositories DROP COLUMN IF EXISTS scan_profile_id;
DROP TRIGGER IF EXISTS scan_profile_versions_mandatory ON scan_profile_versions;
DROP FUNCTION IF EXISTS pathos_check_mandatory_scanners();
DROP TABLE IF EXISTS profile_scanners;
ALTER TABLE scan_profiles DROP CONSTRAINT IF EXISTS scan_profiles_current_version_fk;
DROP TABLE IF EXISTS scan_profile_versions;
DROP TABLE IF EXISTS scan_profiles;
DROP TABLE IF EXISTS scanner_catalog;
