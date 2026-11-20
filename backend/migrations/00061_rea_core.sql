-- +goose Up
-- PATHOS 3.0 M10 reverse engineering, static tier
-- (docs/aspm/PATHOS_REVERSE_ENGINEERING.md, ADR-009). An analysis is a scan
-- execution with trigger "rea" of an uploaded build artifact (scan target
-- of kind artifact or mobile-app), leased only by worker-rea workers, whose
-- analyser runs in the sandbox runner. By default only artifacts PATHOS can
-- tie to its own builds are analysed: a verified signature or a verified
-- SLSA provenance attestation (signature_verifications, cosign); anything
-- else needs an explicit, audited per-artifact authorisation with a reason.
-- All tables carry organization_id, so pathos_apply_app_grants() gives each
-- the standard tenant policy (docs/MULTI_TENANCY.md).

ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_trigger_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'push', 'pull_request', 'merge', 'onboarding', 'emergency', 'import', 'codegraph', 'rea'));

-- Reverse engineering has its own queue lane: an analysis (minutes to an
-- hour) neither waits for nor blocks the repository's scans, so one running
-- execution per repository and lane.
DROP INDEX scan_jobs_running_uq;
CREATE UNIQUE INDEX scan_jobs_running_uq ON scan_jobs (repository_id, (trigger = 'rea')) WHERE status = 'running';

-- A build artifact's SLSA provenance attestation (a Sigstore bundle made
-- with `cosign attest-blob`), verified with cosign against the target's
-- signature policy like the artifact signature itself.
ALTER TABLE scan_targets ADD COLUMN provenance_material text CHECK (length(provenance_material) <= 262144);

-- Organization settings (Configurations > Reverse engineering tools).
-- Without a row the defaults apply: radare2 and binwalk, 4096 MiB, 30
-- minutes, own builds or explicitly authorised artifacts, no AI model may
-- see decompiled code.
CREATE TABLE rea_settings (
    organization_id    uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    enabled_tools      text[] NOT NULL DEFAULT ARRAY['radare2', 'binwalk']::text[]
                       CHECK (enabled_tools <@ ARRAY['radare2', 'binwalk', 'ghidra', 'jadx', 'ilspy']::text[]),
    memory_mb          integer NOT NULL DEFAULT 4096 CHECK (memory_mb BETWEEN 512 AND 16384),
    timeout_minutes    integer NOT NULL DEFAULT 30 CHECK (timeout_minutes BETWEEN 5 AND 230),
    -- own_builds_or_authorized: own builds, other artifacts only with a
    -- per-artifact authorisation; own_builds_only: no authorisations.
    input_policy       text NOT NULL DEFAULT 'own_builds_or_authorized'
                       CHECK (input_policy IN ('own_builds_or_authorized', 'own_builds_only')),
    -- Which AI model may see decompiled code: none, local (self-hosted
    -- providers only) or cloud (also needs the AI configuration's
    -- send_code_context).
    decompiled_code_ai text NOT NULL DEFAULT 'none' CHECK (decompiled_code_ai IN ('none', 'local', 'cloud')),
    updated_by         uuid,
    updated_at         timestamptz NOT NULL DEFAULT now()
);

-- "Analyse untrusted artifact": one active authorisation per artifact
-- target, bound to the artifact's SHA-256, with a reason (audited).
CREATE TABLE rea_authorizations (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id       uuid NOT NULL,
    artifact_sha256 text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    reason          text NOT NULL CHECK (length(reason) BETWEEN 10 AND 1000),
    authorized_by   uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    revoked_at      timestamptz,
    revoked_by      uuid,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, target_id) REFERENCES scan_targets(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, authorized_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (authorized_by),
    FOREIGN KEY (organization_id, revoked_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (revoked_by)
);
CREATE UNIQUE INDEX rea_authorizations_active_uq ON rea_authorizations (target_id) WHERE revoked_at IS NULL;

CREATE TABLE rea_analyses (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_id          uuid NOT NULL,
    repository_id      uuid NOT NULL,
    application_id     uuid,
    scan_job_id        uuid,
    artifact_name      text NOT NULL DEFAULT '' CHECK (length(artifact_name) <= 255),
    artifact_sha256    text NOT NULL CHECK (artifact_sha256 ~ '^[0-9a-f]{64}$'),
    -- Why the artifact was accepted (the input policy).
    trust_basis        text NOT NULL CHECK (trust_basis IN ('signature', 'provenance', 'authorization')),
    authorization_id   uuid,
    trust_detail       jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(trust_detail) = 'object' AND pg_column_size(trust_detail) <= 16384),
    status             text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'ready', 'partial', 'failed')),
    -- The source commit the binary was built from: provenance (verified
    -- attestation), binary (build information embedded in the artifact),
    -- user (chosen by a person).
    commit_sha         text NOT NULL DEFAULT '' CHECK (commit_sha = '' OR commit_sha ~ '^[0-9a-f]{7,64}$'),
    commit_source      text NOT NULL DEFAULT '' CHECK (commit_source IN ('', 'provenance', 'binary', 'user')),
    snapshot_id        uuid,
    source_snapshot_id uuid,
    diff_status        text NOT NULL DEFAULT 'pending' CHECK (diff_status IN ('pending', 'ready', 'no_commit', 'no_source_snapshot')),
    format             text NOT NULL DEFAULT '' CHECK (length(format) <= 32),
    arch               text NOT NULL DEFAULT '' CHECK (length(arch) <= 32),
    language           text NOT NULL DEFAULT '' CHECK (length(language) <= 32),
    tools              jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(tools) = 'object' AND pg_column_size(tools) <= 16384),
    stats              jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(stats) = 'object' AND pg_column_size(stats) <= 65536),
    error_code         text NOT NULL DEFAULT '' CHECK (error_code = '' OR error_code ~ '^PTH-[A-Z]+-[0-9]{4}$'),
    error              text NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    requested_by       uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    started_at         timestamptz,
    finished_at        timestamptz,
    UNIQUE (organization_id, id),
    CHECK (trust_basis <> 'authorization' OR authorization_id IS NOT NULL),
    FOREIGN KEY (organization_id, target_id) REFERENCES scan_targets(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE SET NULL (application_id),
    FOREIGN KEY (organization_id, scan_job_id) REFERENCES scan_jobs(organization_id, id) ON DELETE SET NULL (scan_job_id),
    FOREIGN KEY (organization_id, authorization_id) REFERENCES rea_authorizations(organization_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (organization_id, requested_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (requested_by)
);
CREATE INDEX rea_analyses_target_idx ON rea_analyses (organization_id, target_id, created_at DESC);
CREATE INDEX rea_analyses_repo_idx ON rea_analyses (organization_id, repository_id, created_at DESC);
CREATE UNIQUE INDEX rea_analyses_job_uq ON rea_analyses (scan_job_id) WHERE scan_job_id IS NOT NULL;

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS rea_analyses;
DROP TABLE IF EXISTS rea_authorizations;
DROP TABLE IF EXISTS rea_settings;
ALTER TABLE scan_targets DROP COLUMN IF EXISTS provenance_material;
DELETE FROM scan_jobs WHERE trigger = 'rea';
DROP INDEX scan_jobs_running_uq;
CREATE UNIQUE INDEX scan_jobs_running_uq ON scan_jobs (repository_id) WHERE status = 'running';
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_trigger_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'push', 'pull_request', 'merge', 'onboarding', 'emergency', 'import', 'codegraph'));
