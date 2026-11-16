-- +goose Up
-- Enterprise repository asset management and onboarding
-- (docs/REPOSITORY_ONBOARDING.md): asset metadata, classification catalogs,
-- GitLab / Bitbucket / OAuth / Entra ID connections, resumable uploads,
-- source snapshots, background import jobs and sync history.

-- ---------------------------------------------------------------------------
-- Classification catalogs and settings
-- ---------------------------------------------------------------------------

CREATE TABLE asset_classifications (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('criticality', 'data_classification', 'environment', 'application_type',
                                                  'internet_exposure', 'compliance', 'hosting_region', 'lifecycle_status')),
    key             text NOT NULL CHECK (key ~ '^[a-z0-9][a-z0-9_]{0,62}$'),
    label           text NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
    color           text NOT NULL DEFAULT '' CHECK (color = '' OR color ~ '^#[0-9a-f]{6}$'),
    sort_order      int NOT NULL DEFAULT 0,
    is_system       boolean NOT NULL DEFAULT false,
    archived_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, kind, key),
    UNIQUE (organization_id, id)
);

CREATE TABLE asset_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    required_fields text[] NOT NULL DEFAULT '{business_owner,technical_owner,business_unit,business_region,criticality,data_classification,environment}',
    scan_on_import  boolean NOT NULL DEFAULT false,
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Applications and tags
-- ---------------------------------------------------------------------------

ALTER TABLE applications ADD COLUMN external_ref text NOT NULL DEFAULT '' CHECK (length(external_ref) <= 100);

ALTER TABLE tags ADD COLUMN description text NOT NULL DEFAULT '' CHECK (length(description) <= 500);
ALTER TABLE tags ADD COLUMN created_by uuid;
ALTER TABLE tags DROP CONSTRAINT tags_color_check;
ALTER TABLE tags ADD CONSTRAINT tags_color_check
    CHECK (color IN ('slate', 'blue', 'green', 'amber', 'red', 'purple', 'teal', 'pink') OR color ~ '^#[0-9a-f]{6}$');

-- ---------------------------------------------------------------------------
-- SCM connections: new providers and authentication methods
-- ---------------------------------------------------------------------------

CREATE TABLE scm_oauth_apps (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    provider        text NOT NULL CHECK (provider IN ('github', 'github_enterprise', 'gitlab', 'bitbucket', 'azure_devops')),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    -- Self-managed servers (GitHub Enterprise, GitLab); '' = provider cloud.
    base_url        text NOT NULL DEFAULT '' CHECK (base_url = '' OR base_url ~ '^https?://'),
    -- Microsoft Entra ID tenant (GUID, domain or 'organizations').
    tenant_id       text NOT NULL DEFAULT '' CHECK (length(tenant_id) <= 100),
    client_id       text NOT NULL CHECK (length(client_id) BETWEEN 1 AND 300),
    secret_id       uuid NOT NULL REFERENCES secrets(id),
    scopes          text NOT NULL DEFAULT '' CHECK (length(scopes) <= 500),
    created_by      uuid,
    archived_at     timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX scm_oauth_apps_name_uq ON scm_oauth_apps (organization_id, lower(name)) WHERE archived_at IS NULL;

ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_provider_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_provider_check
    CHECK (provider IN ('github', 'github_enterprise', 'gitlab', 'bitbucket', 'azure_devops', 'azure_devops_server'));
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_auth_type_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_auth_type_check
    CHECK (auth_type IN ('pat', 'github_app', 'oauth', 'api_token', 'service_principal'));
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_status_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_status_check
    CHECK (status IN ('untested', 'ok', 'error', 'expired', 'revoked'));
ALTER TABLE scm_connections
    ADD COLUMN oauth_app_id      uuid,
    ADD COLUMN account           text NOT NULL DEFAULT '',
    ADD COLUMN token_expires_at  timestamptz,
    -- Azure DevOps service principals: organizations to discover.
    ADD COLUMN organizations     text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT scm_connections_oauth_app_fk FOREIGN KEY (organization_id, oauth_app_id) REFERENCES scm_oauth_apps(organization_id, id),
    ADD CONSTRAINT scm_connections_oauth_ck CHECK ((auth_type = 'oauth') = (oauth_app_id IS NOT NULL)),
    ADD CONSTRAINT scm_connections_auth_provider_ck CHECK (
        (auth_type <> 'api_token' OR provider = 'bitbucket') AND
        (auth_type <> 'service_principal' OR provider = 'azure_devops'));
CREATE INDEX scm_connections_token_expiry_idx ON scm_connections (token_expires_at) WHERE archived_at IS NULL AND token_expires_at IS NOT NULL;

CREATE TABLE scm_oauth_states (
    state_sha256    text PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id         uuid NOT NULL,
    oauth_app_id    uuid NOT NULL,
    pkce_verifier   text NOT NULL,
    connection_name text NOT NULL DEFAULT '',
    owner           text NOT NULL DEFAULT '',
    -- Reconnect: refresh the credential of an existing connection.
    connection_id   uuid,
    return_to       text NOT NULL DEFAULT '/admin/scm',
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, user_id) REFERENCES users(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, oauth_app_id) REFERENCES scm_oauth_apps(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX scm_oauth_states_expiry_idx ON scm_oauth_states (expires_at);

-- ---------------------------------------------------------------------------
-- Uploads and source snapshots
-- ---------------------------------------------------------------------------

CREATE TABLE source_uploads (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by      uuid NOT NULL,
    filename        text NOT NULL CHECK (length(filename) BETWEEN 1 AND 255),
    format          text NOT NULL CHECK (format IN ('zip', 'tar', 'tar.gz')),
    declared_size   bigint NOT NULL CHECK (declared_size > 0),
    declared_sha256 text NOT NULL CHECK (declared_sha256 ~ '^[0-9a-f]{64}$'),
    chunk_size      int NOT NULL CHECK (chunk_size > 0),
    status          text NOT NULL DEFAULT 'uploading' CHECK (status IN ('uploading', 'complete', 'consumed', 'expired', 'cancelled')),
    expires_at      timestamptz NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    completed_at    timestamptz,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, created_by) REFERENCES users(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX source_uploads_expiry_idx ON source_uploads (expires_at) WHERE status IN ('uploading', 'complete');

CREATE TABLE source_upload_parts (
    upload_id   uuid NOT NULL REFERENCES source_uploads(id) ON DELETE CASCADE,
    part_number int NOT NULL CHECK (part_number >= 0),
    size_bytes  int NOT NULL CHECK (size_bytes > 0),
    sha256      text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    object_key  text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (upload_id, part_number)
);

CREATE TABLE source_snapshots (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id      uuid,
    object_key         text NOT NULL UNIQUE,
    archive_filename   text NOT NULL DEFAULT '',
    archive_sha256     text NOT NULL CHECK (archive_sha256 ~ '^[0-9a-f]{64}$'),
    archive_size       bigint NOT NULL,
    snapshot_sha256    text NOT NULL CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    snapshot_size      bigint NOT NULL,
    uncompressed_bytes bigint NOT NULL,
    file_count         int NOT NULL,
    languages          jsonb NOT NULL DEFAULT '{}'::jsonb,
    manifests          text[] NOT NULL DEFAULT '{}',
    skipped            jsonb NOT NULL DEFAULT '{}'::jsonb,
    malware_scan       text NOT NULL CHECK (malware_scan IN ('clean', 'not_configured', 'unavailable')),
    malware_engine     text NOT NULL DEFAULT '',
    created_by         uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX source_snapshots_repo_idx ON source_snapshots (repository_id, created_at DESC);
CREATE INDEX source_snapshots_sha_idx ON source_snapshots (organization_id, archive_sha256);

-- ---------------------------------------------------------------------------
-- Repositories: source type and enterprise asset metadata
-- ---------------------------------------------------------------------------

ALTER TABLE repositories ALTER COLUMN scm_connection_id DROP NOT NULL;
ALTER TABLE repositories DROP CONSTRAINT repositories_environment_check;
ALTER TABLE repositories
    ADD COLUMN source_type          text NOT NULL DEFAULT 'scm' CHECK (source_type IN ('scm', 'upload')),
    ADD COLUMN scm_organization     text NOT NULL DEFAULT '',
    ADD COLUMN scm_project          text NOT NULL DEFAULT '',
    ADD COLUMN display_name         text NOT NULL DEFAULT '' CHECK (length(display_name) <= 200),
    ADD COLUMN asset_name           text NOT NULL DEFAULT '' CHECK (length(asset_name) <= 200),
    ADD COLUMN business_purpose     text NOT NULL DEFAULT '' CHECK (length(business_purpose) <= 2000),
    ADD COLUMN application_type     text NOT NULL DEFAULT '',
    ADD COLUMN business_owner_id    uuid,
    ADD COLUMN technical_owner_id   uuid,
    ADD COLUMN application_owner_id uuid,
    ADD COLUMN responsible_team_id  uuid,
    ADD COLUMN supporting_team_id   uuid,
    ADD COLUMN department_id        uuid,
    ADD COLUMN cost_centre          text NOT NULL DEFAULT '' CHECK (length(cost_centre) <= 100),
    ADD COLUMN business_region_id   uuid,
    ADD COLUMN data_residency_region_id uuid,
    ADD COLUMN hosting_region       text NOT NULL DEFAULT '',
    ADD COLUMN operational_location text NOT NULL DEFAULT '' CHECK (length(operational_location) <= 200),
    ADD COLUMN data_classification  text NOT NULL DEFAULT '',
    ADD COLUMN internet_exposure    text NOT NULL DEFAULT 'unknown',
    ADD COLUMN lifecycle_status     text NOT NULL DEFAULT 'active',
    ADD COLUMN go_live_date         date,
    ADD COLUMN retirement_date      date,
    ADD COLUMN color                text NOT NULL DEFAULT '' CHECK (color = '' OR color ~ '^#[0-9a-f]{6}$'),
    ADD COLUMN full_history         boolean NOT NULL DEFAULT false,
    ADD COLUMN latest_commit_sha    text NOT NULL DEFAULT '',
    ADD COLUMN latest_commit_at     timestamptz,
    ADD COLUMN size_bytes           bigint,
    ADD COLUMN file_count           int,
    ADD COLUMN languages            jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN last_sync_at         timestamptz,
    ADD COLUMN last_sync_ok_at      timestamptz,
    ADD COLUMN sync_status          text NOT NULL DEFAULT 'never'
        CHECK (sync_status IN ('never', 'ok', 'failed', 'missing', 'permission_denied', 'archived_upstream')),
    ADD COLUMN sync_error           text NOT NULL DEFAULT '',
    ADD COLUMN current_snapshot_id  uuid,
    ADD COLUMN updated_by           uuid,
    ADD CONSTRAINT repositories_environment_ck CHECK (environment ~ '^[a-z0-9][a-z0-9_]{0,62}$'),
    ADD CONSTRAINT repositories_source_ck CHECK ((source_type = 'scm') = (scm_connection_id IS NOT NULL)),
    ADD CONSTRAINT repositories_dates_ck CHECK (retirement_date IS NULL OR go_live_date IS NULL OR retirement_date >= go_live_date),
    ADD CONSTRAINT repositories_business_owner_fk FOREIGN KEY (organization_id, business_owner_id) REFERENCES users(organization_id, id),
    ADD CONSTRAINT repositories_technical_owner_fk FOREIGN KEY (organization_id, technical_owner_id) REFERENCES users(organization_id, id),
    ADD CONSTRAINT repositories_application_owner_fk FOREIGN KEY (organization_id, application_owner_id) REFERENCES users(organization_id, id),
    ADD CONSTRAINT repositories_responsible_team_fk FOREIGN KEY (organization_id, responsible_team_id) REFERENCES teams(organization_id, id),
    ADD CONSTRAINT repositories_supporting_team_fk FOREIGN KEY (organization_id, supporting_team_id) REFERENCES teams(organization_id, id),
    ADD CONSTRAINT repositories_department_fk FOREIGN KEY (organization_id, department_id) REFERENCES business_units(organization_id, id),
    ADD CONSTRAINT repositories_business_region_fk FOREIGN KEY (organization_id, business_region_id) REFERENCES regions(organization_id, id),
    ADD CONSTRAINT repositories_residency_region_fk FOREIGN KEY (organization_id, data_residency_region_id) REFERENCES regions(organization_id, id),
    ADD CONSTRAINT repositories_snapshot_fk FOREIGN KEY (organization_id, current_snapshot_id) REFERENCES source_snapshots(organization_id, id);
-- Legacy repositories: the business region follows the country.
UPDATE repositories r SET business_region_id = c.region_id FROM countries c WHERE c.id = r.country_id;

CREATE UNIQUE INDEX repositories_asset_name_uq ON repositories (organization_id, lower(asset_name))
    WHERE asset_name <> '' AND archived_at IS NULL;
CREATE INDEX repositories_business_owner_idx ON repositories (business_owner_id);
CREATE INDEX repositories_technical_owner_idx ON repositories (technical_owner_id);
CREATE INDEX repositories_application_owner_idx ON repositories (application_owner_id);
CREATE INDEX repositories_responsible_team_idx ON repositories (responsible_team_id);
CREATE INDEX repositories_business_region_idx ON repositories (business_region_id);
CREATE INDEX repositories_classification_idx ON repositories (organization_id, data_classification);
CREATE INDEX repositories_lifecycle_idx ON repositories (organization_id, lifecycle_status);
CREATE INDEX repositories_sync_status_idx ON repositories (organization_id, sync_status);
CREATE INDEX repositories_source_idx ON repositories (organization_id, source_type);
CREATE INDEX repositories_created_idx ON repositories (organization_id, created_at, id);
CREATE INDEX repositories_clone_url_idx ON repositories (organization_id, lower(clone_url)) WHERE clone_url <> '';

CREATE TABLE repository_compliance_scopes (
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    scope_key       text NOT NULL CHECK (scope_key ~ '^[a-z0-9][a-z0-9_]{0,62}$'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, scope_key),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX repository_compliance_scope_idx ON repository_compliance_scopes (organization_id, scope_key);

-- ---------------------------------------------------------------------------
-- Import engine
-- ---------------------------------------------------------------------------

CREATE TABLE repository_import_jobs (
    id                  uuid PRIMARY KEY,
    organization_id     uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    source_type         text NOT NULL CHECK (source_type IN ('upload', 'git', 'devops')),
    scm_connection_id   uuid,
    status              text NOT NULL DEFAULT 'queued' CHECK (status IN ('draft', 'pending', 'queued', 'validating', 'importing',
                                                      'registering', 'completed', 'failed', 'cancelled', 'needs_attention')),
    requested_by        uuid NOT NULL,
    idempotency_key     text CHECK (idempotency_key IS NULL OR length(idempotency_key) BETWEEN 8 AND 100),
    total_items         int NOT NULL DEFAULT 0,
    start_scan          boolean NOT NULL DEFAULT false,
    cancel_requested_at timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    started_at          timestamptz,
    completed_at        timestamptz,
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, scm_connection_id) REFERENCES scm_connections(organization_id, id),
    FOREIGN KEY (organization_id, requested_by) REFERENCES users(organization_id, id)
);
CREATE UNIQUE INDEX repository_import_jobs_idem_uq ON repository_import_jobs (organization_id, requested_by, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
CREATE INDEX repository_import_jobs_org_idx ON repository_import_jobs (organization_id, created_at DESC, id);
CREATE INDEX repository_import_jobs_user_idx ON repository_import_jobs (requested_by, created_at DESC);

CREATE TABLE repository_import_items (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL,
    job_id            uuid NOT NULL,
    position          int NOT NULL,
    source_ref        jsonb NOT NULL,
    display_name      text NOT NULL,
    metadata          jsonb NOT NULL,
    status            text NOT NULL DEFAULT 'queued' CHECK (status IN ('draft', 'pending', 'queued', 'validating', 'importing',
                                                    'registering', 'completed', 'failed', 'cancelled', 'needs_attention')),
    result            text NOT NULL DEFAULT '' CHECK (result IN ('', 'imported', 'already_imported', 'snapshot_added')),
    -- Last processing stage reached (shows where a failed item stopped).
    stage             text NOT NULL DEFAULT 'queued' CHECK (stage IN ('queued', 'validating', 'importing', 'registering', 'completed')),
    progress          int NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
    progress_message  text NOT NULL DEFAULT '',
    repository_id     uuid,
    snapshot_id       uuid,
    attempts          int NOT NULL DEFAULT 0,
    max_attempts      int NOT NULL DEFAULT 3,
    next_attempt_at   timestamptz NOT NULL DEFAULT now(),
    lease_owner       text NOT NULL DEFAULT '',
    lease_expires_at  timestamptz,
    allow_duplicate   boolean NOT NULL DEFAULT false,
    error_code        text NOT NULL DEFAULT '',
    error_message     text NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT now(),
    started_at        timestamptz,
    completed_at      timestamptz,
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (job_id, position),
    FOREIGN KEY (organization_id, job_id) REFERENCES repository_import_jobs(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE SET NULL (repository_id),
    FOREIGN KEY (organization_id, snapshot_id) REFERENCES source_snapshots(organization_id, id) ON DELETE SET NULL (snapshot_id)
);
CREATE INDEX repository_import_items_queue_idx ON repository_import_items (next_attempt_at) WHERE status = 'queued';
CREATE INDEX repository_import_items_running_idx ON repository_import_items (lease_expires_at)
    WHERE status IN ('validating', 'importing', 'registering');
CREATE INDEX repository_import_items_job_idx ON repository_import_items (job_id, position);
CREATE INDEX repository_import_items_repo_idx ON repository_import_items (repository_id);

-- An upload is consumed by at most one active import item.
CREATE UNIQUE INDEX repository_import_items_upload_uq ON repository_import_items ((source_ref->>'upload_id'))
    WHERE source_ref ? 'upload_id' AND status NOT IN ('failed', 'cancelled');

ALTER TABLE source_snapshots ADD COLUMN import_item_id uuid REFERENCES repository_import_items(id) ON DELETE SET NULL;

-- ---------------------------------------------------------------------------
-- Synchronization history
-- ---------------------------------------------------------------------------

CREATE TABLE repository_sync_runs (
    id                  uuid PRIMARY KEY,
    organization_id     uuid NOT NULL,
    repository_id       uuid NOT NULL,
    trigger             text NOT NULL CHECK (trigger IN ('manual', 'schedule', 'webhook', 'import', 'upload')),
    status              text NOT NULL CHECK (status IN ('ok', 'failed', 'missing', 'permission_denied', 'archived_upstream')),
    branch              text NOT NULL DEFAULT '',
    previous_commit_sha text NOT NULL DEFAULT '',
    commit_sha          text NOT NULL DEFAULT '',
    changed             boolean NOT NULL DEFAULT false,
    error               text NOT NULL DEFAULT '',
    triggered_by        uuid,
    started_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX repository_sync_runs_repo_idx ON repository_sync_runs (repository_id, started_at DESC);
CREATE INDEX repository_sync_runs_time_idx ON repository_sync_runs (started_at);

-- ---------------------------------------------------------------------------
-- Scans of uploaded snapshots
-- ---------------------------------------------------------------------------

ALTER TABLE scan_jobs ADD COLUMN snapshot_id uuid;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_snapshot_fk
    FOREIGN KEY (organization_id, snapshot_id) REFERENCES source_snapshots(organization_id, id) ON DELETE SET NULL (snapshot_id);
CREATE INDEX scan_jobs_snapshot_idx ON scan_jobs (snapshot_id) WHERE snapshot_id IS NOT NULL;

-- ---------------------------------------------------------------------------
-- Notifications and permissions
-- ---------------------------------------------------------------------------

-- New permissions. pathosctl migrate re-synchronizes descriptions from the
-- Go catalog; the rows must exist here so existing custom roles that could
-- manage tags (repos.manage) keep that ability.
INSERT INTO permissions (key, category, description, org_only, sort_order) VALUES
    ('tags.manage', 'Assets', 'Create, edit and delete tags and tag categories', true, 0),
    ('assets.configure', 'Assets', 'Configure asset classifications, required fields and colours', true, 0)
ON CONFLICT (key) DO NOTHING;
INSERT INTO role_permissions (role_id, permission_key)
SELECT DISTINCT rp.role_id, 'tags.manage' FROM role_permissions rp
JOIN roles r ON r.id = rp.role_id
WHERE rp.permission_key = 'repos.manage' AND NOT r.is_system
ON CONFLICT DO NOTHING;

SELECT pathos_apply_app_grants();

-- +goose Down
DELETE FROM role_permissions WHERE permission_key IN ('tags.manage', 'assets.configure');
DELETE FROM permissions WHERE key IN ('tags.manage', 'assets.configure');

DROP INDEX IF EXISTS scan_jobs_snapshot_idx;
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_snapshot_fk;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS snapshot_id;

DROP TABLE IF EXISTS repository_sync_runs;
ALTER TABLE source_snapshots DROP COLUMN IF EXISTS import_item_id;
DROP TABLE IF EXISTS repository_import_items;
DROP TABLE IF EXISTS repository_import_jobs;
DROP TABLE IF EXISTS repository_compliance_scopes;

-- Uploaded repositories cannot exist without an SCM connection in the
-- previous schema.
DELETE FROM repositories WHERE source_type = 'upload';
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_snapshot_fk;
DROP INDEX IF EXISTS repositories_asset_name_uq;
ALTER TABLE repositories
    DROP CONSTRAINT IF EXISTS repositories_environment_ck,
    DROP CONSTRAINT IF EXISTS repositories_source_ck,
    DROP CONSTRAINT IF EXISTS repositories_dates_ck,
    DROP COLUMN IF EXISTS source_type, DROP COLUMN IF EXISTS scm_organization, DROP COLUMN IF EXISTS scm_project,
    DROP COLUMN IF EXISTS display_name, DROP COLUMN IF EXISTS asset_name, DROP COLUMN IF EXISTS business_purpose,
    DROP COLUMN IF EXISTS application_type, DROP COLUMN IF EXISTS business_owner_id, DROP COLUMN IF EXISTS technical_owner_id,
    DROP COLUMN IF EXISTS application_owner_id, DROP COLUMN IF EXISTS responsible_team_id, DROP COLUMN IF EXISTS supporting_team_id,
    DROP COLUMN IF EXISTS department_id, DROP COLUMN IF EXISTS cost_centre, DROP COLUMN IF EXISTS business_region_id,
    DROP COLUMN IF EXISTS data_residency_region_id, DROP COLUMN IF EXISTS hosting_region, DROP COLUMN IF EXISTS operational_location,
    DROP COLUMN IF EXISTS data_classification, DROP COLUMN IF EXISTS internet_exposure, DROP COLUMN IF EXISTS lifecycle_status,
    DROP COLUMN IF EXISTS go_live_date, DROP COLUMN IF EXISTS retirement_date, DROP COLUMN IF EXISTS color,
    DROP COLUMN IF EXISTS full_history, DROP COLUMN IF EXISTS latest_commit_sha, DROP COLUMN IF EXISTS latest_commit_at,
    DROP COLUMN IF EXISTS size_bytes, DROP COLUMN IF EXISTS file_count, DROP COLUMN IF EXISTS languages,
    DROP COLUMN IF EXISTS last_sync_at, DROP COLUMN IF EXISTS last_sync_ok_at, DROP COLUMN IF EXISTS sync_status,
    DROP COLUMN IF EXISTS sync_error, DROP COLUMN IF EXISTS current_snapshot_id, DROP COLUMN IF EXISTS updated_by;
UPDATE repositories SET environment = 'other' WHERE environment NOT IN ('production', 'staging', 'development', 'test', 'other');
ALTER TABLE repositories ADD CONSTRAINT repositories_environment_check
    CHECK (environment IN ('production', 'staging', 'development', 'test', 'other'));
ALTER TABLE repositories ALTER COLUMN scm_connection_id SET NOT NULL;
DROP INDEX IF EXISTS repositories_clone_url_idx;
DROP INDEX IF EXISTS repositories_created_idx;

DROP TABLE IF EXISTS source_snapshots;
DROP TABLE IF EXISTS source_upload_parts;
DROP TABLE IF EXISTS source_uploads;
DROP TABLE IF EXISTS scm_oauth_states;

-- Connections of the new kinds (and their repositories) cannot be
-- represented by the previous schema.
DELETE FROM repositories WHERE scm_connection_id IN
    (SELECT id FROM scm_connections WHERE provider IN ('gitlab', 'bitbucket') OR auth_type IN ('oauth', 'api_token', 'service_principal'));
DELETE FROM scm_connections WHERE provider IN ('gitlab', 'bitbucket') OR auth_type IN ('oauth', 'api_token', 'service_principal');
ALTER TABLE scm_connections
    DROP CONSTRAINT IF EXISTS scm_connections_oauth_app_fk,
    DROP CONSTRAINT IF EXISTS scm_connections_oauth_ck,
    DROP CONSTRAINT IF EXISTS scm_connections_auth_provider_ck,
    DROP COLUMN IF EXISTS oauth_app_id, DROP COLUMN IF EXISTS account,
    DROP COLUMN IF EXISTS token_expires_at, DROP COLUMN IF EXISTS organizations;
UPDATE scm_connections SET status = 'error' WHERE status IN ('expired', 'revoked');
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_provider_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_provider_check
    CHECK (provider IN ('github', 'github_enterprise', 'azure_devops', 'azure_devops_server'));
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_auth_type_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_auth_type_check CHECK (auth_type IN ('pat', 'github_app'));
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_status_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_status_check CHECK (status IN ('untested', 'ok', 'error'));
DROP TABLE IF EXISTS scm_oauth_apps;

ALTER TABLE tags DROP CONSTRAINT tags_color_check;
UPDATE tags SET color = 'slate' WHERE color LIKE '#%';
ALTER TABLE tags ADD CONSTRAINT tags_color_check CHECK (color IN ('slate', 'blue', 'green', 'amber', 'red', 'purple', 'teal', 'pink'));
ALTER TABLE tags DROP COLUMN IF EXISTS created_by;
ALTER TABLE tags DROP COLUMN IF EXISTS description;
ALTER TABLE applications DROP COLUMN IF EXISTS external_ref;

DROP TABLE IF EXISTS asset_settings;
DROP TABLE IF EXISTS asset_classifications;
