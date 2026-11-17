-- +goose Up
-- ASPM phase 2b: scan targets beyond source code. A target belongs to a
-- repository (and so inherits its application, owners, criticality and
-- exposure): a container image, a web application URL (DAST), an API
-- described by an OpenAPI document, or an imported SBOM. Findings remember
-- their target, so auto-resolution and de-duplication stay per target.

ALTER TABLE secrets DROP CONSTRAINT secrets_kind_check;
ALTER TABLE secrets ADD CONSTRAINT secrets_kind_check CHECK (kind IN ('scm', 'ai', 'mcp', 'smtp', 'webhook', 'worker', 'scan_target'));

CREATE TABLE scan_targets (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id      uuid NOT NULL,
    kind               text NOT NULL CHECK (kind IN ('image', 'url', 'api', 'sbom')),
    name               text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    -- image: registry reference; url and api: base URL; sbom: file name.
    reference          text NOT NULL CHECK (length(reference) BETWEEN 1 AND 1000),
    -- Host the worker must reach through the egress proxy ("" = none).
    egress_host        text NOT NULL DEFAULT '' CHECK (length(egress_host) <= 255),
    config             jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(config) = 'object' AND pg_column_size(config) <= 8192),
    api_spec           text CHECK (length(api_spec) <= 2097152),
    sbom_gzip          bytea,
    sbom_format        text NOT NULL DEFAULT '' CHECK (sbom_format IN ('', 'cyclonedx', 'spdx')),
    sbom_sha256        text NOT NULL DEFAULT '',
    sbom_size          bigint NOT NULL DEFAULT 0,
    sbom_components    integer NOT NULL DEFAULT 0,
    auth_type          text NOT NULL DEFAULT 'none' CHECK (auth_type IN ('none', 'basic', 'header')),
    auth_username      text NOT NULL DEFAULT '' CHECK (length(auth_username) <= 300),
    auth_header_name   text NOT NULL DEFAULT '' CHECK (length(auth_header_name) <= 100),
    secret_id          uuid REFERENCES secrets(id),
    -- Testing a running application needs the owner's permission.
    authorized_by      uuid,
    authorized_at      timestamptz,
    authorization_note text NOT NULL DEFAULT '' CHECK (length(authorization_note) <= 2000),
    enabled            boolean NOT NULL DEFAULT true,
    created_by         uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    CHECK (kind NOT IN ('url', 'api') OR authorized_at IS NOT NULL),
    CHECK (kind <> 'api' OR api_spec IS NOT NULL),
    CHECK (kind <> 'sbom' OR sbom_gzip IS NOT NULL)
);
CREATE UNIQUE INDEX scan_targets_ref_uq ON scan_targets (repository_id, kind, lower(reference));
CREATE INDEX scan_targets_org_idx ON scan_targets (organization_id, kind);

ALTER TABLE scan_jobs ADD COLUMN target_id uuid, ADD COLUMN target_kind text NOT NULL DEFAULT 'repository'
    CHECK (target_kind IN ('repository', 'image', 'url', 'api', 'sbom'));
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_target_fk FOREIGN KEY (organization_id, target_id)
    REFERENCES scan_targets(organization_id, id) ON DELETE SET NULL (target_id);
CREATE INDEX scan_jobs_target_idx ON scan_jobs (target_id, queued_at DESC) WHERE target_id IS NOT NULL;
-- One queued execution per repository, profile version and target.
DROP INDEX scan_jobs_queued_uq;
CREATE UNIQUE INDEX scan_jobs_queued_uq ON scan_jobs (repository_id, profile_version_id, COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE status = 'queued';

ALTER TABLE findings ADD COLUMN scan_target_id uuid;
ALTER TABLE findings ADD CONSTRAINT findings_scan_target_fk FOREIGN KEY (organization_id, scan_target_id)
    REFERENCES scan_targets(organization_id, id);
CREATE INDEX findings_target_idx ON findings (scan_target_id) WHERE scan_target_id IS NOT NULL;

SELECT pathos_apply_app_grants();

-- +goose Down
DROP INDEX IF EXISTS findings_target_idx;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_scan_target_fk;
ALTER TABLE findings DROP COLUMN IF EXISTS scan_target_id;
DELETE FROM scan_jobs WHERE target_kind <> 'repository';
DROP INDEX IF EXISTS scan_jobs_queued_uq;
CREATE UNIQUE INDEX scan_jobs_queued_uq ON scan_jobs (repository_id, profile_version_id) WHERE status = 'queued';
DROP INDEX IF EXISTS scan_jobs_target_idx;
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_target_fk;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS target_kind, DROP COLUMN IF EXISTS target_id;
DROP TABLE IF EXISTS scan_targets;
DELETE FROM secrets WHERE kind = 'scan_target';
ALTER TABLE secrets DROP CONSTRAINT secrets_kind_check;
ALTER TABLE secrets ADD CONSTRAINT secrets_kind_check CHECK (kind IN ('scm', 'ai', 'mcp', 'smtp', 'webhook', 'worker'));
