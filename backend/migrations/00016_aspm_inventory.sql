-- +goose Up
-- ASPM phase 3: dependency graph and SCM inventory.

-- Dependency graph of each repository's SBOM. bom_ref is the component's
-- identifier in the SBOM; depth is its shortest distance from a root
-- (0 root, 1 direct dependency, 2+ transitive; NULL = no dependency data).
ALTER TABLE sbom_components ADD COLUMN bom_ref text NOT NULL DEFAULT '' CHECK (length(bom_ref) <= 1000),
                            ADD COLUMN depth integer CHECK (depth >= 0);
CREATE INDEX sbom_components_ref_idx ON sbom_components (repository_id, bom_ref) WHERE bom_ref <> '';

CREATE TABLE sbom_dependencies (
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    parent_ref      text NOT NULL CHECK (length(parent_ref) <= 1000),
    child_ref       text NOT NULL CHECK (length(child_ref) <= 1000),
    PRIMARY KEY (repository_id, parent_ref, child_ref),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX sbom_dependencies_child_idx ON sbom_dependencies (repository_id, child_ref);

-- What each SCM connection can see, refreshed by the jobs service. The
-- unmanaged-asset report compares it with the repositories in PATHOS.
CREATE TABLE scm_remote_repositories (
    organization_id   uuid NOT NULL,
    scm_connection_id uuid NOT NULL,
    external_id       text NOT NULL CHECK (length(external_id) <= 200),
    full_name         text NOT NULL CHECK (length(full_name) <= 500),
    url               text NOT NULL DEFAULT '' CHECK (length(url) <= 1000),
    visibility        text NOT NULL DEFAULT '' CHECK (length(visibility) <= 20),
    archived          boolean NOT NULL DEFAULT false,
    pushed_at         timestamptz,
    scm_organization  text NOT NULL DEFAULT '' CHECK (length(scm_organization) <= 200),
    scm_project       text NOT NULL DEFAULT '' CHECK (length(scm_project) <= 200),
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scm_connection_id, external_id),
    FOREIGN KEY (organization_id, scm_connection_id) REFERENCES scm_connections(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX scm_remote_repositories_org_idx ON scm_remote_repositories (organization_id, pushed_at DESC);

CREATE TABLE scm_inventory_runs (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL,
    scm_connection_id uuid NOT NULL,
    started_at        timestamptz NOT NULL DEFAULT now(),
    finished_at       timestamptz,
    status            text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'failed')),
    repositories      integer NOT NULL DEFAULT 0,
    truncated         boolean NOT NULL DEFAULT false,
    error             text NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    FOREIGN KEY (organization_id, scm_connection_id) REFERENCES scm_connections(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX scm_inventory_runs_conn_idx ON scm_inventory_runs (scm_connection_id, started_at DESC);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS scm_inventory_runs;
DROP TABLE IF EXISTS scm_remote_repositories;
DROP TABLE IF EXISTS sbom_dependencies;
DROP INDEX IF EXISTS sbom_components_ref_idx;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS depth, DROP COLUMN IF EXISTS bom_ref;
