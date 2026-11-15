-- +goose Up
-- Phase 3: SCM connections, applications, repositories, tags, webhooks.

CREATE TABLE scm_connections (
    id                   uuid PRIMARY KEY,
    organization_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                 text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    provider             text NOT NULL CHECK (provider IN ('github', 'github_enterprise', 'azure_devops', 'azure_devops_server')),
    -- API base URL: https://api.github.com, https://ghe.example.com/api/v3,
    -- https://dev.azure.com/<org>, https://ado.example.com/<collection>
    base_url             text NOT NULL CHECK (base_url ~ '^https?://'),
    auth_type            text NOT NULL CHECK (auth_type IN ('pat', 'github_app')),
    -- GitHub: optional org/user to limit discovery to. Azure DevOps: optional project.
    owner                text NOT NULL DEFAULT '',
    github_app_id        bigint,
    github_installation_id bigint,
    secret_id            uuid NOT NULL REFERENCES secrets(id),
    webhook_secret_id    uuid NOT NULL REFERENCES secrets(id),
    status               text NOT NULL DEFAULT 'untested' CHECK (status IN ('untested', 'ok', 'error')),
    status_message       text NOT NULL DEFAULT '',
    last_checked_at      timestamptz,
    created_by           uuid,
    archived_at          timestamptz,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    CHECK (auth_type <> 'github_app' OR (provider IN ('github', 'github_enterprise') AND github_app_id IS NOT NULL AND github_installation_id IS NOT NULL))
);
CREATE UNIQUE INDEX scm_connections_name_uq ON scm_connections (organization_id, lower(name)) WHERE archived_at IS NULL;

CREATE TABLE applications (
    id                     uuid PRIMARY KEY,
    organization_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name                   text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description            text NOT NULL DEFAULT '',
    business_unit_id       uuid,
    owner_user_id          uuid,
    security_owner_user_id uuid,
    criticality            text NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    archived_at            timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, business_unit_id) REFERENCES business_units(organization_id, id),
    FOREIGN KEY (organization_id, owner_user_id) REFERENCES users(organization_id, id),
    FOREIGN KEY (organization_id, security_owner_user_id) REFERENCES users(organization_id, id)
);
CREATE UNIQUE INDEX applications_name_uq ON applications (organization_id, lower(name)) WHERE archived_at IS NULL;

CREATE TABLE repositories (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    scm_connection_id uuid NOT NULL,
    external_id       text NOT NULL,
    full_name         text NOT NULL,           -- owner/name or project/name
    name              text NOT NULL,
    url               text NOT NULL,           -- browser URL
    clone_url         text NOT NULL,
    default_branch    text NOT NULL DEFAULT '',
    scan_branch       text NOT NULL DEFAULT '',  -- '' = default branch
    visibility        text NOT NULL DEFAULT 'private' CHECK (visibility IN ('public', 'private', 'internal')),
    description       text NOT NULL DEFAULT '',
    technologies      text[] NOT NULL DEFAULT '{}',
    application_id    uuid,
    business_unit_id  uuid,
    country_id        uuid,
    environment       text NOT NULL DEFAULT 'production' CHECK (environment IN ('production', 'staging', 'development', 'test', 'other')),
    criticality       text NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
    scan_enabled      boolean NOT NULL DEFAULT true,
    remote_archived   boolean NOT NULL DEFAULT false,
    last_pushed_at    timestamptz,
    imported_by       uuid,
    archived_at       timestamptz,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    UNIQUE (scm_connection_id, external_id),
    FOREIGN KEY (organization_id, scm_connection_id) REFERENCES scm_connections(organization_id, id),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id),
    FOREIGN KEY (organization_id, business_unit_id) REFERENCES business_units(organization_id, id)
);
-- Countries carry organization_id; enforce same-org through a composite FK.
ALTER TABLE countries ADD CONSTRAINT countries_org_id_uq UNIQUE (organization_id, id);
ALTER TABLE repositories ADD CONSTRAINT repositories_country_fk
    FOREIGN KEY (organization_id, country_id) REFERENCES countries(organization_id, id);
CREATE INDEX repositories_org_idx ON repositories (organization_id, archived_at);
CREATE INDEX repositories_bu_idx ON repositories (business_unit_id);
CREATE INDEX repositories_country_idx ON repositories (country_id);
CREATE INDEX repositories_app_idx ON repositories (application_id);
CREATE INDEX repositories_name_idx ON repositories (organization_id, lower(full_name));

CREATE TABLE tag_categories (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    description     text NOT NULL DEFAULT '',
    is_mandatory    boolean NOT NULL DEFAULT false,
    allow_multiple  boolean NOT NULL DEFAULT true,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX tag_categories_name_uq ON tag_categories (organization_id, lower(name));

CREATE TABLE tags (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    category_id     uuid NOT NULL,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    color           text NOT NULL DEFAULT 'slate' CHECK (color IN ('slate', 'blue', 'green', 'amber', 'red', 'purple', 'teal', 'pink')),
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, category_id) REFERENCES tag_categories(organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX tags_name_uq ON tags (category_id, lower(name));

CREATE TABLE repository_tags (
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    tag_id          uuid NOT NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, tag_id),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, tag_id) REFERENCES tags(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX repository_tags_tag_idx ON repository_tags (tag_id);

-- Verified webhook deliveries. Phase 4 turns relevant events into scan jobs.
CREATE TABLE webhook_deliveries (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL,
    scm_connection_id uuid NOT NULL,
    delivery_id       text NOT NULL,
    event             text NOT NULL CHECK (event IN ('push', 'pull_request', 'merge', 'ping', 'ignored')),
    repository_id     uuid,
    ref               text NOT NULL DEFAULT '',
    commit_sha        text NOT NULL DEFAULT '',
    pull_request      int,
    payload_sha256    text NOT NULL,
    status            text NOT NULL DEFAULT 'received' CHECK (status IN ('received', 'unknown_repository', 'processed')),
    received_at       timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, scm_connection_id) REFERENCES scm_connections(organization_id, id) ON DELETE CASCADE,
    UNIQUE (scm_connection_id, delivery_id)
);
CREATE INDEX webhook_deliveries_repo_idx ON webhook_deliveries (repository_id, received_at DESC);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS webhook_deliveries;
DROP TABLE IF EXISTS repository_tags;
DROP TABLE IF EXISTS tags;
DROP TABLE IF EXISTS tag_categories;
DROP TABLE IF EXISTS repositories;
ALTER TABLE countries DROP CONSTRAINT IF EXISTS countries_org_id_uq;
DROP TABLE IF EXISTS applications;
DROP TABLE IF EXISTS scm_connections;
