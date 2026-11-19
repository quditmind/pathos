-- +goose Up
-- PATHOS 3.0 M3: tag framework (docs/user-guide/tags.md,
-- docs/api-reference/applications.md "Tag framework").
--
-- * tag_categories.color: the category colour (tags keep their own).
-- * tag_categories.mandatory_asset_types: application types (keys of the
--   application_type catalogue, or 'all') whose applications must carry a
--   tag of the category. Repositories keep is_mandatory.
-- * application_tags: tags on applications (repositories already have
--   repository_tags); source says whether a person, a rule or a bulk action
--   added the tag.
-- * tag_rules: automatic tagging from classification, repository topics
--   (technology labels) or repository path patterns.
-- * tag_assignment_history: who changed which tags of which asset, when,
--   with the old and new tags of the category.
-- Additive only; tenant policies via pathos_apply_app_grants().

ALTER TABLE tag_categories
    ADD COLUMN color                 text NOT NULL DEFAULT '' CHECK (color = '' OR color ~ '^#[0-9a-f]{6}$'),
    ADD COLUMN mandatory_asset_types text[] NOT NULL DEFAULT '{}' CHECK (cardinality(mandatory_asset_types) <= 30);

CREATE TABLE tag_rules (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    tag_id          uuid NOT NULL,
    target_type     text NOT NULL CHECK (target_type IN ('application', 'repository')),
    condition       text NOT NULL CHECK (condition IN ('classification', 'repository_topic', 'path_pattern')),
    -- classification: the application field compared (e.g. data_classification).
    field           text NOT NULL DEFAULT '' CHECK (length(field) <= 63),
    -- Value to compare, topic label, or glob pattern (* and ?).
    value           text NOT NULL CHECK (length(value) BETWEEN 1 AND 200),
    enabled         boolean NOT NULL DEFAULT true,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, tag_id) REFERENCES tags(organization_id, id) ON DELETE CASCADE,
    CHECK ((condition = 'classification') = (field <> '')),
    CHECK (condition <> 'classification' OR target_type = 'application')
);
CREATE UNIQUE INDEX tag_rules_name_uq ON tag_rules (organization_id, lower(name));
CREATE INDEX tag_rules_tag_idx ON tag_rules (tag_id);

CREATE TABLE application_tags (
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id  uuid NOT NULL,
    tag_id          uuid NOT NULL,
    source          text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'rule', 'bulk', 'onboarding')),
    rule_id         uuid,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (application_id, tag_id),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, tag_id) REFERENCES tags(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, rule_id) REFERENCES tag_rules(organization_id, id) ON DELETE SET NULL (rule_id)
);
CREATE INDEX application_tags_tag_idx ON application_tags (tag_id);

CREATE TABLE tag_assignment_history (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    target_type     text NOT NULL CHECK (target_type IN ('application', 'repository')),
    target_id       uuid NOT NULL,
    target_name     text NOT NULL DEFAULT '' CHECK (length(target_name) <= 500),
    category_id     uuid,
    category_name   text NOT NULL DEFAULT '' CHECK (length(category_name) <= 100),
    old_tags        text[] NOT NULL DEFAULT '{}',
    new_tags        text[] NOT NULL DEFAULT '{}',
    source          text NOT NULL CHECK (source IN ('manual', 'rule', 'bulk', 'onboarding')),
    rule_id         uuid,
    actor_id        uuid,
    actor_email     text NOT NULL DEFAULT '',
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);
CREATE INDEX tag_assignment_history_target_idx ON tag_assignment_history (organization_id, target_type, target_id, created_at DESC);
CREATE INDEX tag_assignment_history_org_idx ON tag_assignment_history (organization_id, created_at DESC);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS tag_assignment_history;
DROP TABLE IF EXISTS application_tags;
DROP TABLE IF EXISTS tag_rules;
ALTER TABLE tag_categories DROP COLUMN IF EXISTS mandatory_asset_types, DROP COLUMN IF EXISTS color;
