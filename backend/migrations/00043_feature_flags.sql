-- +goose Up
-- PATHOS 3.0 feature flags (docs/api-reference/administration.md, "Feature
-- flags"). One row per organization and flag that an administrator has set;
-- a flag without a row is off. Every new module stays behind its flag until
-- its milestone is approved. The table has organization_id, so
-- pathos_apply_app_grants() gives it the standard tenant policy
-- (docs/MULTI_TENANCY.md).
CREATE TABLE feature_flags (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (name ~ '^[a-z][a-z0-9_]{1,62}$'),
    enabled         boolean NOT NULL DEFAULT false,
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, name),
    UNIQUE (organization_id, id)
);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS feature_flags;
