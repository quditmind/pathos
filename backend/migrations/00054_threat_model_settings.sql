-- +goose Up
-- PATHOS 3.0 M5: threat-model settings per organization. Without a row the
-- default applies: auto_update on (a new ready CodeGraph snapshot of an
-- application regenerates its threat models in a draft).
CREATE TABLE threat_model_settings (
    organization_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    auto_update     boolean NOT NULL DEFAULT true,
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now()
);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS threat_model_settings;
