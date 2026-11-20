-- +goose Up
-- PATHOS 3.0 M6: the Quick, Standard and Comprehensive scan profiles are
-- seeded per organization beside the existing Default profile (decision C9,
-- docs/user-guide/scan-profiles.md). template records which seeded profile a
-- row is, so seeding is idempotent: a template is seeded once per
-- organization, and never again after an administrator renames or archives
-- it. Custom profiles (the profile editor) have no template. scan_profiles
-- already has organization_id and its tenant policy (docs/MULTI_TENANCY.md).
ALTER TABLE scan_profiles ADD COLUMN template text
    CHECK (template IS NULL OR template IN ('quick', 'standard', 'comprehensive'));
CREATE UNIQUE INDEX scan_profiles_template_idx ON scan_profiles (organization_id, template) WHERE template IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS scan_profiles_template_idx;
ALTER TABLE scan_profiles DROP COLUMN IF EXISTS template;
