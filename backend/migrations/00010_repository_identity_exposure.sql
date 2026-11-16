-- +goose Up
-- Permanent human-readable Repository IDs (QD-REPO-000001), application
-- URLs and public internet exposure (docs/REPOSITORY_ONBOARDING.md §3).

-- Prefix for new Repository IDs; existing IDs never change.
ALTER TABLE asset_settings ADD COLUMN repository_key_prefix text NOT NULL DEFAULT 'QD-REPO'
    CHECK (repository_key_prefix ~ '^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$' AND length(repository_key_prefix) <= 20);

-- A sequence never hands out a number twice (not even after rollbacks or
-- deletions), so IDs are never reused. Numbers may have gaps.
CREATE SEQUENCE repository_key_seq AS bigint START 1;

ALTER TABLE repositories
    ADD COLUMN repository_key  text,
    ADD COLUMN staging_url     text NOT NULL DEFAULT '' CHECK (staging_url = '' OR (staging_url ~ '^https?://' AND length(staging_url) <= 2048)),
    ADD COLUMN production_url  text NOT NULL DEFAULT '' CHECK (production_url = '' OR (production_url ~ '^https?://' AND length(production_url) <= 2048)),
    ADD COLUMN public_exposure text NOT NULL DEFAULT 'unknown' CHECK (public_exposure IN ('yes', 'no', 'unknown')),
    ADD COLUMN exposure_notes  text NOT NULL DEFAULT '' CHECK (length(exposure_notes) <= 2000);

-- Existing repositories: numbered in registration order.
WITH ordered AS (SELECT id, row_number() OVER (ORDER BY created_at, id) AS n FROM repositories)
UPDATE repositories r SET repository_key = 'QD-REPO-' || lpad(o.n::text, greatest(6, length(o.n::text)), '0')
FROM ordered o WHERE o.id = r.id;
SELECT setval('repository_key_seq', GREATEST((SELECT count(*) FROM repositories), 1), (SELECT count(*) FROM repositories) > 0);

-- Exposure answers derived from the existing network exposure detail.
UPDATE repositories SET public_exposure = CASE internet_exposure
    WHEN 'public' THEN 'yes' WHEN 'internal' THEN 'no' WHEN 'private' THEN 'no' ELSE 'unknown' END;

ALTER TABLE repositories ALTER COLUMN repository_key SET NOT NULL;
CREATE UNIQUE INDEX repositories_key_uq ON repositories (repository_key);
CREATE INDEX repositories_public_exposure_idx ON repositories (organization_id, public_exposure);
CREATE INDEX repositories_production_url_idx ON repositories (organization_id, lower(production_url)) WHERE production_url <> '';
CREATE INDEX repositories_staging_url_idx ON repositories (organization_id, lower(staging_url)) WHERE staging_url <> '';

-- The database assigns the key on insert (whatever the application sends)
-- and refuses any later change, so it cannot be set or edited by users.
-- SECURITY DEFINER: the runtime role needs no rights on the sequence.
-- +goose StatementBegin
CREATE FUNCTION pathos_assign_repository_key() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    prefix text;
    n bigint;
BEGIN
    SELECT repository_key_prefix INTO prefix FROM asset_settings WHERE organization_id = NEW.organization_id;
    n := nextval('repository_key_seq');
    NEW.repository_key := COALESCE(prefix, 'QD-REPO') || '-' || lpad(n::text, greatest(6, length(n::text)), '0');
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION pathos_protect_repository_key() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.repository_key IS DISTINCT FROM OLD.repository_key THEN
        RAISE EXCEPTION 'repository_key is permanent and cannot be changed' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER repositories_assign_key BEFORE INSERT ON repositories
    FOR EACH ROW EXECUTE FUNCTION pathos_assign_repository_key();
CREATE TRIGGER repositories_protect_key BEFORE UPDATE OF repository_key ON repositories
    FOR EACH ROW EXECUTE FUNCTION pathos_protect_repository_key();

-- Public-facing endpoints (metadata only: never fetched or scanned).
CREATE TABLE repository_public_endpoints (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('url', 'domain', 'ip')),
    value           text NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
    position        int NOT NULL DEFAULT 0,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repository_id, kind, value),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX repository_public_endpoints_search_idx ON repository_public_endpoints (organization_id, kind, lower(value));

SELECT pathos_apply_app_grants();

-- +goose Down
-- Repository IDs cannot be restored after a rollback: a later re-upgrade
-- renumbers repositories in registration order.
DROP TABLE IF EXISTS repository_public_endpoints;
DROP TRIGGER IF EXISTS repositories_protect_key ON repositories;
DROP TRIGGER IF EXISTS repositories_assign_key ON repositories;
DROP FUNCTION IF EXISTS pathos_protect_repository_key();
DROP FUNCTION IF EXISTS pathos_assign_repository_key();
DROP INDEX IF EXISTS repositories_staging_url_idx;
DROP INDEX IF EXISTS repositories_production_url_idx;
DROP INDEX IF EXISTS repositories_public_exposure_idx;
DROP INDEX IF EXISTS repositories_key_uq;
ALTER TABLE repositories DROP COLUMN IF EXISTS exposure_notes, DROP COLUMN IF EXISTS public_exposure,
    DROP COLUMN IF EXISTS production_url, DROP COLUMN IF EXISTS staging_url, DROP COLUMN IF EXISTS repository_key;
DROP SEQUENCE IF EXISTS repository_key_seq;
ALTER TABLE asset_settings DROP COLUMN IF EXISTS repository_key_prefix;
