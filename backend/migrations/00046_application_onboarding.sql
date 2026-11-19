-- +goose Up
-- PATHOS 3.0 M3: application onboarding and classification
-- (docs/user-guide/application-onboarding.md, docs/api-reference/applications.md).
--
-- * Applications gain an onboarding status (a draft stays visible in the
--   inventory as "Onboarding: N of M fields") and the classification fields
--   of the onboarding flow: technical (type, languages, frameworks,
--   runtimes), security (data classification, internet exposure, compliance
--   scope, authentication model) and geography (hosting region, data
--   residency). Business (owner, business unit, criticality) and
--   environment already exist. detected_fields records which values came
--   from repository metadata or the SBOM.
-- * asset_settings.application_required_fields: the mandatory application
--   fields (Configurations › Asset settings).
-- * asset_onboardings: one row per repository being onboarded. The unique
--   key on (organization_id, source_key) is what guarantees that onboarding
--   the same repository twice, even concurrently, never creates a second
--   asset.
-- Additive only; every new table has organization_id, so
-- pathos_apply_app_grants() gives it the tenant policy (docs/MULTI_TENANCY.md).

-- Authentication model is a new classification catalogue.
ALTER TABLE asset_classifications DROP CONSTRAINT asset_classifications_kind_check;
ALTER TABLE asset_classifications ADD CONSTRAINT asset_classifications_kind_check
    CHECK (kind IN ('criticality', 'data_classification', 'environment', 'application_type', 'internet_exposure',
                    'compliance', 'hosting_region', 'lifecycle_status', 'authentication_model'));

ALTER TABLE applications
    ADD COLUMN onboarding_status        text NOT NULL DEFAULT 'complete' CHECK (onboarding_status IN ('draft', 'complete')),
    ADD COLUMN application_type         text NOT NULL DEFAULT '' CHECK (length(application_type) <= 63),
    ADD COLUMN languages                text[] NOT NULL DEFAULT '{}' CHECK (cardinality(languages) <= 50),
    ADD COLUMN frameworks               text[] NOT NULL DEFAULT '{}' CHECK (cardinality(frameworks) <= 50),
    ADD COLUMN runtimes                 text[] NOT NULL DEFAULT '{}' CHECK (cardinality(runtimes) <= 20),
    ADD COLUMN data_classification      text NOT NULL DEFAULT '' CHECK (length(data_classification) <= 63),
    ADD COLUMN internet_exposure        text NOT NULL DEFAULT '' CHECK (length(internet_exposure) <= 63),
    ADD COLUMN compliance_scopes        text[] NOT NULL DEFAULT '{}' CHECK (cardinality(compliance_scopes) <= 30),
    ADD COLUMN authentication_model     text NOT NULL DEFAULT '' CHECK (length(authentication_model) <= 63),
    ADD COLUMN hosting_region           text NOT NULL DEFAULT '' CHECK (length(hosting_region) <= 63),
    ADD COLUMN data_residency_region_id uuid,
    -- field -> {"source": "repository" | "sbom" | "scm", "detail": "..."}
    ADD COLUMN detected_fields          jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD CONSTRAINT applications_residency_region_fk
        FOREIGN KEY (organization_id, data_residency_region_id) REFERENCES regions(organization_id, id);
CREATE INDEX applications_onboarding_draft_idx ON applications (organization_id)
    WHERE onboarding_status = 'draft' AND archived_at IS NULL;

ALTER TABLE asset_settings ADD COLUMN application_required_fields text[] NOT NULL
    DEFAULT '{owner,business_unit,criticality,languages,frameworks,data_classification,internet_exposure,hosting_region,environment}';

CREATE TABLE asset_onboardings (
    id                uuid PRIMARY KEY,
    organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id    uuid NOT NULL,
    -- Normalised repository location: host/path in lower case, without
    -- scheme, credentials, ".git" or a trailing slash (or "upload:<id>").
    source_key        text NOT NULL CHECK (length(source_key) BETWEEN 1 AND 600),
    scm_connection_id uuid,
    external_id       text NOT NULL DEFAULT '' CHECK (length(external_id) <= 200),
    full_name         text NOT NULL CHECK (length(full_name) BETWEEN 1 AND 500),
    url               text NOT NULL DEFAULT '' CHECK (length(url) <= 1000),
    organization      text NOT NULL DEFAULT '' CHECK (length(organization) <= 200),
    project           text NOT NULL DEFAULT '' CHECK (length(project) <= 200),
    -- The repository once it exists in PATHOS (linked or imported).
    repository_id     uuid,
    decision          text NOT NULL CHECK (decision IN ('linked_existing', 'registered_new')),
    -- kept: the repository belongs to another application and the person
    -- chose to leave it there at "Save to inventory".
    status            text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'saved', 'discovery_started', 'kept')),
    -- The person asked (at registration) to move the repository out of its
    -- current application; the move itself needs the explicit list at
    -- completion (move_repositories).
    move_requested    boolean NOT NULL DEFAULT false,
    import_job_id     uuid,
    -- Discovery hints (primary language reported by the provider).
    hints             jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by        uuid,
    created_at        timestamptz NOT NULL DEFAULT now(),
    updated_at        timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, source_key),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, scm_connection_id) REFERENCES scm_connections(organization_id, id) ON DELETE SET NULL (scm_connection_id),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE SET NULL (repository_id),
    FOREIGN KEY (organization_id, import_job_id) REFERENCES repository_import_jobs(organization_id, id) ON DELETE SET NULL (import_job_id)
);
CREATE INDEX asset_onboardings_app_idx ON asset_onboardings (application_id);
CREATE UNIQUE INDEX asset_onboardings_conn_ext_uq ON asset_onboardings (scm_connection_id, external_id)
    WHERE scm_connection_id IS NOT NULL AND external_id <> '';
CREATE UNIQUE INDEX asset_onboardings_repo_uq ON asset_onboardings (repository_id) WHERE repository_id IS NOT NULL;

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS asset_onboardings;
ALTER TABLE asset_settings DROP COLUMN IF EXISTS application_required_fields;
DROP INDEX IF EXISTS applications_onboarding_draft_idx;
ALTER TABLE applications DROP CONSTRAINT IF EXISTS applications_residency_region_fk;
ALTER TABLE applications
    DROP COLUMN IF EXISTS onboarding_status, DROP COLUMN IF EXISTS application_type, DROP COLUMN IF EXISTS languages,
    DROP COLUMN IF EXISTS frameworks, DROP COLUMN IF EXISTS runtimes, DROP COLUMN IF EXISTS data_classification,
    DROP COLUMN IF EXISTS internet_exposure, DROP COLUMN IF EXISTS compliance_scopes, DROP COLUMN IF EXISTS authentication_model,
    DROP COLUMN IF EXISTS hosting_region, DROP COLUMN IF EXISTS data_residency_region_id, DROP COLUMN IF EXISTS detected_fields;
DELETE FROM asset_classifications WHERE kind = 'authentication_model';
ALTER TABLE asset_classifications DROP CONSTRAINT asset_classifications_kind_check;
ALTER TABLE asset_classifications ADD CONSTRAINT asset_classifications_kind_check
    CHECK (kind IN ('criticality', 'data_classification', 'environment', 'application_type', 'internet_exposure',
                    'compliance', 'hosting_region', 'lifecycle_status'));
