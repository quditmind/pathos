-- +goose Up
-- ASPM phase 2a: importing results (SARIF, Grype JSON, PATHOS findings JSON)
-- and SBOMs (CycloneDX, SPDX) from tools PATHOS does not run, a DAST
-- finding category, and custom detection rules managed in PATHOS.

-- DAST and imported web findings get their own category.
ALTER TABLE findings DROP CONSTRAINT findings_category_check;
ALTER TABLE findings ADD CONSTRAINT findings_category_check
    CHECK (category IN ('secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'other'));
ALTER TABLE human_review_settings DROP CONSTRAINT human_review_settings_auto_categories_check;
ALTER TABLE human_review_settings ADD CONSTRAINT human_review_settings_auto_categories_check
    CHECK (auto_categories <@ ARRAY['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'other']::text[]);

-- Imports are recorded as scan executions with trigger "import".
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_trigger_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'push', 'pull_request', 'merge', 'onboarding', 'emergency', 'import'));

-- The scanner catalog stays owned by migrations; the only rows the
-- application may add are imported tools, through this function.
-- +goose StatementBegin
CREATE FUNCTION pathos_register_import_tool(p_key text, p_name text, p_category text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    IF p_key !~ '^import-(sast|sca|secrets|iac|container|license|dast|other)-[a-z0-9][a-z0-9-]{0,22}$' THEN
        RAISE EXCEPTION 'invalid import tool key %', p_key USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO scanner_catalog (key, name, category, license_spdx, decision, worker_family, output_format, notes, sort_order)
    VALUES (p_key, left(p_name, 100), p_category, 'NOASSERTION', 'use', 'import', 'sarif', 'Results imported from an external tool', 10000)
    ON CONFLICT (key) DO NOTHING;
END;
$$;
-- +goose StatementEnd

CREATE TABLE import_jobs (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    kind            text NOT NULL CHECK (kind IN ('results', 'sbom')),
    format          text NOT NULL CHECK (format IN ('sarif', 'grype', 'pathos', 'cyclonedx', 'spdx')),
    tool            text NOT NULL DEFAULT '' CHECK (length(tool) <= 100),
    scanner_key     text,
    category        text NOT NULL DEFAULT '',
    repository_id   uuid NOT NULL,
    scan_job_id     uuid,
    file_name       text NOT NULL DEFAULT '' CHECK (length(file_name) <= 255),
    sha256          text NOT NULL,
    size_bytes      bigint NOT NULL,
    commit_sha      text NOT NULL DEFAULT '',
    resolve_missing boolean NOT NULL DEFAULT false,
    status          text NOT NULL CHECK (status IN ('succeeded', 'failed')),
    records         int NOT NULL DEFAULT 0,
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, scan_job_id) REFERENCES scan_jobs(organization_id, id) ON DELETE SET NULL (scan_job_id)
);
CREATE INDEX import_jobs_org_idx ON import_jobs (organization_id, created_at DESC);
CREATE INDEX import_jobs_repo_idx ON import_jobs (repository_id, created_at DESC);

-- Imported SBOMs are kept per repository in the component inventory;
-- record where each inventory came from.
ALTER TABLE sbom_components ADD COLUMN source text NOT NULL DEFAULT 'scan' CHECK (source IN ('scan', 'import'));
ALTER TABLE sbom_components ALTER COLUMN scan_job_id DROP NOT NULL;

-- Custom detection rules (Opengrep YAML), delivered to workers with each job.
CREATE TABLE custom_rules (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    engine          text NOT NULL DEFAULT 'opengrep' CHECK (engine IN ('opengrep')),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    content         text NOT NULL CHECK (length(content) BETWEEN 1 AND 262144),
    rule_ids        text[] NOT NULL DEFAULT '{}',
    enabled         boolean NOT NULL DEFAULT true,
    version         int NOT NULL DEFAULT 1 CHECK (version > 0),
    created_by      uuid,
    updated_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id)
);
CREATE UNIQUE INDEX custom_rules_name_uq ON custom_rules (organization_id, lower(name));

-- Every saved version is kept (who changed which rule, and how).
CREATE TABLE custom_rule_versions (
    rule_id     uuid NOT NULL REFERENCES custom_rules(id) ON DELETE CASCADE,
    version     int NOT NULL,
    content     text NOT NULL,
    enabled     boolean NOT NULL,
    change_note text NOT NULL DEFAULT '' CHECK (length(change_note) <= 2000),
    created_by  uuid,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, version)
);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS custom_rule_versions;
DROP TABLE IF EXISTS custom_rules;
DELETE FROM sbom_components WHERE scan_job_id IS NULL;
ALTER TABLE sbom_components ALTER COLUMN scan_job_id SET NOT NULL;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS source;
DROP TABLE IF EXISTS import_jobs;
DROP FUNCTION IF EXISTS pathos_register_import_tool(text, text, text);
DELETE FROM scan_jobs WHERE trigger = 'import';
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_trigger_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'push', 'pull_request', 'merge', 'onboarding', 'emergency'));
UPDATE findings SET category = 'other' WHERE category = 'dast';
ALTER TABLE findings DROP CONSTRAINT findings_category_check;
ALTER TABLE findings ADD CONSTRAINT findings_category_check
    CHECK (category IN ('secrets', 'sast', 'sca', 'iac', 'container', 'license', 'other'));
UPDATE human_review_settings SET auto_categories = array_remove(auto_categories, 'dast');
ALTER TABLE human_review_settings DROP CONSTRAINT human_review_settings_auto_categories_check;
ALTER TABLE human_review_settings ADD CONSTRAINT human_review_settings_auto_categories_check
    CHECK (auto_categories <@ ARRAY['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'other']::text[]);
DELETE FROM finding_occurrences WHERE scan_result_id IN (SELECT id FROM scan_results WHERE scanner_key LIKE 'import-%');
DELETE FROM scan_results WHERE scanner_key LIKE 'import-%';
DELETE FROM scanner_catalog WHERE key LIKE 'import-%';
