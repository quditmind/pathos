-- +goose Up
-- PATHOS 1.1: malware scanning of repository content (ClamAV), licence
-- policy violations as findings with file-level licence detection, binary
-- hardening checks and framework configuration rules. New finding
-- categories: malware, misconfiguration, binary.

ALTER TABLE findings DROP CONSTRAINT findings_category_check;
ALTER TABLE findings ADD CONSTRAINT findings_category_check
    CHECK (category IN ('secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'malware', 'misconfiguration', 'binary', 'other'));
ALTER TABLE human_review_settings DROP CONSTRAINT human_review_settings_auto_categories_check;
ALTER TABLE human_review_settings ADD CONSTRAINT human_review_settings_auto_categories_check
    CHECK (auto_categories <@ ARRAY['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'malware', 'misconfiguration', 'binary', 'other']::text[]);

-- Licences found in repository files (licensecheck), replaced by each
-- successful licensecheck run, like sbom_components. Together with the
-- SBOM inventory it is evaluated against license_policies to produce
-- licence findings.
CREATE TABLE repository_file_licenses (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    scan_job_id     uuid,
    file_path       text NOT NULL CHECK (length(file_path) BETWEEN 1 AND 1000),
    spdx_id         text NOT NULL CHECK (length(spdx_id) BETWEEN 1 AND 100),
    method          text NOT NULL CHECK (method IN ('spdx-tag', 'license-text')),
    line            int,
    -- Other licences of an SPDX "OR" expression: the file conflicts with
    -- the policy only if every alternative does.
    alternatives    text[] NOT NULL DEFAULT '{}',
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    UNIQUE (repository_id, file_path, spdx_id)
);
CREATE INDEX repository_file_licenses_org_spdx_idx ON repository_file_licenses (organization_id, spdx_id);

-- Licence findings are matched to policies through this function: an
-- entry for "GPL-3.0-only" or "GPL-3.0-or-later" also matches a detected
-- licence text "GPL-3.0" (a licence text does not say which variant).
-- +goose StatementBegin
CREATE FUNCTION pathos_license_decision(p_org uuid, p_spdx text) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT min(lp.decision) FROM license_policies lp
    WHERE lp.organization_id = p_org
      AND (lower(lp.spdx_id) = lower(p_spdx)
           OR lower(regexp_replace(lp.spdx_id, '-(only|or-later)$', '')) = lower(p_spdx))
$$;
-- +goose StatementEnd

SELECT pathos_apply_app_grants();
GRANT EXECUTE ON FUNCTION pathos_license_decision(uuid, text) TO pathos_app;

-- +goose Down
DROP FUNCTION IF EXISTS pathos_license_decision(uuid, text);
DROP TABLE IF EXISTS repository_file_licenses;
UPDATE findings SET category = 'other' WHERE category IN ('malware', 'misconfiguration', 'binary');
UPDATE human_review_settings SET auto_categories = array_remove(array_remove(array_remove(auto_categories, 'malware'), 'misconfiguration'), 'binary');
ALTER TABLE findings DROP CONSTRAINT findings_category_check;
ALTER TABLE findings ADD CONSTRAINT findings_category_check
    CHECK (category IN ('secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'other'));
ALTER TABLE human_review_settings DROP CONSTRAINT human_review_settings_auto_categories_check;
ALTER TABLE human_review_settings ADD CONSTRAINT human_review_settings_auto_categories_check
    CHECK (auto_categories <@ ARRAY['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'other']::text[]);
