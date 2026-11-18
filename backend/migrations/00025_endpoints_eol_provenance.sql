-- +goose Up
-- PATHOS 1.1: verification of declared public endpoints, end-of-life dates
-- of runtimes and frameworks (endoflife.date), the exact introducing commit
-- of code findings and push change summaries, and Sigstore (cosign)
-- signature and attestation verification of images and artifacts.

-- Allowed values of a CHECK (col IN (...)) constraint are extended in
-- place: whatever values other migrations added are kept.
-- +goose StatementBegin
CREATE FUNCTION pathos_tmp_set_check_values(p_table regclass, p_con text, p_col text, p_add text[], p_remove text[]) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    def  text;
    vals text[];
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint WHERE conrelid = p_table AND conname = p_con;
    IF def IS NULL THEN
        RAISE EXCEPTION 'constraint % not found on %', p_con, p_table;
    END IF;
    -- Values appear as 'a'::text items or as one '{a,b}'::text[] literal.
    SELECT array_agg(v) INTO vals FROM regexp_matches(def, '''([^'']*)''', 'g') AS t(x),
        LATERAL unnest(CASE WHEN x[1] LIKE '{%}' THEN string_to_array(trim(both '{}' from x[1]), ',') ELSE ARRAY[x[1]] END) AS v;
    vals := ARRAY(SELECT DISTINCT v FROM unnest(COALESCE(vals, '{}') || p_add) v WHERE NOT (v = ANY (p_remove)) ORDER BY v);
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', p_table, p_con);
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I CHECK (%I IN (%s))', p_table, p_con, p_col,
        (SELECT string_agg(quote_literal(v), ', ') FROM unnest(vals) v));
END;
$$;
-- +goose StatementEnd

-- ------------------------------------------------- declared endpoint checks
-- A repository's declared public endpoints are verified by a scan target of
-- kind "endpoints" (one per repository). Like web application targets it
-- needs a recorded authorization statement.
SELECT pathos_tmp_set_check_values('scan_targets', 'scan_targets_kind_check', 'kind', ARRAY['endpoints'], '{}');
SELECT pathos_tmp_set_check_values('scan_jobs', 'scan_jobs_target_kind_check', 'target_kind', ARRAY['endpoints'], '{}');
ALTER TABLE scan_targets ADD CONSTRAINT scan_targets_endpoints_authorized_check CHECK (kind <> 'endpoints' OR authorized_at IS NOT NULL);
-- The endpoints ("kind:value") the authorization statement covers; endpoints
-- declared later are not checked until someone confirms them.
ALTER TABLE scan_targets ADD COLUMN authorized_scope text[] NOT NULL DEFAULT '{}' CHECK (cardinality(authorized_scope) <= 200);

-- Latest verification result per declared endpoint. Keyed by value, so
-- editing the endpoint list keeps the results of endpoints that remain.
CREATE TABLE endpoint_verifications (
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('url', 'domain', 'ip')),
    value           text NOT NULL CHECK (length(value) BETWEEN 1 AND 2048),
    status          text NOT NULL CHECK (status IN ('verified', 'unreachable', 'dns_failed', 'blocked', 'skipped', 'error')),
    detail          text NOT NULL DEFAULT '' CHECK (length(detail) <= 2000),
    -- DNS, HTTP, TLS and header observations (see docs/user-guide).
    checks          jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(checks) = 'object' AND pg_column_size(checks) <= 65536),
    scan_job_id     uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
    checked_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, kind, value),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);

-- ------------------------------------------------------------ end of life
SELECT pathos_tmp_set_check_values('intel_feeds', 'intel_feeds_feed_check', 'feed', ARRAY['endoflife'], '{}');
-- Off by default like deps.dev; the request carries no customer data, but
-- every outbound connection is an administrator's decision.
INSERT INTO intel_feeds (feed, url, enabled, interval_hours) VALUES ('endoflife', 'https://endoflife.date/api/v1/products/full', false, 24)
    ON CONFLICT DO NOTHING;

-- Reference data from endoflife.date (organization-independent).
CREATE TABLE eol_products (
    name        text PRIMARY KEY CHECK (length(name) BETWEEN 1 AND 100),
    label       text NOT NULL DEFAULT '' CHECK (length(label) <= 200),
    category    text NOT NULL DEFAULT '' CHECK (length(category) <= 50),
    aliases     text[] NOT NULL DEFAULT '{}',
    -- Package URLs without version or qualifiers (lower case).
    identifiers text[] NOT NULL DEFAULT '{}',
    link        text NOT NULL DEFAULT '' CHECK (length(link) <= 500),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE eol_cycles (
    product        text NOT NULL REFERENCES eol_products(name) ON DELETE CASCADE,
    cycle          text NOT NULL CHECK (length(cycle) BETWEEN 1 AND 100),
    label          text NOT NULL DEFAULT '' CHECK (length(label) <= 200),
    codename       text NOT NULL DEFAULT '' CHECK (length(codename) <= 100),
    release_date   date,
    -- End of (security) support; is_eol is the feed's own verdict when it
    -- has no date.
    eol_date       date,
    is_eol         boolean NOT NULL DEFAULT false,
    support_until  date,
    lts            boolean NOT NULL DEFAULT false,
    latest_version text NOT NULL DEFAULT '' CHECK (length(latest_version) <= 100),
    PRIMARY KEY (product, cycle)
);

-- Runtimes and base images declared in a repository's files (version files,
-- manifests, Dockerfiles), recorded by the worker on each repository scan.
CREATE TABLE repository_runtimes (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('runtime', 'image')),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 300),
    version         text NOT NULL DEFAULT '' CHECK (length(version) <= 300),
    source_path     text NOT NULL DEFAULT '' CHECK (length(source_path) <= 1000),
    scan_job_id     uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
    detected_at     timestamptz NOT NULL DEFAULT now(),
    UNIQUE (repository_id, kind, name, version, source_path),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);

-- End-of-life status of each component, runtime and image of a repository
-- (recomputed after scans and feed updates).
CREATE TABLE component_eol (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    scan_target_id  uuid,
    source          text NOT NULL CHECK (source IN ('sbom', 'runtime', 'image')),
    component       text NOT NULL CHECK (length(component) <= 600),
    version         text NOT NULL DEFAULT '' CHECK (length(version) <= 300),
    purl            text NOT NULL DEFAULT '' CHECK (length(purl) <= 1000),
    source_path     text NOT NULL DEFAULT '' CHECK (length(source_path) <= 1000),
    product         text NOT NULL,
    product_label   text NOT NULL DEFAULT '',
    cycle           text NOT NULL,
    eol_date        date,
    status          text NOT NULL CHECK (status IN ('eol', 'approaching', 'supported')),
    latest_version  text NOT NULL DEFAULT '',
    computed_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, scan_target_id) REFERENCES scan_targets(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX component_eol_repo_idx ON component_eol (repository_id, status);
CREATE INDEX component_eol_org_idx ON component_eol (organization_id, status);

SELECT pathos_tmp_set_check_values('findings', 'findings_category_check', 'category', ARRAY['eol', 'supply-chain'], '{}');
-- Human Eye can queue the new categories automatically too.
ALTER TABLE human_review_settings DROP CONSTRAINT human_review_settings_auto_categories_check;
ALTER TABLE human_review_settings ADD CONSTRAINT human_review_settings_auto_categories_check
    CHECK (auto_categories <@ ARRAY['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'malware', 'misconfiguration', 'binary', 'eol', 'supply-chain', 'other']::text[]);

-- ------------------------------------------------- introducing commit (blame)
-- known: git blame of the scanned commit; shallow_clone: unknown because the
-- repository is cloned without history; not_found: the line is not in the
-- scanned commit (e.g. a secret found in history).
ALTER TABLE findings
    ADD COLUMN introduced_status     text NOT NULL DEFAULT '' CHECK (introduced_status IN ('', 'known', 'shallow_clone', 'not_found')),
    ADD COLUMN introduced_commit_sha text NOT NULL DEFAULT '' CHECK (introduced_commit_sha ~ '^([0-9a-f]{40}|[0-9a-f]{64})?$'),
    -- Author name only; e-mail addresses are not stored.
    ADD COLUMN introduced_author     text NOT NULL DEFAULT '' CHECK (length(introduced_author) <= 200),
    ADD COLUMN introduced_at         timestamptz;

-- New and fixed findings between the previous scanned commit and this one
-- (push and merge scans).
ALTER TABLE scan_jobs ADD COLUMN change_summary jsonb CHECK (change_summary IS NULL OR (jsonb_typeof(change_summary) = 'object' AND pg_column_size(change_summary) <= 8192));

-- ------------------------------------------------- signature verification
-- Detached signature or Sigstore bundle of an artifact target.
ALTER TABLE scan_targets ADD COLUMN signature_material text CHECK (length(signature_material) <= 65536);

CREATE TABLE signature_verifications (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL,
    scan_target_id     uuid NOT NULL,
    scan_job_id        uuid REFERENCES scan_jobs(id) ON DELETE CASCADE,
    status             text NOT NULL CHECK (status IN ('verified', 'unsigned', 'invalid', 'skipped', 'error')),
    mode               text NOT NULL CHECK (mode IN ('none', 'key', 'keyless')),
    required           boolean NOT NULL DEFAULT false,
    attestation_status text NOT NULL DEFAULT '' CHECK (attestation_status IN ('', 'verified', 'missing', 'invalid', 'skipped', 'error')),
    details            jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(details) = 'object' AND pg_column_size(details) <= 65536),
    created_at         timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, scan_target_id) REFERENCES scan_targets(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX signature_verifications_target_idx ON signature_verifications (scan_target_id, created_at DESC);

DROP FUNCTION pathos_tmp_set_check_values(regclass, text, text, text[], text[]);

SELECT pathos_apply_app_grants();

-- +goose Down
-- +goose StatementBegin
CREATE FUNCTION pathos_tmp_set_check_values(p_table regclass, p_con text, p_col text, p_add text[], p_remove text[]) RETURNS void
LANGUAGE plpgsql AS $$
DECLARE
    def  text;
    vals text[];
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint WHERE conrelid = p_table AND conname = p_con;
    IF def IS NULL THEN
        RETURN;
    END IF;
    -- Values appear as 'a'::text items or as one '{a,b}'::text[] literal.
    SELECT array_agg(v) INTO vals FROM regexp_matches(def, '''([^'']*)''', 'g') AS t(x),
        LATERAL unnest(CASE WHEN x[1] LIKE '{%}' THEN string_to_array(trim(both '{}' from x[1]), ',') ELSE ARRAY[x[1]] END) AS v;
    vals := ARRAY(SELECT DISTINCT v FROM unnest(COALESCE(vals, '{}') || p_add) v WHERE NOT (v = ANY (p_remove)) ORDER BY v);
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', p_table, p_con);
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I CHECK (%I IN (%s))', p_table, p_con, p_col,
        (SELECT string_agg(quote_literal(v), ', ') FROM unnest(vals) v));
END;
$$;
-- +goose StatementEnd
DROP TABLE IF EXISTS signature_verifications;
ALTER TABLE scan_targets DROP COLUMN IF EXISTS signature_material;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS change_summary;
ALTER TABLE findings DROP COLUMN IF EXISTS introduced_at, DROP COLUMN IF EXISTS introduced_author,
    DROP COLUMN IF EXISTS introduced_commit_sha, DROP COLUMN IF EXISTS introduced_status;
-- End-of-life and supply-chain findings become "other" (kept, not deleted).
UPDATE findings SET category = 'other' WHERE category IN ('eol', 'supply-chain');
UPDATE human_review_settings SET auto_categories = array_remove(array_remove(auto_categories, 'eol'), 'supply-chain');
ALTER TABLE human_review_settings DROP CONSTRAINT human_review_settings_auto_categories_check;
ALTER TABLE human_review_settings ADD CONSTRAINT human_review_settings_auto_categories_check
    CHECK (auto_categories <@ ARRAY['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'malware', 'misconfiguration', 'binary', 'other']::text[]);
SELECT pathos_tmp_set_check_values('findings', 'findings_category_check', 'category', '{}', ARRAY['eol', 'supply-chain']);
DROP TABLE IF EXISTS component_eol;
DROP TABLE IF EXISTS repository_runtimes;
DROP TABLE IF EXISTS eol_cycles;
DROP TABLE IF EXISTS eol_products;
DELETE FROM intel_feed_runs WHERE feed = 'endoflife';
DELETE FROM intel_feeds WHERE feed = 'endoflife';
SELECT pathos_tmp_set_check_values('intel_feeds', 'intel_feeds_feed_check', 'feed', '{}', ARRAY['endoflife']);
DROP TABLE IF EXISTS endpoint_verifications;
ALTER TABLE scan_targets DROP CONSTRAINT IF EXISTS scan_targets_endpoints_authorized_check;
ALTER TABLE scan_targets DROP COLUMN IF EXISTS authorized_scope;
UPDATE findings SET scan_target_id = NULL WHERE scan_target_id IN (SELECT id FROM scan_targets WHERE kind = 'endpoints');
DELETE FROM scan_jobs WHERE target_kind = 'endpoints';
DELETE FROM scan_targets WHERE kind = 'endpoints';
SELECT pathos_tmp_set_check_values('scan_jobs', 'scan_jobs_target_kind_check', 'target_kind', '{}', ARRAY['endpoints']);
SELECT pathos_tmp_set_check_values('scan_targets', 'scan_targets_kind_check', 'kind', '{}', ARRAY['endpoints']);
DROP FUNCTION pathos_tmp_set_check_values(regclass, text, text, text[], text[]);
