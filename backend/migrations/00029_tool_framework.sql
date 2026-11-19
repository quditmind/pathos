-- +goose Up
-- PATHOS 2.0 tool framework: finding categories for the 25 scan types,
-- tool manifests (v2) advertised by workers, the parser recorded with each
-- raw tool report, and the per-target "intrusive testing authorized" flag.

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

-- ------------------------------------------------- finding categories
-- api (API security), iast, mobile (MAST), fuzz, crypto, cicd (CI/CD
-- pipelines), ai (AI/LLM), runtime, compliance, database and code-quality
-- (code-quality security). Configuration findings keep misconfiguration.
SELECT pathos_tmp_set_check_values('findings', 'findings_category_check', 'category',
    ARRAY['api', 'iast', 'mobile', 'fuzz', 'crypto', 'cicd', 'ai', 'runtime', 'compliance', 'database', 'code-quality'], '{}');
-- Human Eye can queue the new categories automatically too.
ALTER TABLE human_review_settings DROP CONSTRAINT human_review_settings_auto_categories_check;
ALTER TABLE human_review_settings ADD CONSTRAINT human_review_settings_auto_categories_check
    CHECK (auto_categories <@ ARRAY['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'api', 'iast', 'mobile', 'fuzz',
        'malware', 'misconfiguration', 'binary', 'crypto', 'cicd', 'ai', 'runtime', 'compliance', 'database', 'code-quality',
        'eol', 'supply-chain', 'other']::text[]);

-- ------------------------------------------------- scanner catalog
-- Keys of plugins and imported tools carry their category
-- (plugin-code-quality-<name> is up to 43 characters).
ALTER TABLE scanner_catalog DROP CONSTRAINT scanner_catalog_key_check;
ALTER TABLE scanner_catalog ADD CONSTRAINT scanner_catalog_key_check CHECK (key ~ '^[a-z0-9-]{2,60}$');
-- What a tool manifest declares: its scan types and targets, what it
-- contacts while it runs, and whether it sends attack traffic.
ALTER TABLE scanner_catalog
    ADD COLUMN scan_types text[] NOT NULL DEFAULT '{}' CHECK (cardinality(scan_types) <= 10),
    ADD COLUMN targets    text[] NOT NULL DEFAULT '{}' CHECK (targets <@ ARRAY['repository', 'image', 'url', 'api', 'mobile-app', 'binary', 'model']::text[]),
    ADD COLUMN network    text NOT NULL DEFAULT 'none' CHECK (network IN ('none', 'target', 'registry')),
    ADD COLUMN intrusive  boolean NOT NULL DEFAULT false;

-- Imported tools: the key pattern lists the new categories.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_register_import_tool(p_key text, p_name text, p_category text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    IF p_key !~ '^import-(secrets|sast|sca|iac|container|license|dast|api|iast|mobile|fuzz|malware|misconfiguration|binary|crypto|cicd|ai|runtime|compliance|database|code-quality|supply-chain|other)-[a-z0-9][a-z0-9-]{0,22}$' THEN
        RAISE EXCEPTION 'invalid import tool key %', p_key USING ERRCODE = 'check_violation';
    END IF;
    INSERT INTO scanner_catalog (key, name, category, license_spdx, decision, worker_family, output_format, notes, sort_order)
    VALUES (p_key, left(p_name, 100), p_category, 'NOASSERTION', 'use', 'import', 'sarif', 'Results imported from an external tool', 10000)
    ON CONFLICT (key) DO NOTHING;
END;
$$;
-- +goose StatementEnd

-- Operator plugins (v1 registration): the category is read from the key
-- by pattern, since categories may contain dashes.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_register_plugin_scanner(p_key text, p_name text, p_category text, p_homepage text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    PERFORM pathos_register_tool_manifest(p_key, p_name, p_category, p_homepage, 'NOASSERTION', '{}', ARRAY['repository'], 'none', false, 'sarif');
END;
$$;
-- +goose StatementEnd

-- Operator plugins (v2 manifests): the application role may add catalog
-- entries only through this function and only for plugin keys.
-- +goose StatementBegin
CREATE FUNCTION pathos_register_tool_manifest(p_key text, p_name text, p_category text, p_homepage text, p_license text,
    p_scan_types text[], p_targets text[], p_network text, p_intrusive boolean, p_output text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    cat text;
BEGIN
    cat := substring(p_key from '^plugin-(secrets|sast|sca|iac|container|license|dast|api|iast|mobile|fuzz|malware|misconfiguration|binary|crypto|cicd|ai|runtime|compliance|database|code-quality|supply-chain|other)-[a-z0-9][a-z0-9-]{0,22}$');
    IF cat IS NULL OR p_category IS DISTINCT FROM cat THEN
        RAISE EXCEPTION 'invalid plugin scanner key %', p_key USING ERRCODE = 'check_violation';
    END IF;
    IF p_homepage IS NULL OR (p_homepage <> '' AND p_homepage !~ '^https://') THEN
        p_homepage := '';
    END IF;
    IF p_license IS NULL OR p_license !~ '^[A-Za-z0-9.+:() -]{1,100}$' THEN
        p_license := 'NOASSERTION';
    END IF;
    IF p_network IS NULL OR p_network NOT IN ('none', 'target', 'registry') THEN
        p_network := 'target';
    END IF;
    INSERT INTO scanner_catalog (key, name, category, license_spdx, decision, worker_family, adapter_available, output_format, homepage, notes,
        sort_order, scan_types, targets, network, intrusive)
    VALUES (p_key, left(p_name, 100), cat, p_license, 'use', 'plugin', true, left(COALESCE(p_output, 'sarif'), 40), left(p_homepage, 300),
            'Declarative adapter defined on a worker', 9000, COALESCE(p_scan_types[1:10], '{}'), COALESCE(p_targets, '{}'), p_network,
            COALESCE(p_intrusive, false))
    ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, homepage = EXCLUDED.homepage, license_spdx = EXCLUDED.license_spdx,
        output_format = EXCLUDED.output_format, scan_types = EXCLUDED.scan_types, targets = EXCLUDED.targets,
        -- A tool once declared intrusive or contacting its target stays so:
        -- a later registration cannot lower the authorization it needs.
        network = CASE WHEN scanner_catalog.network = 'target' THEN 'target' ELSE EXCLUDED.network END,
        intrusive = scanner_catalog.intrusive OR EXCLUDED.intrusive
    WHERE scanner_catalog.worker_family = 'plugin';
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION pathos_register_tool_manifest(text, text, text, text, text, text[], text[], text, boolean, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pathos_register_tool_manifest(text, text, text, text, text, text[], text[], text, boolean, text) TO pathos_app;

-- ------------------------------------------------- workers
-- Tool manifests a worker advertised when it registered (metadata only:
-- never commands or arguments). Jobs that use a manifest tool are routed
-- to the workers that advertise it.
ALTER TABLE workers ADD COLUMN tools jsonb NOT NULL DEFAULT '{}'
    CHECK (jsonb_typeof(tools) = 'object' AND pg_column_size(tools) <= 1048576);

-- ------------------------------------------------- raw reports
-- The parser of a tool manifest whose output is not SARIF (import format or
-- JSON mapping), kept with the original report to locate findings in it.
ALTER TABLE scan_artifacts ADD COLUMN parser jsonb
    CHECK (parser IS NULL OR (jsonb_typeof(parser) = 'object' AND pg_column_size(parser) <= 16384));

-- ------------------------------------------------- intrusive testing
-- Intrusive tools (active scans, fuzzers, injection probes) need this flag
-- in addition to the target's authorization statement.
ALTER TABLE scan_targets
    ADD COLUMN intrusive_authorized_by uuid REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN intrusive_authorized_at timestamptz,
    ADD COLUMN intrusive_authorization_note text NOT NULL DEFAULT '' CHECK (length(intrusive_authorization_note) <= 2000);
ALTER TABLE scan_targets ADD CONSTRAINT scan_targets_intrusive_authorized_check
    CHECK (intrusive_authorized_at IS NULL OR (kind IN ('url', 'api') AND authorized_at IS NOT NULL));

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
    SELECT array_agg(v) INTO vals FROM regexp_matches(def, '''([^'']*)''', 'g') AS t(x),
        LATERAL unnest(CASE WHEN x[1] LIKE '{%}' THEN string_to_array(trim(both '{}' from x[1]), ',') ELSE ARRAY[x[1]] END) AS v;
    vals := ARRAY(SELECT DISTINCT v FROM unnest(COALESCE(vals, '{}') || p_add) v WHERE NOT (v = ANY (p_remove)) ORDER BY v);
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I', p_table, p_con);
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I CHECK (%I IN (%s))', p_table, p_con, p_col,
        (SELECT string_agg(quote_literal(v), ', ') FROM unnest(vals) v));
END;
$$;
-- +goose StatementEnd
ALTER TABLE scan_targets DROP CONSTRAINT IF EXISTS scan_targets_intrusive_authorized_check;
ALTER TABLE scan_targets DROP COLUMN IF EXISTS intrusive_authorization_note, DROP COLUMN IF EXISTS intrusive_authorized_at,
    DROP COLUMN IF EXISTS intrusive_authorized_by;
ALTER TABLE scan_artifacts DROP COLUMN IF EXISTS parser;
ALTER TABLE workers DROP COLUMN IF EXISTS tools;
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_register_plugin_scanner(p_key text, p_name text, p_category text, p_homepage text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    IF p_key !~ '^plugin-(sast|sca|secrets|iac|container|license|dast|other)-[a-z0-9][a-z0-9-]{0,22}$'
       OR p_category IS DISTINCT FROM split_part(p_key, '-', 2) THEN
        RAISE EXCEPTION 'invalid plugin scanner key %', p_key USING ERRCODE = 'check_violation';
    END IF;
    IF p_homepage <> '' AND p_homepage !~ '^https://' THEN
        p_homepage := '';
    END IF;
    INSERT INTO scanner_catalog (key, name, category, license_spdx, decision, worker_family, adapter_available, output_format, homepage, notes, sort_order)
    VALUES (p_key, left(p_name, 100), p_category, 'NOASSERTION', 'use', 'plugin', true, 'sarif', left(p_homepage, 300),
            'Declarative adapter defined on a worker', 9000)
    ON CONFLICT (key) DO UPDATE SET name = EXCLUDED.name, homepage = EXCLUDED.homepage
    WHERE scanner_catalog.worker_family = 'plugin';
END;
$$;
-- +goose StatementEnd
DROP FUNCTION IF EXISTS pathos_register_tool_manifest(text, text, text, text, text, text[], text[], text, boolean, text);
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_register_import_tool(p_key text, p_name text, p_category text) RETURNS void
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
ALTER TABLE scanner_catalog DROP COLUMN IF EXISTS intrusive, DROP COLUMN IF EXISTS network, DROP COLUMN IF EXISTS targets,
    DROP COLUMN IF EXISTS scan_types;
-- Catalog rows with longer keys stay; the old limit applies to new rows only.
ALTER TABLE scanner_catalog DROP CONSTRAINT scanner_catalog_key_check;
ALTER TABLE scanner_catalog ADD CONSTRAINT scanner_catalog_key_check CHECK (key ~ '^[a-z0-9-]{2,40}$') NOT VALID;
-- Findings of the new categories become "other" (kept, not deleted).
UPDATE findings SET category = 'other'
    WHERE category IN ('api', 'iast', 'mobile', 'fuzz', 'crypto', 'cicd', 'ai', 'runtime', 'compliance', 'database', 'code-quality');
UPDATE human_review_settings SET auto_categories = ARRAY(SELECT c FROM unnest(auto_categories) c
    WHERE c NOT IN ('api', 'iast', 'mobile', 'fuzz', 'crypto', 'cicd', 'ai', 'runtime', 'compliance', 'database', 'code-quality'));
ALTER TABLE human_review_settings DROP CONSTRAINT human_review_settings_auto_categories_check;
ALTER TABLE human_review_settings ADD CONSTRAINT human_review_settings_auto_categories_check
    CHECK (auto_categories <@ ARRAY['secrets', 'sast', 'sca', 'iac', 'container', 'license', 'dast', 'malware', 'misconfiguration', 'binary', 'eol', 'supply-chain', 'other']::text[]);
SELECT pathos_tmp_set_check_values('findings', 'findings_category_check', 'category', '{}',
    ARRAY['api', 'iast', 'mobile', 'fuzz', 'crypto', 'cicd', 'ai', 'runtime', 'compliance', 'database', 'code-quality']);
DROP FUNCTION pathos_tmp_set_check_values(regclass, text, text, text[], text[]);
