-- +goose Up
-- PATHOS 2.0 worker-mobile, -binary, -ai and -fuzz: mobile app targets
-- (uploaded APK, AAB or IPA packages, stored like build artifacts), LLM
-- endpoint targets (red-teaming of an authorized chat completions API) and
-- AI-BOM entries in the component inventory.

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

-- ------------------------------------------------- scan targets
SELECT pathos_tmp_set_check_values('scan_targets', 'scan_targets_kind_check', 'kind', ARRAY['mobile-app', 'llm-endpoint'], '{}');
SELECT pathos_tmp_set_check_values('scan_jobs', 'scan_jobs_target_kind_check', 'target_kind', ARRAY['mobile-app', 'llm-endpoint'], '{}');
-- A mobile app is an uploaded file, like a build artifact.
ALTER TABLE scan_targets ADD CONSTRAINT scan_targets_mobile_app_check
    CHECK (kind <> 'mobile-app' OR artifact_key IS NOT NULL OR artifact_gzip IS NOT NULL);
-- An LLM endpoint is a running system: it needs an authorization statement,
-- and intrusive testing (red-teaming probes) can be authorized for it.
ALTER TABLE scan_targets ADD CONSTRAINT scan_targets_llm_endpoint_authorized_check
    CHECK (kind <> 'llm-endpoint' OR authorized_at IS NOT NULL);
ALTER TABLE scan_targets DROP CONSTRAINT scan_targets_intrusive_authorized_check;
ALTER TABLE scan_targets ADD CONSTRAINT scan_targets_intrusive_authorized_check
    CHECK (intrusive_authorized_at IS NULL OR (kind IN ('url', 'api', 'llm-endpoint') AND authorized_at IS NOT NULL));

-- ------------------------------------------------- scanner catalog
-- Tool manifests may declare llm-endpoint targets.
ALTER TABLE scanner_catalog DROP CONSTRAINT scanner_catalog_targets_check;
ALTER TABLE scanner_catalog ADD CONSTRAINT scanner_catalog_targets_check
    CHECK (targets <@ ARRAY['repository', 'image', 'url', 'api', 'mobile-app', 'binary', 'model', 'llm-endpoint']::text[]);

-- ------------------------------------------------- component inventory
-- AI-BOM entries (scanner ai-bom): AI frameworks, models and LLM APIs. They
-- are replaced by the next AI-BOM, not by SBOM scans or imports.
SELECT pathos_tmp_set_check_values('sbom_components', 'sbom_components_source_check', 'source', ARRAY['aibom'], '{}');

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
DELETE FROM sbom_components WHERE source = 'aibom';
SELECT pathos_tmp_set_check_values('sbom_components', 'sbom_components_source_check', 'source', '{}', ARRAY['aibom']);
UPDATE scanner_catalog SET targets = array_remove(targets, 'llm-endpoint') WHERE 'llm-endpoint' = ANY (targets);
ALTER TABLE scanner_catalog DROP CONSTRAINT scanner_catalog_targets_check;
ALTER TABLE scanner_catalog ADD CONSTRAINT scanner_catalog_targets_check
    CHECK (targets <@ ARRAY['repository', 'image', 'url', 'api', 'mobile-app', 'binary', 'model']::text[]);
-- Findings of removed targets are kept (detached from the target).
UPDATE findings SET scan_target_id = NULL WHERE scan_target_id IN (SELECT id FROM scan_targets WHERE kind IN ('mobile-app', 'llm-endpoint'));
DELETE FROM scan_jobs WHERE target_kind IN ('mobile-app', 'llm-endpoint');
-- The targets go first (they reference their credential), then the
-- credentials of the LLM endpoints.
WITH removed AS (DELETE FROM scan_targets WHERE kind IN ('mobile-app', 'llm-endpoint') RETURNING secret_id)
DELETE FROM secrets WHERE id IN (SELECT secret_id FROM removed WHERE secret_id IS NOT NULL);
ALTER TABLE scan_targets DROP CONSTRAINT IF EXISTS scan_targets_intrusive_authorized_check;
ALTER TABLE scan_targets ADD CONSTRAINT scan_targets_intrusive_authorized_check
    CHECK (intrusive_authorized_at IS NULL OR (kind IN ('url', 'api') AND authorized_at IS NOT NULL));
ALTER TABLE scan_targets DROP CONSTRAINT IF EXISTS scan_targets_llm_endpoint_authorized_check;
ALTER TABLE scan_targets DROP CONSTRAINT IF EXISTS scan_targets_mobile_app_check;
SELECT pathos_tmp_set_check_values('scan_jobs', 'scan_jobs_target_kind_check', 'target_kind', '{}', ARRAY['mobile-app', 'llm-endpoint']);
SELECT pathos_tmp_set_check_values('scan_targets', 'scan_targets_kind_check', 'kind', '{}', ARRAY['mobile-app', 'llm-endpoint']);
DROP FUNCTION pathos_tmp_set_check_values(regclass, text, text, text[], text[]);
