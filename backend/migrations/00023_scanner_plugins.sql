-- +goose Up
-- ASPM phase 10: declarative scanner adapters. Workers register the
-- plugins defined in their configuration; the application role may add
-- catalog entries only through this function and only for plugin keys.
-- +goose StatementBegin
CREATE FUNCTION pathos_register_plugin_scanner(p_key text, p_name text, p_category text, p_homepage text) RETURNS void
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
REVOKE ALL ON FUNCTION pathos_register_plugin_scanner(text, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION pathos_register_plugin_scanner(text, text, text, text) TO pathos_app;

-- +goose Down
DROP FUNCTION IF EXISTS pathos_register_plugin_scanner(text, text, text, text);
DELETE FROM scanner_catalog c WHERE c.worker_family = 'plugin'
  AND NOT EXISTS (SELECT 1 FROM profile_scanners p WHERE p.scanner_key = c.key)
  AND NOT EXISTS (SELECT 1 FROM scan_results r WHERE r.scanner_key = c.key);
