-- Synthetic load-test data: 300 repositories and 100,000 findings in an
-- archived (inert) SCM connection named "loadtest". Repositories are not
-- scan-enabled, so schedules and webhooks ignore them. Remove with
-- cleanup.sql. Run as the database superuser:
--   docker compose exec -T postgres psql -U postgres -d pathos -f - < scripts/load/seed.sql
\set ON_ERROR_STOP on
\set repos 300
\set findings 100000
BEGIN;
CREATE TEMP TABLE lt_org AS SELECT id FROM organizations ORDER BY created_at LIMIT 1;

INSERT INTO secrets (id, organization_id, kind, name, ciphertext, wrapped_dek, key_version)
SELECT v.id, o.id, v.kind, 'loadtest (inert)', '\x00', '\x00', 1
FROM lt_org o, (VALUES ('0000000a-0000-7000-8000-000000000001'::uuid, 'scm'), ('0000000a-0000-7000-8000-000000000002'::uuid, 'webhook')) v(id, kind)
ON CONFLICT (id) DO NOTHING;

INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, secret_id, webhook_secret_id, archived_at)
SELECT '0000000a-0000-7000-8000-0000000000c1', id, 'loadtest', 'github', 'https://api.github.com', 'pat',
       '0000000a-0000-7000-8000-000000000001', '0000000a-0000-7000-8000-000000000002', now()
FROM lt_org ON CONFLICT (id) DO NOTHING;

INSERT INTO repositories (id, organization_id, scm_connection_id, external_id, full_name, name, url, clone_url, default_branch,
                          criticality, environment, scan_enabled, technologies)
SELECT ('0000000a-0000-7000-8001-' || lpad(to_hex(g), 12, '0'))::uuid, o.id, '0000000a-0000-7000-8000-0000000000c1',
       'lt-' || g, 'loadtest/service-' || g, 'service-' || g, 'https://example.invalid/loadtest/service-' || g,
       'https://example.invalid/loadtest/service-' || g || '.git', 'main',
       (ARRAY['low', 'medium', 'high', 'critical'])[1 + g % 4], (ARRAY['production', 'staging', 'development'])[1 + g % 3],
       false, ARRAY[(ARRAY['go', 'java', 'python', 'typescript'])[1 + g % 4]]
FROM lt_org o, generate_series(1, :repos) g
ON CONFLICT DO NOTHING;

-- Severity mix roughly like real scans: 3% critical, 17% high, 40% medium, 30% low, 10% info.
INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, description, severity,
                      file_path, start_line, package_name, package_version, cve, first_seen_at, last_seen_at)
SELECT gen_random_uuid(), o.id,
       ('0000000a-0000-7000-8001-' || lpad(to_hex(1 + (g * 7919) % :repos), 12, '0'))::uuid,
       'lt' || md5(g::text),
       c.cat, ARRAY[c.scanner], c.rule || '.' || (g % 400),
       c.title || ' #' || g, 'Synthetic load-test finding ' || g,
       CASE WHEN r < 0.03 THEN 'critical' WHEN r < 0.20 THEN 'high' WHEN r < 0.60 THEN 'medium' WHEN r < 0.90 THEN 'low' ELSE 'info' END,
       CASE WHEN c.cat = 'sca' THEN 'package-lock.json' ELSE 'src/module' || (g % 97) || '/file' || (g % 31) || '.ts' END,
       CASE WHEN c.cat = 'sca' THEN NULL ELSE 1 + g % 500 END,
       CASE WHEN c.cat = 'sca' THEN 'lib-' || (g % 900) ELSE '' END,
       CASE WHEN c.cat = 'sca' THEN '1.' || (g % 20) || '.0' ELSE '' END,
       CASE WHEN c.cat = 'sca' THEN 'CVE-2026-' || (10000 + g % 5000) ELSE '' END,
       now() - (g % 400) * interval '1 day', now() - (g % 7) * interval '1 day'
FROM lt_org o,
     generate_series(1, :findings) g
     -- Deterministic per-row value in [0,1) (an uncorrelated random() would
     -- be evaluated only once).
     CROSS JOIN LATERAL (SELECT ((g::bigint * 2654435761) % 1000) / 1000.0 AS r) rr
     CROSS JOIN LATERAL (SELECT * FROM (VALUES
        (0, 'sast', 'opengrep', 'pathos.ts.injection', 'Possible injection in handler'),
        (1, 'sca', 'osv-scanner', 'osv', 'Vulnerable dependency'),
        (2, 'secrets', 'gitleaks', 'generic-api-key', 'Hard-coded credential'),
        (3, 'iac', 'checkov', 'CKV_K8S', 'Insecure Kubernetes setting'),
        (4, 'sca', 'trivy-fs', 'trivy', 'Vulnerable dependency')) v(k, cat, scanner, rule, title) WHERE v.k = g % 5) c;
COMMIT;
ANALYZE repositories; ANALYZE findings;
SELECT (SELECT count(*) FROM repositories WHERE scm_connection_id = '0000000a-0000-7000-8000-0000000000c1') AS repos,
       (SELECT count(*) FROM findings f JOIN repositories r ON r.id = f.repository_id
         WHERE r.scm_connection_id = '0000000a-0000-7000-8000-0000000000c1') AS findings;
