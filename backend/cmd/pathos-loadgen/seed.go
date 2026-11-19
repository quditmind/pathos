package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

type seedOptions struct {
	Repos, Findings, Chunk, Apps, ComponentsPerRepo, CVEs, EPSS int
}

// Synthetic ids are deterministic so that rows can reference each other
// without lookups: 0000000b-0000-7000-800<kind>-<12 hex digits of n>.
const (
	kindRepo       = 1
	kindJob        = 2
	kindResult     = 3
	kindFinding    = 4
	kindBU         = 5
	kindApp        = 6
	kindOccurrence = 7
	scansPerRepo   = 10 // jobs per repository (k = 0..9, 9 is the latest)
	connectionID   = "0000000b-0000-7000-8000-0000000000c1"
)

// Scanners of the synthetic scan results, by index (see scannerIdx).
var resultScanners = []string{"opengrep", "osv-scanner", "gitleaks", "trivy-fs"}

// helpers are session-local SQL functions (pg_temp), inlined by the
// planner: lg_u is a deterministic uniform value in [0,1) for (row, stream),
// lg_id builds a synthetic id, lg_n reads its number back.
const helpers = `
CREATE OR REPLACE FUNCTION pg_temp.lg_u(g bigint, k int) RETURNS float8 LANGUAGE sql IMMUTABLE AS
  $$ SELECT (hashint8(g * 64 + k)::bigint + 2147483648)::float8 / 4294967296.0 $$;
CREATE OR REPLACE FUNCTION pg_temp.lg_id(kind int, n bigint) RETURNS uuid LANGUAGE sql IMMUTABLE AS
  $$ SELECT ('0000000b-0000-7000-800' || to_hex(kind) || '-' || lpad(to_hex(n), 12, '0'))::uuid $$;
CREATE OR REPLACE FUNCTION pg_temp.lg_n(id uuid) RETURNS bigint LANGUAGE sql IMMUTABLE AS
  $$ SELECT ('x' || right(replace(id::text, '-', ''), 12))::bit(48)::bigint $$;
CREATE OR REPLACE FUNCTION pg_temp.lg_hex(g bigint, len int) RETURNS text LANGUAGE sql IMMUTABLE AS
  $$ SELECT left(md5(g::text) || md5((g + 1)::text), len) $$;`

func seed(ctx context.Context, dsn string, o seedOptions) error {
	if dsn == "" {
		return errors.New("-db is required")
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	start := time.Now()
	if _, err := conn.Exec(ctx, helpers); err != nil {
		return err
	}
	var org, admin, profileVersion string
	if err := conn.QueryRow(ctx, `SELECT o.id::text, (SELECT id::text FROM users WHERE organization_id = o.id ORDER BY created_at LIMIT 1),
		(SELECT current_version_id::text FROM scan_profiles WHERE organization_id = o.id AND is_default AND archived_at IS NULL)
		FROM organizations o ORDER BY created_at LIMIT 1`).Scan(&org, &admin, &profileVersion); err != nil {
		return fmt.Errorf("the bootstrap organization, its first user and the default scan profile must exist (sign in once): %w", err)
	}
	var existing int
	_ = conn.QueryRow(ctx, `SELECT count(*) FROM repositories WHERE id = '0000000b-0000-7000-8001-000000000001'`).Scan(&existing)
	if existing > 0 {
		return fmt.Errorf("%d synthetic repositories already exist; run cleanup first", existing)
	}
	fmt.Printf("seeding org %s: %d repositories, %d findings\n", org, o.Repos, o.Findings)
	ex := func(sql string, args ...any) (int64, error) {
		tag, err := conn.Exec(ctx, sql, args...)
		return tag.RowsAffected(), err
	}

	steps := []struct {
		name string
		sql  string
		args []any
	}{
		{"connection and secrets", `
			WITH s AS (INSERT INTO secrets (id, organization_id, kind, name, ciphertext, wrapped_dek, key_version)
			  SELECT v.id, $1, v.kind, 'loadgen (inert)', '\x00', '\x00', 1
			  FROM (VALUES ('0000000b-0000-7000-8000-000000000001'::uuid, 'scm'), ('0000000b-0000-7000-8000-000000000002'::uuid, 'webhook')) v(id, kind)
			  RETURNING 1)
			INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, secret_id, webhook_secret_id, archived_at)
			SELECT '` + connectionID + `', $1, 'loadgen', 'github', 'https://example.invalid', 'pat',
			       '0000000b-0000-7000-8000-000000000001', '0000000b-0000-7000-8000-000000000002', now()
			WHERE (SELECT count(*) FROM s) = 2`, []any{org}},
		{"business units", `
			INSERT INTO business_units (id, organization_id, name)
			SELECT pg_temp.lg_id(5, b), $1, 'loadgen BU ' || b FROM generate_series(1, 12) b`, []any{org}},
		{"applications", `
			INSERT INTO applications (id, organization_id, name, criticality, business_unit_id, application_key)
			SELECT pg_temp.lg_id(6, a), $1, 'loadgen-app-' || a, (ARRAY['low','medium','high','critical'])[1 + a % 4],
			       pg_temp.lg_id(5, 1 + a % 12), 'LG-APP-' || lpad(a::text, 6, '0')
			FROM generate_series(1, $2::int) a`, []any{org, o.Apps}},
		{"repositories", `
			INSERT INTO repositories (id, organization_id, scm_connection_id, external_id, full_name, name, url, clone_url, default_branch,
			  criticality, environment, scan_enabled, technologies, application_id, business_unit_id, public_exposure, internet_exposure,
			  created_at, last_pushed_at, latest_commit_sha, latest_commit_at, languages, size_bytes, file_count, source_type)
			SELECT pg_temp.lg_id(1, r), $1, CASE WHEN r % 10 <> 0 THEN '` + connectionID + `'::uuid END, 'lg-' || r,
			       'loadgen/' || t.team || '/service-' || r, 'service-' || r,
			       'https://example.invalid/loadgen/service-' || r, 'https://example.invalid/loadgen/service-' || r || '.git', 'main',
			       CASE WHEN u1 < 0.10 THEN 'critical' WHEN u1 < 0.35 THEN 'high' WHEN u1 < 0.80 THEN 'medium' ELSE 'low' END,
			       (ARRAY['production','production','staging','development'])[1 + r % 4], false,
			       ARRAY[t.lang], CASE WHEN u2 < 0.7 THEN pg_temp.lg_id(6, 1 + (r % $2::int)) END, pg_temp.lg_id(5, 1 + r % 12),
			       CASE WHEN u3 < 0.2 THEN 'yes' WHEN u3 < 0.7 THEN 'no' ELSE 'unknown' END,
			       CASE WHEN u3 < 0.2 THEN 'internet' WHEN u3 < 0.7 THEN 'internal' ELSE 'unknown' END,
			       now() - (u4 * 900) * interval '1 day', now() - (u5 * 60) * interval '1 day',
			       pg_temp.lg_hex(r, 40), now() - (u5 * 60) * interval '1 day',
			       jsonb_build_object(t.lang, 80 + (r % 20)), (1e6 + u4 * 5e8)::bigint, (50 + u5 * 20000)::int,
			       CASE WHEN r % 10 <> 0 THEN 'scm' ELSE 'upload' END
			FROM generate_series(1, $3::int) r
			CROSS JOIN LATERAL (SELECT pg_temp.lg_u(r, 1) u1, pg_temp.lg_u(r, 2) u2, pg_temp.lg_u(r, 3) u3, pg_temp.lg_u(r, 4) u4, pg_temp.lg_u(r, 5) u5) h
			CROSS JOIN LATERAL (SELECT (ARRAY['payments','identity','platform','data','mobile','web','infra','growth'])[1 + r % 8] team,
			                           (ARRAY['go','java','python','typescript','csharp','ruby'])[1 + (r / 3) % 6] lang) t`,
			[]any{org, o.Apps, o.Repos}},
		// Every tenth repository is an uploaded one with a source snapshot
		// record (its archive is never stored: fake workers do not download
		// it). The ingest command scans these, because SCM repositories of
		// the inert connection have no usable clone credential.
		{"source snapshots", `
			WITH s AS (
			  INSERT INTO source_snapshots (id, organization_id, repository_id, object_key, archive_filename, archive_sha256, archive_size,
			    snapshot_sha256, snapshot_size, uncompressed_bytes, file_count, malware_scan)
			  SELECT pg_temp.lg_id(8, r), $1, pg_temp.lg_id(1, r), 'loadgen/' || r, 'service-' || r || '.zip',
			         encode(sha256(('a' || r)::bytea), 'hex'), 1000000, encode(sha256(('s' || r)::bytea), 'hex'), 1000000, 5000000, 400, 'not_configured'
			  FROM generate_series(10, $2::int, 10) r RETURNING id, repository_id)
			UPDATE repositories r SET current_snapshot_id = s.id FROM s WHERE r.id = s.repository_id`, []any{org, o.Repos}},
		{"scan jobs", `
			INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, priority, status, ref, commit_sha, attempts,
			  findings_new, findings_fixed, queued_at, started_at, finished_at, name, progress, stage)
			SELECT pg_temp.lg_id(2, r * 16 + k), $1, pg_temp.lg_id(1, r), $2, CASE WHEN k % 3 = 0 THEN 'push' ELSE 'schedule' END, 50,
			       CASE WHEN pg_temp.lg_u(r * 16 + k, 1) < 0.03 THEN 'failed' ELSE 'succeeded' END, 'main', pg_temp.lg_hex(r * 16 + k, 40), 1,
			       (pg_temp.lg_u(r * 16 + k, 2) * 12)::int, (pg_temp.lg_u(r * 16 + k, 3) * 10)::int, q, q + interval '20 seconds',
			       q + (120 + pg_temp.lg_u(r * 16 + k, 4) * 900) * interval '1 second', 'service-' || r || ' · Default', 100, 'done'
			FROM generate_series(1, $3::int) r, generate_series(0, 9) k
			CROSS JOIN LATERAL (SELECT now() - ((9 - k) * 7 + pg_temp.lg_u(r * 16 + k, 5)) * interval '1 day' AS q) t`,
			[]any{org, profileVersion, o.Repos}},
		{"scan results", `
			INSERT INTO scan_results (id, organization_id, scan_job_id, scanner_key, scanner_version, status, duration_ms, findings_count, created_at)
			SELECT pg_temp.lg_id(3, (r * 16 + k) * 4 + s), $1, pg_temp.lg_id(2, r * 16 + k), ($3::text[])[s + 1], '1.0.0', 'succeeded',
			       (5000 + pg_temp.lg_u((r * 16 + k) * 4 + s, 6) * 300000)::int, (pg_temp.lg_u((r * 16 + k) * 4 + s, 7) * 40)::int,
			       now() - (9 - k) * 7 * interval '1 day'
			FROM generate_series(1, $2::int) r, generate_series(0, 9) k, generate_series(0, 3) s`,
			[]any{org, o.Repos, resultScanners}},
		{"vulnerability intelligence: OSV", `
			INSERT INTO intel_vulns (id, aliases, summary, details, published, modified, cvss_vectors, cwes, exploit_refs, source, found)
			SELECT 'GHSA-lg' || lpad(to_hex(c), 4, '0') || '-' || left(md5(c::text), 4) || '-' || substr(md5(c::text), 5, 4),
			       ARRAY['CVE-' || (2017 + c % 9) || '-' || (10000 + c)], 'Synthetic advisory ' || c, repeat('Advisory details. ', 20),
			       now() - (c % 2000) * interval '1 day', now() - (c % 300) * interval '1 day',
			       ARRAY['CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'], ARRAY['CWE-' || (20 + c % 900)],
			       CASE WHEN c % 23 = 0 THEN 1 ELSE 0 END, 'osv-online', true
			FROM generate_series(0, $1::int - 1) c`, []any{o.CVEs}},
		{"vulnerability intelligence: EPSS", `
			INSERT INTO intel_epss (cve_id, score, percentile, as_of)
			SELECT 'CVE-' || (2017 + c % 9) || '-' || (10000 + c), round(power(pg_temp.lg_u(c, 8), 6)::numeric, 5),
			       round(pg_temp.lg_u(c, 9)::numeric, 5), current_date
			FROM generate_series(0, $1::int - 1) c ON CONFLICT DO NOTHING`, []any{o.EPSS}},
		{"vulnerability intelligence: KEV", `
			INSERT INTO intel_kev (cve_id, vendor, product, name, added_on, due_date)
			SELECT 'CVE-' || (2017 + c % 9) || '-' || (10000 + c), 'vendor', 'product', 'Synthetic KEV entry', current_date - 100, current_date + 21
			FROM generate_series(0, $1::int - 1) c WHERE c % 97 = 0 ON CONFLICT DO NOTHING`, []any{o.CVEs}},
		{"text pool", `
			CREATE TEMP TABLE lg_text AS
			SELECT i, 'Synthetic description ' || i || '. ' ||
			          string_agg(md5((i * 100 + j)::text), ' ') || '. Upgrade or apply the vendor fix; see the advisory references.' AS body
			FROM generate_series(0, 5999) i, generate_series(1, 12) j GROUP BY i;
			ALTER TABLE lg_text ADD PRIMARY KEY (i)`, nil},
	}
	for _, s := range steps {
		if err := step(s.name, func() (int64, error) { return ex(s.sql, s.args...) }); err != nil {
			return err
		}
	}

	for lo := 1; lo <= o.Findings; lo += o.Chunk {
		hi := min(lo+o.Chunk-1, o.Findings)
		if err := step(fmt.Sprintf("findings %d-%d", lo, hi), func() (int64, error) {
			return insertFindings(ctx, conn, org, admin, o, lo, hi)
		}); err != nil {
			return err
		}
	}

	post := []struct {
		name string
		sql  string
		args []any
	}{
		{"status history", `
			INSERT INTO finding_status_history (organization_id, finding_id, from_status, to_status, actor_id, source, reason, created_at)
			SELECT f.organization_id, f.id, 'open', f.status, CASE WHEN f.status = 'fixed' THEN NULL ELSE $2::uuid END,
			       CASE WHEN f.status = 'fixed' THEN 'scanner' ELSE 'user' END,
			       CASE WHEN f.status = 'fixed' THEN 'not detected by the latest scan' ELSE 'triaged' END, f.status_changed_at
			FROM findings f WHERE f.organization_id = $1 AND f.status <> 'open' AND f.id >= pg_temp.lg_id(4, 0) AND f.id <= pg_temp.lg_id(4, 281474976710655)
			UNION ALL
			SELECT f.organization_id, f.id, x.from_s, x.to_s, NULL, 'scanner', x.why, f.first_seen_at + x.d * (f.last_seen_at - f.first_seen_at)
			FROM findings f, (VALUES ('open', 'fixed', 'not detected by the latest scan', 0.3), ('fixed', 'open', 'detected again after being fixed', 0.6)) x(from_s, to_s, why, d)
			WHERE f.organization_id = $1 AND f.recurrence_count > 0 AND f.id >= pg_temp.lg_id(4, 0) AND f.id <= pg_temp.lg_id(4, 281474976710655)`,
			[]any{org, admin}},
		{"SBOM components", `
			INSERT INTO sbom_components (organization_id, repository_id, scan_job_id, name, version, purl, type, licenses, bom_ref, depth, created_at)
			SELECT $1, pg_temp.lg_id(1, r), pg_temp.lg_id(2, r * 16 + 9), p.name, p.ver, 'pkg:' || p.eco || '/' || p.name || '@' || p.ver, 'library',
			       CASE WHEN lu < 0.50 THEN ARRAY['MIT'] WHEN lu < 0.75 THEN ARRAY['Apache-2.0'] WHEN lu < 0.85 THEN ARRAY['BSD-3-Clause']
			            WHEN lu < 0.89 THEN ARRAY['ISC'] WHEN lu < 0.92 THEN ARRAY['GPL-3.0-only'] WHEN lu < 0.93 THEN ARRAY['AGPL-3.0-only']
			            WHEN lu < 0.95 THEN ARRAY['LGPL-2.1-only'] ELSE '{}'::text[] END,
			       'pkg:' || p.eco || '/' || p.name || '@' || p.ver, CASE WHEN c = 1 THEN 0 ELSE least(4, 1 + floor(ln(c::float8) / ln(2.0))::int) END,
			       now() - interval '1 day'
			FROM generate_series(1, $2::int) r
			CROSS JOIN LATERAL generate_series(1, greatest(5, (pg_temp.lg_u(r, 10) * 2 * $3::int)::int)) c
			CROSS JOIN LATERAL (SELECT 'pkg-' || ((r * 31 + c * 7919) % 2400) AS name,
			                           '1.' || ((r + c) % 30) || '.' || (c % 7) AS ver,
			                           (ARRAY['golang','maven','pypi','npm','nuget','gem'])[1 + (r / 3) % 6] AS eco,
			                           pg_temp.lg_u(((r * 31 + c * 7919) % 2400), 11) AS lu) p`,
			[]any{org, o.Repos, o.ComponentsPerRepo}},
		{"SBOM dependency edges", `
			INSERT INTO sbom_dependencies (organization_id, repository_id, parent_ref, child_ref)
			SELECT c.organization_id, c.repository_id, p.bom_ref, c.bom_ref
			FROM (SELECT organization_id, repository_id, bom_ref, row_number() OVER (PARTITION BY repository_id ORDER BY bom_ref) AS n
			      FROM sbom_components WHERE scan_job_id >= pg_temp.lg_id(2, 0) AND scan_job_id <= pg_temp.lg_id(2, 281474976710655)) c
			JOIN (SELECT repository_id, bom_ref, row_number() OVER (PARTITION BY repository_id ORDER BY bom_ref) AS n
			      FROM sbom_components WHERE scan_job_id >= pg_temp.lg_id(2, 0) AND scan_job_id <= pg_temp.lg_id(2, 281474976710655)) p
			  ON p.repository_id = c.repository_id AND p.n = c.n / 2
			WHERE c.n > 1 ON CONFLICT DO NOTHING`, nil},
		{"analyze", `ANALYZE`, nil},
	}
	for _, s := range post {
		if err := step(s.name, func() (int64, error) { return ex(s.sql, s.args...) }); err != nil {
			return err
		}
	}
	fmt.Printf("seed finished in %.1f s\n", time.Since(start).Seconds())
	return sizes(ctx, dsn)
}

// insertFindings writes findings lo..hi and their occurrences in one
// transaction. Distributions (deterministic per row):
//   - repository: power law (the first 1% of repositories hold about 12%
//     of the findings, the largest about 1.5%);
//   - category: sca 42%, sast 22%, secrets 5%, iac 9%, container 12%,
//     license 3%, misconfiguration 2%, dast 2%, code-quality 1.5%, api 1.5%;
//   - severity: critical 3%, high 17%, medium 40%, low 30%, info 10%;
//   - status: open 50%, in_progress 3%, needs_review 2%, fixed 32%,
//     false_positive 6%, accepted_risk 7%; 3% of open ones were reopened;
//   - duplicates: CVEs and rules come from shared pools with a skewed
//     popularity, so the same CVE appears in many repositories; half of the
//     SCA findings were reported by two scanners; 0.5% carry the
//     human disposition "duplicate";
//   - 1 to 5 occurrences (scan sightings) per finding, 3 on average.
func insertFindings(ctx context.Context, conn *pgx.Conn, org, admin string, o seedOptions, lo, hi int) (int64, error) {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx, `
		INSERT INTO findings (id, organization_id, repository_id, fingerprint, category, scanner_keys, rule_id, title, description, severity,
		  cwe, cve, cvss, package_name, package_version, fixed_version, file_path, start_line, end_line, status, first_seen_at, last_seen_at,
		  first_scan_job_id, last_scan_job_id, resolved_at, created_at, updated_at, status_changed_at, snippet, snippet_start_line, assignee_id,
		  recurrence_count, accepted_until, human_disposition, cvss_version, cvss_vector, confidence, epss_score, epss_percentile, kev,
		  kev_due_date, exploit_available, reachability, reachability_method, reachability_basis, risk_score, risk_scored_at, risk_dirty,
		  secret_validation_status)
		SELECT pg_temp.lg_id(4, g), $1, pg_temp.lg_id(1, repo), encode(sha256(('lg' || g)::bytea), 'hex'), cat, scn, rule, title,
		       (SELECT body FROM lg_text WHERE i = idx % 6000), sev,
		       CASE WHEN cat IN ('sast', 'code-quality', 'dast', 'api') THEN ARRAY['CWE-' || (20 + idx % 900)] ELSE '{}' END,
		       cve, CASE WHEN cve <> '' THEN round((2 + u7 * 8)::numeric, 1) END,
		       pkg, CASE WHEN pkg <> '' THEN '1.' || (idx % 30) || '.' || (g % 7) ELSE '' END,
		       CASE WHEN pkg <> '' AND u8 < 0.7 THEN '1.' || (idx % 30 + 1) || '.0' ELSE '' END,
		       path, CASE WHEN line THEN 1 + (g % 800)::int END, CASE WHEN line THEN 4 + (g % 800)::int END,
		       st, fs, ls, pg_temp.lg_id(2, repo * 16 + (g % 10)), pg_temp.lg_id(2, repo * 16 + 9), res, fs, ls, COALESCE(res, fs),
		       CASE WHEN line THEN 'func handler' || (g % 50) || '(w http.ResponseWriter, r *http.Request) {' || chr(10) ||
		                      '    q := r.URL.Query().Get("id")' || chr(10) || '    rows, _ := db.Query("SELECT * FROM t WHERE id = " + q)' || chr(10) || '}'
		            ELSE '' END,
		       CASE WHEN line THEN greatest(1, (g % 800)::int - 1) END,
		       CASE WHEN u9 < 0.08 THEN $2::uuid END,
		       CASE WHEN st = 'open' AND u10 < 0.03 THEN 1 ELSE 0 END,
		       CASE WHEN st = 'accepted_risk' THEN now() + (u10 * 180) * interval '1 day' END,
		       CASE WHEN u11 < 0.005 THEN 'duplicate' WHEN u11 < 0.010 THEN 'confirmed' WHEN u11 < 0.013 THEN 'not_exploitable' END,
		       CASE WHEN cve <> '' THEN '3.1' ELSE '' END,
		       CASE WHEN cve <> '' THEN 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' ELSE '' END,
		       CASE WHEN cat = 'sast' THEN (ARRAY['high','medium','low'])[1 + (idx % 3)] WHEN cve <> '' THEN 'high' ELSE 'unknown' END,
		       CASE WHEN cve <> '' THEN round(power(pg_temp.lg_u(idx, 8), 6)::numeric, 5) END,
		       CASE WHEN cve <> '' THEN round(pg_temp.lg_u(idx, 9)::numeric, 5) END,
		       kev, CASE WHEN kev THEN current_date + 21 END, kev OR (cve <> '' AND idx % 23 = 0),
		       CASE WHEN cat <> 'sca' THEN 'unknown' WHEN u12 < 0.2 THEN 'reachable' WHEN u12 < 0.5 THEN 'not_reachable' ELSE 'unknown' END,
		       CASE WHEN cat = 'sca' AND u12 < 0.5 THEN 'import' ELSE '' END,
		       CASE WHEN cat = 'sca' AND u12 < 0.5 THEN 'package imported by 3 files' ELSE '' END,
		       round(least(100, CASE sev WHEN 'critical' THEN 80 WHEN 'high' THEN 60 WHEN 'medium' THEN 38 WHEN 'low' THEN 18 ELSE 4 END + u13 * 18)::numeric, 2),
		       now(), false,
		       CASE WHEN cat = 'secrets' AND u13 < 0.2 THEN 'inactive' ELSE 'not_checked' END
		FROM generate_series($3::bigint, $4::bigint) g
		CROSS JOIN LATERAL (SELECT pg_temp.lg_u(g, 0) u0, pg_temp.lg_u(g, 1) u1, pg_temp.lg_u(g, 2) u2, pg_temp.lg_u(g, 3) u3,
		                           pg_temp.lg_u(g, 4) u4, pg_temp.lg_u(g, 5) u5, pg_temp.lg_u(g, 6) u6, pg_temp.lg_u(g, 7) u7,
		                           pg_temp.lg_u(g, 8) u8, pg_temp.lg_u(g, 9) u9, pg_temp.lg_u(g, 10) u10, pg_temp.lg_u(g, 11) u11,
		                           pg_temp.lg_u(g, 12) u12, pg_temp.lg_u(g, 13) u13) h
		CROSS JOIN LATERAL (SELECT 1 + least($5::int - 1, floor($5::int * power(u0, 2.2)))::int AS repo,
		       CASE WHEN u2 < 0.42 THEN 'sca' WHEN u2 < 0.64 THEN 'sast' WHEN u2 < 0.69 THEN 'secrets' WHEN u2 < 0.78 THEN 'iac'
		            WHEN u2 < 0.90 THEN 'container' WHEN u2 < 0.93 THEN 'license' WHEN u2 < 0.95 THEN 'misconfiguration'
		            WHEN u2 < 0.97 THEN 'dast' WHEN u2 < 0.985 THEN 'code-quality' ELSE 'api' END AS cat,
		       CASE WHEN u1 < 0.03 THEN 'critical' WHEN u1 < 0.20 THEN 'high' WHEN u1 < 0.60 THEN 'medium' WHEN u1 < 0.90 THEN 'low' ELSE 'info' END AS sev,
		       CASE WHEN u3 < 0.50 THEN 'open' WHEN u3 < 0.53 THEN 'in_progress' WHEN u3 < 0.55 THEN 'needs_review' WHEN u3 < 0.87 THEN 'fixed'
		            WHEN u3 < 0.93 THEN 'false_positive' ELSE 'accepted_risk' END AS st,
		       floor($6::int * power(u6, 2))::int AS idx,
		       now() - power(u4, 1.3) * 420 * interval '1 day' AS fs) a
		CROSS JOIN LATERAL (SELECT
		       CASE WHEN cat IN ('sca', 'container') THEN 'CVE-' || (2017 + idx % 9) || '-' || (10000 + idx) ELSE '' END AS cve,
		       CASE WHEN cat IN ('sca', 'container', 'license') THEN 'pkg-' || (idx % 2400) ELSE '' END AS pkg,
		       cat IN ('sca', 'container') AND idx % 97 = 0 AS kev,
		       cat IN ('sast', 'secrets', 'iac', 'code-quality', 'misconfiguration') AS line,
		       CASE WHEN st IN ('fixed', 'false_positive', 'accepted_risk') THEN fs + u5 * (now() - fs) END AS res) b
		CROSS JOIN LATERAL (SELECT
		       CASE cat WHEN 'sca' THEN CASE WHEN u7 < 0.5 THEN ARRAY['osv-scanner', 'trivy-fs'] ELSE ARRAY['osv-scanner'] END
		                WHEN 'sast' THEN ARRAY['opengrep'] WHEN 'code-quality' THEN ARRAY['opengrep'] WHEN 'secrets' THEN ARRAY['gitleaks']
		                ELSE ARRAY['trivy-fs'] END AS scn,
		       CASE WHEN cve <> '' THEN cve WHEN cat = 'secrets' THEN (ARRAY['generic-api-key','aws-access-token','private-key','slack-webhook'])[1 + idx % 4]
		            WHEN cat = 'license' THEN 'license-' || (ARRAY['GPL-3.0-only','AGPL-3.0-only','SSPL-1.0'])[1 + idx % 3]
		            ELSE 'pathos.' || cat || '.rule-' || (idx % 400) END AS rule,
		       CASE WHEN cve <> '' THEN cve || ': vulnerability in pkg-' || (idx % 2400)
		            WHEN cat = 'secrets' THEN 'Hard-coded credential (' || (ARRAY['generic API key','AWS access key','private key','Slack webhook'])[1 + idx % 4] || ')'
		            ELSE initcap(replace(cat, '-', ' ')) || ' issue ' || (idx % 400) || ': ' ||
		                 (ARRAY['possible injection in handler','weak cryptographic algorithm','missing authorization check',
		                        'insecure TLS configuration','container runs as root','unvalidated redirect'])[1 + idx % 6] END AS title,
		       CASE cat WHEN 'sca' THEN (ARRAY['go.sum','pom.xml','requirements.txt','package-lock.json','packages.lock.json','Gemfile.lock'])[1 + (repo / 3) % 6]
		                WHEN 'container' THEN 'Dockerfile' WHEN 'license' THEN 'package-lock.json'
		                WHEN 'iac' THEN 'deploy/terraform/module' || (g % 40) || '/main.tf'
		                WHEN 'dast' THEN '' WHEN 'api' THEN ''
		                ELSE 'src/module' || (g % 120) || '/file' || (g % 50) || (ARRAY['.go','.java','.py','.ts','.cs','.rb'])[1 + (repo / 3) % 6] END AS path,
		       CASE WHEN res IS NULL THEN now() - u5 * 7 * interval '1 day' WHEN st = 'fixed' THEN res - interval '12 hours'
		            ELSE now() - u5 * 7 * interval '1 day' END AS ls) c`,
		org, admin, lo, hi, o.Repos, o.CVEs)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO finding_occurrences (id, organization_id, finding_id, scan_result_id, commit_sha, file_path, start_line, end_line, created_at)
		SELECT pg_temp.lg_id(7, pg_temp.lg_n(f.id) * 8 + i), f.organization_id, f.id,
		       pg_temp.lg_id(3, (pg_temp.lg_n(f.repository_id) * 16 + (9 - i)) * 4 +
		         CASE WHEN f.category IN ('sast', 'code-quality') THEN 0 WHEN f.category = 'sca' THEN 1 WHEN f.category = 'secrets' THEN 2 ELSE 3 END),
		       pg_temp.lg_hex(pg_temp.lg_n(f.repository_id) * 16 + (9 - i), 40), f.file_path, f.start_line, f.end_line,
		       f.last_seen_at - i * interval '7 days'
		FROM findings f
		CROSS JOIN LATERAL generate_series(0, (pg_temp.lg_u(pg_temp.lg_n(f.id), 14) * 5)::int % 5) i
		WHERE f.id >= pg_temp.lg_id(4, $1) AND f.id <= pg_temp.lg_id(4, $2)`, lo, hi); err != nil {
		return 0, err
	}
	return tag.RowsAffected(), tx.Commit(ctx)
}

func sizes(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	var db string
	var dbBytes int64
	if err := conn.QueryRow(ctx, `SELECT pg_size_pretty(pg_database_size(current_database())), pg_database_size(current_database())`).Scan(&db, &dbBytes); err != nil {
		return err
	}
	fmt.Printf("\ndatabase size: %s (%d bytes)\n", db, dbBytes)
	rows, err := conn.Query(ctx, `SELECT c.relname, c.reltuples::bigint, pg_size_pretty(pg_table_size(c.oid)), pg_size_pretty(pg_indexes_size(c.oid)),
		pg_size_pretty(pg_total_relation_size(c.oid))
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
		WHERE c.relkind = 'r' ORDER BY pg_total_relation_size(c.oid) DESC LIMIT 15`)
	if err != nil {
		return err
	}
	defer rows.Close()
	fmt.Printf("%-32s %12s %10s %10s %10s\n", "table", "rows (est.)", "table", "indexes", "total")
	for rows.Next() {
		var name, t, i, total string
		var n int64
		if err := rows.Scan(&name, &n, &t, &i, &total); err != nil {
			return err
		}
		fmt.Printf("%-32s %12d %10s %10s %10s\n", name, n, t, i, total)
	}
	return rows.Err()
}

// cleanup removes every synthetic row (repositories cascade to findings,
// scans and SBOM data) and the synthetic intelligence records.
func cleanup(ctx context.Context, dsn string) error {
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	for _, q := range []string{
		`DELETE FROM repositories WHERE id >= '0000000b-0000-7000-8001-000000000000' AND id <= '0000000b-0000-7000-8001-ffffffffffff'`,
		`DELETE FROM applications WHERE name LIKE 'loadgen-app-%'`,
		`DELETE FROM business_units WHERE name LIKE 'loadgen BU %'`,
		`DELETE FROM scm_connections WHERE id = '` + connectionID + `'`,
		`DELETE FROM secrets WHERE id IN ('0000000b-0000-7000-8000-000000000001', '0000000b-0000-7000-8000-000000000002')`,
		`DELETE FROM intel_vulns WHERE id LIKE 'GHSA-lg%'`,
		`DELETE FROM intel_kev WHERE name = 'Synthetic KEV entry'`,
		`DELETE FROM workers WHERE name LIKE 'loadgen-%'`,
	} {
		if err := step(q[:min(len(q), 40)], func() (int64, error) {
			tag, err := conn.Exec(ctx, q)
			return tag.RowsAffected(), err
		}); err != nil {
			return err
		}
	}
	return nil
}
