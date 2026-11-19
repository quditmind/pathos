-- +goose NO TRANSACTION
-- +goose Up
-- Keyset indexes for the findings list (docs/PERFORMANCE.md). The list is
-- ordered by (rank, last_seen_at, id) and paged with a cursor on the same
-- columns; the rank expressions are exactly the ones in
-- internal/scans/findings.go (sevRank, riskRank), so a page is an index
-- range scan instead of a sort of every open finding. Measured with 1
-- million findings: the default list went from about 2 s to under 40 ms.
-- Built concurrently, so upgrading a large installation does not block
-- scans writing findings.
CREATE INDEX CONCURRENTLY IF NOT EXISTS findings_open_severity_rank_idx ON findings
    (organization_id, (array_position(ARRAY['info','low','medium','high','critical'], severity) - 1), last_seen_at, id)
    WHERE status IN ('open', 'in_progress', 'needs_review');
CREATE INDEX CONCURRENTLY IF NOT EXISTS findings_severity_rank_idx ON findings
    (organization_id, (array_position(ARRAY['info','low','medium','high','critical'], severity) - 1), last_seen_at, id);
CREATE INDEX CONCURRENTLY IF NOT EXISTS findings_open_risk_rank_idx ON findings
    (organization_id, (COALESCE(round(risk_score * 100)::int, -1)), last_seen_at, id)
    WHERE status IN ('open', 'in_progress', 'needs_review');
-- The severity counts above the list (GET /api/v1/findings/summary) with
-- the default filters: an index-only scan joined to repositories instead of
-- reading every open finding (about 420 ms to 80 ms at 1 million).
CREATE INDEX CONCURRENTLY IF NOT EXISTS findings_status_severity_repo_idx ON findings
    (organization_id, status, severity, repository_id);
-- Open vulnerabilities of a component in the SBOM inventory
-- (GET /api/v1/sbom/components): an index-only lookup per package version
-- instead of reading the repositories' findings (with 10 million findings
-- the page took 136 s, 8.6 s with this index).
CREATE INDEX CONCURRENTLY IF NOT EXISTS findings_open_sca_package_idx ON findings
    (package_name, package_version, repository_id)
    WHERE category = 'sca' AND status IN ('open', 'in_progress', 'needs_review');

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS findings_open_sca_package_idx;
DROP INDEX CONCURRENTLY IF EXISTS findings_status_severity_repo_idx;
DROP INDEX CONCURRENTLY IF EXISTS findings_open_risk_rank_idx;
DROP INDEX CONCURRENTLY IF EXISTS findings_severity_rank_idx;
DROP INDEX CONCURRENTLY IF EXISTS findings_open_severity_rank_idx;
