-- +goose Up
-- Concurrent executions per repository (2.2.2, VALIDATION_REPORT O2),
-- brought forward into 3.0. In 2.2.x this was migration 00043; the 3.0 line
-- had already used 00043 (feature flags), so it is 00066 here. It is
-- idempotent: an install upgraded from 2.2.x has the 2.2.x indexes already
-- (internal/platform/db reconciles the goose version table first, see
-- reconcile22.go), a fresh install gets them here.
--
-- Until 2.2.1 only one execution per repository could run at a time
-- (scan_jobs_running_uq on repository_id), including target scans (image,
-- URL, API, artifact, SBOM) and result imports, so a 15-minute DAST scan
-- made CI imports fail with 409 and held back code scans.
--
-- The one-at-a-time rule now applies only where it protects consistency:
--   * one running repository (code) scan per repository, and one per pull
--     request of the repository (pull request results are kept apart);
--     a CodeGraph discovery (trigger codegraph) shares this lane;
--   * one running scan per scan target.
-- Reverse-engineering analyses (trigger rea, 3.0 M10, migration 00061)
-- keep their own lane in both indexes: they neither wait for nor block the
-- other executions. Result imports and target scans run next to a
-- repository scan. Findings of target scans carry scan_target_id and are
-- resolved per target; the database writes of results and finalization are
-- serialized per repository with an advisory lock (internal/scans). The
-- lease query (internal/scans/worker_api.go, runningConflict) mirrors these
-- indexes.
DROP INDEX IF EXISTS scan_jobs_running_uq;
DROP INDEX IF EXISTS scan_jobs_running_target_uq;
CREATE UNIQUE INDEX scan_jobs_running_uq ON scan_jobs (repository_id, COALESCE(pull_request, 0), (trigger = 'rea'))
    WHERE status = 'running' AND target_id IS NULL AND trigger <> 'import';
CREATE UNIQUE INDEX scan_jobs_running_target_uq ON scan_jobs (target_id, (trigger = 'rea'))
    WHERE status = 'running' AND target_id IS NOT NULL;

-- +goose Down
-- Back to the 3.0 index of migration 00061 (one running execution per
-- repository and lane): executions running next to the oldest one of their
-- repository and lane are failed first.
UPDATE scan_jobs j SET status = 'failed', finished_at = now(), lease_expires_at = NULL,
       error = 'stopped by the downgrade of migration 00066 (one running execution per repository)'
WHERE j.status = 'running' AND j.id <> (SELECT x.id FROM scan_jobs x
                                        WHERE x.repository_id = j.repository_id AND x.status = 'running'
                                          AND (x.trigger = 'rea') = (j.trigger = 'rea')
                                        ORDER BY x.started_at NULLS LAST, x.id LIMIT 1);
DROP INDEX IF EXISTS scan_jobs_running_target_uq;
DROP INDEX IF EXISTS scan_jobs_running_uq;
CREATE UNIQUE INDEX scan_jobs_running_uq ON scan_jobs (repository_id, (trigger = 'rea')) WHERE status = 'running';
