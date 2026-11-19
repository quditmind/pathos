-- +goose Up
-- Concurrent executions per repository (2.2.2, VALIDATION_REPORT O2).
-- Until 2.2.1 only one execution per repository could run at a time
-- (scan_jobs_running_uq on repository_id), including target scans (image,
-- URL, API, artifact, SBOM) and result imports, so a 15-minute DAST scan
-- made CI imports fail with 409 and held back code scans.
--
-- The one-at-a-time rule now applies only where it protects consistency:
--   * one running repository (code) scan per repository, and one per pull
--     request of the repository (pull request results are kept apart);
--   * one running scan per scan target.
-- Result imports and target scans run next to a repository scan. Findings
-- of target scans carry scan_target_id and are resolved per target; the
-- database writes of results and finalization are serialized per
-- repository with an advisory lock (internal/scans).
DROP INDEX IF EXISTS scan_jobs_running_uq;
CREATE UNIQUE INDEX scan_jobs_running_uq ON scan_jobs (repository_id, COALESCE(pull_request, 0))
    WHERE status = 'running' AND target_id IS NULL AND trigger <> 'import';
CREATE UNIQUE INDEX scan_jobs_running_target_uq ON scan_jobs (target_id)
    WHERE status = 'running' AND target_id IS NOT NULL;

-- +goose Down
DROP INDEX IF EXISTS scan_jobs_running_target_uq;
DROP INDEX IF EXISTS scan_jobs_running_uq;
CREATE UNIQUE INDEX scan_jobs_running_uq ON scan_jobs (repository_id) WHERE status = 'running';
