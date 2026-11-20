-- +goose Up
-- PATHOS 3.0 M4: CodeGraph discovery runs as a scan execution with trigger
-- "codegraph" (the existing job, lease and worker system). The execution
-- uses a per-organization system profile that selects only the
-- pathos-graph tool (worker-graph family); the profile is stored archived
-- so it never appears in profile choices and is never a default
-- (docs/aspm/PATHOS_CODEGRAPH_ARCHITECTURE.md, "Build jobs").
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_trigger_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'push', 'pull_request', 'merge', 'onboarding', 'emergency', 'import', 'codegraph'));

SELECT pathos_apply_app_grants();

-- +goose Down
DELETE FROM scan_jobs WHERE trigger = 'codegraph';
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_trigger_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_trigger_check
    CHECK (trigger IN ('manual', 'schedule', 'push', 'pull_request', 'merge', 'onboarding', 'emergency', 'import'));
