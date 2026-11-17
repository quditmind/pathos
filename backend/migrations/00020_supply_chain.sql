-- +goose Up
-- ASPM phase 7: supply chain.

-- Malicious packages (OSV MAL-*), maintained by the risk engine.
ALTER TABLE findings ADD COLUMN malicious boolean NOT NULL DEFAULT false;
CREATE INDEX findings_malicious_idx ON findings (organization_id) WHERE malicious;
UPDATE findings SET risk_dirty = true WHERE NOT risk_dirty AND category IN ('sca', 'container');

-- Package health from deps.dev, per package (purl without version).
CREATE TABLE package_health (
    purl_base           text PRIMARY KEY CHECK (length(purl_base) <= 600),
    system              text NOT NULL,
    name                text NOT NULL,
    found               boolean NOT NULL DEFAULT true,
    latest_version      text NOT NULL DEFAULT '',
    latest_published_at timestamptz,
    deprecated_versions text[] NOT NULL DEFAULT '{}',
    scorecard           numeric(4,1),
    scorecard_project   text NOT NULL DEFAULT '',
    fetched_at          timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE intel_feeds DROP CONSTRAINT intel_feeds_feed_check;
ALTER TABLE intel_feeds ADD CONSTRAINT intel_feeds_feed_check CHECK (feed IN ('epss', 'kev', 'osv', 'depsdev'));
INSERT INTO intel_feeds (feed, url) VALUES ('depsdev', 'https://api.deps.dev/v3/') ON CONFLICT DO NOTHING;

-- Build artifact targets: an uploaded release artifact (archive, Java
-- archive, binary). The file is kept gzip-compressed in the object store
-- (artifact_key) or inline; sbom_sha256/sbom_size hold its digest and size.
ALTER TABLE scan_targets DROP CONSTRAINT scan_targets_kind_check;
ALTER TABLE scan_targets ADD CONSTRAINT scan_targets_kind_check CHECK (kind IN ('image', 'url', 'api', 'sbom', 'artifact'));
ALTER TABLE scan_targets ADD COLUMN artifact_name text NOT NULL DEFAULT '' CHECK (length(artifact_name) <= 255),
                         ADD COLUMN artifact_key text,
                         ADD COLUMN artifact_gzip bytea;
ALTER TABLE scan_targets ADD CONSTRAINT scan_targets_artifact_check CHECK (kind <> 'artifact' OR artifact_key IS NOT NULL OR artifact_gzip IS NOT NULL);
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_target_kind_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_target_kind_check CHECK (target_kind IN ('repository', 'image', 'url', 'api', 'sbom', 'artifact'));

-- Pull request checks. A PR scan runs the repository's profile on the PR
-- head; its results are kept apart from the repository's findings (which
-- track the scan branch) and compared with them: what the PR introduces is
-- "new". The gate fails when a new finding is at or above the repository's
-- gate severity, and the result is posted as a commit status.
ALTER TABLE repositories ADD COLUMN pr_checks_enabled boolean NOT NULL DEFAULT false,
                         ADD COLUMN pr_gate_severity text NOT NULL DEFAULT 'high'
                           CHECK (pr_gate_severity IN ('critical', 'high', 'medium', 'low', 'none'));
ALTER TABLE scan_jobs ADD COLUMN pull_request integer CHECK (pull_request > 0);
DROP INDEX scan_jobs_queued_uq;
CREATE UNIQUE INDEX scan_jobs_queued_uq ON scan_jobs (repository_id, profile_version_id,
    COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid), COALESCE(pull_request, 0)) WHERE status = 'queued';

CREATE TABLE pr_checks (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id    uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    scan_job_id      uuid NOT NULL UNIQUE REFERENCES scan_jobs(id) ON DELETE CASCADE,
    pull_request     integer NOT NULL CHECK (pull_request > 0),
    head_ref         text NOT NULL DEFAULT '',
    head_sha         text NOT NULL DEFAULT '',
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'passed', 'failed', 'error')),
    gate_severity    text NOT NULL,
    new_findings     integer NOT NULL DEFAULT 0,
    new_by_severity  jsonb NOT NULL DEFAULT '{}',
    existing_findings integer NOT NULL DEFAULT 0,
    summary          text NOT NULL DEFAULT '',
    status_posted    text NOT NULL DEFAULT '' CHECK (status_posted IN ('', 'pending', 'final', 'failed', 'not_supported')),
    status_error     text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now(),
    finished_at      timestamptz
);
CREATE INDEX pr_checks_repo_idx ON pr_checks (repository_id, pull_request, created_at DESC);

CREATE TABLE pr_findings (
    id             uuid PRIMARY KEY,
    pr_check_id    uuid NOT NULL REFERENCES pr_checks(id) ON DELETE CASCADE,
    fingerprint    text NOT NULL,
    scanner_key    text NOT NULL,
    category       text NOT NULL,
    rule_id        text NOT NULL DEFAULT '',
    title          text NOT NULL,
    severity       text NOT NULL,
    file_path      text NOT NULL DEFAULT '',
    start_line     integer,
    cve            text,
    is_new         boolean NOT NULL DEFAULT true,
    existing_finding_id uuid REFERENCES findings(id) ON DELETE SET NULL,
    UNIQUE (pr_check_id, fingerprint)
);
CREATE INDEX pr_findings_new_idx ON pr_findings (pr_check_id) WHERE is_new;

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS pr_findings;
DROP TABLE IF EXISTS pr_checks;
DELETE FROM scan_jobs WHERE pull_request IS NOT NULL;
DROP INDEX scan_jobs_queued_uq;
CREATE UNIQUE INDEX scan_jobs_queued_uq ON scan_jobs (repository_id, profile_version_id,
    COALESCE(target_id, '00000000-0000-0000-0000-000000000000'::uuid)) WHERE status = 'queued';
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS pull_request;
ALTER TABLE repositories DROP COLUMN IF EXISTS pr_gate_severity, DROP COLUMN IF EXISTS pr_checks_enabled;
DELETE FROM scan_jobs WHERE target_kind = 'artifact';
ALTER TABLE scan_jobs DROP CONSTRAINT scan_jobs_target_kind_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_target_kind_check CHECK (target_kind IN ('repository', 'image', 'url', 'api', 'sbom'));
UPDATE findings SET scan_target_id = NULL WHERE scan_target_id IN (SELECT id FROM scan_targets WHERE kind = 'artifact');
DELETE FROM scan_targets WHERE kind = 'artifact';
ALTER TABLE scan_targets DROP CONSTRAINT IF EXISTS scan_targets_artifact_check;
ALTER TABLE scan_targets DROP COLUMN IF EXISTS artifact_gzip, DROP COLUMN IF EXISTS artifact_key, DROP COLUMN IF EXISTS artifact_name;
ALTER TABLE scan_targets DROP CONSTRAINT scan_targets_kind_check;
ALTER TABLE scan_targets ADD CONSTRAINT scan_targets_kind_check CHECK (kind IN ('image', 'url', 'api', 'sbom'));
DELETE FROM intel_feed_runs WHERE feed = 'depsdev';
DELETE FROM intel_feeds WHERE feed = 'depsdev';
ALTER TABLE intel_feeds DROP CONSTRAINT intel_feeds_feed_check;
ALTER TABLE intel_feeds ADD CONSTRAINT intel_feeds_feed_check CHECK (feed IN ('epss', 'kev', 'osv'));
DROP TABLE IF EXISTS package_health;
DROP INDEX IF EXISTS findings_malicious_idx;
ALTER TABLE findings DROP COLUMN IF EXISTS malicious;
