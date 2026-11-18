-- +goose Up
-- Developer context: security-material change detection between scanned
-- commits and opt-in developer attribution of findings (who introduced and
-- who fixed them). Attribution stores git author NAMES only, never e-mail
-- addresses, and is off until an administrator enables it.

-- One row per branch scan of a Git repository: the comparison outcome.
CREATE TABLE material_change_runs (
    scan_job_id       uuid PRIMARY KEY REFERENCES scan_jobs(id) ON DELETE CASCADE,
    organization_id   uuid NOT NULL,
    repository_id     uuid NOT NULL,
    status            text NOT NULL CHECK (status IN ('computed', 'baseline', 'unchanged', 'unavailable')),
    reason            text NOT NULL DEFAULT '' CHECK (length(reason) <= 1000),
    base_sha          text NOT NULL DEFAULT '' CHECK (length(base_sha) <= 64),
    head_sha          text NOT NULL DEFAULT '' CHECK (length(head_sha) <= 64),
    files_changed     integer NOT NULL DEFAULT 0,
    truncated         boolean NOT NULL DEFAULT false,
    change_count      integer NOT NULL DEFAULT 0,
    -- Dependencies compare the SBOMs of the two scans: computed, baseline
    -- (no earlier SBOM) or none (this scan produced no SBOM).
    dependency_status text NOT NULL DEFAULT 'none' CHECK (dependency_status IN ('computed', 'baseline', 'none')),
    commits_complete  boolean NOT NULL DEFAULT false,
    created_at        timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX material_change_runs_repo_idx ON material_change_runs (repository_id, created_at DESC);

CREATE TABLE material_changes (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    scan_job_id     uuid NOT NULL REFERENCES material_change_runs(scan_job_id) ON DELETE CASCADE,
    category        text NOT NULL CHECK (category IN ('auth', 'api_endpoint', 'dependency', 'crypto', 'iac_exposure',
                                                      'secrets_handling', 'cicd', 'sensitive_data')),
    rule_id         text NOT NULL CHECK (length(rule_id) <= 100),
    level           text NOT NULL CHECK (level IN ('high', 'medium', 'low')),
    file_path       text NOT NULL DEFAULT '' CHECK (length(file_path) <= 1000),
    change_type     text NOT NULL DEFAULT '' CHECK (change_type IN ('', 'added', 'modified', 'deleted', 'renamed')),
    side            text NOT NULL DEFAULT 'file' CHECK (side IN ('added', 'removed', 'file')),
    start_line      integer,
    end_line        integer,
    match_count     integer NOT NULL DEFAULT 1,
    -- The matched line, redacted for secrets on ingest.
    snippet         text NOT NULL DEFAULT '' CHECK (length(snippet) <= 1000),
    explanation     text NOT NULL DEFAULT '' CHECK (length(explanation) <= 2000),
    detail          text NOT NULL DEFAULT '' CHECK (length(detail) <= 500),
    -- Author name of the last commit in the range that touched the file
    -- (only while developer attribution is enabled).
    author_name     text NOT NULL DEFAULT '' CHECK (length(author_name) <= 200),
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX material_changes_job_idx ON material_changes (scan_job_id);
CREATE INDEX material_changes_repo_idx ON material_changes (repository_id, created_at DESC);
CREATE INDEX material_changes_file_idx ON material_changes (repository_id, file_path);

-- The dependency set of a repository's latest branch SBOM, for the next
-- comparison (sbom_components only keeps the current inventory).
CREATE TABLE material_dependency_baselines (
    repository_id   uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    scan_job_id     uuid NOT NULL,
    components      text[] NOT NULL DEFAULT '{}',
    updated_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);

-- Organization switch for developer attribution (off by default).
CREATE TABLE developer_insight_settings (
    organization_id     uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    attribution_enabled boolean NOT NULL DEFAULT false,
    updated_by          uuid,
    updated_at          timestamptz NOT NULL DEFAULT now()
);

-- Commits between the previous and the current scanned commit (author
-- name and touched files; collected only while attribution is enabled).
CREATE TABLE scan_commits (
    scan_job_id     uuid NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id   uuid NOT NULL,
    position        integer NOT NULL, -- 0 = newest
    sha             text NOT NULL CHECK (length(sha) <= 64),
    author_name     text NOT NULL CHECK (length(author_name) <= 200),
    authored_at     timestamptz,
    files           text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (scan_job_id, sha)
);
CREATE INDEX scan_commits_repo_idx ON scan_commits (repository_id);

-- Who introduced and who fixed a finding, inferred from the commits of the
-- scan that first reported it and of the scan that no longer did.
CREATE TABLE finding_attribution (
    finding_id             uuid PRIMARY KEY,
    organization_id        uuid NOT NULL,
    repository_id          uuid NOT NULL,
    introduced_by          text NOT NULL DEFAULT '' CHECK (length(introduced_by) <= 200),
    introduced_commit      text NOT NULL DEFAULT '' CHECK (length(introduced_commit) <= 64),
    introduced_scan_job_id uuid,
    introduced_at          timestamptz,
    fixed_by               text NOT NULL DEFAULT '' CHECK (length(fixed_by) <= 200),
    fixed_commit           text NOT NULL DEFAULT '' CHECK (length(fixed_commit) <= 64),
    fixed_scan_job_id      uuid,
    fixed_at               timestamptz,
    updated_at             timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX finding_attribution_introduced_idx ON finding_attribution (organization_id, lower(introduced_by), introduced_at);
CREATE INDEX finding_attribution_fixed_idx ON finding_attribution (organization_id, lower(fixed_by), fixed_at);

-- Administrator-maintained links from a git author name to a PATHOS user.
CREATE TABLE developer_identities (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    author_name     text NOT NULL CHECK (length(author_name) BETWEEN 1 AND 200),
    user_id         uuid NOT NULL,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (organization_id, user_id) REFERENCES users(organization_id, id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX developer_identities_name_uq ON developer_identities (organization_id, lower(author_name));

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS developer_identities;
DROP TABLE IF EXISTS finding_attribution;
DROP TABLE IF EXISTS scan_commits;
DROP TABLE IF EXISTS developer_insight_settings;
DROP TABLE IF EXISTS material_dependency_baselines;
DROP TABLE IF EXISTS material_changes;
DROP TABLE IF EXISTS material_change_runs;
