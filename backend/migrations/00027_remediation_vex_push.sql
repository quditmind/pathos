-- +goose Up
-- PATHOS 1.1: automatic fix pull requests, VEX and application versions,
-- SBOM portfolio policies, and secret push protection. Additive only.

----------------------------------------------------------------------------
-- 1. Fix pull requests for vulnerable dependencies.
--
-- Opt-in per repository. A request is queued here; a worker clones the
-- repository and edits the manifest (never running project code); the API
-- then creates a branch, a commit and a pull/merge request through the SCM
-- API. The PR state is tracked; findings are resolved only by a later scan.
----------------------------------------------------------------------------
ALTER TABLE repositories ADD COLUMN fix_prs_enabled boolean NOT NULL DEFAULT false,
                         ADD COLUMN fix_pr_grouping text NOT NULL DEFAULT 'package'
                           CHECK (fix_pr_grouping IN ('finding', 'package'));

CREATE TABLE fix_pull_requests (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id    uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ecosystem        text NOT NULL DEFAULT '' CHECK (length(ecosystem) <= 40),
    package_name     text NOT NULL CHECK (length(package_name) BETWEEN 1 AND 300),
    current_version  text NOT NULL DEFAULT '' CHECK (length(current_version) <= 100),
    target_version   text NOT NULL CHECK (length(target_version) BETWEEN 1 AND 100),
    manifest_hint    text NOT NULL DEFAULT '' CHECK (length(manifest_hint) <= 1000),
    grouping         text NOT NULL CHECK (grouping IN ('finding', 'package')),
    -- queued → running (worker) → creating (API talks to the SCM) → open;
    -- open → merged | closed (polled). failed and not_supported are final.
    status           text NOT NULL DEFAULT 'queued'
                       CHECK (status IN ('queued', 'running', 'creating', 'open', 'merged', 'closed', 'failed', 'not_supported')),
    error            text NOT NULL DEFAULT '' CHECK (length(error) <= 1000),
    base_branch      text NOT NULL DEFAULT '' CHECK (length(base_branch) <= 255),
    base_commit      text NOT NULL DEFAULT '' CHECK (length(base_commit) <= 64),
    branch           text NOT NULL DEFAULT '' CHECK (length(branch) <= 255),
    commit_sha       text NOT NULL DEFAULT '' CHECK (length(commit_sha) <= 64),
    changed_files    text[] NOT NULL DEFAULT '{}',
    pr_number        text NOT NULL DEFAULT '' CHECK (length(pr_number) <= 40),
    pr_url           text NOT NULL DEFAULT '' CHECK (length(pr_url) <= 1000),
    leased_by        uuid REFERENCES workers(id) ON DELETE SET NULL,
    lease_expires_at timestamptz,
    attempts         integer NOT NULL DEFAULT 0,
    requested_by     uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    state_checked_at timestamptz,
    finished_at      timestamptz
);
CREATE INDEX fix_pull_requests_queue_idx ON fix_pull_requests (created_at) WHERE status = 'queued';
CREATE INDEX fix_pull_requests_open_idx ON fix_pull_requests (state_checked_at NULLS FIRST) WHERE status = 'open';
CREATE INDEX fix_pull_requests_repo_idx ON fix_pull_requests (repository_id, created_at DESC);

CREATE TABLE fix_pull_request_findings (
    fix_pull_request_id uuid NOT NULL REFERENCES fix_pull_requests(id) ON DELETE CASCADE,
    finding_id          uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    PRIMARY KEY (fix_pull_request_id, finding_id)
);
CREATE INDEX fix_pull_request_findings_finding_idx ON fix_pull_request_findings (finding_id);

----------------------------------------------------------------------------
-- 2. Application versions (releases), VEX and SBOM portfolio policies.
----------------------------------------------------------------------------
CREATE TABLE application_versions (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id  uuid NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    version         text NOT NULL CHECK (length(version) BETWEEN 1 AND 100),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    released_at     timestamptz,
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (application_id, version)
);
CREATE INDEX application_versions_org_idx ON application_versions (organization_id, created_at DESC);

-- What a version is made of: one commit (and the scan of it whose SBOM and
-- findings were snapshotted) per repository.
CREATE TABLE application_version_repositories (
    version_id      uuid NOT NULL REFERENCES application_versions(id) ON DELETE CASCADE,
    repository_id   uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref             text NOT NULL DEFAULT '' CHECK (length(ref) <= 255),
    commit_sha      text NOT NULL DEFAULT '' CHECK (length(commit_sha) <= 64),
    scan_job_id     uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
    PRIMARY KEY (version_id, repository_id)
);

-- Frozen copies: later scans do not change what a released version contained.
CREATE TABLE application_version_components (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    version_id      uuid NOT NULL REFERENCES application_versions(id) ON DELETE CASCADE,
    repository_id   uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    name            text NOT NULL,
    version         text NOT NULL DEFAULT '',
    purl            text NOT NULL DEFAULT '',
    type            text NOT NULL DEFAULT '',
    licenses        text[] NOT NULL DEFAULT '{}'
);
CREATE INDEX application_version_components_version_idx ON application_version_components (version_id);
CREATE INDEX application_version_components_name_idx ON application_version_components (organization_id, lower(name), version);
CREATE INDEX application_version_components_purl_idx ON application_version_components (organization_id, purl);

CREATE TABLE application_version_findings (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    version_id      uuid NOT NULL REFERENCES application_versions(id) ON DELETE CASCADE,
    repository_id   uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    finding_id      uuid REFERENCES findings(id) ON DELETE SET NULL,
    fingerprint     text NOT NULL,
    category        text NOT NULL,
    title           text NOT NULL,
    severity        text NOT NULL,
    cve             text NOT NULL DEFAULT '',
    package_name    text NOT NULL DEFAULT '',
    package_version text NOT NULL DEFAULT '',
    fixed_version   text NOT NULL DEFAULT '',
    status          text NOT NULL,
    UNIQUE (version_id, repository_id, fingerprint)
);
CREATE INDEX application_version_findings_cve_idx ON application_version_findings (organization_id, cve) WHERE cve <> '';

-- VEX documents imported (OpenVEX or CycloneDX VEX). The document itself
-- is not kept; its digest is.
CREATE TABLE vex_imports (
    id                     uuid PRIMARY KEY,
    organization_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id          uuid REFERENCES repositories(id) ON DELETE CASCADE,
    application_version_id uuid REFERENCES application_versions(id) ON DELETE CASCADE,
    format                 text NOT NULL CHECK (format IN ('openvex', 'cyclonedx')),
    filename               text NOT NULL DEFAULT '' CHECK (length(filename) <= 255),
    document_sha256        text NOT NULL,
    author                 text NOT NULL DEFAULT '' CHECK (length(author) <= 300),
    statements             integer NOT NULL DEFAULT 0,
    matched                integer NOT NULL DEFAULT 0,
    imported_by            uuid NOT NULL,
    created_at             timestamptz NOT NULL DEFAULT now(),
    CHECK (repository_id IS NOT NULL OR application_version_id IS NOT NULL)
);

-- A VEX statement matched to a finding is only a suggestion: a reviewer
-- other than the importer approves it before anything changes.
CREATE TABLE vex_suggestions (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    import_id        uuid NOT NULL REFERENCES vex_imports(id) ON DELETE CASCADE,
    finding_id       uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    repository_id    uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    vulnerability    text NOT NULL CHECK (length(vulnerability) <= 200),
    vex_status       text NOT NULL CHECK (vex_status IN ('not_affected', 'fixed', 'affected', 'under_investigation')),
    justification    text NOT NULL DEFAULT '' CHECK (length(justification) <= 200),
    impact_statement text NOT NULL DEFAULT '' CHECK (length(impact_statement) <= 4000),
    status           text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected', 'superseded')),
    requested_by     uuid NOT NULL,
    decided_by       uuid,
    decided_at       timestamptz,
    decision_note    text NOT NULL DEFAULT '' CHECK (length(decision_note) <= 2000),
    created_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (decided_by IS NULL OR decided_by <> requested_by)
);
CREATE INDEX vex_suggestions_pending_idx ON vex_suggestions (organization_id, created_at DESC) WHERE status = 'pending';
CREATE UNIQUE INDEX vex_suggestions_pending_uq ON vex_suggestions (finding_id, vex_status) WHERE status = 'pending';

-- Operational policies over the component inventory (Dependency-Track
-- style): conditions on component age, being outdated, licence or known
-- vulnerability severity.
CREATE TABLE component_policies (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    enabled         boolean NOT NULL DEFAULT true,
    condition_kind  text NOT NULL CHECK (condition_kind IN ('component_age', 'outdated', 'license', 'vulnerability_severity')),
    -- component_age: {"max_days": n}; outdated: {"versions_behind": "major"|"any"};
    -- license: {"licenses": ["GPL-3.0-only", ...], "match": "any"|"unknown"};
    -- vulnerability_severity: {"min_severity": "high"}.
    params          jsonb NOT NULL DEFAULT '{}',
    violation_state text NOT NULL DEFAULT 'warn' CHECK (violation_state IN ('fail', 'warn', 'info')),
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    evaluated_at    timestamptz,
    UNIQUE (organization_id, name)
);

CREATE TABLE component_policy_violations (
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id   uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    policy_id         uuid NOT NULL REFERENCES component_policies(id) ON DELETE CASCADE,
    repository_id     uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    component_name    text NOT NULL,
    component_version text NOT NULL DEFAULT '',
    purl              text NOT NULL DEFAULT '',
    detail            text NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
    first_seen_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    resolved_at       timestamptz,
    UNIQUE (policy_id, repository_id, component_name, component_version)
);
CREATE INDEX component_policy_violations_open_idx ON component_policy_violations (organization_id, policy_id) WHERE resolved_at IS NULL;

----------------------------------------------------------------------------
-- 3. Secret push protection: scan the diff of pushed commits.
--
-- Opt-in per repository. Only the location, rule and a digest of the match
-- are stored; never the secret value.
----------------------------------------------------------------------------
ALTER TABLE repositories ADD COLUMN push_secret_scan_enabled boolean NOT NULL DEFAULT false;

CREATE TABLE push_secret_scans (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id   uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    ref             text NOT NULL DEFAULT '' CHECK (length(ref) <= 255),
    before_sha      text NOT NULL DEFAULT '' CHECK (length(before_sha) <= 64),
    after_sha       text NOT NULL CHECK (length(after_sha) <= 64),
    status          text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'done', 'failed', 'not_supported')),
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 1000),
    files_scanned   integer NOT NULL DEFAULT 0,
    alerts          integer NOT NULL DEFAULT 0,
    attempts        integer NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    UNIQUE (repository_id, after_sha, before_sha)
);
CREATE INDEX push_secret_scans_queue_idx ON push_secret_scans (created_at) WHERE status = 'queued';
CREATE INDEX push_secret_scans_repo_idx ON push_secret_scans (repository_id, created_at DESC);

CREATE TABLE pushed_secrets (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    push_scan_id    uuid NOT NULL REFERENCES push_secret_scans(id) ON DELETE CASCADE,
    repository_id   uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    commit_sha      text NOT NULL DEFAULT '' CHECK (length(commit_sha) <= 64),
    file_path       text NOT NULL CHECK (length(file_path) <= 1000),
    line            integer,
    rule_id         text NOT NULL CHECK (length(rule_id) <= 100),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 300),
    -- First 16 hex characters of SHA-256(match): de-duplication only.
    match_digest    text NOT NULL CHECK (length(match_digest) <= 64),
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (push_scan_id, file_path, line, rule_id, match_digest)
);
CREATE INDEX pushed_secrets_repo_idx ON pushed_secrets (repository_id, created_at DESC);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS pushed_secrets;
DROP TABLE IF EXISTS push_secret_scans;
ALTER TABLE repositories DROP COLUMN IF EXISTS push_secret_scan_enabled;
DROP TABLE IF EXISTS component_policy_violations;
DROP TABLE IF EXISTS component_policies;
DROP TABLE IF EXISTS vex_suggestions;
DROP TABLE IF EXISTS vex_imports;
DROP TABLE IF EXISTS application_version_findings;
DROP TABLE IF EXISTS application_version_components;
DROP TABLE IF EXISTS application_version_repositories;
DROP TABLE IF EXISTS application_versions;
DROP TABLE IF EXISTS fix_pull_request_findings;
DROP TABLE IF EXISTS fix_pull_requests;
ALTER TABLE repositories DROP COLUMN IF EXISTS fix_pr_grouping, DROP COLUMN IF EXISTS fix_prs_enabled;
