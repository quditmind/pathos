-- +goose Up
-- PATHOS 2.0 verified AI fixes: an AI-proposed code change for a SAST,
-- secrets or IaC finding, verified by a worker before anyone can open a
-- pull request from it (apply to a fresh checkout, re-run the scanner on
-- the changed file, optionally run the repository's tests in the sandboxed
-- worker). Pull requests reuse fix_pull_requests (kind 'ai_code').

-- Running a repository's tests executes its code: off unless an
-- administrator chooses a runner for the repository.
ALTER TABLE repositories ADD COLUMN ai_fix_test_runner text NOT NULL DEFAULT ''
    CHECK (ai_fix_test_runner IN ('', 'go', 'python'));

CREATE TABLE ai_fix_proposals (
    id                 uuid PRIMARY KEY,
    organization_id    uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id      uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    finding_id         uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    -- generating (AI call) → rejected (diff refused by policy) | queued →
    -- running (worker: apply + scanner) → tests_queued → testing (sandboxed
    -- test run) → verified | failed. failed, rejected and verified are final.
    status             text NOT NULL DEFAULT 'generating'
                         CHECK (status IN ('generating', 'rejected', 'queued', 'running', 'tests_queued', 'testing', 'verified', 'failed')),
    failure_reason     text NOT NULL DEFAULT '' CHECK (length(failure_reason) <= 2000),
    -- What was verified: the scanner that reported the finding, its rule
    -- and the file, at the commit of the finding's last scan.
    scanner_key        text NOT NULL CHECK (length(scanner_key) BETWEEN 1 AND 100),
    scanner_config     jsonb NOT NULL DEFAULT '{}',
    rule_id            text NOT NULL DEFAULT '' CHECK (length(rule_id) <= 500),
    file_path          text NOT NULL CHECK (length(file_path) BETWEEN 1 AND 1000),
    start_line         integer,
    commit_sha         text NOT NULL DEFAULT '' CHECK (length(commit_sha) <= 64),
    test_runner        text NOT NULL DEFAULT '' CHECK (test_runner IN ('', 'go', 'python')),
    -- AI provenance (the request is stored by its SHA-256, like AI reviews).
    provider           text NOT NULL DEFAULT '',
    model              text NOT NULL DEFAULT '',
    config_version_id  uuid,
    transmitted_sha256 text NOT NULL DEFAULT '',
    input_tokens       bigint NOT NULL DEFAULT 0,
    output_tokens      bigint NOT NULL DEFAULT 0,
    summary            text NOT NULL DEFAULT '' CHECK (length(summary) <= 8000),
    diff               text NOT NULL DEFAULT '' CHECK (length(diff) <= 40000),
    changed_files      text[] NOT NULL DEFAULT '{}',
    -- Verification evidence.
    steps              jsonb NOT NULL DEFAULT '[]',
    scan_evidence      jsonb NOT NULL DEFAULT '{}',
    before_report_gzip bytea,
    after_report_gzip  bytea,
    test_log           text NOT NULL DEFAULT '' CHECK (length(test_log) <= 300000),
    base_commit        text NOT NULL DEFAULT '' CHECK (length(base_commit) <= 64),
    -- Patched file contents (base64), committed as-is when a pull request
    -- is opened.
    patched_files      jsonb NOT NULL DEFAULT '[]',
    fix_pull_request_id uuid REFERENCES fix_pull_requests(id) ON DELETE SET NULL,
    leased_by          uuid REFERENCES workers(id) ON DELETE SET NULL,
    lease_expires_at   timestamptz,
    attempts           integer NOT NULL DEFAULT 0,
    requested_by       uuid,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    finished_at        timestamptz
);
CREATE INDEX ai_fix_proposals_finding_idx ON ai_fix_proposals (finding_id, created_at DESC);
CREATE INDEX ai_fix_proposals_queue_idx ON ai_fix_proposals (created_at) WHERE status IN ('queued', 'tests_queued');
CREATE INDEX ai_fix_proposals_user_idx ON ai_fix_proposals (requested_by, created_at DESC);
CREATE INDEX ai_fix_proposals_org_idx ON ai_fix_proposals (organization_id, created_at DESC);
-- One proposal in flight per finding.
CREATE UNIQUE INDEX ai_fix_proposals_active_uq ON ai_fix_proposals (finding_id)
    WHERE status IN ('generating', 'queued', 'running', 'tests_queued', 'testing');

-- Fix pull requests: dependency upgrades (manifest edits) or verified AI
-- code fixes.
ALTER TABLE fix_pull_requests ADD COLUMN kind text NOT NULL DEFAULT 'dependency' CHECK (kind IN ('dependency', 'ai_code'));
ALTER TABLE fix_pull_requests ADD COLUMN ai_fix_id uuid REFERENCES ai_fix_proposals(id) ON DELETE SET NULL;
CREATE UNIQUE INDEX fix_pull_requests_ai_fix_uq ON fix_pull_requests (ai_fix_id) WHERE ai_fix_id IS NOT NULL;

SELECT pathos_apply_app_grants();

-- +goose Down
DROP INDEX IF EXISTS fix_pull_requests_ai_fix_uq;
ALTER TABLE fix_pull_requests DROP COLUMN IF EXISTS ai_fix_id, DROP COLUMN IF EXISTS kind;
DROP TABLE IF EXISTS ai_fix_proposals;
ALTER TABLE repositories DROP COLUMN IF EXISTS ai_fix_test_runner;
