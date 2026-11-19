-- +goose Up
-- PATHOS 3.0, M8: security gates at every stage (IDE, pre-commit, pull
-- request, CI, release, deploy), their decisions and exceptions
-- (docs/aspm/PATHOS_ARCHITECTURE_DECISION_RECORDS.md ADR-010).
--
-- Rule 7 ("no blocking without policy") is enforced by the database:
--   * a gate cannot exist without a security policy (policy_id NOT NULL);
--   * a decision of block or approval_required cannot be stored without at
--     least one policy id (CHECK on gate_decisions);
--   * decisions are append-only (trigger).
-- Exceptions and approvals expire and are never decided by their requester.

-- +goose StatementBegin
DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['security_policies', 'pr_checks', 'applications', 'repositories', 'scan_jobs', 'users'] LOOP
        IF NOT EXISTS (
            SELECT 1 FROM pg_index i
            WHERE i.indrelid = t::regclass AND i.indisunique AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts = 2
              AND (SELECT array_agg(attname::text ORDER BY attname) FROM pg_attribute
                   WHERE attrelid = t::regclass AND attnum = ANY (i.indkey)) = ARRAY['id', 'organization_id']
        ) THEN
            EXECUTE format('CREATE UNIQUE INDEX %I ON %I (organization_id, id)', 'org_ref_uq_' || substr(md5(t || '.id'), 1, 12), t);
            EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I UNIQUE USING INDEX %I', t,
                           'org_ref_uq_' || substr(md5(t || '.id'), 1, 12), 'org_ref_uq_' || substr(md5(t || '.id'), 1, 12));
        END IF;
    END LOOP;
END $$;
-- +goose StatementEnd

-- Policies generated from a repository's pull request settings (C6) are
-- managed there: the policies API refuses to edit or delete them.
ALTER TABLE security_policies
    ADD COLUMN managed_by text NOT NULL DEFAULT '' CHECK (managed_by IN ('', 'repository_pr_gate')),
    ADD COLUMN managed_repository_id uuid,
    ADD CONSTRAINT security_policies_managed_repo_fk FOREIGN KEY (organization_id, managed_repository_id)
        REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    ADD CONSTRAINT security_policies_managed_ck CHECK ((managed_by = '') = (managed_repository_id IS NULL));
CREATE UNIQUE INDEX security_policies_managed_repo_uq ON security_policies (managed_repository_id) WHERE managed_by = 'repository_pr_gate';

CREATE TABLE security_gates (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    stage            text NOT NULL CHECK (stage IN ('ide', 'pre_commit', 'pull_request', 'ci', 'release', 'deploy')),
    policy_id        uuid NOT NULL,                     -- a gate cannot exist without a policy (rule 7)
    mode             text NOT NULL CHECK (mode IN ('block', 'warn', 'require_approval')),
    allow_exceptions boolean NOT NULL DEFAULT true,
    application_id   uuid,                              -- null: every application in scope
    repository_id    uuid,                              -- null: every repository in scope
    enabled          boolean NOT NULL DEFAULT true,
    -- Generated from a repository's pull request settings (C6).
    managed          boolean NOT NULL DEFAULT false,
    created_by       uuid,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    UNIQUE (organization_id, name),
    CHECK (NOT managed OR (stage = 'pull_request' AND repository_id IS NOT NULL)),
    FOREIGN KEY (organization_id, policy_id) REFERENCES security_policies(organization_id, id),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX security_gates_stage_idx ON security_gates (organization_id, stage) WHERE enabled;
CREATE UNIQUE INDEX security_gates_managed_repo_uq ON security_gates (repository_id) WHERE managed;

CREATE TABLE gate_decisions (               -- append-only
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    stage            text NOT NULL CHECK (stage IN ('ide', 'pre_commit', 'pull_request', 'ci', 'release', 'deploy')),
    repository_id    uuid,
    application_id   uuid,
    scan_job_id      uuid,
    pr_check_id      uuid,
    commit_sha       text NOT NULL DEFAULT '' CHECK (length(commit_sha) <= 64),
    pull_request     integer,
    outcome          text NOT NULL CHECK (outcome IN ('pass', 'warn', 'block', 'approval_required', 'exception_applied')),
    gate_ids         uuid[] NOT NULL DEFAULT '{}',
    policy_ids       uuid[] NOT NULL DEFAULT '{}',
    policy_versions  integer[] NOT NULL DEFAULT '{}',
    gates            jsonb NOT NULL DEFAULT '[]',
    reasons          jsonb NOT NULL DEFAULT '[]',
    evidence         jsonb NOT NULL DEFAULT '{}',
    requested_by     uuid,
    request_id       text NOT NULL DEFAULT '' CHECK (length(request_id) <= 100),
    created_at       timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    -- Rule 7: no blocking decision without a policy.
    CONSTRAINT gate_decisions_block_needs_policy CHECK (outcome NOT IN ('block', 'approval_required') OR cardinality(policy_ids) > 0),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, scan_job_id) REFERENCES scan_jobs(organization_id, id) ON DELETE SET NULL (scan_job_id),
    FOREIGN KEY (organization_id, pr_check_id) REFERENCES pr_checks(organization_id, id) ON DELETE SET NULL (pr_check_id),
    FOREIGN KEY (organization_id, requested_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (requested_by)
);
CREATE INDEX gate_decisions_list_idx ON gate_decisions (organization_id, created_at DESC);
CREATE INDEX gate_decisions_repo_idx ON gate_decisions (organization_id, repository_id, created_at DESC);
CREATE INDEX gate_decisions_stage_idx ON gate_decisions (organization_id, stage, outcome, created_at DESC);

-- +goose StatementBegin
CREATE FUNCTION pathos_gate_decisions_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Only references to deleted rows may be cleared (ON DELETE SET NULL).
    IF (NEW.id, NEW.organization_id, NEW.stage, NEW.outcome, NEW.policy_ids, NEW.gate_ids, NEW.reasons, NEW.evidence, NEW.gates, NEW.commit_sha, NEW.created_at)
       IS DISTINCT FROM (OLD.id, OLD.organization_id, OLD.stage, OLD.outcome, OLD.policy_ids, OLD.gate_ids, OLD.reasons, OLD.evidence, OLD.gates, OLD.commit_sha, OLD.created_at) THEN
        RAISE EXCEPTION 'gate decisions are append-only' USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER gate_decisions_append_only BEFORE UPDATE ON gate_decisions
    FOR EACH ROW EXECUTE FUNCTION pathos_gate_decisions_append_only();

CREATE TABLE gate_exceptions (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    gate_id          uuid NOT NULL,
    decision_id      uuid,
    -- exception: lets a blocking gate pass; approval: the sign-off a
    -- require_approval gate asks for.
    kind             text NOT NULL CHECK (kind IN ('exception', 'approval')),
    repository_id    uuid,
    application_id   uuid,
    -- Narrower scope inside the repository: {commit_sha?, pull_request?}.
    scope            jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(scope) = 'object'),
    reason           text NOT NULL CHECK (length(reason) BETWEEN 1 AND 4000),
    status           text NOT NULL DEFAULT 'requested' CHECK (status IN ('requested', 'approved', 'rejected', 'expired', 'revoked')),
    requested_by     uuid NOT NULL,
    decided_by       uuid,
    decision_note    text NOT NULL DEFAULT '' CHECK (length(decision_note) <= 2000),
    expires_at       timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    decided_at       timestamptz,
    UNIQUE (organization_id, id),
    CHECK (expires_at > created_at),
    CHECK (repository_id IS NOT NULL OR application_id IS NOT NULL),
    -- The approver is never the requester.
    CONSTRAINT gate_exceptions_four_eyes CHECK (decided_by IS NULL OR decided_by <> requested_by),
    CHECK (status NOT IN ('approved', 'rejected') OR (decided_by IS NOT NULL AND decided_at IS NOT NULL)),
    FOREIGN KEY (organization_id, gate_id) REFERENCES security_gates(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, decision_id) REFERENCES gate_decisions(organization_id, id) ON DELETE SET NULL (decision_id),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, requested_by) REFERENCES users(organization_id, id),
    FOREIGN KEY (organization_id, decided_by) REFERENCES users(organization_id, id)
);
CREATE INDEX gate_exceptions_gate_idx ON gate_exceptions (gate_id, status, expires_at);
CREATE INDEX gate_exceptions_list_idx ON gate_exceptions (organization_id, status, created_at DESC);

-- Pull request checks record the gate decision they were given.
ALTER TABLE pr_checks
    ADD COLUMN gate_mode text NOT NULL DEFAULT '' CHECK (gate_mode IN ('', 'block', 'warn')),
    ADD COLUMN gate_decision_id uuid,
    ADD CONSTRAINT pr_checks_gate_decision_fk FOREIGN KEY (organization_id, gate_decision_id)
        REFERENCES gate_decisions(organization_id, id) ON DELETE SET NULL (gate_decision_id);

SELECT pathos_apply_app_grants();

-- +goose Down
ALTER TABLE pr_checks DROP CONSTRAINT IF EXISTS pr_checks_gate_decision_fk, DROP COLUMN IF EXISTS gate_decision_id, DROP COLUMN IF EXISTS gate_mode;
DROP TABLE IF EXISTS gate_exceptions;
DROP TABLE IF EXISTS gate_decisions;
DROP FUNCTION IF EXISTS pathos_gate_decisions_append_only();
DROP TABLE IF EXISTS security_gates;
DROP INDEX IF EXISTS security_policies_managed_repo_uq;
ALTER TABLE security_policies DROP CONSTRAINT IF EXISTS security_policies_managed_ck,
    DROP CONSTRAINT IF EXISTS security_policies_managed_repo_fk, DROP COLUMN IF EXISTS managed_repository_id, DROP COLUMN IF EXISTS managed_by;
