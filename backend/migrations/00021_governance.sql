-- +goose Up
-- ASPM phase 8: security policies (conditions on findings and their context
-- → actions) and compliance mapping.

CREATE TABLE security_policies (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
    enabled         boolean NOT NULL DEFAULT true,
    conditions      jsonb NOT NULL,
    actions         jsonb NOT NULL,
    version         integer NOT NULL DEFAULT 1,
    created_by      uuid,
    updated_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    evaluated_at    timestamptz,
    UNIQUE (organization_id, name)
);

-- An open finding that matches an enabled policy. Resolved when the finding
-- is no longer open or no longer matches; kept for the record.
CREATE TABLE policy_violations (
    policy_id        uuid NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    finding_id       uuid NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    repository_id    uuid NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    first_matched_at timestamptz NOT NULL DEFAULT now(),
    last_matched_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at      timestamptz,
    notified_at      timestamptz,
    PRIMARY KEY (policy_id, finding_id)
);
CREATE INDEX policy_violations_open_idx ON policy_violations (finding_id) WHERE resolved_at IS NULL;
CREATE INDEX policy_violations_policy_idx ON policy_violations (policy_id, resolved_at);

-- PR checks: policies a PR finding violates (blocking ones fail the check).
ALTER TABLE pr_findings ADD COLUMN cwe text[] NOT NULL DEFAULT '{}',
                        ADD COLUMN policy_ids uuid[] NOT NULL DEFAULT '{}';

SELECT pathos_apply_app_grants();

-- +goose Down
ALTER TABLE pr_findings DROP COLUMN IF EXISTS policy_ids, DROP COLUMN IF EXISTS cwe;
DROP TABLE IF EXISTS policy_violations;
DROP TABLE IF EXISTS security_policies;
