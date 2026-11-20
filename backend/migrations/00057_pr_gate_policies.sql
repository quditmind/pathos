-- +goose Up
-- PATHOS 3.0, M8, decision C6 (docs/aspm/PATHOS_ARCHITECTURE_ASSESSMENT.md §8.6):
-- a repository's pull request gate threshold is an explicit policy, but one
-- default was not: pull request checks blocked at "high" when enabled
-- without a threshold. From now on enabling pull request checks requires
-- choosing block or warn (pr_gate_mode, enforced below), and every
-- repository that has pull request checks on is migrated to an explicit
-- policy with its current behaviour, so nothing silently changes:
--
--   * threshold critical/high/medium/low: pr_gate_mode = 'block', plus a
--     generated security policy (minimum severity = the threshold, this
--     repository only) and a managed pull request gate that blocks on it;
--   * threshold none: pr_gate_mode = 'warn' (it never blocked on severity).
--
-- Security policies with the block action keep failing pull requests as
-- before. Repositories with pull request checks off keep their threshold as
-- the suggested value and must choose block or warn when enabling them.
-- UUIDv7 keys of the generated rows come from PostgreSQL 18's uuidv7()
-- (a data migration has no application code to generate them).

ALTER TABLE repositories ADD COLUMN pr_gate_mode text CHECK (pr_gate_mode IN ('block', 'warn'));

UPDATE repositories SET pr_gate_mode = CASE WHEN pr_gate_severity = 'none' THEN 'warn' ELSE 'block' END
WHERE pr_checks_enabled;

WITH src AS (
    SELECT r.id AS repository_id, r.organization_id, r.pr_gate_severity,
           left(COALESCE(NULLIF(r.display_name, ''), r.full_name), 120) AS repo_name,
           uuidv7() AS policy_id, uuidv7() AS gate_id
    FROM repositories r
    WHERE r.pr_checks_enabled AND r.pr_gate_severity <> 'none'
      AND NOT EXISTS (SELECT 1 FROM security_policies p WHERE p.managed_by = 'repository_pr_gate' AND p.managed_repository_id = r.id)
), pol AS (
    INSERT INTO security_policies (id, organization_id, name, description, enabled, conditions, actions, managed_by, managed_repository_id)
    SELECT policy_id, organization_id,
           'Pull request gate: ' || repo_name || ' (' || left(repository_id::text, 8) || ')',
           'Generated from the repository''s pull request settings (block new findings at ' || pr_gate_severity ||
           ' or above). Migrated by PATHOS 3.0 M8 with the behaviour the repository had; change it in the repository''s pull request settings.',
           true,
           jsonb_build_object('min_severity', pr_gate_severity, 'repository_ids', jsonb_build_array(repository_id::text)),
           jsonb_build_object('block', true),
           'repository_pr_gate', repository_id
    FROM src
    RETURNING id
)
INSERT INTO security_gates (id, organization_id, name, stage, policy_id, mode, allow_exceptions, repository_id, enabled, managed)
SELECT gate_id, organization_id, 'Pull request gate: ' || repo_name || ' (' || left(repository_id::text, 8) || ')',
       'pull_request', policy_id, 'block', true, repository_id, true, true
FROM src WHERE policy_id IN (SELECT id FROM pol);

-- New repositories cannot run pull request checks without an explicit choice.
ALTER TABLE repositories ADD CONSTRAINT repositories_pr_gate_mode_required CHECK (NOT pr_checks_enabled OR pr_gate_mode IS NOT NULL);

SELECT pathos_apply_app_grants();

-- +goose Down
DELETE FROM security_gates WHERE managed;
DELETE FROM security_policies WHERE managed_by = 'repository_pr_gate';
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_pr_gate_mode_required, DROP COLUMN IF EXISTS pr_gate_mode;
