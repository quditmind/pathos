-- +goose Up
-- Multi-tenancy (docs/MULTI_TENANCY.md): organization lifecycle, platform
-- administrators, and membership of one person in several organizations.
--
-- A person is identified by the OIDC subject. Membership of an
-- organization is a users row in that organization; one subject can now
-- have one row per organization (previously one row in total). Existing
-- single-organization data is unchanged: every existing row keeps its
-- organization, and the existing organization stays the first one.

ALTER TABLE organizations
    ADD COLUMN status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    ADD COLUMN suspended_at     timestamptz,
    ADD COLUMN suspended_reason text NOT NULL DEFAULT '' CHECK (length(suspended_reason) <= 500),
    ADD CONSTRAINT organizations_suspension_ck CHECK ((status = 'suspended') = (suspended_at IS NOT NULL));

-- One users row per (organization, subject) instead of per subject.
ALTER TABLE users DROP CONSTRAINT users_keycloak_subject_key;
ALTER TABLE users ADD CONSTRAINT users_organization_subject_key UNIQUE (organization_id, keycloak_subject);
CREATE INDEX users_keycloak_subject_idx ON users (keycloak_subject) WHERE keycloak_subject IS NOT NULL;

-- Platform administrators manage organizations (create, list, suspend,
-- resume, delete). The role grants no access to any organization's data;
-- a platform administrator sees an organization's data only through an
-- ordinary membership with ordinary roles in it.
CREATE TABLE installation_admins (
    keycloak_subject text PRIMARY KEY CHECK (length(keycloak_subject) BETWEEN 1 AND 255),
    email            text NOT NULL DEFAULT '' CHECK (length(email) <= 320),
    created_by       text NOT NULL DEFAULT '',
    created_at       timestamptz NOT NULL DEFAULT now()
);

-- Platform-level audit trail (organization lifecycle, platform
-- administrator changes). Organization audit logs stay per organization.
CREATE TABLE installation_audit_logs (
    id           uuid PRIMARY KEY,
    actor_subject text NOT NULL DEFAULT '',
    actor_email  text NOT NULL DEFAULT '',
    action       text NOT NULL CHECK (length(action) BETWEEN 1 AND 100),
    organization_id uuid,
    outcome      text NOT NULL DEFAULT 'success' CHECK (outcome IN ('success', 'denied', 'failure')),
    ip           inet,
    request_id   text NOT NULL DEFAULT '',
    metadata     jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX installation_audit_logs_time_idx ON installation_audit_logs (created_at DESC);

-- Deletes every row of one organization, then the organization.
-- SECURITY DEFINER: runs as the migration owner (which also owns the
-- append-only audit log), so the application role needs no DELETE right on
-- the audit log. Rows are deleted table by table; a table that still has
-- referencing rows is retried after the others (foreign keys between
-- tenant tables), up to 20 passes. Callers must check that the
-- organization is suspended first (the platform API does).
-- +goose StatementBegin
CREATE FUNCTION pathos_delete_organization(org uuid) RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    t        text;
    pending  text[];
    failed   text[];
    pass     int := 0;
    n        bigint;
    total    bigint := 0;
BEGIN
    IF org IS NULL THEN
        RAISE EXCEPTION 'organization id required';
    END IF;
    SELECT array_agg(c.relname ORDER BY c.relname) INTO pending
    FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace AND ns.nspname = 'public'
    JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped
    WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition AND c.relname <> 'installation_audit_logs';
    LOOP
        pass := pass + 1;
        failed := '{}';
        FOREACH t IN ARRAY pending LOOP
            BEGIN
                EXECUTE format('DELETE FROM %I WHERE organization_id = $1', t) USING org;
                GET DIAGNOSTICS n = ROW_COUNT;
                total := total + n;
            EXCEPTION WHEN foreign_key_violation THEN
                failed := failed || t;
            END;
        END LOOP;
        EXIT WHEN cardinality(failed) = 0;
        IF pass >= 20 THEN
            RAISE EXCEPTION 'could not delete organization %: tables still referenced: %', org, failed;
        END IF;
        pending := failed;
    END LOOP;
    DELETE FROM organizations WHERE id = org;
    RETURN total;
END;
$$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION pathos_delete_organization(uuid) FROM PUBLIC;
-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pathos_app') THEN
        GRANT EXECUTE ON FUNCTION pathos_delete_organization(uuid) TO pathos_app;
    END IF;
END $$;
-- +goose StatementEnd

SELECT pathos_apply_app_grants();

-- +goose Down
-- Rolling back keeps only the first rows per subject linkable: it fails if
-- one subject is a member of several organizations (remove the extra
-- memberships first).
DROP FUNCTION IF EXISTS pathos_delete_organization(uuid);
DROP TABLE IF EXISTS installation_audit_logs;
DROP TABLE IF EXISTS installation_admins;
DROP INDEX IF EXISTS users_keycloak_subject_idx;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_organization_subject_key;
ALTER TABLE users ADD CONSTRAINT users_keycloak_subject_key UNIQUE (keycloak_subject);
ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_suspension_ck,
    DROP COLUMN IF EXISTS suspended_reason, DROP COLUMN IF EXISTS suspended_at, DROP COLUMN IF EXISTS status;
