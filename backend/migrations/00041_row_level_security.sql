-- +goose Up
-- Row-level security for multi-tenancy (docs/MULTI_TENANCY.md).
--
-- This migration defines a tenant policy on every tenant table. The
-- policies are enforced only once multi-tenancy is enabled with
-- `pathosctl multi-tenancy enable` (installation_settings.multi_tenant), which
-- turns row-level security on for all of them. A single-organization
-- install keeps row-level security off and behaves exactly as before
-- (with one organization the policies could not hide anything, and
-- PostgreSQL plans queries under row-level security more conservatively).
--
-- The application connects as pathos_app, which is subject to the
-- policies. The API sets two session variables on every connection
-- checkout (internal/platform/db):
--   app.organization_id  the organization of the request (from the
--                        authenticated session, token or worker)
--   app.rls_bypass       'on' only for system work that spans
--                        organizations (scheduler, jobs, the lookups that
--                        authenticate a request)
-- With neither set, every tenant table looks empty.
--
-- pathos_owner owns the tables and runs migrations; table owners are not
-- subject to row-level security (no FORCE), so migrations and pathosctl
-- keep working unchanged.

CREATE TABLE installation_settings (
    id           boolean PRIMARY KEY DEFAULT true CHECK (id),
    multi_tenant boolean NOT NULL DEFAULT false,
    changed_at   timestamptz NOT NULL DEFAULT now()
);
INSERT INTO installation_settings (id) VALUES (true);

-- The organizations the current statement may see. A scalar subquery
-- around the call, (SELECT pathos_visible_orgs()), is evaluated once per
-- statement and keeps organization_id indexes usable. Policies use it
-- alone in USING (an OR there would prevent index use); WITH CHECK also
-- accepts system scope, which may write rows of an organization created
-- in the same statement or transaction. SECURITY DEFINER so
-- the bypass branch can read the organizations table without recursing
-- into its own policy.
-- +goose StatementBegin
CREATE FUNCTION pathos_visible_orgs() RETURNS uuid[]
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = public AS $$
DECLARE
    org text := current_setting('app.organization_id', true);
BEGIN
    IF org IS NOT NULL AND org <> '' THEN
        RETURN ARRAY[org::uuid];
    END IF;
    IF current_setting('app.rls_bypass', true) = 'on' THEN
        RETURN ARRAY(SELECT id FROM organizations);
    END IF;
    RETURN '{}'::uuid[];
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION pathos_rls_bypass() RETURNS boolean
LANGUAGE sql STABLE AS $$
    SELECT COALESCE(current_setting('app.rls_bypass', true), '') = 'on'
       AND COALESCE(current_setting('app.organization_id', true), '') = ''
$$;
-- +goose StatementEnd

-- Creates the standard tenant policy on every table that has an
-- organization_id column and no policy yet, and turns row-level security
-- on for every table with a tenant policy when multi-tenancy is enabled.
-- It runs at the end of every migration (from pathos_apply_app_grants), so
-- a table added later is isolated by default.
-- +goose StatementBegin
CREATE FUNCTION pathos_enable_tenant_rls() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    t text;
BEGIN
    FOR t IN
        SELECT c.relname FROM pg_class c
        JOIN pg_namespace ns ON ns.oid = c.relnamespace AND ns.nspname = 'public'
        JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped
        WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
          AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
    LOOP
        EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (organization_id = ANY ((SELECT pathos_visible_orgs())::uuid[])) '
                       'WITH CHECK (organization_id = ANY ((SELECT pathos_visible_orgs())::uuid[]) OR (SELECT pathos_rls_bypass()))', t);
    END LOOP;
    IF (SELECT multi_tenant FROM installation_settings) THEN
        FOR t IN
            SELECT DISTINCT c.relname FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
            JOIN pg_namespace ns ON ns.oid = c.relnamespace AND ns.nspname = 'public'
            WHERE p.polname IN ('tenant_isolation', 'installation_only') AND NOT c.relrowsecurity
        LOOP
            EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        END LOOP;
    END IF;
END;
$$;
-- +goose StatementEnd

-- Turns multi-tenancy (row-level security on every tenant table) on or
-- off. Run by `pathosctl multi-tenancy enable|disable` as the owner.
-- Disabling is refused while more than one organization exists.
-- +goose StatementBegin
CREATE FUNCTION pathos_set_multi_tenant(enabled boolean) RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    t text;
BEGIN
    IF NOT enabled AND (SELECT count(*) FROM organizations) > 1 THEN
        RAISE EXCEPTION 'multi-tenancy cannot be disabled while more than one organization exists';
    END IF;
    UPDATE installation_settings SET multi_tenant = enabled, changed_at = now();
    IF enabled THEN
        PERFORM pathos_enable_tenant_rls();
    ELSE
        FOR t IN
            SELECT DISTINCT c.relname FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
            JOIN pg_namespace ns ON ns.oid = c.relnamespace AND ns.nspname = 'public'
            WHERE p.polname IN ('tenant_isolation', 'installation_only') AND c.relrowsecurity
        LOOP
            EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', t);
        END LOOP;
    END IF;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION pathos_set_multi_tenant(boolean) FROM PUBLIC;

-- Tenant tables that would not be isolated: no policy, or (with
-- multi-tenancy enabled) row-level security off. The API refuses to start
-- in multi-tenant mode unless this is empty.
-- +goose StatementBegin
CREATE FUNCTION pathos_tenant_rls_gaps() RETURNS SETOF text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
    SELECT c.relname::text FROM pg_class c
    JOIN pg_namespace ns ON ns.oid = c.relnamespace AND ns.nspname = 'public'
    WHERE c.relkind IN ('r', 'p') AND NOT c.relispartition
      AND (EXISTS (SELECT 1 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped)
           OR EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid))
      AND (NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
           OR (NOT c.relrowsecurity AND (SELECT multi_tenant FROM installation_settings)))
    ORDER BY 1
$$;
-- +goose StatementEnd

-- Organizations: a request sees its own organization only.
CREATE POLICY tenant_isolation ON organizations
    USING (id = ANY ((SELECT pathos_visible_orgs())::uuid[]))
    WITH CHECK (id = ANY ((SELECT pathos_visible_orgs())::uuid[]) OR (SELECT pathos_rls_bypass()));

-- Roles: system roles (organization_id NULL) are readable by everyone and
-- written only by migrations (pathosctl runs as the owner).
CREATE POLICY tenant_isolation ON roles
    USING (organization_id IS NULL OR organization_id = ANY ((SELECT pathos_visible_orgs())::uuid[]))
    WITH CHECK (organization_id = ANY ((SELECT pathos_visible_orgs())::uuid[]) OR (SELECT pathos_rls_bypass()));
CREATE POLICY tenant_isolation ON role_permissions
    USING (EXISTS (SELECT 1 FROM roles r WHERE r.id = role_permissions.role_id))
    WITH CHECK (EXISTS (SELECT 1 FROM roles r WHERE r.id = role_permissions.role_id AND r.organization_id IS NOT NULL));

-- Child tables without an organization_id column follow their parents
-- (the parents' own policies apply inside the subqueries). Where a child
-- links two tenant tables, both must be visible.
CREATE POLICY tenant_isolation ON application_version_repositories
    USING (EXISTS (SELECT 1 FROM application_versions v WHERE v.id = application_version_repositories.version_id)
       AND EXISTS (SELECT 1 FROM repositories r WHERE r.id = application_version_repositories.repository_id));
CREATE POLICY tenant_isolation ON custom_rule_versions
    USING (EXISTS (SELECT 1 FROM custom_rules r WHERE r.id = custom_rule_versions.rule_id));
CREATE POLICY tenant_isolation ON fix_pull_request_findings
    USING (EXISTS (SELECT 1 FROM fix_pull_requests p WHERE p.id = fix_pull_request_findings.fix_pull_request_id)
       AND EXISTS (SELECT 1 FROM findings f WHERE f.id = fix_pull_request_findings.finding_id));
CREATE POLICY tenant_isolation ON pr_findings
    USING (EXISTS (SELECT 1 FROM pr_checks c WHERE c.id = pr_findings.pr_check_id)
       AND (pr_findings.existing_finding_id IS NULL OR EXISTS (SELECT 1 FROM findings f WHERE f.id = pr_findings.existing_finding_id)));
CREATE POLICY tenant_isolation ON profile_scanners
    USING (EXISTS (SELECT 1 FROM scan_profile_versions v WHERE v.id = profile_scanners.profile_version_id));
CREATE POLICY tenant_isolation ON source_upload_parts
    USING (EXISTS (SELECT 1 FROM source_uploads u WHERE u.id = source_upload_parts.upload_id));

-- Platform tables: system scope only (the platform API runs its queries
-- with the bypass after checking the caller is a platform administrator).
CREATE POLICY installation_only ON installation_admins USING ((SELECT pathos_rls_bypass())) WITH CHECK ((SELECT pathos_rls_bypass()));
CREATE POLICY installation_only ON installation_audit_logs USING ((SELECT pathos_rls_bypass())) WITH CHECK ((SELECT pathos_rls_bypass()));

-- Every other table with organization_id (row-level security itself stays
-- off until `pathosctl multi-tenancy enable`).
SELECT pathos_enable_tenant_rls();

-- Grants: as before, plus row-level security for new tables and no direct
-- access to audit log partitions (the application uses the parent table,
-- whose policy applies; inserts route to partitions without partition
-- privileges).
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_apply_app_grants() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    t text;
BEGIN
    -- Tenant policies for new tables (row-level security itself follows
    -- installation_settings.multi_tenant).
    PERFORM pathos_enable_tenant_rls();
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pathos_app') THEN
        RETURN;
    END IF;
    GRANT USAGE ON SCHEMA public TO pathos_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM pathos_app;
    -- No direct access to audit log partitions: the application uses the
    -- parent table, whose policy applies; inserts route to partitions
    -- without partition privileges.
    FOR t IN
        SELECT c.relname FROM pg_class c
        WHERE c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'public.audit_logs'::regclass)
    LOOP
        EXECUTE format('REVOKE ALL ON %I FROM pathos_app', t);
    END LOOP;
    REVOKE UPDATE, DELETE, TRUNCATE ON finding_status_history FROM pathos_app;
    REVOKE DELETE, TRUNCATE ON notifications FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON permissions FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON scanner_catalog FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON goose_db_version FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_history FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_decisions FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_approvals FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_comments FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_recommendations FROM pathos_app;
    -- AI suggestions stay immutable; only a patch proposal's human decision
    -- is recorded on it.
    GRANT UPDATE (patch_status, patch_decided_by, patch_decided_at, patch_note) ON human_review_recommendations TO pathos_app;
    REVOKE DELETE, TRUNCATE ON human_review_evidence FROM pathos_app;
    -- Platform tables: the audit log is append-only; settings are changed
    -- by pathosctl only.
    REVOKE UPDATE, DELETE, TRUNCATE ON installation_audit_logs FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON installation_settings FROM pathos_app;
    GRANT EXECUTE ON FUNCTION pathos_ensure_audit_partitions(int) TO pathos_app;
    GRANT EXECUTE ON FUNCTION pathos_delete_organization(uuid) TO pathos_app;
END;
$$;
-- +goose StatementEnd
SELECT pathos_apply_app_grants();

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_apply_app_grants() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    t text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pathos_app') THEN
        RETURN;
    END IF;
    GRANT USAGE ON SCHEMA public TO pathos_app;
    GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO pathos_app;
    FOR t IN
        SELECT c.relname FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
        WHERE c.relname = 'audit_logs'
           OR c.oid IN (SELECT inhrelid FROM pg_inherits WHERE inhparent = 'public.audit_logs'::regclass)
    LOOP
        EXECUTE format('REVOKE UPDATE, DELETE, TRUNCATE ON %I FROM pathos_app', t);
    END LOOP;
    REVOKE UPDATE, DELETE, TRUNCATE ON finding_status_history FROM pathos_app;
    REVOKE DELETE, TRUNCATE ON notifications FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON permissions FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON scanner_catalog FROM pathos_app;
    REVOKE INSERT, UPDATE, DELETE ON goose_db_version FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_history FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_decisions FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_approvals FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_comments FROM pathos_app;
    REVOKE UPDATE, DELETE, TRUNCATE ON human_review_recommendations FROM pathos_app;
    -- AI suggestions stay immutable; only a patch proposal's human decision
    -- is recorded on it.
    GRANT UPDATE (patch_status, patch_decided_by, patch_decided_at, patch_note) ON human_review_recommendations TO pathos_app;
    REVOKE DELETE, TRUNCATE ON human_review_evidence FROM pathos_app;
    GRANT EXECUTE ON FUNCTION pathos_ensure_audit_partitions(int) TO pathos_app;
END;
$$;
-- +goose StatementEnd
-- +goose StatementBegin
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT c.relname, p.polname FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
             JOIN pg_namespace ns ON ns.oid = c.relnamespace AND ns.nspname = 'public'
             WHERE p.polname IN ('tenant_isolation', 'installation_only')
    LOOP
        EXECUTE format('DROP POLICY %I ON %I', r.polname, r.relname);
        EXECUTE format('ALTER TABLE %I DISABLE ROW LEVEL SECURITY', r.relname);
    END LOOP;
END $$;
-- +goose StatementEnd
DROP FUNCTION IF EXISTS pathos_tenant_rls_gaps();
DROP FUNCTION IF EXISTS pathos_set_multi_tenant(boolean);
DROP FUNCTION IF EXISTS pathos_enable_tenant_rls();
DROP TABLE IF EXISTS installation_settings;
DROP FUNCTION IF EXISTS pathos_rls_bypass();
DROP FUNCTION IF EXISTS pathos_visible_orgs();
SELECT pathos_apply_app_grants();
