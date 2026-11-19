-- +goose Up
-- Same-organization references (docs/MULTI_TENANCY.md). Many tenant tables
-- already reference each other through composite (organization_id, id)
-- foreign keys. The remaining single-column references between two tenant
-- tables (for example scm_connections.secret_id -> secrets.id) let a row
-- point at another organization's row as far as the database is
-- concerned, because foreign key checks do not apply row-level security.
-- This migration adds a composite foreign key next to each of them, so
-- the database itself rejects a reference across organizations.
--
-- The new keys are NO ACTION: checked at the end of the statement, after
-- the original key's CASCADE or SET NULL action ran, so deletes behave as
-- before. MATCH SIMPLE: a NULL reference is not checked, as before.
-- Validation scans the referencing tables once; on large installs this
-- migration takes correspondingly longer. It cannot fail on a
-- single-organization install (every row has the same organization).

-- +goose StatementBegin
DO $$
DECLARE
    r record;
    idx text;
BEGIN
    FOR r IN
        SELECT c.conrelid::regclass::text AS tbl, c.confrelid::regclass::text AS ref,
               a.attname AS col, fa.attname AS refcol
        FROM pg_constraint c
        JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = c.conkey[1]
        JOIN pg_attribute fa ON fa.attrelid = c.confrelid AND fa.attnum = c.confkey[1]
        WHERE c.contype = 'f' AND c.connamespace = 'public'::regnamespace AND cardinality(c.conkey) = 1
          AND c.confrelid <> 'organizations'::regclass AND c.confrelid <> 'roles'::regclass
          AND a.attname <> 'organization_id'
          AND EXISTS (SELECT 1 FROM pg_attribute x WHERE x.attrelid = c.conrelid AND x.attname = 'organization_id' AND x.attnotnull AND NOT x.attisdropped)
          AND EXISTS (SELECT 1 FROM pg_attribute x WHERE x.attrelid = c.confrelid AND x.attname = 'organization_id' AND x.attnotnull AND NOT x.attisdropped)
        ORDER BY 1, 3
    LOOP
        -- The referenced side needs a unique key on (organization_id, refcol).
        IF NOT EXISTS (
            SELECT 1 FROM pg_index i
            WHERE i.indrelid = r.ref::regclass AND i.indisunique AND i.indpred IS NULL AND i.indexprs IS NULL
              AND i.indnatts = 2
              AND (SELECT array_agg(attname::text ORDER BY attname) FROM pg_attribute
                   WHERE attrelid = r.ref::regclass AND attnum = ANY (i.indkey)) = (SELECT array_agg(x ORDER BY x) FROM unnest(ARRAY['organization_id', r.refcol::text]) x)
        ) THEN
            idx := 'org_ref_uq_' || substr(md5(r.ref || '.' || r.refcol), 1, 12);
            EXECUTE format('CREATE UNIQUE INDEX %I ON %I (organization_id, %I)', idx, r.ref, r.refcol);
            EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I UNIQUE USING INDEX %I', r.ref, idx, idx);
        END IF;
        EXECUTE format('ALTER TABLE %I ADD CONSTRAINT %I FOREIGN KEY (organization_id, %I) REFERENCES %I (organization_id, %I) NOT VALID',
                       r.tbl, 'same_org_' || substr(md5(r.tbl || '.' || r.col), 1, 12), r.col, r.ref, r.refcol);
        EXECUTE format('ALTER TABLE %I VALIDATE CONSTRAINT %I', r.tbl, 'same_org_' || substr(md5(r.tbl || '.' || r.col), 1, 12));
    END LOOP;
END $$;
-- +goose StatementEnd

-- Role assignments may use a system role or a custom role of the same
-- organization only (system roles have no organization, so this is a
-- trigger rather than a foreign key).
-- +goose StatementBegin
CREATE FUNCTION pathos_check_role_org() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM roles WHERE id = NEW.role_id AND (organization_id IS NULL OR organization_id = NEW.organization_id)) THEN
        RAISE EXCEPTION 'role % does not belong to organization %', NEW.role_id, NEW.organization_id USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER role_assignments_same_org BEFORE INSERT OR UPDATE OF role_id, organization_id ON role_assignments
    FOR EACH ROW EXECUTE FUNCTION pathos_check_role_org();

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TRIGGER IF EXISTS role_assignments_same_org ON role_assignments;
DROP FUNCTION IF EXISTS pathos_check_role_org();
-- +goose StatementBegin
DO $$
DECLARE
    r record;
BEGIN
    FOR r IN SELECT conrelid::regclass::text AS tbl, conname FROM pg_constraint
             WHERE connamespace = 'public'::regnamespace AND conname LIKE 'same\_org\_%'
    LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', r.tbl, r.conname);
    END LOOP;
    FOR r IN SELECT conrelid::regclass::text AS tbl, conname FROM pg_constraint
             WHERE connamespace = 'public'::regnamespace AND conname LIKE 'org\_ref\_uq\_%'
    LOOP
        EXECUTE format('ALTER TABLE %I DROP CONSTRAINT %I', r.tbl, r.conname);
    END LOOP;
END $$;
-- +goose StatementEnd
