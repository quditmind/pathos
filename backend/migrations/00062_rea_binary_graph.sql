-- +goose Up
-- PATHOS 3.0 M10: the facts of a reverse-engineering analysis are stored in
-- the CodeGraph store as a binary graph (snapshot kind "binary"): node types
-- binary (the artifact), binary_function, import, string_ref and section;
-- edges defines, calls, imports and references; every edge verified, with
-- evidence of kind "binary" (ref: the file offset, detail: the tool). Source
-- snapshots keep kind "source" and every CodeGraph and threat-model query
-- reads source snapshots only. A binary snapshot belongs to the artifact's
-- repository; its application is optional (a repository need not belong to
-- one), so application_id becomes nullable for binary snapshots only.

ALTER TABLE codegraph_snapshots ADD COLUMN kind text NOT NULL DEFAULT 'source' CHECK (kind IN ('source', 'binary'));
ALTER TABLE codegraph_snapshots ALTER COLUMN application_id DROP NOT NULL;
ALTER TABLE codegraph_snapshots ADD CONSTRAINT codegraph_snapshots_source_app_check CHECK (kind = 'binary' OR application_id IS NOT NULL);
ALTER TABLE codegraph_snapshots DROP CONSTRAINT codegraph_snapshots_trigger_check;
ALTER TABLE codegraph_snapshots ADD CONSTRAINT codegraph_snapshots_trigger_check CHECK (trigger IN ('manual', 'scan', 'rea'));
ALTER TABLE codegraph_snapshots ADD CONSTRAINT codegraph_snapshots_kind_trigger_check CHECK ((kind = 'binary') = (trigger = 'rea'));
CREATE INDEX codegraph_snapshots_kind_idx ON codegraph_snapshots (repository_id, kind, created_at DESC);

ALTER TABLE codegraph_nodes DROP CONSTRAINT codegraph_nodes_type_check;
ALTER TABLE codegraph_nodes ADD CONSTRAINT codegraph_nodes_type_check CHECK (type IN ('repository', 'module', 'file', 'function',
    'class', 'route', 'api_operation', 'datastore', 'queue', 'external_service', 'container', 'iac_resource', 'component',
    'secret_ref', 'trust_boundary', 'application', 'binary', 'binary_function', 'import', 'string_ref', 'section'));

ALTER TABLE codegraph_edges DROP CONSTRAINT codegraph_edges_type_check;
ALTER TABLE codegraph_edges ADD CONSTRAINT codegraph_edges_type_check CHECK (type IN ('calls', 'imports', 'defines', 'exposes',
    'reads', 'writes', 'publishes', 'consumes', 'depends_on', 'deployed_as', 'crosses_boundary', 'owns', 'references'));

-- Evidence kind "binary" (verified, static): ref "0x<file offset>".
ALTER TABLE codegraph_evidence DROP CONSTRAINT codegraph_evidence_kind_check;
ALTER TABLE codegraph_evidence ADD CONSTRAINT codegraph_evidence_kind_check
    CHECK (kind IN ('file_line', 'sbom', 'scan', 'registry', 'runtime', 'ai_record', 'binary'));
-- +goose StatementBegin
DO $$
DECLARE
    c text;
BEGIN
    -- The unnamed table check that ties the evidence type to the kind.
    FOR c IN SELECT conname FROM pg_constraint WHERE conrelid = 'codegraph_evidence'::regclass AND contype = 'c'
             AND pg_get_constraintdef(oid) LIKE '%ai_record%' AND pg_get_constraintdef(oid) LIKE '%runtime%'
             AND conname <> 'codegraph_evidence_kind_check' LOOP
        EXECUTE format('ALTER TABLE codegraph_evidence DROP CONSTRAINT %I', c);
    END LOOP;
END $$;
-- +goose StatementEnd
ALTER TABLE codegraph_evidence ADD CONSTRAINT codegraph_evidence_type_kind_check
    CHECK ((evidence = 'verified' AND kind IN ('file_line', 'sbom', 'scan', 'registry', 'binary'))
        OR (evidence = 'observed' AND kind = 'runtime')
        OR (evidence = 'ai_inferred' AND kind = 'ai_record'));
ALTER TABLE codegraph_evidence ADD CONSTRAINT codegraph_evidence_binary_ref_check
    CHECK (kind <> 'binary' OR ref ~ '^0x[0-9a-f]{1,16}$');

-- Code views of selected functions (pseudo-C from the decompiler, or the
-- disassembly), secrets redacted by the analyser and again by the API.
-- Decompiled code is source-equivalent: it is shown to people with
-- findings.read and sent to an AI model only as rea_settings allow.
CREATE TABLE rea_code (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    analysis_id     uuid NOT NULL,
    node_key        text NOT NULL CHECK (length(node_key) BETWEEN 1 AND 300),
    tool            text NOT NULL CHECK (tool IN ('radare2', 'ghidra', 'jadx', 'ilspy')),
    kind            text NOT NULL CHECK (kind IN ('pseudo_c', 'disassembly', 'java', 'csharp')),
    body            text NOT NULL CHECK (length(body) <= 20000),
    UNIQUE (organization_id, id),
    UNIQUE (analysis_id, node_key),
    FOREIGN KEY (organization_id, analysis_id) REFERENCES rea_analyses(organization_id, id) ON DELETE CASCADE
);

ALTER TABLE rea_analyses ADD FOREIGN KEY (organization_id, snapshot_id)
    REFERENCES codegraph_snapshots(organization_id, id) ON DELETE SET NULL (snapshot_id);
ALTER TABLE rea_analyses ADD FOREIGN KEY (organization_id, source_snapshot_id)
    REFERENCES codegraph_snapshots(organization_id, id) ON DELETE SET NULL (source_snapshot_id);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS rea_code;
DELETE FROM codegraph_snapshots WHERE kind = 'binary';
-- Fire the deferred evidence triggers of the cascaded deletes now: a table
-- with pending trigger events cannot be altered.
SET CONSTRAINTS ALL IMMEDIATE;
ALTER TABLE codegraph_evidence DROP CONSTRAINT IF EXISTS codegraph_evidence_binary_ref_check;
ALTER TABLE codegraph_evidence DROP CONSTRAINT IF EXISTS codegraph_evidence_type_kind_check;
ALTER TABLE codegraph_evidence ADD CHECK ((evidence = 'verified' AND kind IN ('file_line', 'sbom', 'scan', 'registry'))
        OR (evidence = 'observed' AND kind = 'runtime')
        OR (evidence = 'ai_inferred' AND kind = 'ai_record'));
ALTER TABLE codegraph_evidence DROP CONSTRAINT codegraph_evidence_kind_check;
ALTER TABLE codegraph_evidence ADD CONSTRAINT codegraph_evidence_kind_check
    CHECK (kind IN ('file_line', 'sbom', 'scan', 'registry', 'runtime', 'ai_record'));
ALTER TABLE codegraph_edges DROP CONSTRAINT codegraph_edges_type_check;
ALTER TABLE codegraph_edges ADD CONSTRAINT codegraph_edges_type_check CHECK (type IN ('calls', 'imports', 'defines', 'exposes',
    'reads', 'writes', 'publishes', 'consumes', 'depends_on', 'deployed_as', 'crosses_boundary', 'owns'));
ALTER TABLE codegraph_nodes DROP CONSTRAINT codegraph_nodes_type_check;
ALTER TABLE codegraph_nodes ADD CONSTRAINT codegraph_nodes_type_check CHECK (type IN ('repository', 'module', 'file', 'function',
    'class', 'route', 'api_operation', 'datastore', 'queue', 'external_service', 'container', 'iac_resource', 'component',
    'secret_ref', 'trust_boundary', 'application'));
DROP INDEX IF EXISTS codegraph_snapshots_kind_idx;
ALTER TABLE codegraph_snapshots DROP CONSTRAINT codegraph_snapshots_kind_trigger_check;
ALTER TABLE codegraph_snapshots DROP CONSTRAINT codegraph_snapshots_trigger_check;
ALTER TABLE codegraph_snapshots ADD CONSTRAINT codegraph_snapshots_trigger_check CHECK (trigger IN ('manual', 'scan'));
ALTER TABLE codegraph_snapshots DROP CONSTRAINT codegraph_snapshots_source_app_check;
ALTER TABLE codegraph_snapshots ALTER COLUMN application_id SET NOT NULL;
ALTER TABLE codegraph_snapshots DROP COLUMN kind;
