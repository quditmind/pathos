-- +goose Up
-- PATHOS 3.0 M4 CodeGraph store (docs/aspm/PATHOS_CODEGRAPH_ARCHITECTURE.md,
-- ADR-004: PostgreSQL tables, no graph database). One snapshot per
-- application, repository and commit; nodes form a containment tree
-- (parent_id) used for server-side aggregation; every edge carries at least
-- one evidence row (rule 5: verified, observed or ai_inferred). All tables
-- carry organization_id, so pathos_apply_app_grants() gives each the standard
-- tenant policy (docs/MULTI_TENANCY.md). Rows are written only by the API
-- (graph ingest after a discovery job) and the jobs runner (retention).

CREATE TABLE codegraph_snapshots (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    application_id  uuid NOT NULL,
    repository_id   uuid NOT NULL,
    scan_job_id     uuid,
    ref             text NOT NULL DEFAULT '' CHECK (length(ref) <= 255),
    commit_sha      text NOT NULL DEFAULT '' CHECK (length(commit_sha) <= 64),
    -- manual (API), scan (rediscovery after a scan or new commit).
    trigger         text NOT NULL CHECK (trigger IN ('manual', 'scan')),
    status          text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'building', 'ready', 'partial', 'failed', 'archived')),
    -- rows: nodes and edges are in the tables below; object: archived, only
    -- the gzip JSON export in object storage remains (object_key);
    -- none: archived without object storage (summary only).
    storage         text NOT NULL DEFAULT 'rows' CHECK (storage IN ('rows', 'object', 'none')),
    object_key      text CHECK (object_key IS NULL OR length(object_key) <= 500),
    engines         jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(engines) = 'object' AND pg_column_size(engines) <= 8192),
    stats           jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(stats) = 'object' AND pg_column_size(stats) <= 65536),
    node_count      integer NOT NULL DEFAULT 0 CHECK (node_count >= 0),
    edge_count      integer NOT NULL DEFAULT 0 CHECK (edge_count >= 0),
    error_code      text NOT NULL DEFAULT '' CHECK (error_code = '' OR error_code ~ '^PTH-[A-Z]+-[0-9]{4}$'),
    error           text NOT NULL DEFAULT '' CHECK (length(error) <= 2000),
    requested_by    uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    started_at      timestamptz,
    finished_at     timestamptz,
    archived_at     timestamptz,
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, scan_job_id) REFERENCES scan_jobs(organization_id, id) ON DELETE SET NULL (scan_job_id)
);
CREATE INDEX codegraph_snapshots_app_idx ON codegraph_snapshots (organization_id, application_id, created_at DESC);
CREATE INDEX codegraph_snapshots_repo_idx ON codegraph_snapshots (repository_id, created_at DESC);
CREATE UNIQUE INDEX codegraph_snapshots_job_uq ON codegraph_snapshots (scan_job_id) WHERE scan_job_id IS NOT NULL;

CREATE TABLE codegraph_nodes (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    snapshot_id     uuid NOT NULL,
    -- Stable across snapshots (type and qualified name, never a line):
    -- diffs compare keys.
    node_key        text NOT NULL CHECK (length(node_key) BETWEEN 1 AND 300),
    type            text NOT NULL CHECK (type IN ('repository', 'module', 'file', 'function', 'class', 'route', 'api_operation',
                       'datastore', 'queue', 'external_service', 'container', 'iac_resource', 'component', 'secret_ref',
                       'trust_boundary', 'application')),
    label           text NOT NULL CHECK (length(label) BETWEEN 1 AND 500),
    layer           text NOT NULL CHECK (layer IN ('code', 'api', 'data', 'deploy', 'dependency', 'ownership')),
    parent_id       uuid,
    depth           smallint NOT NULL DEFAULT 0 CHECK (depth BETWEEN 0 AND 64),
    -- Aggregation group: the nearest module (directory) ancestor, else the
    -- node's type bucket ("type:<type>"). Used when a view is over its limit.
    group_key       text NOT NULL DEFAULT '' CHECK (length(group_key) <= 300),
    language        text NOT NULL DEFAULT '' CHECK (length(language) <= 64),
    technology      text NOT NULL DEFAULT '' CHECK (length(technology) <= 200),
    file_path       text NOT NULL DEFAULT '' CHECK (length(file_path) <= 1000),
    start_line      integer CHECK (start_line IS NULL OR start_line >= 0),
    end_line        integer CHECK (end_line IS NULL OR end_line >= 0),
    attrs           jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(attrs) = 'object' AND pg_column_size(attrs) <= 8192),
    -- Open findings attached by file and line at ingest: {"critical": n, ...}.
    finding_counts  jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(finding_counts) = 'object'),
    finding_total   integer NOT NULL DEFAULT 0 CHECK (finding_total >= 0),
    UNIQUE (organization_id, id),
    UNIQUE (snapshot_id, node_key),
    FOREIGN KEY (organization_id, snapshot_id) REFERENCES codegraph_snapshots(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, parent_id) REFERENCES codegraph_nodes(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX codegraph_nodes_type_idx ON codegraph_nodes (snapshot_id, type);
CREATE INDEX codegraph_nodes_parent_idx ON codegraph_nodes (snapshot_id, parent_id);
CREATE INDEX codegraph_nodes_group_idx ON codegraph_nodes (snapshot_id, group_key);
CREATE INDEX codegraph_nodes_file_idx ON codegraph_nodes (snapshot_id, file_path) WHERE file_path <> '';
CREATE INDEX codegraph_nodes_findings_idx ON codegraph_nodes (snapshot_id) WHERE finding_total > 0;

CREATE TABLE codegraph_edges (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    snapshot_id     uuid NOT NULL,
    -- source node_key + type + target node_key (diffs).
    edge_key        text NOT NULL CHECK (length(edge_key) BETWEEN 3 AND 700),
    source_id       uuid NOT NULL,
    target_id       uuid NOT NULL,
    type            text NOT NULL CHECK (type IN ('calls', 'imports', 'defines', 'exposes', 'reads', 'writes', 'publishes',
                       'consumes', 'depends_on', 'deployed_as', 'crosses_boundary', 'owns')),
    -- Strongest evidence held (verified > observed > ai_inferred); the
    -- evidence rows below are the proof.
    evidence        text NOT NULL CHECK (evidence IN ('verified', 'observed', 'ai_inferred')),
    UNIQUE (organization_id, id),
    UNIQUE (snapshot_id, edge_key),
    FOREIGN KEY (organization_id, snapshot_id) REFERENCES codegraph_snapshots(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, source_id) REFERENCES codegraph_nodes(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, target_id) REFERENCES codegraph_nodes(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX codegraph_edges_out_idx ON codegraph_edges (snapshot_id, source_id, type);
CREATE INDEX codegraph_edges_in_idx ON codegraph_edges (snapshot_id, target_id, type);
CREATE INDEX codegraph_edges_type_idx ON codegraph_edges (snapshot_id, type);

CREATE TABLE codegraph_evidence (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    snapshot_id     uuid NOT NULL,
    edge_id         uuid NOT NULL,
    evidence        text NOT NULL CHECK (evidence IN ('verified', 'observed', 'ai_inferred')),
    -- file_line: "<path>:<line>"; sbom: bom-ref or purl; scan: rule or scan
    -- reference; registry: the PATHOS inventory record (ownership);
    -- runtime: the observed workload; ai_record: an AI evidence record.
    kind            text NOT NULL CHECK (kind IN ('file_line', 'sbom', 'scan', 'registry', 'runtime', 'ai_record')),
    ref             text NOT NULL CHECK (length(ref) BETWEEN 1 AND 1000),
    detail          text NOT NULL DEFAULT '' CHECK (length(detail) <= 500),
    file_path       text NOT NULL DEFAULT '' CHECK (length(file_path) <= 1000),
    line            integer CHECK (line IS NULL OR line >= 0),
    -- The evidence type follows from the kind: static references are
    -- verified, runtime ones observed, AI records ai_inferred.
    CHECK ((evidence = 'verified' AND kind IN ('file_line', 'sbom', 'scan', 'registry'))
        OR (evidence = 'observed' AND kind = 'runtime')
        OR (evidence = 'ai_inferred' AND kind = 'ai_record')),
    CHECK (kind <> 'file_line' OR file_path <> ''),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, snapshot_id) REFERENCES codegraph_snapshots(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, edge_id) REFERENCES codegraph_edges(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX codegraph_evidence_edge_idx ON codegraph_evidence (edge_id);
CREATE INDEX codegraph_evidence_file_idx ON codegraph_evidence (snapshot_id, file_path) WHERE file_path <> '';

-- An edge without evidence is invalid (rule 5). Deferred constraint
-- triggers check it at commit, after the loader wrote the edge and its
-- evidence in the same transaction: a new edge must have an evidence row,
-- an edge's strongest evidence type must be one of its rows, and removing
-- evidence must not leave an edge without any.
-- +goose StatementBegin
CREATE FUNCTION codegraph_edge_has_evidence() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    e_id uuid;
BEGIN
    IF TG_TABLE_NAME = 'codegraph_edges' THEN
        e_id := NEW.id;
    ELSE
        e_id := OLD.edge_id;
    END IF;
    -- The edge itself was deleted (cascade): nothing to check.
    IF NOT EXISTS (SELECT 1 FROM codegraph_edges WHERE id = e_id) THEN
        RETURN NULL;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM codegraph_evidence v JOIN codegraph_edges e ON e.id = v.edge_id
                   WHERE v.edge_id = e_id AND v.evidence = e.evidence) THEN
        RAISE EXCEPTION 'codegraph edge % has no evidence of its evidence type', e_id
            USING ERRCODE = 'check_violation', CONSTRAINT = 'codegraph_edge_evidence_required';
    END IF;
    RETURN NULL;
END $$;
-- +goose StatementEnd

CREATE CONSTRAINT TRIGGER codegraph_edges_evidence_required
    AFTER INSERT OR UPDATE OF evidence ON codegraph_edges
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION codegraph_edge_has_evidence();
CREATE CONSTRAINT TRIGGER codegraph_evidence_keep_one
    AFTER DELETE OR UPDATE OF evidence, edge_id ON codegraph_evidence
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION codegraph_edge_has_evidence();

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS codegraph_evidence;
DROP TABLE IF EXISTS codegraph_edges;
DROP TABLE IF EXISTS codegraph_nodes;
DROP TABLE IF EXISTS codegraph_snapshots;
DROP FUNCTION IF EXISTS codegraph_edge_has_evidence();
