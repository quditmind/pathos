-- +goose Up
-- PATHOS 3.0 M5 threat models (docs/aspm/PATHOS_THREAT_MODELLING.md, ADR-007).
-- A threat model is versioned: every version is one threat_models row of the
-- same lineage. Threats belong to one version; a new version copies them with
-- every human edit. Every threat has evidence, a method (rule and version for
-- generated threats), a severity, a confidence and a mitigation field (the M5
-- "done when"); a submitted model has a mitigation on every open or accepted
-- threat (service check, PTH-TM-1004). All tables carry organization_id, so
-- pathos_apply_app_grants() gives each the standard tenant policy
-- (docs/MULTI_TENANCY.md).

CREATE TABLE threat_models (
    id                     uuid PRIMARY KEY,
    organization_id        uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- All versions of one model share the lineage (the id of version 1).
    lineage_id             uuid NOT NULL,
    version                integer NOT NULL DEFAULT 1 CHECK (version >= 1),
    previous_version_id    uuid,
    application_id         uuid NOT NULL,
    -- Optional narrower scope: one repository of the application.
    repository_id          uuid,
    status                 text NOT NULL DEFAULT 'draft' CHECK (status IN ('draft', 'in_review', 'approved', 'superseded', 'archived')),
    method                 text NOT NULL CHECK (method IN ('stride', 'manual', 'imported')),
    imported_format        text NOT NULL DEFAULT '' CHECK (imported_format IN ('', 'threat_dragon', 'pathos')),
    title                  text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
    summary                text NOT NULL DEFAULT '' CHECK (length(summary) <= 8000),
    -- The CodeGraph snapshots of the last generation (one per repository;
    -- snapshots may be archived later, the ids stay as a record).
    codegraph_snapshot_ids uuid[] NOT NULL DEFAULT '{}',
    generated_at           timestamptz,
    generation             jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(generation) = 'object' AND pg_column_size(generation) <= 65536),
    created_by             uuid,
    submitted_by           uuid,
    submitted_at           timestamptz,
    approved_by            uuid,
    approved_at            timestamptz,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    UNIQUE (lineage_id, version),
    -- The approver is never the author or the submitter (also checked by
    -- the service, PTH-TM-1005).
    CHECK (approved_by IS NULL OR (approved_by IS DISTINCT FROM created_by AND approved_by IS DISTINCT FROM submitted_by)),
    CHECK (status <> 'approved' OR approved_by IS NOT NULL),
    FOREIGN KEY (organization_id, application_id) REFERENCES applications(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, previous_version_id) REFERENCES threat_models(organization_id, id) ON DELETE SET NULL (previous_version_id),
    FOREIGN KEY (organization_id, created_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (created_by),
    FOREIGN KEY (organization_id, submitted_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (submitted_by),
    FOREIGN KEY (organization_id, approved_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (approved_by)
);
CREATE INDEX threat_models_app_idx ON threat_models (organization_id, application_id, lineage_id, version DESC);
-- At most one open (draft or in review) version per model.
CREATE UNIQUE INDEX threat_models_open_uq ON threat_models (lineage_id) WHERE status IN ('draft', 'in_review');
-- One model per application and repository scope (version 1 rows).
CREATE UNIQUE INDEX threat_models_scope_uq ON threat_models (organization_id, application_id, COALESCE(repository_id, '00000000-0000-0000-0000-000000000000'::uuid))
    WHERE version = 1;

-- Diagram elements of a version (data-flow diagram), linked to CodeGraph
-- where they come from it.
CREATE TABLE threat_model_elements (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    threat_model_id uuid NOT NULL,
    kind            text NOT NULL CHECK (kind IN ('process', 'data_store', 'external_entity', 'data_flow', 'trust_boundary')),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 500),
    repository_id   uuid,
    -- CodeGraph node key, or edge key for a data flow ('' for imported or
    -- manual elements without a CodeGraph link).
    codegraph_key   text NOT NULL DEFAULT '' CHECK (length(codegraph_key) <= 700),
    node_type       text NOT NULL DEFAULT '' CHECK (length(node_type) <= 64),
    -- Data flows: the element keys of both ends; imported elements: their
    -- source id and position.
    source_key      text NOT NULL DEFAULT '' CHECK (length(source_key) <= 700),
    target_key      text NOT NULL DEFAULT '' CHECK (length(target_key) <= 700),
    attrs           jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(attrs) = 'object' AND pg_column_size(attrs) <= 16384),
    element_key     text NOT NULL CHECK (length(element_key) BETWEEN 1 AND 800),
    UNIQUE (organization_id, id),
    UNIQUE (threat_model_id, element_key),
    FOREIGN KEY (organization_id, threat_model_id) REFERENCES threat_models(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE SET NULL (repository_id)
);
CREATE INDEX threat_model_elements_model_idx ON threat_model_elements (threat_model_id, kind);

CREATE TABLE threats (
    id                  uuid PRIMARY KEY,
    organization_id     uuid NOT NULL,
    threat_model_id     uuid NOT NULL,
    -- Stable identity of a generated threat: rule | repository | element
    -- (regeneration matches it). '' for manual and imported threats.
    fingerprint         text NOT NULL DEFAULT '' CHECK (length(fingerprint) <= 900),
    title               text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    description         text NOT NULL DEFAULT '' CHECK (length(description) <= 8000),
    category            text NOT NULL CHECK (category IN ('spoofing', 'tampering', 'repudiation', 'information_disclosure',
                           'denial_of_service', 'elevation_of_privilege',
                           'linking', 'identifying', 'non_repudiation', 'detecting', 'data_disclosure', 'unawareness', 'non_compliance')),
    method              text NOT NULL CHECK (method IN ('rule', 'attack_path', 'manual', 'imported', 'ai')),
    rule_id             text NOT NULL DEFAULT '' CHECK (length(rule_id) <= 32),
    rule_version        text NOT NULL DEFAULT '' CHECK (length(rule_version) <= 16),
    -- Rule 5 label; unverified: a manual or imported threat not yet linked
    -- to evidence (assessment §8.6, "imported, unverified").
    evidence_type       text NOT NULL CHECK (evidence_type IN ('verified', 'observed', 'ai_inferred', 'unverified')),
    evidence            jsonb NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(evidence) = 'object' AND pg_column_size(evidence) <= 262144),
    -- The AI evidence record of an AI-suggested threat (M7; no endpoint yet).
    ai_evidence_id      uuid,
    severity            text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    severity_reason     text NOT NULL DEFAULT '' CHECK (length(severity_reason) <= 2000),
    severity_overridden boolean NOT NULL DEFAULT false,
    confidence          numeric(4,3) NOT NULL CHECK (confidence > 0 AND confidence <= 1),
    confidence_reason   text NOT NULL DEFAULT '' CHECK (length(confidence_reason) <= 2000),
    status              text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'mitigated', 'accepted', 'not_applicable')),
    status_reason       text NOT NULL DEFAULT '' CHECK (length(status_reason) <= 2000),
    mitigation          text NOT NULL DEFAULT '' CHECK (length(mitigation) <= 8000),
    mitigation_edited   boolean NOT NULL DEFAULT false,
    -- Against the previous generation.
    change_state        text NOT NULL DEFAULT '' CHECK (change_state IN ('', 'new', 'changed', 'unchanged', 'resolved')),
    evidence_hash       text NOT NULL DEFAULT '' CHECK (length(evidence_hash) <= 64),
    owner_id            uuid,
    created_by          uuid,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    -- Generated threats name their rule and version.
    CHECK (method NOT IN ('rule', 'attack_path') OR (rule_id <> '' AND rule_version <> '' AND fingerprint <> '')),
    -- Generated threats rest on verified or observed evidence only.
    CHECK (method NOT IN ('rule', 'attack_path') OR evidence_type IN ('verified', 'observed')),
    -- Only manual or imported threats can be unverified.
    CHECK (evidence_type <> 'unverified' OR method IN ('manual', 'imported')),
    -- An AI-inferred threat needs its AI evidence record.
    CHECK ((evidence_type = 'ai_inferred') = (method = 'ai')),
    CHECK (evidence_type <> 'ai_inferred' OR ai_evidence_id IS NOT NULL),
    FOREIGN KEY (organization_id, threat_model_id) REFERENCES threat_models(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, owner_id) REFERENCES users(organization_id, id) ON DELETE SET NULL (owner_id),
    FOREIGN KEY (organization_id, created_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (created_by)
);
CREATE INDEX threats_model_idx ON threats (threat_model_id, severity);
CREATE UNIQUE INDEX threats_fingerprint_uq ON threats (threat_model_id, fingerprint) WHERE fingerprint <> '';

-- Elements a threat affects.
CREATE TABLE threat_elements (
    organization_id uuid NOT NULL,
    threat_id       uuid NOT NULL,
    element_id      uuid NOT NULL,
    position        smallint NOT NULL DEFAULT 0,
    PRIMARY KEY (threat_id, element_id),
    FOREIGN KEY (organization_id, threat_id) REFERENCES threats(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, element_id) REFERENCES threat_model_elements(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX threat_elements_element_idx ON threat_elements (element_id);

-- Findings linked to a threat (evidence and mitigation).
CREATE TABLE threat_findings (
    organization_id uuid NOT NULL,
    threat_id       uuid NOT NULL,
    finding_id      uuid NOT NULL,
    -- generated: the engine linked it; user: a person did.
    source          text NOT NULL DEFAULT 'generated' CHECK (source IN ('generated', 'user', 'imported')),
    PRIMARY KEY (threat_id, finding_id),
    FOREIGN KEY (organization_id, threat_id) REFERENCES threats(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, finding_id) REFERENCES findings(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX threat_findings_finding_idx ON threat_findings (finding_id);

-- Framework mappings: ATT&CK, CAPEC, CWE, D3FEND entries (bundled data,
-- internal/threatmodel/frameworks) and LINDDUN category names.
CREATE TABLE threat_framework_mappings (
    organization_id uuid NOT NULL,
    threat_id       uuid NOT NULL,
    framework       text NOT NULL CHECK (framework IN ('attack', 'capec', 'cwe', 'd3fend', 'linddun')),
    entry_id        text NOT NULL CHECK (length(entry_id) BETWEEN 1 AND 50),
    source          text NOT NULL CHECK (source IN ('rule', 'finding', 'user', 'imported', 'ai')),
    PRIMARY KEY (threat_id, framework, entry_id),
    FOREIGN KEY (organization_id, threat_id) REFERENCES threats(organization_id, id) ON DELETE CASCADE
);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS threat_framework_mappings;
DROP TABLE IF EXISTS threat_findings;
DROP TABLE IF EXISTS threat_elements;
DROP TABLE IF EXISTS threats;
DROP TABLE IF EXISTS threat_model_elements;
DROP TABLE IF EXISTS threat_models;
