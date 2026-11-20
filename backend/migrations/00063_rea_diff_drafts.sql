-- +goose Up
-- PATHOS 3.0 M10: source ↔ binary diff and finding drafts. The diff
-- compares a binary graph with the CodeGraph source snapshot of the commit
-- the artifact was built from: functions, packages, routes and strings that
-- are only in the binary, only in the source, or matched, each with its
-- evidence (binary offsets and source file:line references). Items only in
-- the binary that involve sensitive APIs get finding drafts: proposals for
-- a person to create as findings (status needs_review), dismiss or add to a
-- threat model; a draft never becomes a finding by itself.

CREATE TABLE rea_diff_items (
    id               uuid PRIMARY KEY,
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    analysis_id      uuid NOT NULL,
    side             text NOT NULL CHECK (side IN ('binary_only', 'source_only', 'matched')),
    kind             text NOT NULL CHECK (kind IN ('function', 'package', 'route', 'string')),
    name             text NOT NULL CHECK (length(name) BETWEEN 1 AND 500),
    binary_node_key  text NOT NULL DEFAULT '' CHECK (length(binary_node_key) <= 300),
    source_node_key  text NOT NULL DEFAULT '' CHECK (length(source_node_key) <= 300),
    source_file      text NOT NULL DEFAULT '' CHECK (length(source_file) <= 1000),
    source_line      integer CHECK (source_line IS NULL OR source_line >= 0),
    binary_offset    bigint CHECK (binary_offset IS NULL OR binary_offset >= 0),
    tool             text NOT NULL DEFAULT '' CHECK (length(tool) <= 32),
    sensitive        boolean NOT NULL DEFAULT false,
    sensitive_reason text NOT NULL DEFAULT '' CHECK (length(sensitive_reason) <= 500),
    -- [{evidence, kind, ref, detail}], at most a few entries.
    evidence         jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(evidence) = 'array' AND pg_column_size(evidence) <= 8192),
    UNIQUE (organization_id, id),
    CHECK (side = 'source_only' OR binary_node_key <> ''),
    CHECK (side = 'binary_only' OR source_node_key <> '' OR source_file <> ''),
    FOREIGN KEY (organization_id, analysis_id) REFERENCES rea_analyses(organization_id, id) ON DELETE CASCADE
);
CREATE INDEX rea_diff_items_analysis_idx ON rea_diff_items (analysis_id, side, kind, name);
CREATE INDEX rea_diff_items_binary_idx ON rea_diff_items (analysis_id, binary_node_key) WHERE binary_node_key <> '';

CREATE TABLE rea_finding_drafts (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    analysis_id     uuid NOT NULL,
    diff_item_id    uuid NOT NULL,
    title           text NOT NULL CHECK (length(title) BETWEEN 1 AND 300),
    description     text NOT NULL DEFAULT '' CHECK (length(description) <= 8000),
    severity        text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    rule_id         text NOT NULL CHECK (length(rule_id) BETWEEN 1 AND 200),
    cwe             text[] NOT NULL DEFAULT '{}',
    status          text NOT NULL DEFAULT 'proposed' CHECK (status IN ('proposed', 'dismissed', 'created')),
    evidence        jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(evidence) = 'array' AND pg_column_size(evidence) <= 8192),
    finding_id      uuid,
    decided_by      uuid,
    decided_at      timestamptz,
    decision_reason text NOT NULL DEFAULT '' CHECK (length(decision_reason) <= 1000),
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    UNIQUE (analysis_id, diff_item_id),
    -- A draft becomes a finding only by a person's decision.
    CHECK (status = 'proposed' OR decided_by IS NOT NULL OR decided_at IS NOT NULL),
    CHECK (status <> 'created' OR finding_id IS NOT NULL OR decided_at IS NOT NULL),
    FOREIGN KEY (organization_id, analysis_id) REFERENCES rea_analyses(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, diff_item_id) REFERENCES rea_diff_items(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, decided_by) REFERENCES users(organization_id, id) ON DELETE SET NULL (decided_by)
);
CREATE INDEX rea_finding_drafts_analysis_idx ON rea_finding_drafts (analysis_id, status);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS rea_finding_drafts;
DROP TABLE IF EXISTS rea_diff_items;
