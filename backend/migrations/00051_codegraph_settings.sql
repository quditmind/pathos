-- +goose Up
-- PATHOS 3.0 M4: CodeGraph rediscovery and retention settings per
-- organization (docs/api-reference/codegraph.md, "Settings"). Without a row
-- the defaults apply: rediscovery after each repository scan on, at most one
-- rebuild per repository every 60 minutes, the 10 newest snapshots per
-- repository kept in rows (older ones archived).
CREATE TABLE codegraph_settings (
    organization_id      uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    auto_rebuild         boolean NOT NULL DEFAULT true,
    min_interval_minutes integer NOT NULL DEFAULT 60 CHECK (min_interval_minutes BETWEEN 0 AND 10080),
    keep_snapshots       integer NOT NULL DEFAULT 10 CHECK (keep_snapshots BETWEEN 1 AND 1000),
    updated_by           uuid,
    updated_at           timestamptz NOT NULL DEFAULT now()
);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS codegraph_settings;
