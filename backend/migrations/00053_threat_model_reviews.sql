-- +goose Up
-- PATHOS 3.0 M5: the review trail of threat models. Approval decisions are
-- append-only (submitted, approved, rejected, changes requested; the
-- approver is never the version's author or submitter, enforced by the
-- service and by the check on threat_models.approved_by). Threat events
-- record every human change with its reason (severity and status changes
-- require one) and every regeneration. Both are written only by the API.

CREATE TABLE threat_model_approvals (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    threat_model_id uuid NOT NULL,
    lineage_id      uuid NOT NULL,
    version         integer NOT NULL CHECK (version >= 1),
    decision        text NOT NULL CHECK (decision IN ('submitted', 'approved', 'rejected', 'changes_requested')),
    actor_id        uuid,
    note            text NOT NULL DEFAULT '' CHECK (length(note) <= 4000),
    decided_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    FOREIGN KEY (organization_id, threat_model_id) REFERENCES threat_models(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, actor_id) REFERENCES users(organization_id, id) ON DELETE SET NULL (actor_id)
);
CREATE INDEX threat_model_approvals_lineage_idx ON threat_model_approvals (lineage_id, decided_at);

-- Append-only: decisions are never changed or removed (except with the
-- model, by cascade).
-- +goose StatementBegin
CREATE FUNCTION threat_model_approvals_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'threat model approvals are append-only'
        USING ERRCODE = 'check_violation', CONSTRAINT = 'threat_model_approvals_append_only';
END $$;
-- +goose StatementEnd
CREATE TRIGGER threat_model_approvals_no_update BEFORE UPDATE ON threat_model_approvals
    FOR EACH ROW EXECUTE FUNCTION threat_model_approvals_append_only();

CREATE TABLE threat_events (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL,
    threat_id       uuid NOT NULL,
    action          text NOT NULL CHECK (action IN ('created', 'regenerated', 'severity_changed', 'status_changed', 'mitigation_changed',
                       'linked', 'unlinked', 'mapping_added', 'mapping_removed', 'edited', 'copied')),
    from_value      text NOT NULL DEFAULT '' CHECK (length(from_value) <= 2000),
    to_value        text NOT NULL DEFAULT '' CHECK (length(to_value) <= 2000),
    reason          text NOT NULL DEFAULT '' CHECK (length(reason) <= 2000),
    actor_id        uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, id),
    CHECK (action NOT IN ('severity_changed', 'status_changed') OR reason <> ''),
    FOREIGN KEY (organization_id, threat_id) REFERENCES threats(organization_id, id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, actor_id) REFERENCES users(organization_id, id) ON DELETE SET NULL (actor_id)
);
CREATE INDEX threat_events_threat_idx ON threat_events (threat_id, created_at);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS threat_events;
DROP TABLE IF EXISTS threat_model_approvals;
DROP FUNCTION IF EXISTS threat_model_approvals_append_only();
