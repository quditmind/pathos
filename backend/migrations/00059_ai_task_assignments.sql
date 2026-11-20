-- +goose Up
-- PATHOS 3.0 M7: model per task (ADR-008). Each AI task can use its own AI
-- configuration. A task without a row uses, when the ai_intelligence flag
-- is on, a self-hosted (local) configuration for the tasks that carry
-- code or code structure and the organization's default configuration
-- otherwise (internal/ai/tasks.go). Whether source code may be sent stays
-- the configuration's own "send code context" setting: code never goes to
-- a cloud model whose configuration does not allow it.
CREATE TABLE ai_task_assignments (
    organization_id  uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    task             text NOT NULL CHECK (task IN ('finding_validation', 'fix_proposal', 'troubleshooting', 'threat_suggestion',
                        'correlation', 'analyst', 'report', 'graph_inference')),
    configuration_id uuid NOT NULL,
    updated_by       uuid,
    updated_at       timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (organization_id, task),
    FOREIGN KEY (organization_id, configuration_id) REFERENCES ai_configurations(organization_id, id) ON DELETE CASCADE
);

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TABLE IF EXISTS ai_task_assignments;
