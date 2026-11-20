-- +goose Up
-- PATHOS 3.0 M7: link the stored AI results to their evidence records
-- (nullable; rows from before M7 have none) and bind the threat model's
-- reserved AI path (00052: method 'ai' / evidence_type 'ai_inferred'
-- require ai_evidence_id) to the records table.
ALTER TABLE ai_reviews ADD COLUMN evidence_record_id uuid;
ALTER TABLE ai_reviews ADD CONSTRAINT ai_reviews_evidence_fk
    FOREIGN KEY (organization_id, evidence_record_id) REFERENCES ai_evidence_records(organization_id, id) ON DELETE SET NULL (evidence_record_id);
ALTER TABLE ai_fix_proposals ADD COLUMN evidence_record_id uuid;
ALTER TABLE ai_fix_proposals ADD CONSTRAINT ai_fix_proposals_evidence_fk
    FOREIGN KEY (organization_id, evidence_record_id) REFERENCES ai_evidence_records(organization_id, id) ON DELETE SET NULL (evidence_record_id);
ALTER TABLE ai_messages ADD COLUMN evidence_record_id uuid;
ALTER TABLE ai_messages ADD CONSTRAINT ai_messages_evidence_fk
    FOREIGN KEY (organization_id, evidence_record_id) REFERENCES ai_evidence_records(organization_id, id) ON DELETE SET NULL (evidence_record_id);
ALTER TABLE ai_reports ADD COLUMN evidence_record_id uuid;
ALTER TABLE ai_reports ADD CONSTRAINT ai_reports_evidence_fk
    FOREIGN KEY (organization_id, evidence_record_id) REFERENCES ai_evidence_records(organization_id, id) ON DELETE SET NULL (evidence_record_id);
ALTER TABLE human_review_recommendations ADD COLUMN evidence_record_id uuid;
ALTER TABLE human_review_recommendations ADD CONSTRAINT human_review_recommendations_evidence_fk
    FOREIGN KEY (organization_id, evidence_record_id) REFERENCES ai_evidence_records(organization_id, id) ON DELETE SET NULL (evidence_record_id);
-- A threat's AI evidence record stays while the threat exists.
ALTER TABLE threats ADD CONSTRAINT threats_ai_evidence_fk
    FOREIGN KEY (organization_id, ai_evidence_id) REFERENCES ai_evidence_records(organization_id, id);
CREATE INDEX threats_ai_evidence_idx ON threats (ai_evidence_id) WHERE ai_evidence_id IS NOT NULL;
-- A person's acceptance of an AI-suggested threat is a threat event.
ALTER TABLE threat_events DROP CONSTRAINT IF EXISTS threat_events_action_check;
ALTER TABLE threat_events ADD CONSTRAINT threat_events_action_check CHECK (action IN ('created', 'regenerated', 'severity_changed',
    'status_changed', 'mitigation_changed', 'linked', 'unlinked', 'mapping_added', 'mapping_removed', 'edited', 'copied', 'ai_accepted'));

SELECT pathos_apply_app_grants();

-- +goose Down
DELETE FROM threat_events WHERE action = 'ai_accepted';
ALTER TABLE threat_events DROP CONSTRAINT IF EXISTS threat_events_action_check;
ALTER TABLE threat_events ADD CONSTRAINT threat_events_action_check CHECK (action IN ('created', 'regenerated', 'severity_changed',
    'status_changed', 'mitigation_changed', 'linked', 'unlinked', 'mapping_added', 'mapping_removed', 'edited', 'copied'));
DROP INDEX IF EXISTS threats_ai_evidence_idx;
ALTER TABLE threats DROP CONSTRAINT IF EXISTS threats_ai_evidence_fk;
ALTER TABLE human_review_recommendations DROP COLUMN IF EXISTS evidence_record_id;
ALTER TABLE ai_reports DROP COLUMN IF EXISTS evidence_record_id;
ALTER TABLE ai_messages DROP COLUMN IF EXISTS evidence_record_id;
ALTER TABLE ai_fix_proposals DROP COLUMN IF EXISTS evidence_record_id;
ALTER TABLE ai_reviews DROP COLUMN IF EXISTS evidence_record_id;
