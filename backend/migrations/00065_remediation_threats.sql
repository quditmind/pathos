-- +goose Up
-- PATHOS 3.0, M9: remediation ↔ threat link and the "item marked fix
-- submitted → targeted rescan" trigger (feedback loop 5).
--
-- A remediation item of kind threat_mitigation may reference the threat
-- (M5) it mitigates. The threat belongs to a threat model of the item's
-- application (checked by the API); deleting the threat unlinks the item.
-- Verifications gain the trigger fix_submitted: a person marked the fix
-- as submitted (no open fix pull request) and PATHOS queued the targeted
-- rescan.

ALTER TABLE remediation_items ADD COLUMN threat_id uuid;
ALTER TABLE remediation_items ADD CONSTRAINT remediation_items_threat_fk
    FOREIGN KEY (organization_id, threat_id) REFERENCES threats(organization_id, id) ON DELETE SET NULL (threat_id);
ALTER TABLE remediation_items ADD CONSTRAINT remediation_items_threat_kind_check
    CHECK (threat_id IS NULL OR kind = 'threat_mitigation');
CREATE INDEX remediation_items_threat_idx ON remediation_items (threat_id) WHERE threat_id IS NOT NULL;

ALTER TABLE remediation_verifications DROP CONSTRAINT remediation_verifications_trigger_check;
ALTER TABLE remediation_verifications ADD CONSTRAINT remediation_verifications_trigger_check
    CHECK (trigger IN ('manual', 'fix_pr_merged', 'existing_scan', 'fix_submitted'));

SELECT pathos_apply_app_grants();

-- +goose Down
DELETE FROM remediation_verifications WHERE trigger = 'fix_submitted';
ALTER TABLE remediation_verifications DROP CONSTRAINT remediation_verifications_trigger_check;
ALTER TABLE remediation_verifications ADD CONSTRAINT remediation_verifications_trigger_check
    CHECK (trigger IN ('manual', 'fix_pr_merged', 'existing_scan'));
DROP INDEX IF EXISTS remediation_items_threat_idx;
ALTER TABLE remediation_items DROP CONSTRAINT IF EXISTS remediation_items_threat_kind_check;
ALTER TABLE remediation_items DROP CONSTRAINT IF EXISTS remediation_items_threat_fk;
ALTER TABLE remediation_items DROP COLUMN IF EXISTS threat_id;
