-- Phase 8: scan artifacts may live in S3-compatible object storage. The row
-- then keeps metadata and the object key; data_gzip stays NULL. Without an
-- object store configured, artifacts remain inline as before.

-- +goose Up
ALTER TABLE scan_artifacts ALTER COLUMN data_gzip DROP NOT NULL;
ALTER TABLE scan_artifacts ADD COLUMN object_key text;
ALTER TABLE scan_artifacts ADD CONSTRAINT scan_artifacts_location_ck
    CHECK ((data_gzip IS NULL) <> (object_key IS NULL));
CREATE UNIQUE INDEX scan_artifacts_object_key_uq ON scan_artifacts (object_key) WHERE object_key IS NOT NULL;

-- +goose Down
ALTER TABLE scan_artifacts DROP CONSTRAINT IF EXISTS scan_artifacts_location_ck;
DROP INDEX IF EXISTS scan_artifacts_object_key_uq;
ALTER TABLE scan_artifacts DROP COLUMN IF EXISTS object_key;
-- Rows stored in object storage cannot be restored inline by a migration.
DELETE FROM scan_artifacts WHERE data_gzip IS NULL;
ALTER TABLE scan_artifacts ALTER COLUMN data_gzip SET NOT NULL;
