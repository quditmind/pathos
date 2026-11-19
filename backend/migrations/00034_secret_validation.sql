-- +goose Up
-- Live secret validation (off by default): an administrator enables
-- providers; workers then ask each provider's read-only "who am I"
-- endpoint whether a detected credential is still active and report the
-- verdict. The secret itself never leaves the worker and is never stored.

CREATE TABLE secret_validation_settings (
    organization_id     uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    -- Enabled provider IDs (scanners.SecretProviders); empty = off.
    providers           text[] NOT NULL DEFAULT '{}' CHECK (cardinality(providers) <= 50),
    -- Checks per second per scan (1-10) and checks per scan (1-500).
    rate_per_second     integer NOT NULL DEFAULT 1 CHECK (rate_per_second BETWEEN 1 AND 10),
    max_checks_per_scan integer NOT NULL DEFAULT 50 CHECK (max_checks_per_scan BETWEEN 1 AND 500),
    updated_by          uuid,
    updated_at          timestamptz NOT NULL DEFAULT now()
);

-- The verdict on secret findings. evidence holds the request made, the
-- HTTP status, an explanation, the severity before an active verdict
-- raised it and the last inconclusive attempt; never the secret.
ALTER TABLE findings
    ADD COLUMN secret_validation_status     text NOT NULL DEFAULT 'not_checked'
        CHECK (secret_validation_status IN ('active', 'inactive', 'error', 'not_checked')),
    ADD COLUMN secret_validation_provider   text NOT NULL DEFAULT '' CHECK (length(secret_validation_provider) <= 40),
    ADD COLUMN secret_validation_identity   text NOT NULL DEFAULT '' CHECK (length(secret_validation_identity) <= 200),
    ADD COLUMN secret_validation_checked_at timestamptz,
    ADD COLUMN secret_validation_evidence   jsonb
        CHECK (secret_validation_evidence IS NULL OR (jsonb_typeof(secret_validation_evidence) = 'object' AND pg_column_size(secret_validation_evidence) <= 8192)),
    -- Severity before an active verdict raised it to critical (NULL: not raised).
    ADD COLUMN secret_validation_severity_before text
        CHECK (secret_validation_severity_before IN ('critical', 'high', 'medium', 'low', 'info'));

CREATE INDEX findings_secret_validation_idx ON findings (organization_id, secret_validation_status) WHERE category = 'secrets';

-- +goose Down
DROP INDEX IF EXISTS findings_secret_validation_idx;
-- A severity raised by an active verdict goes back to the scanner's.
UPDATE findings SET severity = secret_validation_severity_before WHERE secret_validation_severity_before IS NOT NULL;
ALTER TABLE findings
    DROP COLUMN IF EXISTS secret_validation_severity_before,
    DROP COLUMN IF EXISTS secret_validation_evidence,
    DROP COLUMN IF EXISTS secret_validation_checked_at,
    DROP COLUMN IF EXISTS secret_validation_identity,
    DROP COLUMN IF EXISTS secret_validation_provider,
    DROP COLUMN IF EXISTS secret_validation_status;
DROP TABLE IF EXISTS secret_validation_settings;
