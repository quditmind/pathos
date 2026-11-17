-- +goose Up
-- ASPM phase 1 (docs/aspm/PATHOS_DATABASE_DESIGN.md): unified finding
-- intelligence (CVSS version and vector, confidence, EPSS, CISA KEV,
-- exploitability, reachability, contextual risk score with its factors),
-- vulnerability intelligence feeds, versioned risk models, and application
-- identity and lifecycle. Additive: existing columns, statuses and
-- fingerprints are unchanged.

ALTER TABLE findings
    ADD COLUMN cvss_version      text NOT NULL DEFAULT '' CHECK (cvss_version IN ('', '2.0', '3.0', '3.1', '4.0')),
    ADD COLUMN cvss_vector       text NOT NULL DEFAULT '' CHECK (length(cvss_vector) <= 300),
    ADD COLUMN confidence        text NOT NULL DEFAULT 'unknown' CHECK (confidence IN ('high', 'medium', 'low', 'unknown')),
    ADD COLUMN epss_score        numeric(6,5) CHECK (epss_score BETWEEN 0 AND 1),
    ADD COLUMN epss_percentile   numeric(6,5) CHECK (epss_percentile BETWEEN 0 AND 1),
    ADD COLUMN kev               boolean NOT NULL DEFAULT false,
    ADD COLUMN kev_due_date      date,
    ADD COLUMN exploit_available boolean NOT NULL DEFAULT false,
    ADD COLUMN reachability      text NOT NULL DEFAULT 'unknown' CHECK (reachability IN ('reachable', 'not_reachable', 'unknown')),
    ADD COLUMN risk_score        numeric(5,2) CHECK (risk_score BETWEEN 0 AND 100),
    ADD COLUMN risk_factors      jsonb,
    ADD COLUMN risk_scored_at    timestamptz,
    -- Set by triggers whenever an input of the risk score changes; the
    -- jobs role recomputes dirty findings in batches.
    ADD COLUMN risk_dirty        boolean NOT NULL DEFAULT true;
-- Existing findings get the same category-based confidence new results get
-- at ingest (scans/normalize: confidenceOf); later scans refine it.
UPDATE findings SET confidence = CASE category
    WHEN 'sca' THEN 'high' WHEN 'container' THEN 'high' WHEN 'iac' THEN 'high' WHEN 'license' THEN 'high'
    WHEN 'secrets' THEN 'medium' WHEN 'sast' THEN 'medium' ELSE 'unknown' END;
CREATE INDEX findings_risk_idx ON findings (organization_id, risk_score DESC NULLS LAST) WHERE status IN ('open', 'in_progress', 'needs_review');
CREATE INDEX findings_risk_dirty_idx ON findings (organization_id) WHERE risk_dirty;
CREATE INDEX findings_cve_idx ON findings (cve) WHERE cve <> '';
CREATE INDEX findings_kev_idx ON findings (organization_id) WHERE kev;

-- +goose StatementBegin
CREATE FUNCTION pathos_finding_risk_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.risk_score IS DISTINCT FROM OLD.risk_score OR NEW.risk_scored_at IS DISTINCT FROM OLD.risk_scored_at THEN
        RETURN NEW; -- the risk engine writing its result
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status OR NEW.severity IS DISTINCT FROM OLD.severity OR NEW.cvss IS DISTINCT FROM OLD.cvss
       OR NEW.cvss_vector IS DISTINCT FROM OLD.cvss_vector OR NEW.cve IS DISTINCT FROM OLD.cve OR NEW.confidence IS DISTINCT FROM OLD.confidence
       OR NEW.reachability IS DISTINCT FROM OLD.reachability OR NEW.fixed_version IS DISTINCT FROM OLD.fixed_version
       OR NEW.human_disposition IS DISTINCT FROM OLD.human_disposition OR NEW.human_severity IS DISTINCT FROM OLD.human_severity
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id THEN
        NEW.risk_dirty := true;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER findings_risk_dirty BEFORE UPDATE ON findings FOR EACH ROW EXECUTE FUNCTION pathos_finding_risk_dirty();

-- Context changes on repositories and applications re-score their findings.
-- +goose StatementBegin
CREATE FUNCTION pathos_repository_risk_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.criticality IS DISTINCT FROM OLD.criticality OR NEW.public_exposure IS DISTINCT FROM OLD.public_exposure
       OR NEW.environment IS DISTINCT FROM OLD.environment OR NEW.application_id IS DISTINCT FROM OLD.application_id THEN
        UPDATE findings SET risk_dirty = true WHERE repository_id = NEW.id AND NOT risk_dirty;
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER repositories_risk_dirty AFTER UPDATE ON repositories FOR EACH ROW EXECUTE FUNCTION pathos_repository_risk_dirty();

-- +goose StatementBegin
CREATE FUNCTION pathos_application_risk_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.criticality IS DISTINCT FROM OLD.criticality THEN
        UPDATE findings f SET risk_dirty = true FROM repositories r
        WHERE r.application_id = NEW.id AND f.repository_id = r.id AND NOT f.risk_dirty;
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER applications_risk_dirty AFTER UPDATE ON applications FOR EACH ROW EXECUTE FUNCTION pathos_application_risk_dirty();

-- ---------------------------------------------------------------------------
-- Vulnerability intelligence (reference data shared by all organizations)
-- ---------------------------------------------------------------------------

CREATE TABLE intel_epss (
    cve_id     text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    score      numeric(6,5) NOT NULL CHECK (score BETWEEN 0 AND 1),
    percentile numeric(6,5) NOT NULL CHECK (percentile BETWEEN 0 AND 1),
    as_of      date NOT NULL
);

CREATE TABLE intel_kev (
    cve_id            text PRIMARY KEY CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'),
    vendor            text NOT NULL DEFAULT '',
    product           text NOT NULL DEFAULT '',
    name              text NOT NULL DEFAULT '',
    description       text NOT NULL DEFAULT '',
    required_action   text NOT NULL DEFAULT '',
    added_on          date,
    due_date          date,
    known_ransomware  text NOT NULL DEFAULT '',
    catalog_version   text NOT NULL DEFAULT ''
);

-- Feed configuration: online download daily (default) and/or offline file
-- import. URLs can be changed (mirrors in restricted networks).
CREATE TABLE intel_feeds (
    feed            text PRIMARY KEY CHECK (feed IN ('epss', 'kev')),
    enabled         boolean NOT NULL DEFAULT true,
    url             text NOT NULL CHECK (url ~ '^https://' AND length(url) <= 500),
    interval_hours  int NOT NULL DEFAULT 24 CHECK (interval_hours BETWEEN 1 AND 720),
    updated_by      uuid,
    updated_at      timestamptz NOT NULL DEFAULT now()
);
INSERT INTO intel_feeds (feed, url) VALUES
    ('epss', 'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz'),
    ('kev', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json');

CREATE TABLE intel_feed_runs (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    feed         text NOT NULL REFERENCES intel_feeds(feed),
    mode         text NOT NULL CHECK (mode IN ('online', 'file')),
    status       text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'succeeded', 'failed')),
    records      int NOT NULL DEFAULT 0,
    as_of        text NOT NULL DEFAULT '',
    sha256       text NOT NULL DEFAULT '',
    error        text NOT NULL DEFAULT '',
    triggered_by uuid,
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz
);
CREATE INDEX intel_feed_runs_idx ON intel_feed_runs (feed, started_at DESC);

-- ---------------------------------------------------------------------------
-- Risk models (versioned per organization; findings record the version)
-- ---------------------------------------------------------------------------

CREATE TABLE risk_models (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    version         int NOT NULL CHECK (version > 0),
    weights         jsonb NOT NULL CHECK (jsonb_typeof(weights) = 'object' AND pg_column_size(weights) <= 16384),
    change_note     text NOT NULL DEFAULT '' CHECK (length(change_note) <= 2000),
    created_by      uuid,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (organization_id, version)
);

-- ---------------------------------------------------------------------------
-- Applications: permanent ID, technical owner, lifecycle, environment
-- ---------------------------------------------------------------------------

CREATE SEQUENCE application_key_seq AS bigint START 1;
ALTER TABLE applications
    ADD COLUMN application_key         text,
    ADD COLUMN technical_owner_user_id uuid,
    ADD COLUMN lifecycle               text NOT NULL DEFAULT 'active'
        CHECK (lifecycle IN ('planned', 'development', 'active', 'maintenance', 'deprecated', 'retired')),
    ADD COLUMN environment             text NOT NULL DEFAULT 'production'
        CHECK (environment IN ('production', 'staging', 'development', 'test', 'other'));
ALTER TABLE applications ADD CONSTRAINT applications_technical_owner_fk
    FOREIGN KEY (organization_id, technical_owner_user_id) REFERENCES users(organization_id, id);
WITH ordered AS (SELECT id, row_number() OVER (ORDER BY created_at, id) AS n FROM applications)
UPDATE applications a SET application_key = 'QD-APP-' || lpad(o.n::text, greatest(6, length(o.n::text)), '0') FROM ordered o WHERE o.id = a.id;
SELECT setval('application_key_seq', GREATEST((SELECT count(*) FROM applications), 1), (SELECT count(*) FROM applications) > 0);
ALTER TABLE applications ALTER COLUMN application_key SET NOT NULL;
CREATE UNIQUE INDEX applications_key_uq ON applications (application_key);

-- +goose StatementBegin
CREATE FUNCTION pathos_assign_application_key() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE
    n bigint;
BEGIN
    n := nextval('application_key_seq');
    NEW.application_key := 'QD-APP-' || lpad(n::text, greatest(6, length(n::text)), '0');
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER applications_assign_key BEFORE INSERT ON applications FOR EACH ROW EXECUTE FUNCTION pathos_assign_application_key();

-- +goose StatementBegin
CREATE FUNCTION pathos_protect_application_key() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.application_key IS DISTINCT FROM OLD.application_key THEN
        RAISE EXCEPTION 'application_key is permanent and cannot be changed' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER applications_protect_key BEFORE UPDATE OF application_key ON applications FOR EACH ROW EXECUTE FUNCTION pathos_protect_application_key();

SELECT pathos_apply_app_grants();

-- +goose Down
DROP TRIGGER IF EXISTS applications_protect_key ON applications;
DROP FUNCTION IF EXISTS pathos_protect_application_key();
DROP TRIGGER IF EXISTS applications_assign_key ON applications;
DROP FUNCTION IF EXISTS pathos_assign_application_key();
DROP INDEX IF EXISTS applications_key_uq;
ALTER TABLE applications DROP CONSTRAINT IF EXISTS applications_technical_owner_fk;
ALTER TABLE applications DROP COLUMN IF EXISTS environment, DROP COLUMN IF EXISTS lifecycle,
    DROP COLUMN IF EXISTS technical_owner_user_id, DROP COLUMN IF EXISTS application_key;
DROP SEQUENCE IF EXISTS application_key_seq;
DROP TABLE IF EXISTS risk_models;
DROP TABLE IF EXISTS intel_feed_runs;
DROP TABLE IF EXISTS intel_feeds;
DROP TABLE IF EXISTS intel_kev;
DROP TABLE IF EXISTS intel_epss;
DROP TRIGGER IF EXISTS applications_risk_dirty ON applications;
DROP FUNCTION IF EXISTS pathos_application_risk_dirty();
DROP TRIGGER IF EXISTS repositories_risk_dirty ON repositories;
DROP FUNCTION IF EXISTS pathos_repository_risk_dirty();
DROP TRIGGER IF EXISTS findings_risk_dirty ON findings;
DROP FUNCTION IF EXISTS pathos_finding_risk_dirty();
DROP INDEX IF EXISTS findings_kev_idx;
DROP INDEX IF EXISTS findings_cve_idx;
DROP INDEX IF EXISTS findings_risk_dirty_idx;
DROP INDEX IF EXISTS findings_risk_idx;
ALTER TABLE findings DROP COLUMN IF EXISTS risk_dirty, DROP COLUMN IF EXISTS risk_scored_at, DROP COLUMN IF EXISTS risk_factors,
    DROP COLUMN IF EXISTS risk_score, DROP COLUMN IF EXISTS reachability, DROP COLUMN IF EXISTS exploit_available,
    DROP COLUMN IF EXISTS kev_due_date, DROP COLUMN IF EXISTS kev, DROP COLUMN IF EXISTS epss_percentile,
    DROP COLUMN IF EXISTS epss_score, DROP COLUMN IF EXISTS confidence, DROP COLUMN IF EXISTS cvss_vector,
    DROP COLUMN IF EXISTS cvss_version;
