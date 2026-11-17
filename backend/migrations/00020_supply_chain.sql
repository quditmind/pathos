-- +goose Up
-- ASPM phase 7: supply chain.

-- Malicious packages (OSV MAL-*), maintained by the risk engine.
ALTER TABLE findings ADD COLUMN malicious boolean NOT NULL DEFAULT false;
CREATE INDEX findings_malicious_idx ON findings (organization_id) WHERE malicious;
UPDATE findings SET risk_dirty = true WHERE NOT risk_dirty AND category IN ('sca', 'container');

-- Package health from deps.dev, per package (purl without version).
CREATE TABLE package_health (
    purl_base           text PRIMARY KEY CHECK (length(purl_base) <= 600),
    system              text NOT NULL,
    name                text NOT NULL,
    found               boolean NOT NULL DEFAULT true,
    latest_version      text NOT NULL DEFAULT '',
    latest_published_at timestamptz,
    deprecated_versions text[] NOT NULL DEFAULT '{}',
    scorecard           numeric(4,1),
    scorecard_project   text NOT NULL DEFAULT '',
    fetched_at          timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE intel_feeds DROP CONSTRAINT intel_feeds_feed_check;
ALTER TABLE intel_feeds ADD CONSTRAINT intel_feeds_feed_check CHECK (feed IN ('epss', 'kev', 'osv', 'depsdev'));
INSERT INTO intel_feeds (feed, url) VALUES ('depsdev', 'https://api.deps.dev/v3/') ON CONFLICT DO NOTHING;

SELECT pathos_apply_app_grants();

-- +goose Down
DELETE FROM intel_feed_runs WHERE feed = 'depsdev';
DELETE FROM intel_feeds WHERE feed = 'depsdev';
ALTER TABLE intel_feeds DROP CONSTRAINT intel_feeds_feed_check;
ALTER TABLE intel_feeds ADD CONSTRAINT intel_feeds_feed_check CHECK (feed IN ('epss', 'kev', 'osv'));
DROP TABLE IF EXISTS package_health;
DROP INDEX IF EXISTS findings_malicious_idx;
ALTER TABLE findings DROP COLUMN IF EXISTS malicious;
