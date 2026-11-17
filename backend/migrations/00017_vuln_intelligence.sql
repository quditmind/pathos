-- +goose Up
-- ASPM phase 4: vulnerability intelligence.

-- OSV vulnerability records (description, aliases, references, vendor
-- CVSS, CWEs, affected packages). found = false remembers identifiers OSV
-- does not know, so they are not asked again before the refresh period.
CREATE TABLE intel_vulns (
    id           text PRIMARY KEY CHECK (length(id) BETWEEN 3 AND 101),
    aliases      text[] NOT NULL DEFAULT '{}',
    summary      text NOT NULL DEFAULT '' CHECK (length(summary) <= 1000),
    details      text NOT NULL DEFAULT '' CHECK (length(details) <= 20000),
    published    timestamptz,
    modified     timestamptz,
    withdrawn    timestamptz,
    cvss_vectors text[] NOT NULL DEFAULT '{}',
    cwes         text[] NOT NULL DEFAULT '{}',
    refs         jsonb NOT NULL DEFAULT '[]'::jsonb,
    exploit_refs integer NOT NULL DEFAULT 0,
    affected     jsonb NOT NULL DEFAULT '[]'::jsonb,
    source       text NOT NULL CHECK (source IN ('osv-online', 'osv-file')),
    found        boolean NOT NULL DEFAULT true,
    fetched_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX intel_vulns_aliases_idx ON intel_vulns USING gin (aliases);

ALTER TABLE intel_feeds DROP CONSTRAINT intel_feeds_feed_check;
ALTER TABLE intel_feeds ADD CONSTRAINT intel_feeds_feed_check CHECK (feed IN ('epss', 'kev', 'osv'));
INSERT INTO intel_feeds (feed, url) VALUES ('osv', 'https://api.osv.dev/v1/vulns/') ON CONFLICT DO NOTHING;

-- Code inventory for dependency reachability: the packages each
-- repository's code imports (kind import) or names in string literals
-- (kind string), per ecosystem, from its latest scan.
CREATE TABLE repository_code_imports (
    organization_id uuid NOT NULL,
    repository_id   uuid NOT NULL,
    ecosystem       text NOT NULL CHECK (ecosystem IN ('npm', 'pypi', 'go')),
    kind            text NOT NULL CHECK (kind IN ('import', 'string')),
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 214),
    PRIMARY KEY (repository_id, ecosystem, kind, name),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);
ALTER TABLE repositories ADD COLUMN imports_scanned_at timestamptz, ADD COLUMN imports_files integer NOT NULL DEFAULT 0;
ALTER TABLE findings ADD COLUMN reachability_basis text NOT NULL DEFAULT '' CHECK (length(reachability_basis) <= 500);

-- Suppression rules: governed, expiring decisions for every finding that
-- matches a pattern. Effective only when a different person approves.
CREATE TABLE suppression_rules (
    id              uuid PRIMARY KEY,
    organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name            text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
    scope_type      text NOT NULL CHECK (scope_type IN ('organization', 'application', 'repository')),
    scope_id        uuid,
    match_rule_id   text NOT NULL DEFAULT '' CHECK (length(match_rule_id) <= 300),
    match_path      text NOT NULL DEFAULT '' CHECK (length(match_path) <= 300),
    match_package   text NOT NULL DEFAULT '' CHECK (length(match_package) <= 300),
    match_cve       text NOT NULL DEFAULT '' CHECK (length(match_cve) <= 300),
    match_scanner   text NOT NULL DEFAULT '' CHECK (length(match_scanner) <= 300),
    match_category  text NOT NULL DEFAULT '' CHECK (length(match_category) <= 300),
    decision        text NOT NULL CHECK (decision IN ('accepted_risk', 'false_positive')),
    justification   text NOT NULL CHECK (length(justification) BETWEEN 20 AND 4000),
    expires_at      timestamptz NOT NULL,
    status          text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'rejected', 'revoked', 'expired', 'withdrawn')),
    requested_by    uuid NOT NULL,
    requested_at    timestamptz NOT NULL DEFAULT now(),
    decided_by      uuid,
    decided_at      timestamptz,
    decision_note   text NOT NULL DEFAULT '' CHECK (length(decision_note) <= 2000),
    UNIQUE (organization_id, id),
    CHECK (scope_type = 'organization' OR scope_id IS NOT NULL),
    CHECK (match_rule_id <> '' OR match_path <> '' OR match_package <> '' OR match_cve <> ''),
    -- four eyes: the approver is never the requester
    CHECK (status <> 'active' OR decided_by IS DISTINCT FROM requested_by)
);
CREATE INDEX suppression_rules_active_idx ON suppression_rules (organization_id) WHERE status = 'active';
ALTER TABLE findings ADD COLUMN suppression_rule_id uuid;
ALTER TABLE findings ADD CONSTRAINT findings_suppression_rule_fk FOREIGN KEY (organization_id, suppression_rule_id)
    REFERENCES suppression_rules(organization_id, id);
CREATE INDEX findings_suppression_idx ON findings (suppression_rule_id) WHERE suppression_rule_id IS NOT NULL;

SELECT pathos_apply_app_grants();

-- +goose Down
UPDATE findings SET status = 'open', suppression_rule_id = NULL WHERE suppression_rule_id IS NOT NULL AND status IN ('accepted_risk', 'false_positive');
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_suppression_rule_fk;
ALTER TABLE findings DROP COLUMN IF EXISTS suppression_rule_id;
DROP TABLE IF EXISTS suppression_rules;
ALTER TABLE findings DROP COLUMN IF EXISTS reachability_basis;
ALTER TABLE repositories DROP COLUMN IF EXISTS imports_files, DROP COLUMN IF EXISTS imports_scanned_at;
DROP TABLE IF EXISTS repository_code_imports;
DELETE FROM intel_feed_runs WHERE feed = 'osv';
DELETE FROM intel_feeds WHERE feed = 'osv';
ALTER TABLE intel_feeds DROP CONSTRAINT intel_feeds_feed_check;
ALTER TABLE intel_feeds ADD CONSTRAINT intel_feeds_feed_check CHECK (feed IN ('epss', 'kev'));
DROP TABLE IF EXISTS intel_vulns;
