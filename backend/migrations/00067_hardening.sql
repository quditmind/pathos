-- +goose Up
-- 2.2.2 hardening (docs/VALIDATION_REPORT.md §9), brought forward into 3.0:
-- anonymous public repositories (O1), private CAs for outbound connections
-- (O3) and default secret exclusions (O6). In 2.2.x this was migration
-- 00044; the 3.0 line had already used 00044 (connectors), so it is 00067
-- here. Every statement is idempotent: an install upgraded from 2.2.x
-- already has these objects (internal/platform/db reconciles the goose
-- version table first, see reconcile22.go), a fresh install gets them here.
--
-- O1: anonymous import of PUBLIC repositories by URL. source_type 'git'
-- marks a repository registered without an SCM connection or credential
-- (GitHub, GitLab.com, Bitbucket Cloud, Azure DevOps public projects, or
-- any HTTPS git URL). source_provider records which one. Workers clone
-- these anonymously; private repositories are refused at import time.
-- A 3.0 "Generic Git" repository is different: it belongs to an SCM
-- connection (source_type 'scm', provider generic_git) with a credential.
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_source_type_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_source_type_check CHECK (source_type IN ('scm', 'upload', 'git'));
ALTER TABLE repositories ADD COLUMN IF NOT EXISTS source_provider text NOT NULL DEFAULT ''
    CHECK (source_provider IN ('', 'github', 'gitlab', 'bitbucket', 'azure_devops', 'git'));
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_git_source_ck;
ALTER TABLE repositories ADD CONSTRAINT repositories_git_source_ck CHECK ((source_type = 'git') = (source_provider <> ''));
CREATE UNIQUE INDEX IF NOT EXISTS repositories_git_url_uq ON repositories (organization_id, lower(clone_url))
    WHERE source_type = 'git' AND archived_at IS NULL;

-- O3: private certificate authority per connection for registry
-- connections, outbound webhooks (Slack, Teams, JSON) and ticket
-- connections (Jira, ServiceNow). The PEM bundle is ADDED to the system
-- trust store for that connection only; verification is never disabled and
-- TLS 1.2 is the minimum (backend/internal/scm/tlsca.go, the same approach
-- as the 3.0 SCM connections of migration 00045). CA certificates are
-- public, so they are stored as configuration that administrators can read
-- back.
ALTER TABLE registry_connections ADD COLUMN IF NOT EXISTS ca_bundle_pem text NOT NULL DEFAULT '' CHECK (length(ca_bundle_pem) <= 65536);
ALTER TABLE outbound_webhooks ADD COLUMN IF NOT EXISTS ca_bundle_pem text NOT NULL DEFAULT '' CHECK (length(ca_bundle_pem) <= 65536);
ALTER TABLE ticket_connections ADD COLUMN IF NOT EXISTS ca_bundle_pem text NOT NULL DEFAULT '' CHECK (length(ca_bundle_pem) <= 65536);

-- O6: default secret exclusions per profile version. Secret findings in
-- vendored dependencies, test fixtures, lockfiles and minified files
-- (scanners.DefaultSecretExclusions) are dropped unless a profile turns
-- the defaults off; secret_exclusions adds patterns of its own.
ALTER TABLE scan_profile_versions
    ADD COLUMN IF NOT EXISTS secret_default_exclusions boolean NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS secret_exclusions text[] NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE scan_profile_versions DROP COLUMN IF EXISTS secret_exclusions, DROP COLUMN IF EXISTS secret_default_exclusions;
ALTER TABLE ticket_connections DROP COLUMN IF EXISTS ca_bundle_pem;
ALTER TABLE outbound_webhooks DROP COLUMN IF EXISTS ca_bundle_pem;
ALTER TABLE registry_connections DROP COLUMN IF EXISTS ca_bundle_pem;
-- Anonymous repositories cannot exist before 00067; like the downgrade of
-- 00009 for uploads, they are removed with their data.
DELETE FROM repositories WHERE source_type = 'git';
DROP INDEX IF EXISTS repositories_git_url_uq;
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_git_source_ck;
ALTER TABLE repositories DROP COLUMN IF EXISTS source_provider;
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_source_type_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_source_type_check CHECK (source_type IN ('scm', 'upload'));
