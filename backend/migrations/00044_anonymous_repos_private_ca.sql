-- +goose Up
-- 2.2.2 hardening (docs/VALIDATION_REPORT.md §9): anonymous public
-- repositories (O1) and private CAs for outbound connections (O3).
--
-- O1: anonymous import of PUBLIC repositories by URL. source_type 'git'
-- marks a repository registered without an SCM connection or credential
-- (GitHub, GitLab.com, Bitbucket Cloud, Azure DevOps public projects, or
-- any HTTPS git URL). source_provider records which one. Workers clone
-- these anonymously; private repositories are refused at import time.
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_source_type_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_source_type_check CHECK (source_type IN ('scm', 'upload', 'git'));
ALTER TABLE repositories ADD COLUMN source_provider text NOT NULL DEFAULT ''
    CHECK (source_provider IN ('', 'github', 'gitlab', 'bitbucket', 'azure_devops', 'git'));
ALTER TABLE repositories ADD CONSTRAINT repositories_git_source_ck CHECK ((source_type = 'git') = (source_provider <> ''));
CREATE UNIQUE INDEX repositories_git_url_uq ON repositories (organization_id, lower(clone_url))
    WHERE source_type = 'git' AND archived_at IS NULL;

-- O3: private certificate authority per connection for registry
-- connections, outbound webhooks (Slack, Teams, JSON) and ticket
-- connections (Jira, ServiceNow). The PEM bundle is ADDED to the system
-- trust store for that connection only; verification is never disabled and
-- TLS 1.2 is the minimum (backend/internal/scm/tlsca.go, the same approach
-- as the 3.0 SCM connections). CA certificates are public, so they are
-- stored as configuration that administrators can read back.
ALTER TABLE registry_connections ADD COLUMN ca_bundle_pem text NOT NULL DEFAULT '' CHECK (length(ca_bundle_pem) <= 65536);
ALTER TABLE outbound_webhooks ADD COLUMN ca_bundle_pem text NOT NULL DEFAULT '' CHECK (length(ca_bundle_pem) <= 65536);
ALTER TABLE ticket_connections ADD COLUMN ca_bundle_pem text NOT NULL DEFAULT '' CHECK (length(ca_bundle_pem) <= 65536);

-- +goose Down
ALTER TABLE ticket_connections DROP COLUMN IF EXISTS ca_bundle_pem;
ALTER TABLE outbound_webhooks DROP COLUMN IF EXISTS ca_bundle_pem;
ALTER TABLE registry_connections DROP COLUMN IF EXISTS ca_bundle_pem;
DROP INDEX IF EXISTS repositories_git_url_uq;
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_git_source_ck;
ALTER TABLE repositories DROP COLUMN IF EXISTS source_provider;
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_source_type_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_source_type_check CHECK (source_type IN ('scm', 'upload'));
