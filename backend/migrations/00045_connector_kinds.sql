-- +goose Up
-- PATHOS 3.0, M2 (new connector kinds; docs/aspm/PATHOS_INTEGRATION_TECHNICAL_SPEC.md).
--
-- 1. Per-connection private CA bundle for SCM connections (GitHub Enterprise
--    Server, GitLab self-managed, Bitbucket Data Center, Generic Git). PEM
--    certificates are public: stored as configuration, not as a secret, so
--    administrators can read back what is trusted (backend/internal/scm/tlsca.go).
-- 2. Generic Git (provider generic_git; auth api_token = HTTPS user name +
--    token, ssh_key = SSH deploy key). The base URL is the repository URL and
--    may be ssh://. The pinned SSH host key (known_hosts) is configuration.
-- 3. Bitbucket Data Center (provider bitbucket_data_center; auth pat = project or
--    repository HTTP access token, api_token = user token + user name).
-- No new table: scm_connections keeps its tenant policy (docs/MULTI_TENANCY.md).
ALTER TABLE scm_connections
    ADD COLUMN ca_bundle_pem   text NOT NULL DEFAULT '' CHECK (length(ca_bundle_pem) <= 65536),
    ADD COLUMN ssh_known_hosts text NOT NULL DEFAULT '' CHECK (length(ssh_known_hosts) <= 16384);

ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_provider_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_provider_check
    CHECK (provider IN ('github', 'github_enterprise', 'gitlab', 'bitbucket', 'azure_devops', 'azure_devops_server',
                        'bitbucket_data_center', 'generic_git'));
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_auth_type_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_auth_type_check
    CHECK (auth_type IN ('pat', 'github_app', 'oauth', 'api_token', 'service_principal', 'ssh_key'));
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_auth_provider_ck;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_auth_provider_ck CHECK (
    (auth_type <> 'api_token' OR provider IN ('bitbucket', 'bitbucket_data_center', 'generic_git')) AND
    (auth_type <> 'service_principal' OR provider = 'azure_devops') AND
    (auth_type <> 'ssh_key' OR provider = 'generic_git') AND
    (provider <> 'generic_git' OR auth_type IN ('api_token', 'ssh_key')) AND
    (auth_type <> 'ssh_key' OR ssh_known_hosts <> ''));
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_base_url_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_base_url_check
    CHECK (base_url ~ '^https?://' OR (provider = 'generic_git' AND base_url ~ '^ssh://'));

SELECT pathos_apply_app_grants();

-- +goose Down
DELETE FROM scm_connections WHERE provider IN ('bitbucket_data_center', 'generic_git');
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_base_url_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_base_url_check CHECK (base_url ~ '^https?://');
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_auth_provider_ck;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_auth_provider_ck CHECK (
    (auth_type <> 'api_token' OR provider = 'bitbucket') AND
    (auth_type <> 'service_principal' OR provider = 'azure_devops'));
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_auth_type_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_auth_type_check
    CHECK (auth_type IN ('pat', 'github_app', 'oauth', 'api_token', 'service_principal'));
ALTER TABLE scm_connections DROP CONSTRAINT scm_connections_provider_check;
ALTER TABLE scm_connections ADD CONSTRAINT scm_connections_provider_check
    CHECK (provider IN ('github', 'github_enterprise', 'gitlab', 'bitbucket', 'azure_devops', 'azure_devops_server'));
ALTER TABLE scm_connections DROP COLUMN ssh_known_hosts, DROP COLUMN ca_bundle_pem;
