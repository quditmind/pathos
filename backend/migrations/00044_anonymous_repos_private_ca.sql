-- +goose Up
-- 2.2.2 hardening (docs/VALIDATION_REPORT.md §9).
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

-- +goose Down
DROP INDEX IF EXISTS repositories_git_url_uq;
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_git_source_ck;
ALTER TABLE repositories DROP COLUMN IF EXISTS source_provider;
ALTER TABLE repositories DROP CONSTRAINT IF EXISTS repositories_source_type_check;
ALTER TABLE repositories ADD CONSTRAINT repositories_source_type_check CHECK (source_type IN ('scm', 'upload'));
