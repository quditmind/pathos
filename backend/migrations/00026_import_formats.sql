-- +goose Up
-- PATHOS 1.1: native result import formats (Semgrep, Snyk, SonarQube, ZAP,
-- Burp, Trivy, Gitleaks, TruffleHog, Checkov, Bandit, Gosec, ESLint, npm
-- audit, pip-audit, OSV-Scanner, Nessus, OpenVAS, Nuclei, Dependency-Check,
-- Checkmarx, generic CSV). The format list lives in code
-- (scanners.ImportFormats); the column only bounds the identifier.
-- "unknown" records failed imports whose format could not be determined.
ALTER TABLE import_jobs DROP CONSTRAINT IF EXISTS import_jobs_format_check;
ALTER TABLE import_jobs ADD CONSTRAINT import_jobs_format_check
    CHECK (format ~ '^[a-z0-9][a-z0-9-]{0,39}$');

-- +goose Down
-- Rows written with the new formats stay; the original constraint is
-- restored for new rows only (NOT VALID), so the rollback never deletes
-- import history.
ALTER TABLE import_jobs DROP CONSTRAINT IF EXISTS import_jobs_format_check;
ALTER TABLE import_jobs ADD CONSTRAINT import_jobs_format_check
    CHECK (format IN ('sarif', 'grype', 'pathos', 'cyclonedx', 'spdx')) NOT VALID;
