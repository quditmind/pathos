-- +goose Up
-- PATHOS 2.0: function-level reachability of dependency findings. Besides
-- the package-level answer (does the code import the package?), findings
-- record whether the code calls the vulnerable function, how that was
-- decided and the evidence (call paths, the vulnerable symbols checked, the
-- dynamic constructs that made it unknown).

-- How the reachability was decided: '' (no analysis), import (the code
-- inventory: package level), call_graph (govulncheck: the program's call
-- graph, dependencies included) or symbol_calls (pathos-reach: calls to the
-- advisory's vulnerable functions in the repository's own code).
ALTER TABLE findings ADD COLUMN reachability_method text NOT NULL DEFAULT ''
    CHECK (reachability_method IN ('', 'import', 'call_graph', 'symbol_calls'));
-- The evidence of a function-level answer (JSON: tool, scan job, symbols,
-- call paths, dynamic constructs); NULL for package-level answers.
ALTER TABLE findings ADD COLUMN reachability_evidence jsonb
    CHECK (reachability_evidence IS NULL OR (jsonb_typeof(reachability_evidence) = 'object' AND pg_column_size(reachability_evidence) <= 65536));
UPDATE findings SET reachability_method = 'import' WHERE reachability <> 'unknown' AND category = 'sca';

-- The latest reachability reports of a repository's code, one per tool:
-- pathos-reach (uses of external modules in JavaScript/TypeScript, Python
-- and Java, with call sites, caller chains and dynamic constructs) and
-- govulncheck (the depth each Go vulnerability reaches, with its traces).
-- Replaced by every branch scan that runs the tool; the raw reports stay
-- with the scan results as evidence.
CREATE TABLE repository_reach_reports (
    repository_id   uuid NOT NULL,
    organization_id uuid NOT NULL,
    tool            text NOT NULL CHECK (tool IN ('pathos-reach', 'govulncheck')),
    scan_job_id     uuid REFERENCES scan_jobs(id) ON DELETE SET NULL,
    report          jsonb NOT NULL CHECK (jsonb_typeof(report) = 'object'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (repository_id, tool),
    FOREIGN KEY (organization_id, repository_id) REFERENCES repositories(organization_id, id) ON DELETE CASCADE
);

-- A change of method (package level to function level) re-scores the
-- finding as well: the weights differ.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_finding_risk_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.risk_score IS DISTINCT FROM OLD.risk_score OR NEW.risk_scored_at IS DISTINCT FROM OLD.risk_scored_at THEN
        RETURN NEW; -- the risk engine writing its result
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status OR NEW.severity IS DISTINCT FROM OLD.severity OR NEW.cvss IS DISTINCT FROM OLD.cvss
       OR NEW.cvss_vector IS DISTINCT FROM OLD.cvss_vector OR NEW.cve IS DISTINCT FROM OLD.cve OR NEW.confidence IS DISTINCT FROM OLD.confidence
       OR NEW.reachability IS DISTINCT FROM OLD.reachability OR NEW.reachability_method IS DISTINCT FROM OLD.reachability_method
       OR NEW.fixed_version IS DISTINCT FROM OLD.fixed_version
       OR NEW.human_disposition IS DISTINCT FROM OLD.human_disposition OR NEW.human_severity IS DISTINCT FROM OLD.human_severity
       OR NEW.repository_id IS DISTINCT FROM OLD.repository_id THEN
        NEW.risk_dirty := true;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

SELECT pathos_apply_app_grants();

-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION pathos_finding_risk_dirty() RETURNS trigger LANGUAGE plpgsql AS $$
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
DROP TABLE IF EXISTS repository_reach_reports;
ALTER TABLE findings DROP COLUMN IF EXISTS reachability_evidence;
ALTER TABLE findings DROP COLUMN IF EXISTS reachability_method;
