package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
)

// Policy is a stored security policy.
type Policy struct {
	ID         uuid.UUID
	Name       string
	Version    int
	Conditions Conditions
	Actions    Actions
}

// enabledPolicies returns the enabled policies that act on findings by
// themselves. Policies managed by a repository's pull request settings
// (managed_by, PATHOS 3.0 M8) act only through their security gate.
func enabledPolicies(ctx context.Context, q db.Querier, orgID uuid.UUID) ([]Policy, error) {
	rows, err := q.Query(ctx, `SELECT id, name, version, conditions, actions FROM security_policies
		WHERE organization_id = $1 AND enabled AND managed_by = '' ORDER BY created_at`, orgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Policy, error) {
		var p Policy
		var c, a []byte
		if err := r.Scan(&p.ID, &p.Name, &p.Version, &c, &a); err != nil {
			return p, err
		}
		if err := json.Unmarshal(c, &p.Conditions); err != nil {
			return p, err
		}
		return p, json.Unmarshal(a, &p.Actions)
	})
}

// openStatuses are the finding statuses policies apply to.
const openStatuses = `('open', 'in_progress', 'needs_review')`

// Evaluate refreshes policy violations of an organization (or of one
// repository) and applies the SLA and notification actions. Safe to run
// repeatedly; returns the number of open violations.
func Evaluate(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, repoID *uuid.UUID) (int, error) {
	pols, err := enabledPolicies(ctx, tx, orgID)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, p := range pols {
		args := []any{orgID, p.ID, repoID}
		where, err := Where(p.Conditions, FindingColumns, &args)
		if err != nil {
			return total, fmt.Errorf("policy %q: %w", p.Name, err)
		}
		// Matching open findings → violations (re-opened when they match
		// again); violations whose finding no longer matches are resolved.
		var n int
		if err := tx.QueryRow(ctx, `
			WITH m AS (
			  SELECT f.id, f.repository_id FROM findings f JOIN repositories r ON r.id = f.repository_id
			  WHERE f.organization_id = $1 AND f.status IN `+openStatuses+` AND r.archived_at IS NULL
			    AND ($3::uuid IS NULL OR f.repository_id = $3) AND `+where+`),
			up AS (
			  INSERT INTO policy_violations (policy_id, finding_id, organization_id, repository_id)
			  SELECT $2, id, $1, repository_id FROM m
			  ON CONFLICT (policy_id, finding_id) DO UPDATE SET last_matched_at = now(), resolved_at = NULL,
			    notified_at = CASE WHEN policy_violations.resolved_at IS NOT NULL THEN NULL ELSE policy_violations.notified_at END
			  RETURNING 1),
			res AS (
			  UPDATE policy_violations v SET resolved_at = now()
			  WHERE v.policy_id = $2 AND v.resolved_at IS NULL AND ($3::uuid IS NULL OR v.repository_id = $3)
			    AND NOT EXISTS (SELECT 1 FROM m WHERE m.id = v.finding_id)
			  RETURNING 1)
			-- Data-modifying CTEs always run to completion, read or not.
			SELECT count(*)::int FROM up`, args...).Scan(&n); err != nil {
			return total, fmt.Errorf("policy %q: %w", p.Name, err)
		}
		total += n
		if d := p.Actions.SLADays; d != nil {
			if _, err := tx.Exec(ctx, `UPDATE findings f SET sla_due_at = f.first_seen_at + make_interval(days => $3), updated_at = now()
				FROM policy_violations v
				WHERE v.policy_id = $1 AND v.finding_id = f.id AND v.resolved_at IS NULL AND ($2::uuid IS NULL OR v.repository_id = $2)
				  AND (f.sla_due_at IS NULL OR f.sla_due_at > f.first_seen_at + make_interval(days => $3))`, p.ID, repoID, *d); err != nil {
				return total, err
			}
		}
		if p.Actions.Notify {
			if _, err := tx.Exec(ctx, `
				WITH v AS (
				  UPDATE policy_violations v SET notified_at = now()
				  WHERE v.policy_id = $1 AND v.resolved_at IS NULL AND v.notified_at IS NULL AND ($2::uuid IS NULL OR v.repository_id = $2)
				  RETURNING v.finding_id, v.repository_id, v.organization_id)
				INSERT INTO notification_events (organization_id, event_key, repository_id, severity, payload)
				SELECT v.organization_id, 'policy.violated', v.repository_id,
				       (array_agg(f.severity ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity)))[1],
				       jsonb_build_object('finding_ids', jsonb_agg(v.finding_id), 'count', count(*), 'policy_id', $1::uuid, 'policy_name', $3::text)
				FROM v JOIN findings f ON f.id = v.finding_id GROUP BY v.organization_id, v.repository_id`, p.ID, repoID, p.Name); err != nil {
				return total, err
			}
		} else {
			// Only new violations are notified once notification is enabled.
			if _, err := tx.Exec(ctx, `UPDATE policy_violations SET notified_at = now()
				WHERE policy_id = $1 AND notified_at IS NULL AND resolved_at IS NULL`, p.ID); err != nil {
				return total, err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE security_policies SET evaluated_at = now() WHERE id = $1`, p.ID); err != nil {
			return total, err
		}
	}
	return total, nil
}

// Blocking returns the names of blocking policies that findings first
// detected by a scan execution violate (the execution's gate fails).
func Blocking(ctx context.Context, tx pgx.Tx, jobID uuid.UUID) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT p.name FROM policy_violations v
		JOIN security_policies p ON p.id = v.policy_id AND p.enabled AND p.managed_by = '' AND (p.actions->>'block')::boolean
		JOIN findings f ON f.id = v.finding_id
		WHERE f.first_scan_job_id = $1 AND v.resolved_at IS NULL ORDER BY 1`, jobID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// EvaluatePR records which policies the new findings of a pull request
// check violate and returns the names of violated blocking policies.
// Policies with branch-only conditions (risk, reachability, age, exploit
// availability) do not apply to pull requests.
func EvaluatePR(ctx context.Context, tx pgx.Tx, orgID, checkID uuid.UUID) ([]string, error) {
	hits, err := EvaluatePRPolicies(ctx, tx, orgID, checkID)
	var names []string
	for _, h := range hits {
		names = append(names, h.Name)
	}
	return names, err
}

// PolicyHit is a blocking policy that findings violate.
type PolicyHit struct {
	ID      uuid.UUID
	Name    string
	Version int
}

// EvaluatePRPolicies is EvaluatePR returning the violated blocking
// policies with their ids and versions (gate decisions record them).
func EvaluatePRPolicies(ctx context.Context, tx pgx.Tx, orgID, checkID uuid.UUID) ([]PolicyHit, error) {
	pols, err := enabledPolicies(ctx, tx, orgID)
	if err != nil {
		return nil, err
	}
	var blocking []PolicyHit
	for _, p := range pols {
		if p.Conditions.BranchOnly() {
			continue
		}
		args := []any{checkID, p.ID}
		where, err := Where(p.Conditions, PRColumns, &args)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", p.Name, err)
		}
		tag, err := tx.Exec(ctx, `UPDATE pr_findings pf SET policy_ids = array_append(pf.policy_ids, $2)
			FROM pr_checks c JOIN repositories r ON r.id = c.repository_id
			WHERE pf.pr_check_id = c.id AND c.id = $1 AND pf.is_new AND NOT ($2 = ANY(pf.policy_ids)) AND `+where, args...)
		if err != nil {
			return nil, fmt.Errorf("policy %q: %w", p.Name, err)
		}
		if tag.RowsAffected() > 0 && p.Actions.Block {
			blocking = append(blocking, PolicyHit{ID: p.ID, Name: p.Name, Version: p.Version})
		}
	}
	return blocking, nil
}

// RestoreSLA recomputes, from the SLA policies alone, the deadlines of the
// findings that a policy tightened (open violations). Run Evaluate after it
// so that the remaining policies tighten them again where they apply.
func RestoreSLA(ctx context.Context, tx pgx.Tx, policyID uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE findings f SET updated_at = now(),
		  sla_due_at = (SELECT CASE WHEN p.days IS NULL THEN NULL ELSE f.first_seen_at + make_interval(days => p.days) END
		                FROM sla_policies p WHERE p.organization_id = f.organization_id AND p.severity = f.severity)
		FROM policy_violations v WHERE v.policy_id = $1 AND v.finding_id = f.id AND v.resolved_at IS NULL`, policyID)
	return err
}

// BlockingPolicies is Blocking with the policies' ids and versions (gate
// decisions record them).
func BlockingPolicies(ctx context.Context, tx pgx.Tx, jobID uuid.UUID) ([]PolicyHit, error) {
	rows, err := tx.Query(ctx, `SELECT DISTINCT p.id, p.name, p.version FROM policy_violations v
		JOIN security_policies p ON p.id = v.policy_id AND p.enabled AND p.managed_by = '' AND (p.actions->>'block')::boolean
		JOIN findings f ON f.id = v.finding_id
		WHERE f.first_scan_job_id = $1 AND v.resolved_at IS NULL ORDER BY 2`, jobID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (PolicyHit, error) {
		var h PolicyHit
		return h, r.Scan(&h.ID, &h.Name, &h.Version)
	})
}
