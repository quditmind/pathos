package gates

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/policy"
)

// Pull request gates of repositories (decision C6). A repository's pull
// request settings are a severity threshold and a mode chosen by a person:
// block or warn. They are kept as an explicit, managed security policy
// ("minimum severity, this repository only") and a managed pull_request
// gate in that mode, so the pull request check decides through the same
// engine as every other gate and never blocks without a policy.

// ErrPRModeRequired: enabling pull request checks needs an explicit choice
// of block or warn (PTH-GATE-1106).
var ErrPRModeRequired = httpx.E(http.StatusUnprocessableEntity, "pr_gate_mode_required",
	"choose whether pull request checks block the pull request or only warn (gate_mode block or warn)").WithDiag("PTH-GATE-1106")

// PRGate is the managed policy and gate of a repository.
type PRGate struct {
	PolicyID *uuid.UUID
	GateID   *uuid.UUID
}

// RepositoryPRGate returns the managed policy and gate of a repository.
func RepositoryPRGate(ctx context.Context, q db.Querier, orgID, repoID uuid.UUID) (PRGate, error) {
	var g PRGate
	err := q.QueryRow(ctx, `SELECT p.id, (SELECT g.id FROM security_gates g WHERE g.policy_id = p.id AND g.managed LIMIT 1)
		FROM security_policies p WHERE p.organization_id = $1 AND p.managed_by = 'repository_pr_gate' AND p.managed_repository_id = $2`,
		orgID, repoID).Scan(&g.PolicyID, &g.GateID)
	if errors.Is(err, pgx.ErrNoRows) {
		return PRGate{}, nil
	}
	return g, err
}

// SyncRepositoryPRGate makes the managed policy and gate of a repository
// match its pull request settings. With a mode and a threshold other than
// none the policy is enabled ("minimum severity = threshold, this
// repository") and the gate has the mode; otherwise both are disabled
// (kept, so past decisions still resolve their policy).
func SyncRepositoryPRGate(ctx context.Context, tx pgx.Tx, orgID, repoID uuid.UUID, enabled bool, mode, severity string, actor *uuid.UUID) (PRGate, error) {
	cur, err := RepositoryPRGate(ctx, tx, orgID, repoID)
	if err != nil {
		return cur, err
	}
	want := (mode == "block" || mode == "warn") && severity != "none" && severity != ""
	if !want {
		if cur.PolicyID != nil {
			if _, err := tx.Exec(ctx, `UPDATE security_policies SET enabled = false, version = version + CASE WHEN enabled THEN 1 ELSE 0 END,
				updated_by = $2, updated_at = now() WHERE id = $1`, *cur.PolicyID, actor); err != nil {
				return cur, err
			}
			if _, err := tx.Exec(ctx, `UPDATE security_gates SET enabled = false, updated_at = now() WHERE policy_id = $1 AND managed`, *cur.PolicyID); err != nil {
				return cur, err
			}
		}
		return cur, nil
	}
	cond, _ := json.Marshal(policy.Conditions{MinSeverity: severity, RepositoryIDs: []string{repoID.String()}})
	act, _ := json.Marshal(policy.Actions{Block: mode == "block"})
	var name string
	if err := tx.QueryRow(ctx, `SELECT 'Pull request gate: ' || left(COALESCE(NULLIF(display_name, ''), full_name), 120) || ' (' || left(id::text, 8) || ')'
		FROM repositories WHERE organization_id = $1 AND id = $2`, orgID, repoID).Scan(&name); err != nil {
		return cur, err
	}
	desc := "Generated from the repository's pull request settings (" + mode + " new findings at " + severity +
		" or above). Change it in the repository's pull request settings."
	if cur.PolicyID == nil {
		id := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO security_policies (id, organization_id, name, description, enabled, conditions, actions,
			created_by, updated_by, managed_by, managed_repository_id) VALUES ($1, $2, $3, $4, true, $5, $6, $7, $7, 'repository_pr_gate', $8)`,
			id, orgID, name, desc, cond, act, actor, repoID); err != nil {
			return cur, err
		}
		cur.PolicyID = &id
	} else if _, err := tx.Exec(ctx, `UPDATE security_policies SET enabled = true, conditions = $2, actions = $3, description = $4,
		version = version + CASE WHEN enabled AND conditions = $2::jsonb AND actions = $3::jsonb THEN 0 ELSE 1 END,
		updated_by = $5, updated_at = now() WHERE id = $1`, *cur.PolicyID, cond, act, desc, actor); err != nil {
		return cur, err
	}
	gmode := "warn"
	if mode == "block" {
		gmode = "block"
	}
	if cur.GateID == nil {
		id := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO security_gates (id, organization_id, name, stage, policy_id, mode, allow_exceptions, repository_id,
			enabled, managed, created_by) VALUES ($1, $2, $3, 'pull_request', $4, $5, true, $6, $7, true, $8)`,
			id, orgID, name, *cur.PolicyID, gmode, repoID, enabled, actor); err != nil {
			return cur, err
		}
		cur.GateID = &id
	} else if _, err := tx.Exec(ctx, `UPDATE security_gates SET mode = $2, enabled = $3, updated_at = now() WHERE id = $1`,
		*cur.GateID, gmode, enabled); err != nil {
		return cur, err
	}
	return cur, nil
}
