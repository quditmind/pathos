package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/platform/db"
)

// ErrNotFound means no connector with that id exists in the organization.
var ErrNotFound = errors.New("connector not found")

const connectorCols = `c.id, c.organization_id, c.kind, COALESCE(c.source_table, ''), COALESCE(c.source_key, ''), c.name, c.config, c.secret_id,
	c.enabled, c.status, c.last_check_at, c.last_ok_at, c.last_error_code, c.check_requested_at, c.created_at, c.updated_at`

func scanConnector(r pgx.Row) (Connector, error) {
	var c Connector
	var cfg []byte
	err := r.Scan(&c.ID, &c.OrgID, &c.Kind, &c.SourceTable, &c.SourceKey, &c.Name, &cfg, &c.SecretID, &c.Enabled, &c.Status,
		&c.LastCheckAt, &c.LastOKAt, &c.LastErrorCode, &c.CheckRequestedAt, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.Config = map[string]any{}
	_ = json.Unmarshal(cfg, &c.Config)
	c.Meta = map[string]string{}
	return c, nil
}

// Reconcile brings the registry in step with the legacy tables of one
// organization: a row is added for each new connection and removed when
// its connection is gone (its check history goes with it). It touches
// only the registry and returns every connector of the organization with
// its source's name, state and metadata.
func Reconcile(ctx context.Context, q db.Querier, env *Env, orgID uuid.UUID) ([]Connector, error) {
	src, err := listSources(ctx, q, env, orgID)
	if err != nil {
		return nil, err
	}
	live := make([]string, 0, len(src))
	for _, s := range src {
		if _, ok := LookupKind(s.Kind); !ok {
			continue
		}
		live = append(live, s.Table+"|"+s.Key)
		if _, err := q.Exec(ctx, `INSERT INTO connectors (id, organization_id, kind, source_table, source_key)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (organization_id, source_table, source_key) WHERE source_table IS NOT NULL
			DO UPDATE SET kind = EXCLUDED.kind WHERE connectors.kind <> EXCLUDED.kind`,
			uuid.Must(uuid.NewV7()), orgID, s.Kind, s.Table, s.Key); err != nil {
			return nil, err
		}
	}
	if _, err := q.Exec(ctx, `DELETE FROM connectors WHERE organization_id = $1 AND source_table = ANY($2)
		AND NOT (source_table || '|' || source_key = ANY($3))`, orgID, legacyTables, live); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT `+connectorCols+` FROM connectors c WHERE c.organization_id = $1`, orgID)
	if err != nil {
		return nil, err
	}
	all, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Connector, error) { return scanConnector(r) })
	if err != nil {
		return nil, err
	}
	bySource := map[string]sourceRow{}
	for _, s := range src {
		bySource[s.Table+"|"+s.Key] = s
	}
	out := all[:0]
	for _, c := range all {
		if c.SourceTable != "" {
			s, ok := bySource[c.SourceTable+"|"+c.SourceKey]
			if !ok {
				continue
			}
			c.Name, c.Enabled, c.LastSyncAt, c.Meta = s.Name, s.Enabled, s.LastSyncAt, s.Meta
		}
		if _, ok := LookupKind(c.Kind); !ok {
			continue
		}
		out = append(out, c)
	}
	return out, nil
}

// Get returns one connector (reconciled first, so a deleted source is not
// found).
func Get(ctx context.Context, q db.Querier, env *Env, orgID, id uuid.UUID) (Connector, error) {
	all, err := Reconcile(ctx, q, env, orgID)
	if err != nil {
		return Connector{}, err
	}
	for _, c := range all {
		if c.ID == id {
			return c, nil
		}
	}
	return Connector{}, ErrNotFound
}

// NeedsInternet reports whether a connector can only work online.
func NeedsInternet(c Connector) bool {
	k, ok := LookupKind(c.Kind)
	if !ok {
		return false
	}
	if k.NeedsInternet != nil {
		return k.NeedsInternet(c.Meta, c.Config)
	}
	return !k.OfflineOK
}

// EffectiveStatus is the status shown: disabled when the connection is
// off or needs the internet in an offline install; unknown when the last
// check is older than twice the check interval (a stale check never counts
// as healthy); otherwise the last check's status.
func EffectiveStatus(c Connector, env *Env) (string, string) {
	switch {
	case !c.Enabled:
		return StatusDisabled, ""
	case env != nil && env.Offline && NeedsInternet(c):
		return StatusDisabled, "PTH-CONN-1015"
	case c.LastCheckAt == nil:
		return StatusUnknown, ""
	}
	if (c.Status == StatusHealthy || c.Status == StatusDegraded) && env.now().Sub(*c.LastCheckAt) > 2*env.interval() {
		return StatusUnknown, c.LastErrorCode
	}
	return c.Status, c.LastErrorCode
}

// HealthCheck is one stored check.
type HealthCheck struct {
	ID          uuid.UUID      `json:"id"`
	Status      string         `json:"status"`
	Trigger     string         `json:"trigger"`
	CheckedAt   time.Time      `json:"checked_at"`
	DurationMS  int            `json:"duration_ms"`
	ErrorCode   string         `json:"error_code"`
	Message     string         `json:"message"`
	Steps       []Step         `json:"steps"`
	Observed    map[string]any `json:"observed"`
	TriggeredBy *uuid.UUID     `json:"-"`
}

const checkCols = `id, status, trigger, checked_at, duration_ms, error_code, message, steps, observed, triggered_by`

func scanCheck(r pgx.Row) (HealthCheck, error) {
	var h HealthCheck
	var steps, obs []byte
	err := r.Scan(&h.ID, &h.Status, &h.Trigger, &h.CheckedAt, &h.DurationMS, &h.ErrorCode, &h.Message, &steps, &obs, &h.TriggeredBy)
	if err != nil {
		return h, err
	}
	h.Steps, h.Observed = []Step{}, map[string]any{}
	_ = json.Unmarshal(steps, &h.Steps)
	_ = json.Unmarshal(obs, &h.Observed)
	return h, nil
}

// Checks returns a connector's history, newest first (before: keyset
// cursor on checked_at, id).
func Checks(ctx context.Context, q db.Querier, orgID, connectorID uuid.UUID, limit int, before *HealthCheck) ([]HealthCheck, error) {
	args := []any{orgID, connectorID, limit}
	cond := ""
	if before != nil {
		cond = ` AND (checked_at, id) < ($4, $5)`
		args = append(args, before.CheckedAt, before.ID)
	}
	rows, err := q.Query(ctx, `SELECT `+checkCols+` FROM connector_health_checks
		WHERE organization_id = $1 AND connector_id = $2`+cond+` ORDER BY checked_at DESC, id DESC LIMIT $3`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (HealthCheck, error) { return scanCheck(r) })
}

// LastCheck returns the newest check of a connector (nil when none).
func LastCheck(ctx context.Context, q db.Querier, orgID, connectorID uuid.UUID) (*HealthCheck, error) {
	h, err := scanCheck(q.QueryRow(ctx, `SELECT `+checkCols+` FROM connector_health_checks
		WHERE organization_id = $1 AND connector_id = $2 ORDER BY checked_at DESC, id DESC LIMIT 1`, orgID, connectorID))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}
