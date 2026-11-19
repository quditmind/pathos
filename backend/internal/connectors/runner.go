package connectors

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/featureflags"
	"pathos/internal/platform/db"
	"pathos/internal/platform/diag"
	"pathos/internal/platform/tenant"
)

// Check triggers.
const (
	TriggerSchedule = "schedule"
	TriggerUser     = "user"
	TriggerVerify   = "verify"
)

// checkTimeout bounds one health check.
const checkTimeout = 60 * time.Second

// Run runs the health check of one connector now and records it. The
// caller decides whether this process may run the kind's check (the API
// server never runs "jobs" kinds).
func Run(ctx context.Context, env *Env, c Connector, trigger string, by *uuid.UUID) (HealthCheck, error) {
	start := time.Now()
	res := runChecker(ctx, env, c)
	return Record(ctx, env.DB, c, res, trigger, by, time.Since(start))
}

func runChecker(ctx context.Context, env *Env, c Connector) (res Result) {
	k, ok := LookupKind(c.Kind)
	switch {
	case !ok || k.Checker == nil:
		return Result{Status: StatusUnknown, Message: "no health check exists for this kind"}
	case !c.Enabled:
		return Result{Status: StatusDisabled, Message: "the connection is disabled", Steps: []Step{{Check: "enabled", Status: StepSkipped}}}
	case env.Offline && NeedsInternet(c):
		return Result{Status: StatusDisabled, ErrorCode: "PTH-CONN-1015", Message: "PATHOS runs in offline mode and this connection needs the internet",
			Steps: []Step{{Check: "offline_mode", Status: StepSkipped, ErrorCode: "PTH-CONN-1015"}}}
	}
	t := Target{Connector: c}
	if c.SecretID != nil && env.Secrets != nil {
		sid := *c.SecretID
		t.Credential = func(ctx context.Context) ([]byte, error) {
			return env.Secrets.Reveal(ctx, env.DB, c.OrgID, sid, credentialKind)
		}
	}
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	defer func() {
		if p := recover(); p != nil {
			if env.Log != nil {
				env.Log.Error("connector check panicked", "kind", c.Kind, "connector_id", c.ID, "panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			}
			res = Result{Status: StatusFailing, ErrorCode: "PTH-CONN-1012", Message: "the health check failed unexpectedly"}
		}
	}()
	return k.Checker.Check(ctx, env, t)
}

// normalize enforces the result invariants: a known status, a catalogue
// code (or none), redacted texts, healthy only with no failing step.
func normalize(res Result) Result {
	switch res.Status {
	case StatusHealthy, StatusDegraded, StatusFailing, StatusUnknown, StatusDisabled:
	default:
		res.Status = StatusUnknown
	}
	if _, ok := diag.Lookup(res.ErrorCode); !ok {
		res.ErrorCode = ""
	}
	if res.Status == StatusFailing && res.ErrorCode == "" {
		res.ErrorCode = "PTH-CONN-1012"
	}
	res.Message = Redact(res.Message)
	if res.Steps == nil {
		res.Steps = []Step{}
	}
	for i := range res.Steps {
		res.Steps[i].Detail = Redact(res.Steps[i].Detail)
		if _, ok := diag.Lookup(res.Steps[i].ErrorCode); !ok {
			res.Steps[i].ErrorCode = ""
		}
		if res.Steps[i].Status == StepFail && res.Status == StatusHealthy {
			res.Status = StatusFailing
		}
	}
	if res.Observed == nil {
		res.Observed = map[string]any{}
	}
	return res
}

// Record stores a check result and updates the connector's health.
func Record(ctx context.Context, q db.Querier, c Connector, res Result, trigger string, by *uuid.UUID, dur time.Duration) (HealthCheck, error) {
	res = normalize(res)
	steps, _ := json.Marshal(res.Steps)
	obs, _ := json.Marshal(res.Observed)
	if len(obs) > 8000 {
		obs = []byte(`{}`)
	}
	h := HealthCheck{ID: uuid.Must(uuid.NewV7()), Status: res.Status, Trigger: trigger, DurationMS: int(dur.Milliseconds()), ErrorCode: res.ErrorCode,
		Message: res.Message, Steps: res.Steps, Observed: res.Observed, TriggeredBy: by}
	err := pgx.BeginFunc(ctx, txStarter{q}, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `INSERT INTO connector_health_checks (id, organization_id, connector_id, status, trigger, triggered_by,
			duration_ms, error_code, message, steps, observed) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING checked_at`,
			h.ID, c.OrgID, c.ID, h.Status, trigger, by, h.DurationMS, h.ErrorCode, h.Message, steps, obs).Scan(&h.CheckedAt); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE connectors SET status = $3, last_check_at = $4, last_error_code = $5,
			last_ok_at = CASE WHEN $3 IN ('healthy', 'degraded') THEN $4 ELSE last_ok_at END,
			check_requested_at = CASE WHEN check_requested_at <= $4 THEN NULL ELSE check_requested_at END, updated_at = now()
			WHERE organization_id = $1 AND id = $2`, c.OrgID, c.ID, h.Status, h.CheckedAt, h.ErrorCode)
		return err
	})
	return h, err
}

// txStarter adapts a db.Querier that can begin transactions.
type txStarter struct{ q db.Querier }

func (t txStarter) Begin(ctx context.Context) (pgx.Tx, error) {
	if b, ok := t.q.(interface {
		Begin(context.Context) (pgx.Tx, error)
	}); ok {
		return b.Begin(ctx)
	}
	return nil, errors.New("connectors: querier cannot begin a transaction")
}

// Background is the jobs-service side: scheduled checks of every
// connector of organizations with the connectors flag on, the "Check now"
// requests of kinds only the jobs service may run, and history retention.
type Background struct {
	Env *Env
	// Poll is how often check requests are picked up (default 5 s).
	Poll time.Duration
	// Concurrency bounds parallel scheduled checks (default 4).
	Concurrency int
}

// Run blocks until ctx ends. ctx must be in system scope (the jobs
// service): every row carries its organization and each check narrows to
// it.
func (b *Background) Run(ctx context.Context) {
	poll := b.Poll
	if poll <= 0 {
		poll = 5 * time.Second
	}
	tick := time.NewTicker(poll)
	defer tick.Stop()
	var lastSweep, lastPrune time.Time
	for {
		b.RunRequested(ctx)
		if time.Since(lastSweep) >= 5*time.Minute {
			b.RunDue(ctx)
			lastSweep = time.Now()
		}
		if time.Since(lastPrune) >= 24*time.Hour {
			if err := Prune(ctx, b.Env.DB); err != nil && b.Env.Log != nil {
				b.Env.Log.Warn("connector check retention failed", "err", err)
			}
			lastPrune = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// RunRequested runs pending "Check now" requests (any kind).
func (b *Background) RunRequested(ctx context.Context) int {
	env := b.Env
	n := 0
	for range 20 {
		var id, orgID uuid.UUID
		var by *uuid.UUID
		err := env.DB.QueryRow(ctx, `UPDATE connectors SET check_requested_at = NULL
			WHERE id = (SELECT id FROM connectors WHERE check_requested_at IS NOT NULL ORDER BY check_requested_at LIMIT 1 FOR UPDATE SKIP LOCKED)
			RETURNING id, organization_id, check_requested_by`).Scan(&id, &orgID, &by)
		if errors.Is(err, pgx.ErrNoRows) {
			return n
		}
		if err != nil {
			if env.Log != nil {
				env.Log.Warn("connector check request failed", "err", err)
			}
			return n
		}
		octx := tenant.WithOrg(ctx, orgID)
		c, err := Get(octx, env.DB, env, orgID, id)
		if err != nil {
			continue
		}
		if _, err := Run(octx, env, c, TriggerUser, by); err != nil && env.Log != nil {
			env.Log.Warn("connector check failed to record", "connector_id", id, "err", err)
		}
		n++
	}
	return n
}

// RunDue checks every connector whose last check is older than the
// interval, for each organization with the connectors flag on.
func (b *Background) RunDue(ctx context.Context) int {
	env := b.Env
	rows, err := env.DB.Query(ctx, `SELECT organization_id FROM feature_flags WHERE name = 'connectors' AND enabled`)
	if err != nil {
		if env.Log != nil {
			env.Log.Warn("connector schedule failed", "err", err)
		}
		return 0
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0
	}
	conc := b.Concurrency
	if conc <= 0 {
		conc = 4
	}
	var mu sync.Mutex
	n := 0
	for _, org := range orgs {
		octx := tenant.WithOrg(ctx, org)
		if on, err := featureflags.Enabled(octx, env.DB, org, "connectors"); err != nil || !on {
			continue
		}
		all, err := Reconcile(octx, env.DB, env, org)
		if err != nil {
			if env.Log != nil {
				env.Log.Warn("connector reconcile failed", "organization_id", org, "err", err)
			}
			continue
		}
		sem := make(chan struct{}, conc)
		var wg sync.WaitGroup
		for _, c := range all {
			k, _ := LookupKind(c.Kind)
			if k.Checker == nil || (c.LastCheckAt != nil && env.now().Sub(*c.LastCheckAt) < env.interval()) {
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(c Connector) {
				defer wg.Done()
				defer func() { <-sem }()
				if _, err := Run(octx, env, c, TriggerSchedule, nil); err != nil && env.Log != nil {
					env.Log.Warn("connector check failed to record", "connector_id", c.ID, "err", err)
				}
				mu.Lock()
				n++
				mu.Unlock()
			}(c)
		}
		wg.Wait()
	}
	return n
}

// Prune keeps 30 days of history, and at least the last 200 checks of
// every connector.
func Prune(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, `DELETE FROM connector_health_checks h WHERE h.checked_at < now() - interval '30 days'
		AND h.id NOT IN (SELECT id FROM (SELECT id, row_number() OVER (PARTITION BY connector_id ORDER BY checked_at DESC) AS n
		  FROM connector_health_checks) r WHERE r.n <= 200)`)
	return err
}
