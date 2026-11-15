package schedule

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/platform/db"
	"pathos/internal/scans"
)

// lockKey is the pg advisory lock that elects the scheduler leader.
const lockKey int64 = 0x5041_5448_4f53_0001 // "PATHOS" + 1

// Scheduler runs Tick on the elected leader. Any number of replicas may run;
// standbys poll for the lock and take over when the leader's connection dies.
type Scheduler struct {
	Pool     *pgxpool.Pool
	Log      *slog.Logger
	Holder   string        // identifies this replica (hostname)
	Interval time.Duration // tick interval
}

// Run blocks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) error {
	if s.Interval <= 0 {
		s.Interval = 15 * time.Second
	}
	for {
		led, err := s.lead(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			s.Log.Error("scheduler leadership lost", "err", err)
		} else if !led {
			s.Log.Debug("scheduler standby: another replica is leader")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.Interval):
		}
	}
}

// lead tries to take the lock and, if it does, ticks until the context ends
// or the connection fails. It reports whether it was leader.
func (s *Scheduler) lead(ctx context.Context) (bool, error) {
	conn, err := s.Pool.Acquire(ctx)
	if err != nil {
		return false, err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lockKey).Scan(&got); err != nil || !got {
		return false, err
	}
	defer func() {
		// Best effort; the lock also disappears with the session.
		uctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_, _ = conn.Exec(uctx, `SELECT pg_advisory_unlock($1)`, lockKey)
	}()
	s.Log.Info("scheduler elected leader", "holder", s.Holder)
	t := time.NewTicker(s.Interval)
	defer t.Stop()
	for {
		st, err := Tick(ctx, s.Pool, time.Now(), s.Log)
		if err != nil && ctx.Err() == nil {
			s.Log.Error("scheduler tick failed", "err", err)
		}
		if err := heartbeat(ctx, s.Pool, s.Holder, st); err != nil && ctx.Err() == nil {
			s.Log.Error("scheduler heartbeat failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return true, nil
		case <-t.C:
		}
		// The lock lives on this connection: if it is gone, so is leadership.
		pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = conn.Ping(pctx)
		cancel()
		if err != nil {
			return true, err
		}
	}
}

func heartbeat(ctx context.Context, pool *pgxpool.Pool, holder string, st TickStats) error {
	b, _ := json.Marshal(st)
	_, err := pool.Exec(ctx, `
		INSERT INTO scheduler_state (name, holder, started_at, heartbeat_at, stats) VALUES ('scheduler', $1, now(), now(), $2)
		ON CONFLICT (name) DO UPDATE SET
		  started_at = CASE WHEN scheduler_state.holder = EXCLUDED.holder THEN scheduler_state.started_at ELSE now() END,
		  holder = EXCLUDED.holder, heartbeat_at = now(), stats = EXCLUDED.stats`, holder, b)
	return err
}

// TickStats summarizes one scheduler pass.
type TickStats struct {
	SchedulesRun   int `json:"schedules_run"`
	JobsQueued     int `json:"jobs_queued"`
	MissedRuns     int `json:"missed_runs"`
	WorkersOffline int `json:"workers_offline"`
}

// maxPerTick bounds the schedules handled in one pass so a backlog cannot
// starve the heartbeat.
const maxPerTick = 100

// Tick runs due schedules, detects missed runs, recovers expired leases and
// reports workers that went offline. It is safe to call concurrently (row
// locks with SKIP LOCKED), although only the leader normally does.
func Tick(ctx context.Context, pool *pgxpool.Pool, now time.Time, log *slog.Logger) (TickStats, error) {
	var st TickStats
	if err := scans.RequeueExpired(ctx, pool); err != nil {
		return st, err
	}
	for range maxPerTick {
		ran, queued, missed, err := runOneDue(ctx, pool, now, log)
		if err != nil {
			return st, err
		}
		if !ran {
			break
		}
		st.SchedulesRun++
		st.JobsQueued += queued
		st.MissedRuns += missed
	}
	n, err := workerHealth(ctx, pool)
	st.WorkersOffline = n
	return st, err
}

func runOneDue(ctx context.Context, pool *pgxpool.Pool, now time.Time, log *slog.Logger) (ran bool, queued, missed int, err error) {
	err = db.InTx(ctx, pool, func(tx pgx.Tx) error {
		var (
			id, orgID     uuid.UUID
			expr, tz, typ string
			target        *uuid.UUID
			priority      int
			due           time.Time
		)
		err := tx.QueryRow(ctx, `
			SELECT id, organization_id, cron, timezone, target_type, target_id, priority, next_run_at
			FROM scan_schedules WHERE enabled AND next_run_at <= $1
			ORDER BY next_run_at LIMIT 1 FOR UPDATE SKIP LOCKED`, now).
			Scan(&id, &orgID, &expr, &tz, &typ, &target, &priority, &due)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		ran = true
		c, perr := ParseCron(expr)
		loc, lerr := time.LoadLocation(tz)
		if perr != nil || lerr != nil {
			_, err := tx.Exec(ctx, `UPDATE scan_schedules SET enabled = false, last_status = 'disabled: invalid cron or time zone' WHERE id = $1`, id)
			return err
		}
		// Activations between the due time and now were missed (scheduler
		// down or overloaded). Catch up once rather than once per miss.
		for t := c.Next(due, loc); !t.IsZero() && !t.After(now) && missed < 10000; t = c.Next(t, loc) {
			missed++
		}
		res, err := execute(ctx, tx, orgID, id, typ, target, priority, nil, log)
		if err != nil {
			return err
		}
		queued = res.Queued
		status := res.String()
		if missed > 0 {
			status += "; caught up after missed runs"
			if _, err := tx.Exec(ctx, `
				INSERT INTO notification_events (organization_id, event_key, subject_id, payload)
				VALUES ($1, 'schedule.missed', $2, jsonb_build_object('missed', $3::int, 'due_at', $4::timestamptz))`,
				orgID, id, missed, due); err != nil {
				return err
			}
		}
		_, err = tx.Exec(ctx, `
			UPDATE scan_schedules SET last_run_at = $2, last_status = $3, last_queued = $4,
			       missed_runs = missed_runs + $5, next_run_at = $6
			WHERE id = $1`, id, now, status, res.Queued, missed, nullTime(c.Next(now, loc)))
		return err
	})
	return ran, queued, missed, err
}

func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

// offlineAfter is how long a worker may be silent before it is reported.
// Slightly longer than the online window to avoid flapping.
const offlineAfter = scans.WorkerOnlineWindow + time.Minute

// workerHealth emits one worker.offline event per outage. Workers silent
// for over a week are considered decommissioned and not reported.
func workerHealth(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	tag, err := pool.Exec(ctx, `
		WITH off AS (
		  UPDATE workers SET offline_notified_at = now()
		  WHERE revoked_at IS NULL AND last_seen_at < now() - $1::interval AND last_seen_at > now() - interval '7 days'
		    AND (offline_notified_at IS NULL OR offline_notified_at < last_seen_at)
		  RETURNING id, organization_id, name, family, last_seen_at)
		INSERT INTO notification_events (organization_id, event_key, subject_id, payload)
		SELECT organization_id, 'worker.offline', id,
		       jsonb_build_object('name', name, 'family', family, 'last_seen_at', last_seen_at,
		         'queued', (SELECT count(*) FROM scan_jobs j WHERE j.organization_id = off.organization_id AND j.status = 'queued'))
		FROM off`, offlineAfter.String())
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
