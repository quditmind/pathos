package schedule

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/platform/db"
	"pathos/internal/scans"
)

// Timing describes when a schedule fires.
type Timing struct {
	Kind            string     // cron | once | interval
	Cron            *Cron      // kind cron
	RunAt           *time.Time // kind once; first run for interval
	IntervalMinutes int        // kind interval
	Loc             *time.Location
	Window          *Window
}

// Window restricts activations to approved hours (in the schedule's time
// zone) and optionally weekdays (0 = Sunday). Start > End spans midnight.
type Window struct {
	Start, End time.Duration // since midnight
	Days       []int
}

func (w *Window) contains(t time.Time) bool {
	if w == nil {
		return true
	}
	since := time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute + time.Duration(t.Second())*time.Second
	day := int(t.Weekday())
	in := false
	if w.Start <= w.End {
		in = since >= w.Start && since < w.End
	} else { // overnight: the window belongs to the day it starts
		in = since >= w.Start || since < w.End
		if since < w.End {
			day = (day + 6) % 7
		}
	}
	return in && (len(w.Days) == 0 || slices.Contains(w.Days, day))
}

// nextOpen returns the first instant at or after t inside the window.
func (w *Window) nextOpen(t time.Time) time.Time {
	if w == nil || w.contains(t) {
		return t
	}
	// Candidate starts: today and the next 8 days at Start.
	for i := 0; i <= 8; i++ {
		d := time.Date(t.Year(), t.Month(), t.Day()+i, 0, 0, 0, 0, t.Location()).Add(w.Start)
		if !d.Before(t) && w.contains(d) {
			return d
		}
	}
	return time.Time{}
}

// Next returns the next activation strictly after `after` (zero: none).
func (tm Timing) Next(after time.Time) time.Time {
	var t time.Time
	switch tm.Kind {
	case "cron":
		t = tm.Cron.Next(after, tm.Loc)
	case "once":
		if tm.RunAt != nil && tm.RunAt.After(after) {
			t = *tm.RunAt
		}
	case "interval":
		step := time.Duration(tm.IntervalMinutes) * time.Minute
		start := after
		if tm.RunAt != nil {
			start = *tm.RunAt
		}
		if start.After(after) {
			t = start
		} else {
			n := after.Sub(start)/step + 1
			t = start.Add(n * step)
		}
	}
	if t.IsZero() || tm.Window == nil {
		return t
	}
	return tm.Window.nextOpen(t.In(tm.Loc))
}

// PlanEntry is one row of a schedule's execution plan.
type PlanEntry struct {
	ID          uuid.UUID  `json:"id"`
	TargetType  string     `json:"target_type"`
	TargetID    *uuid.UUID `json:"target_id"`
	TargetName  string     `json:"target_name"`
	ProfileID   *uuid.UUID `json:"profile_id"`   // nil: each repository's own profile
	ProfileName string     `json:"profile_name"` // "" when ProfileID is nil
}

// pair is one repository × profile execution of a run.
type pair struct {
	Repo    uuid.UUID  `json:"repository_id"`
	Profile *uuid.UUID `json:"profile_id"`
}

func (p pair) key() string {
	if p.Profile == nil {
		return p.Repo.String() + "/"
	}
	return p.Repo.String() + "/" + p.Profile.String()
}

func loadPlan(ctx context.Context, q db.Querier, scheduleID uuid.UUID) ([]PlanEntry, error) {
	rows, err := q.Query(ctx, `
		SELECT t.id, t.target_type, t.target_id,
		       COALESCE(CASE t.target_type
		         WHEN 'organization' THEN 'All repositories'
		         WHEN 'region' THEN (SELECT name FROM regions WHERE id = t.target_id)
		         WHEN 'business_unit' THEN (SELECT name FROM business_units WHERE id = t.target_id)
		         WHEN 'repository' THEN (SELECT COALESCE(NULLIF(display_name, ''), full_name) || ' (' || repository_key || ')' FROM repositories WHERE id = t.target_id) END,
		         '(deleted)'),
		       t.profile_id, COALESCE((SELECT name FROM scan_profiles WHERE id = t.profile_id), '')
		FROM scan_schedule_targets t WHERE t.schedule_id = $1 ORDER BY t.position, t.id`, scheduleID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[PlanEntry])
	if out == nil {
		out = []PlanEntry{}
	}
	return out, err
}

// planPairs expands a plan into distinct repository × profile pairs.
func planPairs(ctx context.Context, q db.Querier, orgID uuid.UUID, plan []PlanEntry) ([]pair, error) {
	seen := map[string]bool{}
	var out []pair
	for _, e := range plan {
		repos, err := targetRepos(ctx, q, orgID, e.TargetType, e.TargetID)
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			p := pair{Repo: r, Profile: e.ProfileID}
			if !seen[p.key()] {
				seen[p.key()] = true
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// scheduleRow is what the scheduler needs to run a schedule.
type scheduleRow struct {
	ID, OrgID     uuid.UUID
	Name          string
	Priority      int
	MaxConcurrent int
}

// activeJobs counts queued or running executions created by a schedule.
func activeJobs(ctx context.Context, q db.Querier, scheduleID uuid.UUID) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM scan_jobs WHERE schedule_id = $1 AND status IN ('queued', 'running')`, scheduleID).Scan(&n)
	return n, err
}

// enqueuePairs queues executions for pairs within the concurrency limit and
// returns those left pending.
func enqueuePairs(ctx context.Context, q db.Querier, sc scheduleRow, runID uuid.UUID, pairs []pair, by *uuid.UUID, log *slog.Logger) (RunResult, []pair, error) {
	var res RunResult
	capacity := len(pairs)
	if sc.MaxConcurrent > 0 {
		active, err := activeJobs(ctx, q, sc.ID)
		if err != nil {
			return res, nil, err
		}
		capacity = max(0, sc.MaxConcurrent-active)
	}
	sid, rid := sc.ID, runID
	var pending []pair
	for i, pr := range pairs {
		if i >= capacity {
			pending = append(pending, pairs[i:]...)
			break
		}
		er, err := scans.EnqueueWith(ctx, q, sc.OrgID, pr.Repo, "schedule", "", "", by,
			scans.EnqueueOpts{Priority: sc.Priority, ScheduleID: &sid, ScheduleRunID: &rid, ProfileID: pr.Profile, Name: sc.Name})
		switch {
		case errors.Is(err, scans.ErrNotScannable):
			res.Skipped++
		case err != nil:
			res.Failed++
			if log != nil {
				log.Warn("scheduled enqueue failed", "schedule_id", sc.ID, "repository_id", pr.Repo, "err", err)
			}
		case er.Coalesced:
			res.Coalesced++
		default:
			res.Queued++
		}
	}
	res.Deferred = len(pending)
	return res, pending, nil
}

// startRun records an activation (unique per schedule and due time) and
// queues its executions. ok is false when the activation already exists
// (a retried or recovered scheduler pass).
func startRun(ctx context.Context, tx pgx.Tx, sc scheduleRow, due time.Time, trigger string, inWindow bool, by *uuid.UUID, log *slog.Logger) (RunResult, bool, error) {
	var res RunResult
	runID := uuid.Must(uuid.NewV7())
	tag, err := tx.Exec(ctx, `INSERT INTO scan_schedule_runs (id, organization_id, schedule_id, due_at, trigger, requested_by)
		VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (schedule_id, due_at) DO NOTHING`, runID, sc.OrgID, sc.ID, due, trigger, by)
	if err != nil || tag.RowsAffected() == 0 {
		return res, false, err
	}
	plan, err := loadPlan(ctx, tx, sc.ID)
	if err != nil {
		return res, true, err
	}
	pairs, err := planPairs(ctx, tx, sc.OrgID, plan)
	if err != nil {
		return res, true, err
	}
	pending := pairs
	if inWindow {
		if res, pending, err = enqueuePairs(ctx, tx, sc, runID, pairs, by, log); err != nil {
			return res, true, err
		}
	} else {
		res.Deferred = len(pairs)
	}
	status, msg := "running", res.String()
	switch {
	case len(pairs) == 0:
		status, msg = "completed", "no scannable repositories in the plan"
	case !inWindow:
		status, msg = "waiting", "waiting for the approved scan window"
	case len(pending) > 0 && res.Queued == 0 && res.Coalesced == 0:
		status = "waiting"
	}
	b, _ := json.Marshal(nonNilPairs(pending))
	_, err = tx.Exec(ctx, `UPDATE scan_schedule_runs SET status = $2, queued = $3, skipped = $4, failed = $5, pending = $6, message = $7,
		finished_at = CASE WHEN $2 = 'completed' THEN now() END WHERE id = $1`,
		runID, status, res.Queued+res.Coalesced, res.Skipped, res.Failed, b, msg)
	return res, true, err
}

func nonNilPairs(p []pair) []pair {
	if p == nil {
		return []pair{}
	}
	return p
}

// advanceRuns continues open runs: queues pending entries when capacity and
// the scan window allow, retries failed executions per policy, and closes
// finished runs (with notifications).
func advanceRuns(ctx context.Context, pool *pgxpool.Pool, now time.Time, log *slog.Logger) (int, error) {
	rows, err := pool.Query(ctx, `SELECT r.id FROM scan_schedule_runs r WHERE r.status IN ('running', 'waiting') ORDER BY r.started_at LIMIT 200`)
	if err != nil {
		return 0, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return 0, err
	}
	queued := 0
	for _, id := range ids {
		n, err := advanceRun(ctx, pool, id, now, log)
		if err != nil {
			return queued, err
		}
		queued += n
	}
	return queued, nil
}

func advanceRun(ctx context.Context, pool *pgxpool.Pool, runID uuid.UUID, now time.Time, log *slog.Logger) (int, error) {
	queued := 0
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		var sc scheduleRow
		var pendingRaw []byte
		var tm timingRow
		var retryMax, retryDelay int
		var notify []string
		var createdBy *uuid.UUID
		err := tx.QueryRow(ctx, `SELECT s.id, s.organization_id, s.name, s.priority, s.max_concurrent, r.pending,
			`+timingCols+`,
			s.retry_max, s.retry_delay_minutes, s.notify_on, s.created_by
			FROM scan_schedule_runs r JOIN scan_schedules s ON s.id = r.schedule_id
			WHERE r.id = $1 AND r.status IN ('running', 'waiting') FOR UPDATE OF r SKIP LOCKED`, runID).
			Scan(&sc.ID, &sc.OrgID, &sc.Name, &sc.Priority, &sc.MaxConcurrent, &pendingRaw,
				&tm.Kind, &tm.Cron, &tm.Timezone, &tm.RunAt, &tm.Interval, &tm.WindowStart, &tm.WindowEnd, &tm.WindowDays,
				&retryMax, &retryDelay, &notify, &createdBy)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		timing, err := tm.timing()
		if err != nil {
			return nil // invalid schedules are disabled by the due-run pass
		}
		// 1. Pending entries.
		var pending []pair
		_ = json.Unmarshal(pendingRaw, &pending)
		if len(pending) > 0 && (timing.Window == nil || timing.Window.contains(now.In(timing.Loc))) {
			res, rest, err := enqueuePairs(ctx, tx, sc, runID, pending, nil, log)
			if err != nil {
				return err
			}
			queued += res.Queued
			b, _ := json.Marshal(nonNilPairs(rest))
			if _, err := tx.Exec(ctx, `UPDATE scan_schedule_runs SET pending = $2, queued = queued + $3, skipped = skipped + $4,
				failed = failed + $5, status = 'running', message = $6 WHERE id = $1`,
				runID, b, res.Queued+res.Coalesced, res.Skipped, res.Failed, res.String()); err != nil {
				return err
			}
			pending = rest
		}
		// 2. Retries of failed executions (one retry chain per execution).
		if retryMax > 0 {
			rrows, err := tx.Query(ctx, `SELECT j.id, j.repository_id, v.profile_id FROM scan_jobs j
				JOIN scan_profile_versions v ON v.id = j.profile_version_id
				WHERE j.schedule_run_id = $1 AND j.status = 'failed' AND j.retry_count < $2
				  AND j.finished_at < $3::timestamptz - make_interval(mins => $4)
				  AND NOT EXISTS (SELECT 1 FROM scan_jobs k WHERE k.retry_of = j.id)`, runID, retryMax, now, retryDelay)
			if err != nil {
				return err
			}
			type retry struct{ job, repo, profile uuid.UUID }
			list, err := pgx.CollectRows(rrows, func(row pgx.CollectableRow) (retry, error) {
				var r retry
				return r, row.Scan(&r.job, &r.repo, &r.profile)
			})
			if err != nil {
				return err
			}
			sid := sc.ID
			for _, rt := range list {
				job, prof := rt.job, rt.profile
				if _, err := scans.EnqueueWith(ctx, tx, sc.OrgID, rt.repo, "schedule", "", "", nil,
					scans.EnqueueOpts{Priority: sc.Priority, ScheduleID: &sid, ScheduleRunID: &runID, ProfileID: &prof, RetryOf: &job, Name: sc.Name}); err != nil {
					if log != nil {
						log.Warn("scheduled retry failed", "schedule_id", sc.ID, "job_id", job, "err", err)
					}
					continue
				}
				_ = scans.AddEvent(ctx, tx, sc.OrgID, job, "retry", "", "info", "retried by the schedule's retry policy")
				queued++
			}
		}
		// 3. Completion: nothing pending, nothing active, no retry due.
		if len(pending) > 0 {
			return nil
		}
		var active, retryable, failed, done int
		if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE status IN ('queued', 'running')),
			count(*) FILTER (WHERE status = 'failed' AND retry_count < $2 AND NOT EXISTS (SELECT 1 FROM scan_jobs k WHERE k.retry_of = scan_jobs.id)),
			count(*) FILTER (WHERE status = 'failed' AND NOT EXISTS (SELECT 1 FROM scan_jobs k WHERE k.retry_of = scan_jobs.id)),
			count(*) FILTER (WHERE status IN ('succeeded', 'partial'))
			FROM scan_jobs WHERE schedule_run_id = $1`, runID, retryMax).Scan(&active, &retryable, &failed, &done); err != nil {
			return err
		}
		if active > 0 || retryable > 0 {
			return nil
		}
		status := "completed"
		switch {
		case failed > 0 && done == 0:
			status = "failed"
		case failed > 0:
			status = "partial"
		}
		msg := fmt.Sprintf("%d succeeded, %d failed", done, failed)
		if _, err := tx.Exec(ctx, `UPDATE scan_schedule_runs SET status = $2, finished_at = now(), message = $3 WHERE id = $1`,
			runID, status, msg); err != nil {
			return err
		}
		event := ""
		switch {
		case status == "completed" && slices.Contains(notify, "completed"):
			event = "schedule.completed"
		case status != "completed" && slices.Contains(notify, "failed"):
			event = "schedule.failed"
		}
		if event != "" {
			_, err = tx.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, subject_id, payload)
				VALUES ($1, $2, $3, jsonb_build_object('run_id', $4::uuid, 'status', $5::text, 'succeeded', $6::int, 'failed', $7::int))`,
				sc.OrgID, event, sc.ID, runID, status, done, failed)
		}
		return err
	})
	return queued, err
}

// timingRow is a schedule's stored timing.
type timingRow struct {
	Kind        string
	Cron        string
	Timezone    string
	RunAt       *time.Time
	Interval    *int
	WindowStart *int64 // seconds since midnight
	WindowEnd   *int64
	WindowDays  []int32
}

func (t timingRow) timing() (Timing, error) {
	loc, err := time.LoadLocation(t.Timezone)
	if err != nil {
		return Timing{}, err
	}
	tm := Timing{Kind: t.Kind, RunAt: t.RunAt, Loc: loc}
	switch t.Kind {
	case "cron":
		if tm.Cron, err = ParseCron(t.Cron); err != nil {
			return tm, err
		}
	case "interval":
		if t.Interval == nil {
			return tm, errors.New("interval missing")
		}
		tm.IntervalMinutes = *t.Interval
	case "once":
	default:
		return tm, errors.New("unknown schedule kind " + t.Kind)
	}
	if t.WindowStart != nil && t.WindowEnd != nil {
		w := &Window{Start: time.Duration(*t.WindowStart) * time.Second, End: time.Duration(*t.WindowEnd) * time.Second}
		for _, d := range t.WindowDays {
			w.Days = append(w.Days, int(d))
		}
		tm.Window = w
	}
	return tm, nil
}

func describeWindow(w *Window) string {
	if w == nil {
		return ""
	}
	f := func(d time.Duration) string { return fmt.Sprintf("%02d:%02d", int(d.Hours()), int(d.Minutes())%60) }
	s := f(w.Start) + "–" + f(w.End)
	if len(w.Days) > 0 {
		names := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
		var d []string
		for _, x := range w.Days {
			d = append(d, names[x])
		}
		s += " " + strings.Join(d, ",")
	}
	return s
}

// timingCols selects a timingRow (table alias s).
const timingCols = `s.kind, s.cron, s.timezone, s.run_at, s.interval_minutes,
	EXTRACT(EPOCH FROM s.window_start)::bigint, EXTRACT(EPOCH FROM s.window_end)::bigint, s.window_days`
