package schedule

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
	_ "time/tzdata" // schedules name IANA zones; do not depend on the image

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scans"
)

// MinInterval is the shortest allowed gap between two runs of a schedule.
// Full scans are expensive; push webhooks cover faster feedback.
const MinInterval = time.Hour

// Service exposes the schedule API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Schedule is the API representation.
type Schedule struct {
	ID                uuid.UUID   `json:"id"`
	Name              string      `json:"name"`
	Enabled           bool        `json:"enabled"` // false = paused
	Kind              string      `json:"kind"`    // cron | once | interval
	Cron              string      `json:"cron"`
	RunAt             *time.Time  `json:"run_at"`
	IntervalMinutes   *int        `json:"interval_minutes"`
	Timezone          string      `json:"timezone"`
	WindowStart       string      `json:"window_start"` // "HH:MM" or ""
	WindowEnd         string      `json:"window_end"`
	WindowDays        []int       `json:"window_days"`
	RetryMax          int         `json:"retry_max"`
	RetryDelayMinutes int         `json:"retry_delay_minutes"`
	MaxConcurrent     int         `json:"max_concurrent"` // 0 = unlimited
	NotifyOn          []string    `json:"notify_on"`
	Plan              []PlanEntry `json:"plan"`
	// Legacy single target (first plan entry).
	TargetType string     `json:"target_type"`
	TargetID   *uuid.UUID `json:"target_id"`
	TargetName string     `json:"target_name"`
	Priority   int        `json:"priority"`
	NextRunAt  *time.Time `json:"next_run_at"`
	LastRunAt  *time.Time `json:"last_run_at"`
	LastStatus string     `json:"last_status"`
	LastQueued int        `json:"last_queued"`
	MissedRuns int        `json:"missed_runs"`
	CreatedAt  time.Time  `json:"created_at"`
	CanManage  bool       `json:"can_manage"`
}

const selectSchedules = `
	SELECT s.id, s.name, s.enabled, s.kind, s.cron, s.run_at, s.interval_minutes, s.timezone,
	       COALESCE(to_char(s.window_start, 'HH24:MI'), ''), COALESCE(to_char(s.window_end, 'HH24:MI'), ''), s.window_days,
	       s.retry_max, s.retry_delay_minutes, s.max_concurrent, s.notify_on,
	       s.priority, s.next_run_at, s.last_run_at, s.last_status, s.last_queued, s.missed_runs, s.created_at
	FROM scan_schedules s`

func (s *Service) scanSchedule(ctx context.Context, q db.Querier, row pgx.Row) (Schedule, error) {
	var sc Schedule
	var days []int32
	err := row.Scan(&sc.ID, &sc.Name, &sc.Enabled, &sc.Kind, &sc.Cron, &sc.RunAt, &sc.IntervalMinutes, &sc.Timezone,
		&sc.WindowStart, &sc.WindowEnd, &days, &sc.RetryMax, &sc.RetryDelayMinutes, &sc.MaxConcurrent, &sc.NotifyOn,
		&sc.Priority, &sc.NextRunAt, &sc.LastRunAt, &sc.LastStatus, &sc.LastQueued, &sc.MissedRuns, &sc.CreatedAt)
	if err != nil {
		return sc, err
	}
	sc.WindowDays = []int{}
	for _, d := range days {
		sc.WindowDays = append(sc.WindowDays, int(d))
	}
	if sc.NotifyOn == nil {
		sc.NotifyOn = []string{}
	}
	if sc.Plan, err = loadPlan(ctx, q, sc.ID); err != nil {
		return sc, err
	}
	if len(sc.Plan) > 0 {
		sc.TargetType, sc.TargetID, sc.TargetName = sc.Plan[0].TargetType, sc.Plan[0].TargetID, sc.Plan[0].TargetName
	}
	return sc, nil
}

// Register mounts the routes.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/schedules", s.list)
	mux.HandleFunc("POST /api/v1/schedules", s.create)
	mux.HandleFunc("POST /api/v1/schedules/preview", s.preview)
	mux.HandleFunc("GET /api/v1/schedules/{id}", s.get)
	mux.HandleFunc("PUT /api/v1/schedules/{id}", s.update)
	mux.HandleFunc("DELETE /api/v1/schedules/{id}", s.delete)
	mux.HandleFunc("POST /api/v1/schedules/{id}/run", s.runNow)
	mux.HandleFunc("POST /api/v1/schedules/{id}/pause", s.pause)
	mux.HandleFunc("POST /api/v1/schedules/{id}/resume", s.resume)
	mux.HandleFunc("GET /api/v1/schedules/{id}/runs", s.runs)
	mux.HandleFunc("GET /api/v1/scheduler/status", s.status)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

// targetScope maps a plan target to the scope that authorizes it.
func targetScope(orgID uuid.UUID, typ string, id *uuid.UUID) authz.Scope {
	switch typ {
	case "region":
		return authz.Scope{Type: authz.ScopeRegion, ID: *id}
	case "business_unit":
		return authz.Scope{Type: authz.ScopeBusinessUnit, ID: *id}
	case "repository":
		return authz.Scope{Type: authz.ScopeRepository, ID: *id}
	}
	return authz.Scope{Type: authz.ScopeOrganization, ID: orgID}
}

// canPlan reports whether p holds perm on every plan entry (any entry when
// any is set). Deleted targets need the permission organization-wide.
func (s *Service) canPlan(ctx context.Context, p *authz.Principal, perm authz.Permission, plan []PlanEntry, any bool) (bool, error) {
	if len(plan) == 0 {
		return p.HasOrgWide(perm), nil
	}
	for _, e := range plan {
		ok, err := s.Authz.Can(ctx, p, perm, targetScope(p.OrganizationID, e.TargetType, e.TargetID))
		if errors.Is(err, org.ErrScopeNotFound) {
			ok, err = p.HasOrgWide(perm), nil
		}
		if err != nil {
			return false, err
		}
		if any && ok {
			return true, nil
		}
		if !any && !ok {
			return false, nil
		}
	}
	return !any, nil
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermScansRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT id FROM scan_schedules WHERE organization_id = $1 ORDER BY lower(name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]Schedule, 0, len(ids))
	for _, id := range ids {
		sc, err := s.scanSchedule(ctx, s.DB, s.DB.QueryRow(ctx, selectSchedules+` WHERE s.id = $1`, id))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if ok, err := s.canPlan(ctx, p, authz.PermScansRead, sc.Plan, true); err != nil {
			s.fail(w, r, err)
			return
		} else if !ok {
			continue
		}
		sc.CanManage, _ = s.canPlan(ctx, p, authz.PermSchedulesManage, sc.Plan, false)
		out = append(out, sc)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	sc, err := s.scanSchedule(ctx, s.DB, s.DB.QueryRow(ctx, selectSchedules+` WHERE s.organization_id = $1 AND s.id = $2`, p.OrganizationID, id))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	if ok, err := s.canPlan(ctx, p, authz.PermScansRead, sc.Plan, true); err != nil || !ok {
		s.fail(w, r, errNotFound)
		return
	}
	sc.CanManage, _ = s.canPlan(ctx, p, authz.PermSchedulesManage, sc.Plan, false)
	httpx.WriteJSON(w, http.StatusOK, sc)
}

type planRequest struct {
	TargetType string     `json:"target_type"`
	TargetID   *uuid.UUID `json:"target_id"`
	ProfileID  *uuid.UUID `json:"profile_id"`
}

type scheduleRequest struct {
	Name              string        `json:"name"`
	Enabled           *bool         `json:"enabled"`
	Kind              string        `json:"kind"`
	Cron              string        `json:"cron"`
	RunAt             *time.Time    `json:"run_at"`
	IntervalMinutes   *int          `json:"interval_minutes"`
	Timezone          string        `json:"timezone"`
	WindowStart       string        `json:"window_start"`
	WindowEnd         string        `json:"window_end"`
	WindowDays        []int         `json:"window_days"`
	RetryMax          *int          `json:"retry_max"`
	RetryDelayMinutes *int          `json:"retry_delay_minutes"`
	MaxConcurrent     *int          `json:"max_concurrent"`
	NotifyOn          []string      `json:"notify_on"`
	Plan              []planRequest `json:"plan"`
	// Legacy single target (used when plan is empty).
	TargetType string     `json:"target_type"`
	TargetID   *uuid.UUID `json:"target_id"`
	Priority   *int       `json:"priority"`
}

type validated struct {
	timing Timing
	wstart *time.Duration
	wend   *time.Duration
}

func parseClock(v string) (*time.Duration, error) {
	if v == "" {
		return nil, nil
	}
	t, err := time.Parse("15:04", v)
	if err != nil {
		return nil, errors.New("times must be HH:MM")
	}
	d := time.Duration(t.Hour())*time.Hour + time.Duration(t.Minute())*time.Minute
	return &d, nil
}

// validate checks the request and that targets and profiles exist.
func (s *Service) validate(ctx context.Context, q db.Querier, orgID uuid.UUID, req *scheduleRequest) (validated, error) {
	var v validated
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 120 {
		return v, httpx.BadRequest("name is required (at most 120 characters)")
	}
	if req.Timezone == "" {
		req.Timezone = "UTC"
	}
	loc, err := time.LoadLocation(req.Timezone)
	if err != nil || req.Timezone == "Local" {
		return v, httpx.BadRequest("unknown time zone")
	}
	if req.Kind == "" {
		req.Kind = "cron"
	}
	tm := Timing{Kind: req.Kind, Loc: loc}
	switch req.Kind {
	case "cron":
		c, err := ParseCron(req.Cron)
		if err != nil {
			return v, httpx.BadRequest("invalid cron expression: " + err.Error())
		}
		if c.Next(time.Now(), loc).IsZero() {
			return v, httpx.BadRequest("the cron expression never fires")
		}
		if d := c.MinInterval(time.Now(), loc, 48); d < MinInterval {
			return v, httpx.BadRequest(fmt.Sprintf("schedules may run at most once per hour (this one fires every %s); use push webhooks for faster feedback", d))
		}
		tm.Cron = c
		req.RunAt, req.IntervalMinutes = nil, nil
	case "once":
		if req.RunAt == nil || !req.RunAt.After(time.Now()) {
			return v, httpx.BadRequest("run_at must be a time in the future")
		}
		tm.RunAt, req.Cron, req.IntervalMinutes = req.RunAt, "", nil
	case "interval":
		if req.IntervalMinutes == nil || *req.IntervalMinutes < int(MinInterval/time.Minute) || *req.IntervalMinutes > 525600 {
			return v, httpx.BadRequest("interval_minutes must be between 60 and 525600")
		}
		tm.IntervalMinutes, tm.RunAt, req.Cron = *req.IntervalMinutes, req.RunAt, ""
	default:
		return v, httpx.BadRequest("kind must be cron, once or interval")
	}
	if v.wstart, err = parseClock(req.WindowStart); err != nil {
		return v, httpx.BadRequest("window_start: " + err.Error())
	}
	if v.wend, err = parseClock(req.WindowEnd); err != nil {
		return v, httpx.BadRequest("window_end: " + err.Error())
	}
	if (v.wstart == nil) != (v.wend == nil) || (v.wstart != nil && *v.wstart == *v.wend) {
		return v, httpx.BadRequest("set both window_start and window_end (different times), or neither")
	}
	if req.WindowDays == nil {
		req.WindowDays = []int{}
	}
	for _, d := range req.WindowDays {
		if d < 0 || d > 6 {
			return v, httpx.BadRequest("window_days must be 0 (Sunday) to 6 (Saturday)")
		}
	}
	slices.Sort(req.WindowDays)
	req.WindowDays = slices.Compact(req.WindowDays)
	if v.wstart != nil {
		tm.Window = &Window{Start: *v.wstart, End: *v.wend, Days: req.WindowDays}
	} else if len(req.WindowDays) > 0 {
		return v, httpx.BadRequest("window_days needs window_start and window_end")
	}
	if tm.Next(time.Now()).IsZero() {
		return v, httpx.BadRequest("this schedule would never run (check the time and scan window)")
	}
	def := func(p **int, d, lo, hi int, name string) error {
		if *p == nil {
			*p = &d
		}
		if **p < lo || **p > hi {
			return httpx.BadRequest(fmt.Sprintf("%s must be between %d and %d", name, lo, hi))
		}
		return nil
	}
	if err := def(&req.Priority, 30, 0, 90, "priority (100 is reserved for emergency scans)"); err != nil {
		return v, err
	}
	if err := def(&req.RetryMax, 0, 0, 5, "retry_max"); err != nil {
		return v, err
	}
	if err := def(&req.RetryDelayMinutes, 30, 5, 1440, "retry_delay_minutes"); err != nil {
		return v, err
	}
	if err := def(&req.MaxConcurrent, 0, 0, 1000, "max_concurrent"); err != nil {
		return v, err
	}
	if req.NotifyOn == nil {
		req.NotifyOn = []string{}
	}
	for _, n := range req.NotifyOn {
		if n != "completed" && n != "failed" {
			return v, httpx.BadRequest("notify_on accepts completed and failed")
		}
	}
	if len(req.Plan) == 0 {
		if req.TargetType == "" {
			req.TargetType = "organization"
		}
		pr := planRequest{TargetType: req.TargetType, TargetID: req.TargetID}
		if req.TargetType == "profile" { // legacy: repositories using a profile
			pr = planRequest{TargetType: "organization", ProfileID: req.TargetID}
		}
		req.Plan = []planRequest{pr}
	}
	if len(req.Plan) > 50 {
		return v, httpx.BadRequest("at most 50 plan entries")
	}
	table := map[string]string{"region": "regions", "business_unit": "business_units", "repository": "repositories"}
	for i := range req.Plan {
		e := &req.Plan[i]
		switch e.TargetType {
		case "organization":
			e.TargetID = nil
		case "region", "business_unit", "repository":
			if e.TargetID == nil {
				return v, httpx.BadRequest(fmt.Sprintf("plan entry %d: target_id is required", i+1))
			}
			var ok bool
			if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+table[e.TargetType]+` WHERE organization_id = $1 AND id = $2)`, orgID, *e.TargetID).Scan(&ok); err != nil {
				return v, err
			}
			if !ok {
				return v, httpx.BadRequest(fmt.Sprintf("plan entry %d: target not found", i+1))
			}
		default:
			return v, httpx.BadRequest(fmt.Sprintf("plan entry %d: target_type must be organization, region, business_unit or repository", i+1))
		}
		if e.ProfileID != nil {
			var ok bool
			if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scan_profiles WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL)`,
				orgID, *e.ProfileID).Scan(&ok); err != nil {
				return v, err
			}
			if !ok {
				return v, httpx.BadRequest(fmt.Sprintf("plan entry %d: scan profile not found or archived", i+1))
			}
		}
	}
	v.timing = tm
	return v, nil
}

func (s *Service) requirePlan(ctx context.Context, p *authz.Principal, plan []planRequest) error {
	for _, e := range plan {
		if err := s.Authz.Require(ctx, p, authz.PermSchedulesManage, targetScope(p.OrganizationID, e.TargetType, e.TargetID)); err != nil {
			return err
		}
	}
	return nil
}

// save writes a schedule and its plan (insert when create).
func (s *Service) save(ctx context.Context, tx pgx.Tx, p *authz.Principal, id uuid.UUID, req scheduleRequest, v validated, create bool) error {
	enabled := req.Enabled == nil || *req.Enabled
	next := nullTime(v.timing.Next(time.Now()))
	first := req.Plan[0]
	legacyType, legacyID := first.TargetType, first.TargetID
	args := []any{id, p.OrganizationID, req.Name, enabled, strings.TrimSpace(req.Cron), req.Timezone, legacyType, legacyID, *req.Priority, next,
		req.Kind, req.RunAt, req.IntervalMinutes, v.wstart, v.wend, req.WindowDays, *req.RetryMax, *req.RetryDelayMinutes,
		*req.MaxConcurrent, req.NotifyOn}
	if create {
		if _, err := tx.Exec(ctx, `
			INSERT INTO scan_schedules (id, organization_id, name, enabled, cron, timezone, target_type, target_id, priority, next_run_at,
			  kind, run_at, interval_minutes, window_start, window_end, window_days, retry_max, retry_delay_minutes, max_concurrent, notify_on, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14::interval::time, $15::interval::time, $16, $17, $18, $19, $20, $21)`,
			append(args, p.UserID)...); err != nil {
			return err
		}
	} else {
		if _, err := tx.Exec(ctx, `
			UPDATE scan_schedules SET name = $3, enabled = $4, cron = $5, timezone = $6, target_type = $7, target_id = $8, priority = $9,
			       next_run_at = $10, kind = $11, run_at = $12, interval_minutes = $13, window_start = $14::interval::time,
			       window_end = $15::interval::time, window_days = $16, retry_max = $17, retry_delay_minutes = $18,
			       max_concurrent = $19, notify_on = $20, updated_at = now()
			WHERE organization_id = $2 AND id = $1`, args...); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scan_schedule_targets WHERE schedule_id = $1`, id); err != nil {
			return err
		}
	}
	for i, e := range req.Plan {
		if _, err := tx.Exec(ctx, `INSERT INTO scan_schedule_targets (id, organization_id, schedule_id, position, target_type, target_id, profile_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`, uuid.Must(uuid.NewV7()), p.OrganizationID, id, i, e.TargetType, e.TargetID, e.ProfileID); err != nil {
			return err
		}
	}
	return nil
}

func auditMeta(req scheduleRequest) map[string]any {
	return map[string]any{"name": req.Name, "kind": req.Kind, "cron": req.Cron, "run_at": req.RunAt, "interval_minutes": req.IntervalMinutes,
		"timezone": req.Timezone, "window": []any{req.WindowStart, req.WindowEnd, req.WindowDays}, "retry_max": req.RetryMax,
		"max_concurrent": req.MaxConcurrent, "notify_on": req.NotifyOn, "plan": req.Plan, "enabled": req.Enabled}
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req scheduleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.validate(ctx, s.DB, p.OrganizationID, &req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requirePlan(ctx, p, req.Plan); err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if err := s.save(ctx, tx, p, id, req, v, true); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "schedule.create", TargetType: "scan_schedule", TargetID: id.String(), Metadata: auditMeta(req)})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sc, err := s.scanSchedule(ctx, s.DB, s.DB.QueryRow(ctx, selectSchedules+` WHERE s.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sc.CanManage = true
	httpx.WriteJSON(w, http.StatusCreated, sc)
}

// loadForManage loads a schedule and requires schedules.manage on its plan.
func (s *Service) loadForManage(ctx context.Context, q db.Querier, p *authz.Principal, id uuid.UUID, lock bool) (Schedule, error) {
	sql := selectSchedules + ` WHERE s.organization_id = $1 AND s.id = $2`
	if lock {
		sql += ` FOR UPDATE OF s`
	}
	sc, err := s.scanSchedule(ctx, q, q.QueryRow(ctx, sql, p.OrganizationID, id))
	if err != nil {
		return sc, errNotFound
	}
	ok, err := s.canPlan(ctx, p, authz.PermSchedulesManage, sc.Plan, false)
	if err != nil {
		return sc, err
	}
	if !ok {
		return sc, authz.ErrForbidden
	}
	return sc, nil
}

func (s *Service) update(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	var req scheduleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var out Schedule
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := s.loadForManage(ctx, tx, p, id, true); err != nil {
			return err
		}
		v, err := s.validate(ctx, tx, p.OrganizationID, &req)
		if err != nil {
			return err
		}
		if err := s.requirePlan(ctx, p, req.Plan); err != nil {
			return err
		}
		if err := s.save(ctx, tx, p, id, req, v, false); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "schedule.update", TargetType: "scan_schedule", TargetID: id.String(), Metadata: auditMeta(req)}); err != nil {
			return err
		}
		out, err = s.scanSchedule(ctx, tx, tx.QueryRow(ctx, selectSchedules+` WHERE s.id = $1`, id))
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.CanManage = true
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) setEnabled(w http.ResponseWriter, r *http.Request, enabled bool) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	var out Schedule
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		sc, err := s.loadForManage(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		var tr timingRow
		if err := tx.QueryRow(ctx, `SELECT `+timingCols+` FROM scan_schedules s WHERE s.id = $1`, id).
			Scan(&tr.Kind, &tr.Cron, &tr.Timezone, &tr.RunAt, &tr.Interval, &tr.WindowStart, &tr.WindowEnd, &tr.WindowDays); err != nil {
			return err
		}
		var next *time.Time
		if tm, err := tr.timing(); err == nil && enabled {
			// Resuming does not replay activations missed while paused.
			next = nullTime(tm.Next(time.Now()))
		} else if !enabled {
			next = sc.NextRunAt
		}
		if _, err := tx.Exec(ctx, `UPDATE scan_schedules SET enabled = $2, next_run_at = $3, updated_at = now() WHERE id = $1`, id, enabled, next); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: map[bool]string{true: "schedule.resume", false: "schedule.pause"}[enabled], TargetType: "scan_schedule",
			TargetID: id.String(), Metadata: map[string]any{"name": sc.Name}}); err != nil {
			return err
		}
		out, err = s.scanSchedule(ctx, tx, tx.QueryRow(ctx, selectSchedules+` WHERE s.id = $1`, id))
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.CanManage = true
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) pause(w http.ResponseWriter, r *http.Request)  { s.setEnabled(w, r, false) }
func (s *Service) resume(w http.ResponseWriter, r *http.Request) { s.setEnabled(w, r, true) }

func (s *Service) delete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		sc, err := s.loadForManage(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM scan_schedules WHERE id = $1`, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "schedule.delete", TargetType: "scan_schedule", TargetID: id.String(), Metadata: map[string]any{"name": sc.Name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// RunResult summarizes the executions queued by an activation.
type RunResult struct {
	Queued    int `json:"queued"`
	Coalesced int `json:"coalesced"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
	Deferred  int `json:"deferred"` // waiting for capacity or the scan window
}

func (r RunResult) String() string {
	parts := []string{fmt.Sprintf("queued %d", r.Queued)}
	if r.Coalesced > 0 {
		parts = append(parts, fmt.Sprintf("%d already queued", r.Coalesced))
	}
	if r.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d not scannable", r.Skipped))
	}
	if r.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", r.Failed))
	}
	if r.Deferred > 0 {
		parts = append(parts, fmt.Sprintf("%d waiting", r.Deferred))
	}
	return strings.Join(parts, ", ")
}

// targetRepos returns active, scan-enabled repositories of a target.
func targetRepos(ctx context.Context, q db.Querier, orgID uuid.UUID, typ string, id *uuid.UUID) ([]uuid.UUID, error) {
	cond := "true"
	args := []any{orgID}
	switch typ {
	case "region":
		cond, args = "r.country_id IN (SELECT id FROM countries WHERE region_id = $2)", append(args, *id)
	case "business_unit":
		cond = `r.business_unit_id IN (WITH RECURSIVE d AS (SELECT id FROM business_units WHERE id = $2
		         UNION ALL SELECT b.id FROM business_units b JOIN d ON b.parent_id = d.id) SELECT id FROM d)`
		args = append(args, *id)
	case "repository":
		cond, args = "r.id = $2", append(args, *id)
	case "profile":
		cond = `COALESCE(r.scan_profile_id, (SELECT id FROM scan_profiles WHERE organization_id = r.organization_id AND is_default AND archived_at IS NULL)) = $2`
		args = append(args, *id)
	}
	rows, err := q.Query(ctx, `SELECT r.id FROM repositories r
		WHERE r.organization_id = $1 AND r.archived_at IS NULL AND r.scan_enabled AND `+cond+` ORDER BY r.criticality = 'critical' DESC, r.id`, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
}

func (s *Service) runNow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	var res RunResult
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		sc, err := s.loadForManage(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		// Manual runs ignore the scan window (an explicit operator action).
		row := scheduleRow{ID: sc.ID, OrgID: p.OrganizationID, Name: sc.Name, Priority: sc.Priority, MaxConcurrent: sc.MaxConcurrent}
		if res, _, err = startRun(ctx, tx, row, time.Now(), "manual", true, &p.UserID, s.Log); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE scan_schedules SET last_run_at = now(), last_status = $2, last_queued = $3 WHERE id = $1`,
			id, "manual run: "+res.String(), res.Queued); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "schedule.run", TargetType: "scan_schedule", TargetID: id.String(), Metadata: map[string]any{"queued": res.Queued}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// Run is one schedule activation (frontend ScheduleRun).
type Run struct {
	ID         uuid.UUID      `json:"id"`
	DueAt      time.Time      `json:"due_at"`
	Trigger    string         `json:"trigger"`
	Status     string         `json:"status"`
	Queued     int            `json:"queued"`
	Skipped    int            `json:"skipped"`
	Failed     int            `json:"failed"`
	Pending    int            `json:"pending"`
	Message    string         `json:"message"`
	StartedAt  time.Time      `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at"`
	Jobs       map[string]int `json:"jobs"` // execution status -> count
}

func (s *Service) runs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	sc, err := s.scanSchedule(ctx, s.DB, s.DB.QueryRow(ctx, selectSchedules+` WHERE s.organization_id = $1 AND s.id = $2`, p.OrganizationID, id))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	if ok, err := s.canPlan(ctx, p, authz.PermScansRead, sc.Plan, true); err != nil || !ok {
		s.fail(w, r, errNotFound)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT r.id, r.due_at, r.trigger, r.status, r.queued, r.skipped, r.failed, jsonb_array_length(r.pending),
		r.message, r.started_at, r.finished_at,
		COALESCE((SELECT jsonb_object_agg(x.status, x.n) FROM (SELECT status, count(*) AS n FROM scan_jobs WHERE schedule_run_id = r.id GROUP BY status) x), '{}')
		FROM scan_schedule_runs r WHERE r.schedule_id = $1 ORDER BY r.started_at DESC LIMIT 100`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Run])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Run{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) preview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermScansRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var req scheduleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Name == "" {
		req.Name = "preview"
	}
	v, err := s.validate(ctx, s.DB, p.OrganizationID, &req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	runs := make([]time.Time, 0, 5)
	t := time.Now()
	for range 5 {
		if t = v.timing.Next(t); t.IsZero() {
			break
		}
		runs = append(runs, t)
	}
	// Executions per activation (repository × profile pairs) visible to p.
	n, repos := 0, map[uuid.UUID]bool{}
	visible := []PlanEntry{}
	for _, e := range req.Plan {
		if ok, _ := s.Authz.Can(ctx, p, authz.PermScansRead, targetScope(p.OrganizationID, e.TargetType, e.TargetID)); ok {
			visible = append(visible, PlanEntry{TargetType: e.TargetType, TargetID: e.TargetID, ProfileID: e.ProfileID})
		}
	}
	pairs, err := planPairs(ctx, s.DB, p.OrganizationID, visible)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, pr := range pairs {
		repos[pr.Repo] = true
	}
	n = len(pairs)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"next_runs": runs, "repositories": len(repos), "executions": n,
		"window": describeWindow(v.timing.Window)})
}

// Status describes scheduler and worker health.
type Status struct {
	Leader         string     `json:"leader"`
	HeartbeatAt    *time.Time `json:"heartbeat_at"`
	Healthy        bool       `json:"healthy"`
	WorkersOnline  int        `json:"workers_online"`
	WorkersOffline int        `json:"workers_offline"`
	Queued         int        `json:"queued"`
	Running        int        `json:"running"`
	OldestQueuedAt *time.Time `json:"oldest_queued_at"`
	Schedules      int        `json:"schedules"`
	MissedRuns     int        `json:"missed_runs"`
}

// HeartbeatTimeout marks the scheduler unhealthy.
const HeartbeatTimeout = time.Minute

func (s *Service) status(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermScansRead) && !p.HasAnywhere(authz.PermScannersRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var st Status
	err := s.DB.QueryRow(ctx, `
		SELECT COALESCE((SELECT holder FROM scheduler_state WHERE name = 'scheduler'), ''),
		       (SELECT heartbeat_at FROM scheduler_state WHERE name = 'scheduler'),
		       (SELECT count(*) FROM workers WHERE organization_id = $1 AND revoked_at IS NULL AND last_seen_at > now() - $2::interval),
		       (SELECT count(*) FROM workers WHERE organization_id = $1 AND revoked_at IS NULL AND (last_seen_at IS NULL OR last_seen_at <= now() - $2::interval)),
		       (SELECT count(*) FROM scan_jobs WHERE organization_id = $1 AND status = 'queued'),
		       (SELECT count(*) FROM scan_jobs WHERE organization_id = $1 AND status = 'running'),
		       (SELECT min(queued_at) FROM scan_jobs WHERE organization_id = $1 AND status = 'queued'),
		       (SELECT count(*) FROM scan_schedules WHERE organization_id = $1 AND enabled),
		       (SELECT COALESCE(sum(missed_runs), 0) FROM scan_schedules WHERE organization_id = $1)`,
		p.OrganizationID, scans.WorkerOnlineWindow.String()).
		Scan(&st.Leader, &st.HeartbeatAt, &st.WorkersOnline, &st.WorkersOffline, &st.Queued, &st.Running, &st.OldestQueuedAt, &st.Schedules, &st.MissedRuns)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st.Healthy = st.HeartbeatAt != nil && time.Since(*st.HeartbeatAt) < HeartbeatTimeout
	httpx.WriteJSON(w, http.StatusOK, st)
}
