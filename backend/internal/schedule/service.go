package schedule

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
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
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Enabled    bool       `json:"enabled"`
	Cron       string     `json:"cron"`
	Timezone   string     `json:"timezone"`
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
	SELECT s.id, s.name, s.enabled, s.cron, s.timezone, s.target_type, s.target_id,
	       COALESCE(CASE s.target_type
	         WHEN 'organization' THEN 'All repositories'
	         WHEN 'region' THEN (SELECT name FROM regions WHERE id = s.target_id)
	         WHEN 'business_unit' THEN (SELECT name FROM business_units WHERE id = s.target_id)
	         WHEN 'repository' THEN (SELECT full_name FROM repositories WHERE id = s.target_id)
	         WHEN 'profile' THEN (SELECT name FROM scan_profiles WHERE id = s.target_id) END, '(deleted)'),
	       s.priority, s.next_run_at, s.last_run_at, s.last_status, s.last_queued, s.missed_runs, s.created_at
	FROM scan_schedules s`

func scanSchedule(row pgx.Row) (Schedule, error) {
	var s Schedule
	err := row.Scan(&s.ID, &s.Name, &s.Enabled, &s.Cron, &s.Timezone, &s.TargetType, &s.TargetID, &s.TargetName,
		&s.Priority, &s.NextRunAt, &s.LastRunAt, &s.LastStatus, &s.LastQueued, &s.MissedRuns, &s.CreatedAt)
	return s, err
}

// Register mounts the routes.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/schedules", s.list)
	mux.HandleFunc("POST /api/v1/schedules", s.create)
	mux.HandleFunc("POST /api/v1/schedules/preview", s.preview)
	mux.HandleFunc("PUT /api/v1/schedules/{id}", s.update)
	mux.HandleFunc("DELETE /api/v1/schedules/{id}", s.delete)
	mux.HandleFunc("POST /api/v1/schedules/{id}/run", s.runNow)
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

// targetScope maps a schedule target to the scope that authorizes it.
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

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermScansRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(ctx, selectSchedules+` WHERE s.organization_id = $1 ORDER BY s.name`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	all, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Schedule, error) { return scanSchedule(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]Schedule, 0, len(all))
	for _, sc := range all {
		scope := targetScope(p.OrganizationID, sc.TargetType, sc.TargetID)
		if ok, err := s.Authz.Can(ctx, p, authz.PermScansRead, scope); err != nil && !errors.Is(err, org.ErrScopeNotFound) {
			s.fail(w, r, err)
			return
		} else if !ok {
			// Schedules on deleted targets stay visible to org-wide readers.
			if !(errors.Is(err, org.ErrScopeNotFound) && p.HasOrgWide(authz.PermScansRead)) {
				continue
			}
		}
		sc.CanManage, _ = s.Authz.Can(ctx, p, authz.PermSchedulesManage, scope)
		out = append(out, sc)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type scheduleRequest struct {
	Name       string     `json:"name"`
	Enabled    *bool      `json:"enabled"`
	Cron       string     `json:"cron"`
	Timezone   string     `json:"timezone"`
	TargetType string     `json:"target_type"`
	TargetID   *uuid.UUID `json:"target_id"`
	Priority   *int       `json:"priority"`
}

type validated struct {
	cron *Cron
	loc  *time.Location
}

// validate checks the request and that the target exists in the org.
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
	if req.Priority == nil {
		def := 30
		req.Priority = &def
	}
	if *req.Priority < 0 || *req.Priority > 90 {
		return v, httpx.BadRequest("priority must be between 0 and 90 (100 is reserved for emergency scans)")
	}
	table := map[string]string{"region": "regions", "business_unit": "business_units", "repository": "repositories", "profile": "scan_profiles"}
	switch req.TargetType {
	case "organization":
		req.TargetID = nil
	case "region", "business_unit", "repository", "profile":
		if req.TargetID == nil {
			return v, httpx.BadRequest("target_id is required")
		}
		var ok bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+table[req.TargetType]+` WHERE organization_id = $1 AND id = $2)`, orgID, *req.TargetID).Scan(&ok); err != nil {
			return v, err
		}
		if !ok {
			return v, httpx.BadRequest("target not found")
		}
	default:
		return v, httpx.BadRequest("target_type must be organization, region, business_unit, repository or profile")
	}
	return validated{cron: c, loc: loc}, nil
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
	if err := s.Authz.Require(ctx, p, authz.PermSchedulesManage, targetScope(p.OrganizationID, req.TargetType, req.TargetID)); err != nil {
		s.fail(w, r, err)
		return
	}
	enabled := req.Enabled == nil || *req.Enabled
	id := uuid.Must(uuid.NewV7())
	next := v.cron.Next(time.Now(), v.loc)
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO scan_schedules (id, organization_id, name, enabled, cron, timezone, target_type, target_id, priority, next_run_at, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
			id, p.OrganizationID, req.Name, enabled, strings.TrimSpace(req.Cron), req.Timezone, req.TargetType, req.TargetID, *req.Priority, next, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "schedule.create", TargetType: "scan_schedule", TargetID: id.String(),
			Metadata: map[string]any{"name": req.Name, "cron": req.Cron, "timezone": req.Timezone, "target_type": req.TargetType}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sc, err := scanSchedule(s.DB.QueryRow(ctx, selectSchedules+` WHERE s.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	sc.CanManage = true
	httpx.WriteJSON(w, http.StatusCreated, sc)
}

// loadForManage loads a schedule and requires schedules.manage on its target.
func (s *Service) loadForManage(ctx context.Context, q db.Querier, p *authz.Principal, id uuid.UUID, lock bool) (Schedule, error) {
	sql := selectSchedules + ` WHERE s.organization_id = $1 AND s.id = $2`
	if lock {
		sql += ` FOR UPDATE OF s`
	}
	sc, err := scanSchedule(q.QueryRow(ctx, sql, p.OrganizationID, id))
	if err != nil {
		return sc, errNotFound
	}
	scope := targetScope(p.OrganizationID, sc.TargetType, sc.TargetID)
	err = s.Authz.Require(ctx, p, authz.PermSchedulesManage, scope)
	if errors.Is(err, org.ErrScopeNotFound) {
		// Target deleted: only org-wide managers may touch it.
		err = s.Authz.Require(ctx, p, authz.PermSchedulesManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID})
	}
	return sc, err
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
		if err := s.Authz.Require(ctx, p, authz.PermSchedulesManage, targetScope(p.OrganizationID, req.TargetType, req.TargetID)); err != nil {
			return err
		}
		enabled := req.Enabled == nil || *req.Enabled
		if _, err := tx.Exec(ctx, `
			UPDATE scan_schedules SET name = $3, enabled = $4, cron = $5, timezone = $6, target_type = $7, target_id = $8,
			       priority = $9, next_run_at = $10, updated_at = now()
			WHERE organization_id = $1 AND id = $2`,
			p.OrganizationID, id, req.Name, enabled, strings.TrimSpace(req.Cron), req.Timezone, req.TargetType, req.TargetID,
			*req.Priority, v.cron.Next(time.Now(), v.loc)); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "schedule.update", TargetType: "scan_schedule", TargetID: id.String(),
			Metadata: map[string]any{"name": req.Name, "cron": req.Cron, "enabled": enabled, "target_type": req.TargetType}}); err != nil {
			return err
		}
		out, err = scanSchedule(tx.QueryRow(ctx, selectSchedules+` WHERE s.id = $1`, id))
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out.CanManage = true
	httpx.WriteJSON(w, http.StatusOK, out)
}

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

// RunResult summarizes one execution of a schedule.
type RunResult struct {
	Queued    int `json:"queued"`
	Coalesced int `json:"coalesced"`
	Skipped   int `json:"skipped"`
	Failed    int `json:"failed"`
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

// execute enqueues one scan per target repository.
func execute(ctx context.Context, q db.Querier, orgID, scheduleID uuid.UUID, typ string, target *uuid.UUID, priority int, by *uuid.UUID, log *slog.Logger) (RunResult, error) {
	var res RunResult
	repos, err := targetRepos(ctx, q, orgID, typ, target)
	if err != nil {
		return res, err
	}
	sid := scheduleID
	for _, repo := range repos {
		er, err := scans.EnqueueWith(ctx, q, orgID, repo, "schedule", "", "", by, scans.EnqueueOpts{Priority: priority, ScheduleID: &sid})
		switch {
		case errors.Is(err, scans.ErrNotScannable):
			res.Skipped++
		case err != nil:
			res.Failed++
			if log != nil {
				log.Warn("scheduled enqueue failed", "schedule_id", scheduleID, "repository_id", repo, "err", err)
			}
		case er.Coalesced:
			res.Coalesced++
		default:
			res.Queued++
		}
	}
	return res, nil
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
		if res, err = execute(ctx, tx, p.OrganizationID, id, sc.TargetType, sc.TargetID, sc.Priority, &p.UserID, s.Log); err != nil {
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
	if req.TargetType == "" {
		req.TargetType = "organization"
	}
	v, err := s.validate(ctx, s.DB, p.OrganizationID, &req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	runs := make([]time.Time, 0, 5)
	t := time.Now()
	for range 5 {
		if t = v.cron.Next(t, v.loc); t.IsZero() {
			break
		}
		runs = append(runs, t)
	}
	n := 0
	if ok, _ := s.Authz.Can(ctx, p, authz.PermScansRead, targetScope(p.OrganizationID, req.TargetType, req.TargetID)); ok {
		repos, err := targetRepos(ctx, s.DB, p.OrganizationID, req.TargetType, req.TargetID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		n = len(repos)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"next_runs": runs, "repositories": n})
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
