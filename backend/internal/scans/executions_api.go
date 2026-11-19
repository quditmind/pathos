package scans

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
)

// HistoryDays is the supported scan history window (comparison, search).
// Executions are never deleted; logs and events older than the retention
// configured by PATHOS_SCAN_LOG_RETENTION_DAYS are pruned.
const HistoryDays = 360

func (s *Service) registerExecutions(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/scans/overview", s.scanOverview)
	mux.HandleFunc("GET /api/v1/scans/compare", s.compareScans)
	mux.HandleFunc("POST /api/v1/scans/{id}/retry", s.retryScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/findings", s.scanFindings)
	mux.HandleFunc("GET /api/v1/scans/{id}/logs", s.scanLogs)
	mux.HandleFunc("GET /api/v1/scans/{id}/stages", s.scanStages)
	mux.HandleFunc("GET /api/v1/scans/{id}/history", s.scanHistory)
}

// scopeWhere returns the repository visibility condition for perm.
func scopeWhere(p *authz.Principal, perm authz.Permission, first int) (string, []any, bool) {
	f := authz.FilterFor(p, perm)
	if f.None() {
		return "", nil, false
	}
	expr, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", first)
	return expr, args, true
}

// --- retry -------------------------------------------------------------------

func (s *Service) retryScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, j, err := s.loadJobFor(r, authz.PermScansRun)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if j.Status != "failed" && j.Status != "partial" && j.Status != "cancelled" {
		s.fail(w, r, httpx.Conflict("only failed, partial or cancelled scans can be retried"))
		return
	}
	if j.AssetType == "endpoints" && s.Offline {
		s.fail(w, r, httpx.Conflict(errOfflineEndpoints))
		return
	}
	var res EnqueueResult
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if j.TargetID != nil {
			// A target scan is retried as a new scan of the same target.
			res, err = EnqueueTarget(ctx, tx, p.OrganizationID, *j.TargetID, "manual", &p.UserID)
		} else {
			profileID := j.ProfileID
			res, err = EnqueueWith(ctx, tx, p.OrganizationID, j.RepositoryID, j.Trigger, "", j.CommitSHA, &p.UserID,
				EnqueueOpts{ProfileID: &profileID, RetryOf: &j.ID, Name: j.Name, ScheduleID: j.ScheduleID, ScheduleRunID: j.ScheduleRunID})
		}
		if err != nil {
			return err
		}
		if err := AddEvent(ctx, tx, p.OrganizationID, j.ID, "retry", "", "info", "retried as a new execution by "+p.Email); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan.retry", TargetType: "scan_job", TargetID: j.ID.String(),
			Metadata: map[string]any{"scan_key": j.ScanKey, "new_job_id": res.JobID, "repository_key": j.RepositoryKey}})
	})
	if errors.Is(err, ErrNotScannable) || errors.Is(err, ErrScanPrerequisite) {
		err = httpx.Conflict(err.Error())
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	nj, err := scanJob(s.DB.QueryRow(ctx, jobSelect+` WHERE j.id = $1`, res.JobID))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, nj)
}

// --- findings of one execution ----------------------------------------------

// ScanFinding is a finding observed by one execution, with its evidence.
type ScanFinding struct {
	FindingView
	Scanner   string `json:"scanner"`
	Evidence  string `json:"evidence"` // file:line or package@version
	CommitSHA string `json:"occurrence_commit_sha"`
	IsNew     bool   `json:"is_new"` // first seen in this execution
}

func (s *Service) scanFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, j, err := s.loadJobFor(r, authz.PermFindingsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	where := []string{`f.id IN (SELECT o.finding_id FROM finding_occurrences o JOIN scan_results sr ON sr.id = o.scan_result_id WHERE sr.scan_job_id = $2)`}
	args := []any{p.OrganizationID, j.ID}
	if v := q.Get("severity"); v != "" {
		if !slices.Contains([]string{"critical", "high", "medium", "low", "info"}, v) {
			s.fail(w, r, httpx.BadRequest("invalid severity"))
			return
		}
		args = append(args, v)
		where = append(where, fmt.Sprintf("f.severity = $%d", len(args)))
	}
	if v := q.Get("scanner"); v != "" {
		args = append(args, v)
		where = append(where, fmt.Sprintf("$%d = ANY(f.scanner_keys)", len(args)))
	}
	if v := q.Get("kind"); v != "" {
		if _, ok := scanners.LookupKind(v); !ok {
			s.fail(w, r, httpx.BadRequest("invalid kind of check"))
			return
		}
		args = append(args, v)
		where = append(where, fmt.Sprintf("(%s) = $%d", scanners.KindSQL("f"), len(args)))
	}
	rows, err := s.DB.Query(ctx, findingSelect+` WHERE f.organization_id = $1 AND `+strings.Join(where, " AND ")+
		` ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, f.title LIMIT 1000`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	views, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (FindingView, error) { return scanFinding(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]ScanFinding, 0, len(views))
	for _, f := range views {
		sf := ScanFinding{FindingView: f}
		var path string
		var line *int
		_ = s.DB.QueryRow(ctx, `SELECT sr.scanner_key, o.file_path, o.start_line, o.commit_sha,
			(SELECT first_scan_job_id = $2 FROM findings WHERE id = $1)
			FROM finding_occurrences o JOIN scan_results sr ON sr.id = o.scan_result_id
			WHERE o.finding_id = $1 AND sr.scan_job_id = $2 ORDER BY o.created_at LIMIT 1`, f.ID, j.ID).
			Scan(&sf.Scanner, &path, &line, &sf.CommitSHA, &sf.IsNew)
		switch {
		case path != "" && line != nil:
			sf.Evidence = fmt.Sprintf("%s:%d", path, *line)
		case path != "":
			sf.Evidence = path
		case f.PackageName != "":
			sf.Evidence = f.PackageName
			if f.PackageVersion != "" {
				sf.Evidence += "@" + f.PackageVersion
			}
		}
		out = append(out, sf)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// --- logs and stages ---------------------------------------------------------

// LogLine is one execution log line.
type LogLine struct {
	ID      int64     `json:"id"`
	At      time.Time `json:"at"`
	Level   string    `json:"level"`
	Source  string    `json:"source"`
	Message string    `json:"message"`
}

func (s *Service) scanLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, j, err := s.loadJobFor(r, authz.PermScansRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	where := []string{"scan_job_id = $1"}
	args := []any{j.ID}
	if v := q.Get("source"); v != "" {
		args = append(args, v)
		where = append(where, fmt.Sprintf("source = $%d", len(args)))
	}
	if v := q.Get("level"); v != "" {
		levels := map[string][]string{"debug": logLevels, "info": {"info", "warn", "error"}, "warn": {"warn", "error"}, "error": {"error"}}[v]
		if levels == nil {
			s.fail(w, r, httpx.BadRequest("level must be debug, info, warn or error"))
			return
		}
		args = append(args, levels)
		where = append(where, fmt.Sprintf("level = ANY($%d)", len(args)))
	}
	if v := q.Get("after_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid after_id"))
			return
		}
		args = append(args, n)
		where = append(where, fmt.Sprintf("id > $%d", len(args)))
	}
	rows, err := s.DB.Query(ctx, `SELECT id, at, level, source, message FROM scan_job_logs WHERE `+strings.Join(where, " AND ")+
		` ORDER BY id LIMIT 1000`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	lines, err := pgx.CollectRows(rows, pgx.RowToStructByPos[LogLine])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if lines == nil {
		lines = []LogLine{}
	}
	// Platform events are part of the timeline too.
	var sources []string
	_ = s.DB.QueryRow(ctx, `SELECT COALESCE(array_agg(DISTINCT source ORDER BY source), '{}') FROM scan_job_logs WHERE scan_job_id = $1`, j.ID).Scan(&sources)
	var next *int64
	if len(lines) == 1000 {
		next = &lines[len(lines)-1].ID
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": lines, "sources": sources, "next_after_id": next})
}

// Stage is one execution stage or scanner engine job.
type Stage struct {
	Key     string `json:"key"` // queued | leased | source | scanner:<key> | finalize
	Label   string `json:"label"`
	Scanner string `json:"scanner"` // engine key for scanner stages (audit; the UI shows the kind of check)
	// KindOfCheck and KindOfCheckName: the kind of check of a scanner stage.
	KindOfCheck     string     `json:"kind_of_check,omitempty"`
	KindOfCheckName string     `json:"kind_of_check_name,omitempty"`
	Version         string     `json:"scanner_version"`
	Status          string     `json:"status"` // pending | running | succeeded | failed | skipped | timed_out | cancelled
	StartedAt       *time.Time `json:"started_at"`
	FinishedAt      *time.Time `json:"finished_at"`
	DurationMS      *int64     `json:"duration_ms"`
	Findings        *int       `json:"findings"`
	Error           string     `json:"error"`
}

// Event is a recorded stage event.
type Event struct {
	Stage   string    `json:"stage"`
	Scanner string    `json:"scanner"`
	Status  string    `json:"status"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

func (s *Service) loadStages(ctx context.Context, j Job) ([]Stage, []Event, error) {
	rows, err := s.DB.Query(ctx, `SELECT stage, scanner_key, status, message, at FROM scan_job_events WHERE scan_job_id = $1 ORDER BY at, id`, j.ID)
	if err != nil {
		return nil, nil, err
	}
	events, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Event])
	if err != nil {
		return nil, nil, err
	}
	if events == nil {
		events = []Event{}
	}
	first := func(stage, scanner string, statuses ...string) *time.Time {
		for _, e := range events {
			if e.Stage == stage && e.Scanner == scanner && (len(statuses) == 0 || slices.Contains(statuses, e.Status)) {
				t := e.At
				return &t
			}
		}
		return nil
	}
	dur := func(a, b *time.Time) *int64 {
		if a == nil || b == nil {
			return nil
		}
		d := b.Sub(*a).Milliseconds()
		return &d
	}
	terminal := j.Status != "queued" && j.Status != "running"
	stages := []Stage{{Key: "queued", Label: "Queued", Status: "succeeded", StartedAt: &j.QueuedAt, FinishedAt: j.StartedAt}}
	if j.StartedAt == nil {
		stages[0].Status, stages[0].FinishedAt = map[bool]string{true: "cancelled", false: "running"}[terminal], nil
	}
	stages[0].DurationMS = dur(stages[0].StartedAt, stages[0].FinishedAt)

	srcStart, srcOK, srcFail := first("source", "", "started"), first("source", "", "succeeded"), first("source", "", "failed")
	src := Stage{Key: "source", Label: "Source checkout", Status: "pending", StartedAt: srcStart}
	switch {
	case srcFail != nil:
		src.Status, src.FinishedAt = "failed", srcFail
		for _, e := range events {
			if e.Stage == "source" && e.Status == "failed" {
				src.Error = e.Message
			}
		}
	case srcOK != nil:
		src.Status, src.FinishedAt = "succeeded", srcOK
	case srcStart != nil:
		src.Status = "running"
	case j.StartedAt != nil && terminal:
		src.Status = "succeeded" // older workers do not report source events
	}
	src.DurationMS = dur(src.StartedAt, src.FinishedAt)
	stages = append(stages, src)

	// Scanner engine jobs: the profile snapshot lists them; results give outcomes.
	var keys []string
	if sc, ok := j.ConfigSnapshot["scanners"].([]any); ok {
		for _, x := range sc {
			if m, ok := x.(map[string]any); ok {
				if k, ok := m["key"].(string); ok {
					keys = append(keys, k)
				}
			}
		}
	}
	byKey := map[string]Result{}
	for _, res := range j.Results {
		byKey[res.ScannerKey] = res
		if !slices.Contains(keys, res.ScannerKey) {
			keys = append(keys, res.ScannerKey)
		}
	}
	for _, k := range keys {
		kind := scanners.PrimaryKindOfTool(k)
		st := Stage{Key: "scanner:" + k, Label: k, Scanner: k, Status: "pending", StartedAt: first("scanner", k, "started"),
			KindOfCheck: kind, KindOfCheckName: scanners.KindName(kind)}
		if res, ok := byKey[k]; ok {
			st.Status, st.Version, st.Error = res.Status, res.ScannerVersion, res.Error
			n := res.FindingsCount
			st.Findings = &n
			fin := first("scanner", k, "succeeded", "failed", "skipped", "timed_out")
			st.FinishedAt = fin
			d := int64(res.DurationMS)
			st.DurationMS = &d
			if st.StartedAt == nil && fin != nil {
				t := fin.Add(-time.Duration(res.DurationMS) * time.Millisecond)
				st.StartedAt = &t
			}
		} else if st.StartedAt != nil && !terminal {
			st.Status = "running"
		} else if terminal {
			st.Status = map[bool]string{true: "cancelled", false: "skipped"}[j.Status == "cancelled"]
		}
		stages = append(stages, st)
	}
	fin := Stage{Key: "finalize", Label: "Findings and results", Status: "pending"}
	if f := first("finalize", ""); f != nil || (terminal && j.FinishedAt != nil) {
		fin.FinishedAt = j.FinishedAt
		fin.Status = map[string]string{"succeeded": "succeeded", "partial": "succeeded", "failed": "failed", "cancelled": "cancelled"}[j.Status]
	}
	stages = append(stages, fin)
	return stages, events, nil
}

// KindProgress is the progress of one kind of check in a scan: "Infrastructure
// as code: 7 of 10 checks finished" (scan progress names kinds, not tools).
type KindProgress struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Total    int    `json:"total"`
	Finished int    `json:"finished"`
	Failed   int    `json:"failed"`
	Running  int    `json:"running"`
}

// KindProgressOf groups the scanner stages by kind of check, in the order of
// the kinds.
func KindProgressOf(stages []Stage) []KindProgress {
	by := map[string]*KindProgress{}
	for _, st := range stages {
		if st.Scanner == "" {
			continue
		}
		kp := by[st.KindOfCheck]
		if kp == nil {
			kp = &KindProgress{ID: st.KindOfCheck, Name: st.KindOfCheckName}
			by[st.KindOfCheck] = kp
		}
		kp.Total++
		switch st.Status {
		case "succeeded", "skipped", "cancelled":
			kp.Finished++
		case "failed", "timed_out":
			kp.Finished++
			kp.Failed++
		case "running":
			kp.Running++
		}
	}
	out := []KindProgress{}
	for _, k := range append(append([]scanners.CheckKind{}, scanners.CheckKinds...), scanners.OutsideKinds...) {
		if kp := by[k.ID]; kp != nil {
			out = append(out, *kp)
		}
	}
	return out
}

func (s *Service) scanStages(w http.ResponseWriter, r *http.Request) {
	_, j, err := s.loadJobFor(r, authz.PermScansRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.loadDetail(r.Context(), &j); err != nil {
		s.fail(w, r, err)
		return
	}
	stages, events, err := s.loadStages(r.Context(), j)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"stages": stages, "events": events, "kinds": KindProgressOf(stages)})
}

// loadDetail adds results and the configuration snapshot to a job.
func (s *Service) loadDetail(ctx context.Context, j *Job) error {
	rows, err := s.DB.Query(ctx, `SELECT sr.scanner_key, sr.scanner_version, sr.status, sr.duration_ms, sr.findings_count, sr.error,
		EXISTS (SELECT 1 FROM scan_artifacts a WHERE a.scan_result_id = sr.id)
		FROM scan_results sr JOIN scanner_catalog c ON c.key = sr.scanner_key
		WHERE sr.scan_job_id = $1 ORDER BY c.sort_order`, j.ID)
	if err != nil {
		return err
	}
	if j.Results, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Result]); err != nil {
		return err
	}
	if j.Results == nil {
		j.Results = []Result{}
	}
	var snap []byte
	if err := s.DB.QueryRow(ctx, `SELECT config_snapshot FROM scan_jobs WHERE id = $1`, j.ID).Scan(&snap); err != nil {
		return err
	}
	if len(snap) > 0 {
		_ = json.Unmarshal(snap, &j.ConfigSnapshot)
	}
	return nil
}

// --- history -----------------------------------------------------------------

func (s *Service) scanHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, j, err := s.loadJobFor(r, authz.PermScansRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, jobSelect+` WHERE j.organization_id = $1 AND j.repository_id = $2
		AND j.queued_at > now() - make_interval(days => $3) ORDER BY j.queued_at DESC, j.id DESC LIMIT 200`,
		p.OrganizationID, j.RepositoryID, HistoryDays)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	jobs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Job, error) { return scanJob(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if jobs == nil {
		jobs = []Job{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": jobs})
}

// --- overview ------------------------------------------------------------------

func (s *Service) scanOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	days := 30
	if v := r.URL.Query().Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > HistoryDays {
			s.fail(w, r, httpx.BadRequest(fmt.Sprintf("days must be 1-%d", HistoryDays)))
			return
		}
		days = n
	}
	scope, sargs, ok := scopeWhere(p, authz.PermScansRead, 3)
	if !ok {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	args := append([]any{p.OrganizationID, days}, sargs...)
	base := ` FROM scan_jobs j JOIN repositories r ON r.id = j.repository_id
		WHERE j.organization_id = $1 AND ` + scope
	type totals struct {
		Total     int `json:"total"`
		Running   int `json:"running"`
		Queued    int `json:"queued"`
		Completed int `json:"completed"` // succeeded + partial
		Failed    int `json:"failed"`
		Cancelled int `json:"cancelled"`
	}
	var t totals
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FILTER (WHERE j.queued_at > now() - make_interval(days => $2)),
		count(*) FILTER (WHERE j.status = 'running'), count(*) FILTER (WHERE j.status = 'queued'),
		count(*) FILTER (WHERE j.status IN ('succeeded', 'partial') AND j.queued_at > now() - make_interval(days => $2)),
		count(*) FILTER (WHERE j.status = 'failed' AND j.queued_at > now() - make_interval(days => $2)),
		count(*) FILTER (WHERE j.status = 'cancelled' AND j.queued_at > now() - make_interval(days => $2))`+base, args...).
		Scan(&t.Total, &t.Running, &t.Queued, &t.Completed, &t.Failed, &t.Cancelled); err != nil {
		s.fail(w, r, err)
		return
	}
	findings := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
	fscope, fargs, fok := scopeWhere(p, authz.PermFindingsRead, 2)
	if fok {
		rows, err := s.DB.Query(ctx, `SELECT f.severity, count(*) FROM findings f JOIN repositories r ON r.id = f.repository_id
			WHERE f.organization_id = $1 AND f.status IN ('open', 'in_progress', 'needs_review') AND r.archived_at IS NULL AND `+fscope+
			` GROUP BY f.severity`, append([]any{p.OrganizationID}, fargs...)...)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for rows.Next() {
			var sev string
			var n int
			if err := rows.Scan(&sev, &n); err == nil {
				findings[sev] = n
			}
		}
		rows.Close()
	}
	total := 0
	for _, n := range findings {
		total += n
	}
	rscope, rargs, _ := scopeWhere(p, authz.PermScansRead, 2)
	rrows, err := s.DB.Query(ctx, jobSelect+` WHERE j.organization_id = $1 AND `+rscope+` ORDER BY j.queued_at DESC, j.id DESC LIMIT 10`,
		append([]any{p.OrganizationID}, rargs...)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	recent, err := pgx.CollectRows(rrows, func(row pgx.CollectableRow) (Job, error) { return scanJob(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if recent == nil {
		recent = []Job{}
	}
	type point struct {
		Day       string `json:"day"`
		Completed int    `json:"completed"`
		Failed    int    `json:"failed"`
		Cancelled int    `json:"cancelled"`
		Findings  int    `json:"new_findings"`
	}
	rows, err := s.DB.Query(ctx, `SELECT to_char(d.day, 'YYYY-MM-DD'),
		count(j.id) FILTER (WHERE j.status IN ('succeeded', 'partial')), count(j.id) FILTER (WHERE j.status = 'failed'),
		count(j.id) FILTER (WHERE j.status = 'cancelled'), COALESCE(sum(j.findings_new), 0)
		FROM generate_series(date_trunc('day', now()) - make_interval(days => $2 - 1), date_trunc('day', now()), interval '1 day') d(day)
		LEFT JOIN (SELECT j.* `+base+`) j ON date_trunc('day', COALESCE(j.finished_at, j.queued_at)) = d.day
		GROUP BY d.day ORDER BY d.day`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	trend, err := pgx.CollectRows(rows, pgx.RowToStructByPos[point])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	upcoming, err := s.upcomingSchedules(ctx, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"days": days, "scans": t, "open_findings": findings,
		"open_findings_total": total, "critical_high": findings["critical"] + findings["high"],
		"recent": recent, "trend": trend, "upcoming": upcoming})
}

// Upcoming is a scheduled activation.
type Upcoming struct {
	ScheduleID uuid.UUID `json:"schedule_id"`
	Name       string    `json:"name"`
	NextRunAt  time.Time `json:"next_run_at"`
	Kind       string    `json:"kind"`
}

func (s *Service) upcomingSchedules(ctx context.Context, p *authz.Principal) ([]Upcoming, error) {
	out := []Upcoming{}
	if !p.HasAnywhere(authz.PermScansRead) {
		return out, nil
	}
	rows, err := s.DB.Query(ctx, `SELECT id, name, next_run_at, kind FROM scan_schedules
		WHERE organization_id = $1 AND enabled AND next_run_at IS NOT NULL ORDER BY next_run_at LIMIT 10`, p.OrganizationID)
	if err != nil {
		return nil, err
	}
	list, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Upcoming])
	if list != nil {
		out = list
	}
	return out, err
}

// --- comparison ----------------------------------------------------------------

// CompareScan is one execution in a comparison.
type CompareScan struct {
	Job
	Scanners      []Result `json:"scanners"`
	CoveredOK     []string `json:"succeeded_scanners"`
	Complete      bool     `json:"complete"` // succeeded with every scanner reporting
	New           int      `json:"new"`
	Fixed         int      `json:"fixed"`
	Recurring     int      `json:"recurring"`
	Unchanged     int      `json:"unchanged"`
	NotCovered    int      `json:"not_covered"` // absent, but the covering scanner did not succeed
	ProfileChange bool     `json:"profile_changed"`
	EngineChanges []string `json:"engine_changes"`
	DurationDelta *int64   `json:"duration_delta_ms"`
}

// CompareFinding is one finding across the compared executions.
type CompareFinding struct {
	ID       uuid.UUID         `json:"id"`
	Title    string            `json:"title"`
	Severity string            `json:"severity"`
	Scanners []string          `json:"scanners"`
	States   map[string]string `json:"states"` // job id -> new | recurring | unchanged | fixed | not_covered | absent
}

func (s *Service) compareScans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermScansCompare) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var ids []uuid.UUID
	for _, v := range strings.Split(r.URL.Query().Get("ids"), ",") {
		if v = strings.TrimSpace(v); v == "" {
			continue
		}
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("ids must be scan execution UUIDs"))
			return
		}
		if !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) < 2 || len(ids) > 10 {
		s.fail(w, r, httpx.BadRequest("select 2-10 scans to compare"))
		return
	}
	jobs := make([]CompareScan, 0, len(ids))
	for _, id := range ids {
		j, err := scanJob(s.DB.QueryRow(ctx, jobSelect+` WHERE j.organization_id = $1 AND j.id = $2`, p.OrganizationID, id))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if err := s.requireRepo(ctx, p, authz.PermScansCompare, j.RepositoryID); err != nil {
			s.fail(w, r, err)
			return
		}
		if err := s.loadDetail(ctx, &j); err != nil {
			s.fail(w, r, err)
			return
		}
		cs := CompareScan{Job: j, Scanners: j.Results, EngineChanges: []string{}, CoveredOK: []string{}}
		for _, res := range j.Results {
			if res.Status == "succeeded" {
				cs.CoveredOK = append(cs.CoveredOK, res.ScannerKey)
			}
		}
		cs.Complete = j.Status == "succeeded"
		jobs = append(jobs, cs)
	}
	// Chronological order: each execution is compared with the previous one.
	sort.SliceStable(jobs, func(a, b int) bool { return jobs[a].QueuedAt.Before(jobs[b].QueuedAt) })

	// Findings observed per execution.
	seen := make([]map[uuid.UUID]bool, len(jobs))
	all := map[uuid.UUID]*CompareFinding{}
	firstSeen := map[uuid.UUID]time.Time{}
	for i, j := range jobs {
		seen[i] = map[uuid.UUID]bool{}
		rows, err := s.DB.Query(ctx, `SELECT DISTINCT f.id, f.title, f.severity, f.scanner_keys, f.first_seen_at
			FROM finding_occurrences o JOIN scan_results sr ON sr.id = o.scan_result_id JOIN findings f ON f.id = o.finding_id
			WHERE sr.scan_job_id = $1`, j.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for rows.Next() {
			var cf CompareFinding
			var fs time.Time
			if err := rows.Scan(&cf.ID, &cf.Title, &cf.Severity, &cf.Scanners, &fs); err != nil {
				rows.Close()
				s.fail(w, r, err)
				return
			}
			seen[i][cf.ID] = true
			if _, ok := all[cf.ID]; !ok {
				cf.States = map[string]string{}
				c := cf
				all[cf.ID] = &c
				firstSeen[cf.ID] = fs
			}
		}
		rows.Close()
	}
	covers := func(js CompareScan, scanners []string) bool {
		for _, k := range scanners {
			if slices.Contains(js.CoveredOK, k) {
				return true
			}
		}
		return false
	}
	for i := range jobs {
		key := jobs[i].ID.String()
		for id, f := range all {
			in := seen[i][id]
			switch {
			case i == 0 && in:
				f.States[key] = "present"
			case i == 0:
				f.States[key] = "absent"
			case in && seen[i-1][id]:
				f.States[key] = "unchanged"
				jobs[i].Unchanged++
			case in && firstSeen[id].Before(jobs[i-1].QueuedAt):
				// Seen before the previous execution, gone in it, back now.
				f.States[key] = "recurring"
				jobs[i].Recurring++
			case in:
				f.States[key] = "new"
				jobs[i].New++
			case seen[i-1][id] && (jobs[i].Status == "failed" || jobs[i].Status == "cancelled" || !covers(jobs[i], f.Scanners)):
				// A failed or incomplete execution, or one whose covering
				// scanner did not succeed, never proves a fix.
				f.States[key] = "not_covered"
				jobs[i].NotCovered++
			case seen[i-1][id]:
				f.States[key] = "fixed"
				jobs[i].Fixed++
			default:
				f.States[key] = "absent"
			}
		}
		if i > 0 {
			prev := jobs[i-1]
			// Every execution records its profile and version (older ones
			// have no snapshot), so compare those.
			jobs[i].ProfileChange = prev.ProfileID != jobs[i].ProfileID || prev.ProfileVersion != jobs[i].ProfileVersion
			jobs[i].EngineChanges = engineChanges(prev.Results, jobs[i].Results)
			if prev.DurationMS != nil && jobs[i].DurationMS != nil {
				d := *jobs[i].DurationMS - *prev.DurationMS
				jobs[i].DurationDelta = &d
			}
		}
	}
	findings := make([]CompareFinding, 0, len(all))
	for _, f := range all {
		findings = append(findings, *f)
	}
	sort.Slice(findings, func(a, b int) bool {
		ra, rb := severityIndex(findings[a].Severity), severityIndex(findings[b].Severity)
		if ra != rb {
			return ra < rb
		}
		return findings[a].Title < findings[b].Title
	})
	if len(findings) > 2000 {
		findings = findings[:2000]
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"scans": jobs, "findings": findings})
}

func severityIndex(s string) int {
	return map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[s]
}

// engineChanges lists scanners added, removed or with a different version.
func engineChanges(prev, cur []Result) []string {
	pm, cm := map[string]string{}, map[string]string{}
	for _, r := range prev {
		pm[r.ScannerKey] = r.ScannerVersion
	}
	for _, r := range cur {
		cm[r.ScannerKey] = r.ScannerVersion
	}
	out := []string{}
	for k, v := range cm {
		switch pv, ok := pm[k]; {
		case !ok:
			out = append(out, k+" added")
		case pv != v && pv != "" && v != "":
			out = append(out, fmt.Sprintf("%s %s → %s", k, pv, v))
		}
	}
	for k := range pm {
		if _, ok := cm[k]; !ok {
			out = append(out, k+" removed")
		}
	}
	slices.Sort(out)
	return out
}
