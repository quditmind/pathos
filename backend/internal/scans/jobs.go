package scans

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	"pathos/internal/scm"
)

func (s *Service) registerJobs(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/repositories/{id}/scan", s.scanRepository)
	mux.HandleFunc("POST /api/v1/scans", s.bulkScan)
	mux.HandleFunc("GET /api/v1/scans", s.listJobs)
	mux.HandleFunc("GET /api/v1/scans/{id}", s.getJob)
	mux.HandleFunc("POST /api/v1/scans/{id}/cancel", s.cancelJob)
	mux.HandleFunc("GET /api/v1/scans/{id}/results/{scanner}/artifact", s.downloadArtifact)
	mux.HandleFunc("PUT /api/v1/repositories/{id}/scan-profile", s.setRepoProfile)
}

// Trigger priorities: interactive requests jump ahead of automation.
var priorities = map[string]int{"emergency": 100, "manual": 70, "merge": 60, "push": 50, "onboarding": 40, "schedule": 30}

// ErrNotScannable means the repository is archived or scanning is disabled.
var ErrNotScannable = errors.New("repository is archived or scanning is disabled")

// EnqueueResult describes what Enqueue did.
type EnqueueResult struct {
	JobID     uuid.UUID `json:"job_id"`
	Coalesced bool      `json:"coalesced"` // merged into an already queued job
}

// Enqueue creates (or coalesces into) the repository's queued scan job.
// A repository has at most one queued job: a new trigger while one is
// queued updates its commit and raises its priority instead.
func Enqueue(ctx context.Context, q db.Querier, orgID, repoID uuid.UUID, trigger, ref, commit string, by *uuid.UUID) (EnqueueResult, error) {
	var res EnqueueResult
	var scanBranch, defaultBranch string
	var enabled bool
	var archived *time.Time
	var profileVersion *uuid.UUID
	err := q.QueryRow(ctx, `
		SELECT r.scan_branch, r.default_branch, r.scan_enabled, r.archived_at,
		       COALESCE((SELECT current_version_id FROM scan_profiles WHERE id = r.scan_profile_id AND archived_at IS NULL),
		                (SELECT current_version_id FROM scan_profiles WHERE organization_id = r.organization_id AND is_default AND archived_at IS NULL))
		FROM repositories r WHERE r.organization_id = $1 AND r.id = $2`, orgID, repoID).
		Scan(&scanBranch, &defaultBranch, &enabled, &archived, &profileVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, errNotFound
	}
	if err != nil {
		return res, err
	}
	if archived != nil || (!enabled && trigger != "manual" && trigger != "emergency") {
		return res, ErrNotScannable
	}
	if profileVersion == nil {
		return res, errors.New("no scan profile available; create a default profile")
	}
	if ref == "" {
		ref = scanBranch
	}
	if ref == "" {
		ref = defaultBranch
	}
	if ref == "" {
		return res, errors.New("repository has no default branch; set a scan branch")
	}
	prio := priorities[trigger]
	err = q.QueryRow(ctx, `
		UPDATE scan_jobs SET commit_sha = CASE WHEN $3 <> '' THEN $3 ELSE commit_sha END,
		       priority = GREATEST(priority, $4), ref = $5
		WHERE repository_id = $1 AND organization_id = $2 AND status = 'queued' RETURNING id`,
		repoID, orgID, commit, prio, ref).Scan(&res.JobID)
	if err == nil {
		res.Coalesced = true
		return res, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return res, err
	}
	res.JobID = uuid.Must(uuid.NewV7())
	_, err = q.Exec(ctx, `
		INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, priority, ref, commit_sha, requested_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, res.JobID, orgID, repoID, *profileVersion, trigger, prio, ref, commit, by)
	if db.IsUniqueViolation(err) {
		// Lost a race with a concurrent trigger: use its queued job.
		if err := q.QueryRow(ctx, `SELECT id FROM scan_jobs WHERE repository_id = $1 AND status = 'queued'`, repoID).Scan(&res.JobID); err != nil {
			return res, err
		}
		res.Coalesced = true
		return res, nil
	}
	return res, err
}

// OnWebhookEvent queues scans for pushes and merges to the scan branch.
// Pull request scanning is not performed (findings are tracked per scan
// branch).
func (s *Service) OnWebhookEvent(ctx context.Context, orgID, repoID uuid.UUID, ev scm.WebhookEvent) {
	if ev.Kind != "push" && ev.Kind != "merge" {
		return
	}
	var scanBranch, def string
	if err := s.DB.QueryRow(ctx, `SELECT scan_branch, default_branch FROM repositories WHERE id = $1`, repoID).Scan(&scanBranch, &def); err != nil {
		return
	}
	target := scanBranch
	if target == "" {
		target = def
	}
	if ev.Ref != target {
		return
	}
	res, err := Enqueue(ctx, s.DB, orgID, repoID, ev.Kind, ev.Ref, ev.CommitSHA, nil)
	if err != nil && !errors.Is(err, ErrNotScannable) {
		s.Log.Warn("webhook scan enqueue failed", "repository_id", repoID, "err", err)
		return
	}
	if err == nil {
		s.Log.Info("scan queued from webhook", "repository_id", repoID, "job_id", res.JobID, "coalesced", res.Coalesced)
	}
}

func (s *Service) enqueueAs(ctx context.Context, p *authz.Principal, repoID uuid.UUID, trigger string) (EnqueueResult, error) {
	if err := s.requireRepo(ctx, p, authz.PermScansRun, repoID); err != nil {
		return EnqueueResult{}, err
	}
	var res EnqueueResult
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		res, err = Enqueue(ctx, tx, p.OrganizationID, repoID, trigger, "", "", &p.UserID)
		if err != nil {
			return err
		}
		if res.Coalesced {
			return nil
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan.request", TargetType: "repository", TargetID: repoID.String(), Metadata: map[string]any{"job_id": res.JobID, "trigger": trigger}})
	})
	return res, err
}

func (s *Service) scanRepository(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.enqueueAs(r.Context(), p, id, "manual")
	if errors.Is(err, ErrNotScannable) {
		err = httpx.Conflict(err.Error())
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, res)
}

type bulkScanRequest struct {
	RepositoryIDs []uuid.UUID `json:"repository_ids"`
	Trigger       string      `json:"trigger"`
}

func (s *Service) bulkScan(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req bulkScanRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Trigger == "" {
		req.Trigger = "manual"
	}
	if req.Trigger != "manual" && req.Trigger != "emergency" && req.Trigger != "onboarding" {
		s.fail(w, r, httpx.BadRequest("trigger must be manual, emergency or onboarding"))
		return
	}
	if len(req.RepositoryIDs) == 0 || len(req.RepositoryIDs) > 1000 {
		s.fail(w, r, httpx.BadRequest("select 1-1000 repositories"))
		return
	}
	type item struct {
		RepositoryID uuid.UUID  `json:"repository_id"`
		JobID        *uuid.UUID `json:"job_id,omitempty"`
		Coalesced    bool       `json:"coalesced,omitempty"`
		Error        string     `json:"error,omitempty"`
	}
	out := make([]item, 0, len(req.RepositoryIDs))
	for _, id := range req.RepositoryIDs {
		res, err := s.enqueueAs(ctx, p, id, req.Trigger)
		it := item{RepositoryID: id}
		if err != nil {
			it.Error = "not scannable or not permitted"
			if errors.Is(err, ErrNotScannable) {
				it.Error = ErrNotScannable.Error()
			}
		} else {
			it.JobID, it.Coalesced = &res.JobID, res.Coalesced
		}
		out = append(out, it)
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"items": out})
}

// Job is the API view of a scan job.
type Job struct {
	ID             uuid.UUID  `json:"id"`
	RepositoryID   uuid.UUID  `json:"repository_id"`
	RepositoryName string     `json:"repository_name"`
	ProfileName    string     `json:"profile_name"`
	ProfileVersion int        `json:"profile_version"`
	Trigger        string     `json:"trigger"`
	Priority       int        `json:"priority"`
	Status         string     `json:"status"`
	Ref            string     `json:"ref"`
	CommitSHA      string     `json:"commit_sha"`
	Attempts       int        `json:"attempts"`
	WorkerName     *string    `json:"worker_name"`
	RequestedBy    *string    `json:"requested_by"`
	Error          string     `json:"error"`
	FindingsNew    int        `json:"findings_new"`
	FindingsFixed  int        `json:"findings_fixed"`
	GateFailed     bool       `json:"gate_failed"`
	QueuedAt       time.Time  `json:"queued_at"`
	StartedAt      *time.Time `json:"started_at"`
	FinishedAt     *time.Time `json:"finished_at"`
	Results        []Result   `json:"results,omitempty"`
}

// Result is one scanner's outcome within a job.
type Result struct {
	ScannerKey     string `json:"scanner_key"`
	ScannerVersion string `json:"scanner_version"`
	Status         string `json:"status"`
	DurationMS     int    `json:"duration_ms"`
	FindingsCount  int    `json:"findings_count"`
	Error          string `json:"error"`
	HasArtifact    bool   `json:"has_artifact"`
}

const jobSelect = `
	SELECT j.id, j.repository_id, r.full_name, sp.name, v.version, j.trigger, j.priority, j.status, j.ref, j.commit_sha,
	       j.attempts, wk.name, COALESCE(NULLIF(u.display_name, ''), u.email), j.error, j.findings_new, j.findings_fixed,
	       j.gate_failed, j.queued_at, j.started_at, j.finished_at
	FROM scan_jobs j
	JOIN repositories r ON r.id = j.repository_id
	LEFT JOIN countries co ON co.id = r.country_id
	JOIN scan_profile_versions v ON v.id = j.profile_version_id
	JOIN scan_profiles sp ON sp.id = v.profile_id
	LEFT JOIN workers wk ON wk.id = j.leased_by
	LEFT JOIN users u ON u.id = j.requested_by`

func scanJob(row pgx.Row) (Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.RepositoryID, &j.RepositoryName, &j.ProfileName, &j.ProfileVersion, &j.Trigger, &j.Priority,
		&j.Status, &j.Ref, &j.CommitSHA, &j.Attempts, &j.WorkerName, &j.RequestedBy, &j.Error, &j.FindingsNew,
		&j.FindingsFixed, &j.GateFailed, &j.QueuedAt, &j.StartedAt, &j.FinishedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, errNotFound
	}
	return j, err
}

var jobStatuses = map[string]bool{"queued": true, "running": true, "succeeded": true, "partial": true, "failed": true, "cancelled": true}

func (s *Service) listJobs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermScansRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	args := []any{p.OrganizationID}
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	args = append(args, sargs...)
	where := []string{"j.organization_id = $1", scope}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if v := q.Get("repository_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid repository_id"))
			return
		}
		add("j.repository_id = ?", id)
	}
	if v := q.Get("status"); v != "" {
		if v == "active" {
			where = append(where, "j.status IN ('queued', 'running')")
		} else if !jobStatuses[v] {
			s.fail(w, r, httpx.BadRequest("invalid status"))
			return
		} else {
			add("j.status = ?", v)
		}
	}
	if c := q.Get("cursor"); c != "" {
		ts, idStr, ok := strings.Cut(c, "|")
		t, terr := time.Parse(time.RFC3339Nano, ts)
		id, ierr := uuid.Parse(idStr)
		if !ok || terr != nil || ierr != nil {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		args = append(args, t, id)
		where = append(where, fmt.Sprintf("(j.queued_at, j.id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	rows, err := s.DB.Query(ctx, jobSelect+" WHERE "+strings.Join(where, " AND ")+" ORDER BY j.queued_at DESC, j.id DESC LIMIT 50", args...)
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
	var next *string
	if len(jobs) == 50 {
		last := jobs[len(jobs)-1]
		c := last.QueuedAt.Format(time.RFC3339Nano) + "|" + last.ID.String()
		next = &c
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": jobs, "next_cursor": next})
}

func (s *Service) loadJobFor(r *http.Request, perm authz.Permission) (*authz.Principal, Job, error) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		return p, Job{}, err
	}
	j, err := scanJob(s.DB.QueryRow(ctx, jobSelect+` WHERE j.organization_id = $1 AND j.id = $2`, p.OrganizationID, id))
	if err != nil {
		return p, j, err
	}
	if err := s.requireRepo(ctx, p, perm, j.RepositoryID); err != nil {
		return p, Job{}, err
	}
	return p, j, nil
}

func (s *Service) getJob(w http.ResponseWriter, r *http.Request) {
	_, j, err := s.loadJobFor(r, authz.PermScansRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT sr.scanner_key, sr.scanner_version, sr.status, sr.duration_ms, sr.findings_count, sr.error,
		EXISTS (SELECT 1 FROM scan_artifacts a WHERE a.scan_result_id = sr.id)
		FROM scan_results sr JOIN scanner_catalog c ON c.key = sr.scanner_key
		WHERE sr.scan_job_id = $1 ORDER BY c.sort_order`, j.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	j.Results, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Result])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if j.Results == nil {
		j.Results = []Result{}
	}
	httpx.WriteJSON(w, http.StatusOK, j)
}

func (s *Service) cancelJob(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, j, err := s.loadJobFor(r, authz.PermScansRun)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE scan_jobs SET status = 'cancelled', finished_at = now(), lease_expires_at = NULL,
			error = 'cancelled by ' || $2 WHERE id = $1 AND status IN ('queued', 'running')`, j.ID, p.Email)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpx.Conflict("only queued or running scans can be cancelled")
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan.cancel", TargetType: "scan_job", TargetID: j.ID.String(), Metadata: map[string]any{"repository": j.RepositoryName}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// downloadArtifact streams the raw report (or SBOM) of one scanner run.
func (s *Service) downloadArtifact(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	_, j, err := s.loadJobFor(r, authz.PermScansRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	scanner := r.PathValue("scanner")
	var ct string
	var data []byte
	err = s.DB.QueryRow(ctx, `SELECT a.content_type, a.data_gzip FROM scan_artifacts a
		JOIN scan_results sr ON sr.id = a.scan_result_id
		WHERE sr.scan_job_id = $1 AND sr.scanner_key = $2 ORDER BY a.kind LIMIT 1`, j.ID, scanner).Scan(&ct, &data)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer zr.Close()
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-%s.json"`, scanner, j.ID))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = io.Copy(w, io.LimitReader(zr, 512<<20))
}

type setProfileRequest struct {
	ProfileID *uuid.UUID `json:"profile_id"` // null = organization default
}

func (s *Service) setRepoProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermReposManage, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var req setProfileRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if req.ProfileID != nil {
			var ok bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scan_profiles WHERE id = $1 AND organization_id = $2 AND archived_at IS NULL)`,
				*req.ProfileID, p.OrganizationID).Scan(&ok); err != nil {
				return err
			}
			if !ok {
				return httpx.BadRequest("scan profile does not exist")
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE repositories SET scan_profile_id = $2, updated_at = now() WHERE id = $1`, id, req.ProfileID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.set_scan_profile", TargetType: "repository", TargetID: id.String(), Metadata: map[string]any{"profile_id": req.ProfileID}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
