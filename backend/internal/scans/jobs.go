package scans

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"pathos/internal/platform/objstore"
	"slices"
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
	mux.HandleFunc("GET /api/v1/scans/{id}/gate", s.scanGate)
	mux.HandleFunc("POST /api/v1/scans/{id}/cancel", s.cancelJob)
	s.registerExecutions(mux)
	mux.HandleFunc("GET /api/v1/scans/{id}/results/{scanner}/artifact", s.downloadArtifact)
	mux.HandleFunc("PUT /api/v1/repositories/{id}/scan-profile", s.setRepoProfile)
}

// Trigger priorities: interactive requests jump ahead of automation.
var priorities = map[string]int{"emergency": 100, "manual": 70, "merge": 60, "pull_request": 55, "push": 50, "onboarding": 40, "schedule": 30,
	// CodeGraph discovery (rediscovery after scans): after the scans.
	"codegraph": 20}

// ErrNotScannable means the repository is archived or scanning is disabled.
var ErrNotScannable = errors.New("repository is archived or scanning is disabled")

// ErrScanPrerequisite means something must be configured before scanning
// (a scan profile, a snapshot or a branch).
var ErrScanPrerequisite = errors.New("cannot scan yet")

// EnqueueResult describes what Enqueue did.
type EnqueueResult struct {
	JobID     uuid.UUID `json:"job_id"`
	Coalesced bool      `json:"coalesced"` // merged into an already queued job
}

// Enqueue creates (or coalesces into) the repository's queued scan job for
// its own profile. A repository has at most one queued job per profile
// version: a new trigger while one is queued updates its commit and raises
// its priority instead.
func Enqueue(ctx context.Context, q db.Querier, orgID, repoID uuid.UUID, trigger, ref, commit string, by *uuid.UUID) (EnqueueResult, error) {
	return EnqueueWith(ctx, q, orgID, repoID, trigger, ref, commit, by, EnqueueOpts{})
}

// EnqueueOpts carries optional execution metadata.
type EnqueueOpts struct {
	Priority      int        // overrides the trigger's default priority when > 0
	ScheduleID    *uuid.UUID // schedule that produced the job
	ScheduleRunID *uuid.UUID // schedule activation that produced the job
	// ProfileID selects a scan profile (its current version) instead of
	// the repository's own or the default profile.
	ProfileID *uuid.UUID
	Name      string     // execution name; generated when empty
	RetryOf   *uuid.UUID // the failed execution this one retries
	// PullRequest scans a pull request's head (results kept apart from
	// the repository's findings; see prchecks.go).
	PullRequest int
	// ProfileVersionID runs a system profile version (CodeGraph
	// discovery) instead of a selectable profile; ProfileID is ignored.
	ProfileVersionID *uuid.UUID
}

// ErrProfileUnavailable means the requested profile does not exist or is archived.
var ErrProfileUnavailable = errors.New("scan profile not found or archived")

// EnqueueWith is Enqueue with execution options.
func EnqueueWith(ctx context.Context, q db.Querier, orgID, repoID uuid.UUID, trigger, ref, commit string, by *uuid.UUID, opt EnqueueOpts) (EnqueueResult, error) {
	var res EnqueueResult
	var scanBranch, defaultBranch, repoName string
	var enabled bool
	var archived *time.Time
	var profileVersion, snapshotID *uuid.UUID
	var sourceType string
	err := q.QueryRow(ctx, `
		SELECT r.source_type, r.current_snapshot_id, r.scan_branch, r.default_branch, r.scan_enabled, r.archived_at,
		       COALESCE(NULLIF(r.display_name, ''), r.full_name),
		       CASE WHEN $3::uuid IS NOT NULL THEN
		         (SELECT current_version_id FROM scan_profiles WHERE organization_id = r.organization_id AND id = $3 AND archived_at IS NULL)
		       ELSE COALESCE((SELECT current_version_id FROM scan_profiles WHERE id = r.scan_profile_id AND archived_at IS NULL),
		                (SELECT current_version_id FROM scan_profiles WHERE organization_id = r.organization_id AND is_default AND archived_at IS NULL)) END
		FROM repositories r WHERE r.organization_id = $1 AND r.id = $2`, orgID, repoID, opt.ProfileID).
		Scan(&sourceType, &snapshotID, &scanBranch, &defaultBranch, &enabled, &archived, &repoName, &profileVersion)
	if errors.Is(err, pgx.ErrNoRows) {
		return res, errNotFound
	}
	if err != nil {
		return res, err
	}
	if archived != nil || (!enabled && trigger != "manual" && trigger != "emergency") {
		return res, ErrNotScannable
	}
	if opt.ProfileVersionID != nil {
		profileVersion = opt.ProfileVersionID
	}
	if profileVersion == nil {
		if opt.ProfileID != nil {
			return res, fmt.Errorf("%w: %w", ErrScanPrerequisite, ErrProfileUnavailable)
		}
		return res, fmt.Errorf("%w: no scan profile available; create a default profile", ErrScanPrerequisite)
	}
	var pr *int
	if opt.PullRequest > 0 {
		if sourceType == "upload" {
			return res, fmt.Errorf("%w: uploaded repositories have no pull requests", ErrScanPrerequisite)
		}
		pr = &opt.PullRequest
	}
	if sourceType == "upload" {
		// Uploaded repositories are scanned from their current snapshot.
		if snapshotID == nil {
			return res, fmt.Errorf("%w: repository has no source snapshot yet", ErrScanPrerequisite)
		}
		ref, commit = "snapshot", ""
	}
	if ref == "" {
		ref = scanBranch
	}
	if ref == "" {
		ref = defaultBranch
	}
	if ref == "" {
		return res, fmt.Errorf("%w: repository has no default branch; set a scan branch", ErrScanPrerequisite)
	}
	prio := priorities[trigger]
	if opt.Priority > 0 {
		prio = min(opt.Priority, 100)
	}
	// Retries are distinct executions; everything else coalesces into a
	// queued execution of the same profile version.
	if opt.RetryOf == nil {
		err = q.QueryRow(ctx, `
			UPDATE scan_jobs SET commit_sha = CASE WHEN $3 <> '' THEN $3 ELSE commit_sha END,
			       priority = GREATEST(priority, $4), ref = $5, schedule_id = COALESCE(schedule_id, $6), snapshot_id = $7,
			       schedule_run_id = COALESCE(schedule_run_id, $9)
			WHERE repository_id = $1 AND organization_id = $2 AND profile_version_id = $8 AND status = 'queued' AND target_id IS NULL
			  AND pull_request IS NOT DISTINCT FROM $10 RETURNING id`,
			repoID, orgID, commit, prio, ref, opt.ScheduleID, snapshotID, *profileVersion, opt.ScheduleRunID, pr).Scan(&res.JobID)
		if err == nil {
			res.Coalesced = true
			return res, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return res, err
		}
	}
	snapshot, profileName, err := configSnapshot(ctx, q, *profileVersion)
	if err != nil {
		return res, err
	}
	name := strings.TrimSpace(opt.Name)
	if name == "" {
		name = truncate(repoName+" · "+profileName, 200)
	}
	retryCount := 0
	if opt.RetryOf != nil {
		_ = q.QueryRow(ctx, `SELECT retry_count + 1 FROM scan_jobs WHERE id = $1`, *opt.RetryOf).Scan(&retryCount)
	}
	res.JobID = uuid.Must(uuid.NewV7())
	_, err = q.Exec(ctx, `
		INSERT INTO scan_jobs (id, organization_id, repository_id, profile_version_id, trigger, priority, ref, commit_sha, requested_by,
		  schedule_id, snapshot_id, name, config_snapshot, retry_of, retry_count, schedule_run_id, pull_request)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		res.JobID, orgID, repoID, *profileVersion, trigger, prio, ref, commit, by, opt.ScheduleID, snapshotID, name, snapshot,
		opt.RetryOf, retryCount, opt.ScheduleRunID, pr)
	if db.IsUniqueViolation(err) {
		// Lost a race with a concurrent trigger, or this schedule run
		// already created the execution: use the existing one.
		if err := q.QueryRow(ctx, `SELECT id FROM scan_jobs WHERE repository_id = $1 AND profile_version_id = $2 AND target_id IS NULL
			AND pull_request IS NOT DISTINCT FROM $4
			AND (status = 'queued' OR ($3::uuid IS NOT NULL AND schedule_run_id = $3)) ORDER BY queued_at DESC LIMIT 1`,
			repoID, *profileVersion, opt.ScheduleRunID, pr).Scan(&res.JobID); err != nil {
			return res, err
		}
		res.Coalesced = true
		return res, nil
	}
	if err != nil {
		return res, err
	}
	err = AddEvent(ctx, q, orgID, res.JobID, "queued", "", "info", "queued by "+trigger)
	return res, err
}

// configSnapshot captures the effective configuration of a profile version
// (stored immutably on each execution).
func configSnapshot(ctx context.Context, q db.Querier, versionID uuid.UUID) ([]byte, string, error) {
	var profileID uuid.UUID
	var profileName string
	if err := q.QueryRow(ctx, `SELECT p.id, p.name FROM scan_profile_versions v JOIN scan_profiles p ON p.id = v.profile_id WHERE v.id = $1`,
		versionID).Scan(&profileID, &profileName); err != nil {
		return nil, "", err
	}
	v, err := scanVersion(q.QueryRow(ctx, versionSelect+` WHERE v.id = $1`, versionID))
	if err != nil {
		return nil, "", err
	}
	// Custom rule files enabled now, pinned by version.
	rules, err := enabledRuleRefs(ctx, q, versionID)
	if err != nil {
		return nil, "", err
	}
	b, err := json.Marshal(map[string]any{
		"profile_id": profileID, "profile_name": profileName, "profile_version_id": v.ID, "profile_version": v.Version,
		"change_note": v.ChangeNote, "severity_threshold": v.SeverityThreshold, "exclusions": v.Exclusions,
		"timeout_seconds": v.TimeoutSeconds, "sbom": v.SBOM, "fail_on_critical": v.FailOnCritical,
		"retention_days": v.RetentionDays, "scanners": v.Scanners, "captured_at": time.Now().UTC(),
		"custom_rules": rules,
	})
	return b, profileName, err
}

// AddEvent records a stage event of an execution.
func AddEvent(ctx context.Context, q db.Querier, orgID, jobID uuid.UUID, stage, scanner, status, message string) error {
	_, err := q.Exec(ctx, `INSERT INTO scan_job_events (organization_id, scan_job_id, stage, scanner_key, status, message)
		VALUES ($1, $2, $3, $4, $5, $6)`, orgID, jobID, stage, scanner, status, truncate(message, 2000))
	return err
}

// OnWebhookEvent queues scans for pushes and merges to the scan branch,
// and pull request checks when the repository has them enabled.
func (s *Service) OnWebhookEvent(ctx context.Context, orgID, repoID uuid.UUID, ev scm.WebhookEvent) {
	if ev.Kind == "pull_request" {
		s.onPullRequest(ctx, orgID, repoID, ev)
		return
	}
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

func (s *Service) enqueueAs(ctx context.Context, p *authz.Principal, repoID uuid.UUID, trigger string, opts ...EnqueueOpts) (EnqueueResult, error) {
	var opt EnqueueOpts
	if len(opts) > 0 {
		opt = opts[0]
	}
	if err := s.requireRepo(ctx, p, authz.PermScansRun, repoID); err != nil {
		return EnqueueResult{}, err
	}
	var res EnqueueResult
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		res, err = EnqueueWith(ctx, tx, p.OrganizationID, repoID, trigger, "", "", &p.UserID, opt)
		if err != nil {
			return err
		}
		if res.Coalesced {
			return nil
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan.request", TargetType: "repository", TargetID: repoID.String(),
			Metadata: map[string]any{"job_id": res.JobID, "trigger": trigger, "profile_id": opt.ProfileID}})
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
	if errors.Is(err, ErrNotScannable) || errors.Is(err, ErrScanPrerequisite) {
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
	// ProfileID runs an existing scan profile instead of each repository's own.
	ProfileID *uuid.UUID `json:"profile_id"`
	Name      string     `json:"name"`
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
	if req.Name = strings.TrimSpace(req.Name); len(req.Name) > 200 {
		s.fail(w, r, httpx.BadRequest("name must be at most 200 characters"))
		return
	}
	if req.ProfileID != nil {
		var ok bool
		_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scan_profiles WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL)`,
			p.OrganizationID, *req.ProfileID).Scan(&ok)
		if !ok {
			s.fail(w, r, httpx.BadRequest("unknown or archived scan profile"))
			return
		}
	}
	type item struct {
		RepositoryID uuid.UUID  `json:"repository_id"`
		JobID        *uuid.UUID `json:"job_id,omitempty"`
		Coalesced    bool       `json:"coalesced,omitempty"`
		Error        string     `json:"error,omitempty"`
	}
	out := make([]item, 0, len(req.RepositoryIDs))
	for _, id := range req.RepositoryIDs {
		res, err := s.enqueueAs(ctx, p, id, req.Trigger, EnqueueOpts{ProfileID: req.ProfileID, Name: req.Name})
		it := item{RepositoryID: id}
		if err != nil {
			it.Error = "not scannable or not permitted"
			if errors.Is(err, ErrScanPrerequisite) {
				it.Error = err.Error()
			}
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
	ID             uuid.UUID `json:"id"`
	PullRequest    int       `json:"pull_request,omitempty"`
	RepositoryID   uuid.UUID `json:"repository_id"`
	RepositoryName string    `json:"repository_name"`
	RepositoryKey  string    `json:"repository_key"`
	ProfileName    string    `json:"profile_name"`
	ProfileVersion int       `json:"profile_version"`
	Trigger        string    `json:"trigger"`
	Priority       int       `json:"priority"`
	Status         string    `json:"status"`
	Ref            string    `json:"ref"`
	CommitSHA      string    `json:"commit_sha"`
	Attempts       int       `json:"attempts"`
	WorkerName     *string   `json:"worker_name"`
	RequestedBy    *string   `json:"requested_by"`
	Error          string    `json:"error"`
	// ErrorCode is the error catalogue code of Error (empty when none
	// applies).
	ErrorCode     string     `json:"error_code,omitempty"`
	FindingsNew   int        `json:"findings_new"`
	FindingsFixed int        `json:"findings_fixed"`
	GateFailed    bool       `json:"gate_failed"`
	QueuedAt      time.Time  `json:"queued_at"`
	StartedAt     *time.Time `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at"`
	Results       []Result   `json:"results,omitempty"`

	// Scanning module fields.
	ScanKey        string         `json:"scan_key"` // permanent Scan ID, e.g. QD-SCAN-000042
	Name           string         `json:"name"`
	AssetType      string         `json:"asset_type"` // repository | image | url | api | sbom
	TargetID       *uuid.UUID     `json:"target_id"`
	TargetName     *string        `json:"target_name"`
	TargetRef      *string        `json:"target_reference"`
	ProfileID      uuid.UUID      `json:"profile_id"`
	Progress       int            `json:"progress"`
	Stage          string         `json:"stage"`
	RetryOf        *uuid.UUID     `json:"retry_of"`
	RetryCount     int            `json:"retry_count"`
	ScheduleID     *uuid.UUID     `json:"schedule_id"`
	ScheduleRunID  *uuid.UUID     `json:"schedule_run_id"`
	SnapshotID     *uuid.UUID     `json:"snapshot_id"`
	DurationMS     *int64         `json:"duration_ms"`
	FindingsTotal  int            `json:"findings_total"`
	Severity       map[string]int `json:"severity"` // distinct findings observed in this execution
	ConfigSnapshot map[string]any `json:"config_snapshot,omitempty"`
	// ChangeSummary (push and merge scans): new and fixed findings since
	// the previous scanned commit.
	ChangeSummary *ChangeSummary `json:"change_summary,omitempty"`
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
	SELECT j.id, j.repository_id, r.full_name, r.repository_key, sp.name, v.version, j.trigger, j.priority, j.status, j.ref, j.commit_sha,
	       j.attempts, wk.name, COALESCE(NULLIF(u.display_name, ''), u.email), j.error, j.findings_new, j.findings_fixed,
	       j.gate_failed, j.queued_at, j.started_at, j.finished_at,
	       j.scan_key, j.name, sp.id, j.progress, j.stage, j.retry_of, j.retry_count, j.schedule_id, j.schedule_run_id, j.snapshot_id,
	       j.target_kind, j.target_id, st.name, st.reference,
	       (EXTRACT(EPOCH FROM (COALESCE(j.finished_at, CASE WHEN j.status = 'running' THEN now() END) - j.started_at)) * 1000)::bigint,
	       COALESCE((SELECT jsonb_object_agg(x.severity, x.n) FROM (
	         SELECT f.severity, count(DISTINCT f.id) AS n FROM finding_occurrences o
	         JOIN scan_results sr ON sr.id = o.scan_result_id JOIN findings f ON f.id = o.finding_id
	         WHERE sr.scan_job_id = j.id GROUP BY f.severity) x), '{}'::jsonb),
	       j.change_summary
	FROM scan_jobs j
	JOIN repositories r ON r.id = j.repository_id
	LEFT JOIN countries co ON co.id = r.country_id
	JOIN scan_profile_versions v ON v.id = j.profile_version_id
	JOIN scan_profiles sp ON sp.id = v.profile_id
	LEFT JOIN scan_targets st ON st.id = j.target_id
	LEFT JOIN workers wk ON wk.id = j.leased_by
	LEFT JOIN users u ON u.id = j.requested_by`

func scanJob(row pgx.Row) (Job, error) {
	var j Job
	var change []byte
	err := row.Scan(&j.ID, &j.RepositoryID, &j.RepositoryName, &j.RepositoryKey, &j.ProfileName, &j.ProfileVersion, &j.Trigger, &j.Priority,
		&j.Status, &j.Ref, &j.CommitSHA, &j.Attempts, &j.WorkerName, &j.RequestedBy, &j.Error, &j.FindingsNew,
		&j.FindingsFixed, &j.GateFailed, &j.QueuedAt, &j.StartedAt, &j.FinishedAt,
		&j.ScanKey, &j.Name, &j.ProfileID, &j.Progress, &j.Stage, &j.RetryOf, &j.RetryCount, &j.ScheduleID, &j.ScheduleRunID,
		&j.SnapshotID, &j.AssetType, &j.TargetID, &j.TargetName, &j.TargetRef, &j.DurationMS, &j.Severity, &change)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, errNotFound
	}
	if len(change) > 0 {
		_ = json.Unmarshal(change, &j.ChangeSummary)
	}
	j.ErrorCode = JobErrorCode(j.Error)
	for _, k := range []string{"critical", "high", "medium", "low", "info"} {
		if _, ok := j.Severity[k]; !ok {
			if j.Severity == nil {
				j.Severity = map[string]int{}
			}
			j.Severity[k] = 0
		}
		j.FindingsTotal += j.Severity[k]
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
	if v := q.Get("schedule_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid schedule_id"))
			return
		}
		add("j.schedule_id = ?", id)
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		if len(v) > 200 {
			s.fail(w, r, httpx.BadRequest("q is too long"))
			return
		}
		like := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(strings.ToLower(v)) + "%"
		add("(lower(j.scan_key) LIKE ? OR lower(j.name) LIKE ? OR lower(r.full_name) LIKE ? OR lower(r.repository_key) LIKE ? OR lower(r.display_name) LIKE ?)", like)
	}
	if v := strings.TrimSpace(q.Get("scan_key")); v != "" {
		add("upper(j.scan_key) = upper(?)", v)
	}
	if v := strings.TrimSpace(q.Get("repository_key")); v != "" {
		add("upper(r.repository_key) = upper(?)", v)
	}
	if v := q.Get("profile_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid profile_id"))
			return
		}
		add("v.profile_id = ?", id)
	}
	if v := q.Get("trigger"); v != "" {
		if _, ok := priorities[v]; !ok {
			s.fail(w, r, httpx.BadRequest("invalid trigger"))
			return
		}
		add("j.trigger = ?", v)
	}
	if v := q.Get("scanner"); v != "" {
		add("EXISTS (SELECT 1 FROM scan_results sr WHERE sr.scan_job_id = j.id AND sr.scanner_key = ?)", v)
	}
	if v := q.Get("asset_type"); v != "" {
		if !slices.Contains([]string{"repository", "image", "url", "api", "sbom"}, v) {
			httpx.WriteError(w, r, s.Log, httpx.BadRequest("asset_type must be repository, image, url, api or sbom"))
			return
		}
		add("j.target_kind = ?", v)
	}
	if v := q.Get("target_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid target_id"))
			return
		}
		add("j.target_id = ?", id)
	}
	for param, op := range map[string]string{"from": ">=", "to": "<"} {
		if v := q.Get(param); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				if d, derr := time.Parse(time.DateOnly, v); derr == nil {
					t, err = d, nil
					if param == "to" {
						t = t.AddDate(0, 0, 1)
					}
				}
			}
			if err != nil {
				s.fail(w, r, httpx.BadRequest(param+" must be a date (YYYY-MM-DD) or RFC 3339 time"))
				return
			}
			add("j.queued_at "+op+" ?", t)
		}
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
	if err := s.loadDetail(r.Context(), &j); err != nil {
		s.fail(w, r, err)
		return
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
		if err := AddEvent(ctx, tx, p.OrganizationID, j.ID, "cancel", "", "info", "cancelled by "+p.Email); err != nil {
			return err
		}
		if err := updateProgress(ctx, tx, j.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan.cancel", TargetType: "scan_job", TargetID: j.ID.String(), Metadata: map[string]any{"repository": j.RepositoryName, "repository_key": j.RepositoryKey}})
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
	var key *string
	err = s.DB.QueryRow(ctx, `SELECT a.content_type, a.data_gzip, a.object_key FROM scan_artifacts a
		JOIN scan_results sr ON sr.id = a.scan_result_id
		WHERE sr.scan_job_id = $1 AND sr.scanner_key = $2 ORDER BY a.kind LIMIT 1`, j.ID, scanner).Scan(&ct, &data, &key)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if data, err = objstore.Load(ctx, s.Artifacts, key, data); err != nil {
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

// JobErrorCode maps a stored execution error to its error catalogue code
// (backend/internal/platform/diag). The messages are written by failJob
// and requeueExpired (worker_api.go).
func JobErrorCode(msg string) string {
	switch {
	case msg == "":
		return ""
	case strings.HasPrefix(msg, "could not obtain clone credential"):
		return "PTH-SCAN-1001"
	case strings.HasPrefix(msg, "worker lease expired"):
		return "PTH-SCAN-1002"
	}
	return ""
}
