package codegraph

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/featureflags"
	"pathos/internal/monitoring"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/tenant"
	"pathos/internal/scanners"
	"pathos/internal/scans"
)

// SystemProfileName names the per-organization system profile of
// CodeGraph builds. It is stored archived, so it never appears in profile
// lists or selections and is never a default.
const SystemProfileName = "CodeGraph discovery (system)"

// Trigger is the scan execution trigger of CodeGraph builds.
const Trigger = "codegraph"

// Settings are an organization's rediscovery and retention settings.
type Settings struct {
	AutoRebuild        bool       `json:"auto_rebuild"`
	MinIntervalMinutes int        `json:"min_interval_minutes"`
	KeepSnapshots      int        `json:"keep_snapshots"`
	UpdatedAt          *time.Time `json:"updated_at,omitempty"`
}

// DefaultSettings apply without a stored row.
var DefaultSettings = Settings{AutoRebuild: true, MinIntervalMinutes: 60, KeepSnapshots: 10}

func loadSettings(ctx context.Context, q db.Querier, orgID uuid.UUID) (Settings, error) {
	st := DefaultSettings
	var at time.Time
	err := q.QueryRow(ctx, `SELECT auto_rebuild, min_interval_minutes, keep_snapshots, updated_at FROM codegraph_settings
		WHERE organization_id = $1`, orgID).Scan(&st.AutoRebuild, &st.MinIntervalMinutes, &st.KeepSnapshots, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return DefaultSettings, nil
	}
	if err == nil {
		st.UpdatedAt = &at
	}
	return st, err
}

// ensureSystemProfile returns the current version of the organization's
// CodeGraph system profile, creating it on first use. Every profile
// version must list the mandatory scanners (database trigger); the lease
// runs only the graph tool for CodeGraph executions.
func ensureSystemProfile(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) (uuid.UUID, error) {
	// One creator per organization at a time.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('codegraph-profile:' || $1::text, 0))`, orgID); err != nil {
		return uuid.Nil, err
	}
	var vid uuid.UUID
	err := tx.QueryRow(ctx, `SELECT p.current_version_id FROM scan_profiles p WHERE p.organization_id = $1 AND p.name = $2
		AND p.archived_at IS NOT NULL AND p.current_version_id IS NOT NULL ORDER BY p.created_at LIMIT 1`, orgID, SystemProfileName).Scan(&vid)
	if err == nil {
		return vid, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	pid, vid := uuid.Must(uuid.NewV7()), uuid.Must(uuid.NewV7())
	if _, err := tx.Exec(ctx, `INSERT INTO scan_profiles (id, organization_id, name, description, archived_at)
		VALUES ($1, $2, $3, 'System profile of CodeGraph discovery builds (not selectable).', now())`, pid, orgID, SystemProfileName); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO scan_profile_versions (id, organization_id, profile_id, version, timeout_seconds, sbom, change_note)
		VALUES ($1, $2, $3, 1, 3600, false, 'CodeGraph discovery')`, vid, orgID, pid); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO profile_scanners (profile_version_id, scanner_key, config)
		SELECT $1, key, '{}'::jsonb FROM scanner_catalog WHERE mandatory OR key = $2`, vid, scanners.PathosGraph); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE scan_profiles SET current_version_id = $2 WHERE id = $1`, pid, vid); err != nil {
		return uuid.Nil, err
	}
	return vid, nil
}

// graphWorkerOnline reports whether a worker that provides the graph tool
// was seen recently (otherwise a build would run on a worker without it).
func graphWorkerOnline(ctx context.Context, q db.Querier, orgID uuid.UUID) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM workers WHERE organization_id = $1 AND revoked_at IS NULL
		AND last_seen_at > now() - $2::interval AND scanners ? $3)`, orgID, scans.WorkerOnlineWindow.String(), scanners.PathosGraph).Scan(&ok)
	return ok, err
}

// BuildResult is one queued snapshot.
type BuildResult struct {
	SnapshotID   uuid.UUID `json:"snapshot_id"`
	RepositoryID uuid.UUID `json:"repository_id"`
	ScanJobID    uuid.UUID `json:"scan_job_id"`
	Status       string    `json:"status"`
	Coalesced    bool      `json:"coalesced"`
}

// queueBuild queues a discovery execution for one repository of an
// application and creates (or reuses) its snapshot row.
func queueBuild(ctx context.Context, tx pgx.Tx, orgID, appID, repoID uuid.UUID, trigger, ref string, by *uuid.UUID) (BuildResult, error) {
	res := BuildResult{RepositoryID: repoID}
	vid, err := ensureSystemProfile(ctx, tx, orgID)
	if err != nil {
		return res, err
	}
	q, err := scans.EnqueueWith(ctx, tx, orgID, repoID, Trigger, ref, "", by, scans.EnqueueOpts{ProfileVersionID: &vid,
		Name: "CodeGraph discovery"})
	if err != nil {
		return res, err
	}
	res.ScanJobID, res.Coalesced = q.JobID, q.Coalesced
	err = tx.QueryRow(ctx, `SELECT id, status FROM codegraph_snapshots WHERE scan_job_id = $1`, q.JobID).Scan(&res.SnapshotID, &res.Status)
	if err == nil {
		return res, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return res, err
	}
	res.SnapshotID, res.Status = uuid.Must(uuid.NewV7()), "queued"
	var jobRef string
	_ = tx.QueryRow(ctx, `SELECT ref FROM scan_jobs WHERE id = $1`, q.JobID).Scan(&jobRef)
	_, err = tx.Exec(ctx, `INSERT INTO codegraph_snapshots (id, organization_id, application_id, repository_id, scan_job_id, ref, trigger, status, requested_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'queued', $8)`, res.SnapshotID, orgID, appID, repoID, q.JobID, jobRef, trigger, by)
	return res, err
}

// buildError maps scan queue errors to CodeGraph errors.
func buildError(err error) error {
	switch {
	case errors.Is(err, scans.ErrNotScannable):
		return httpx.E(http.StatusConflict, "not_buildable", "the repository is archived or scanning is disabled").WithDiag(CodeNotBuildable)
	case errors.Is(err, scans.ErrScanPrerequisite):
		return httpx.E(http.StatusConflict, "not_buildable", err.Error()).WithDiag(CodeNotBuildable)
	}
	return err
}

// OnScanFinished is the feedback loop: after a successful repository scan
// (a new commit, a schedule, a manual scan) of a repository that belongs
// to an application, CodeGraph is rebuilt when the organization has the
// codegraph flag and automatic rediscovery on, a graph worker is online,
// no build is queued or running, the newest snapshot is older than the
// minimum interval and was built from another commit.
func (s *Service) OnScanFinished(ctx context.Context, orgID, jobID uuid.UUID) {
	ctx = tenant.WithOrg(ctx, orgID)
	queued, reason, err := s.rediscover(ctx, orgID, jobID)
	switch {
	case err != nil:
		s.Log.Warn("CodeGraph rediscovery not queued", "scan_job_id", jobID, "err", err)
	case queued != nil:
		s.Log.Info("CodeGraph rediscovery queued", "scan_job_id", jobID, "snapshot_id", queued.SnapshotID, "repository_id", queued.RepositoryID)
	default:
		s.Log.Debug("CodeGraph rediscovery skipped", "scan_job_id", jobID, "reason", reason)
	}
}

func (s *Service) rediscover(ctx context.Context, orgID, jobID uuid.UUID) (*BuildResult, string, error) {
	var repoID uuid.UUID
	var appID *uuid.UUID
	var trigger, ref, commit, status string
	var target *uuid.UUID
	var pr *int
	if err := s.DB.QueryRow(ctx, `SELECT j.repository_id, r.application_id, j.trigger, j.ref, j.commit_sha, j.status, j.target_id, j.pull_request
		FROM scan_jobs j JOIN repositories r ON r.id = j.repository_id WHERE j.id = $1 AND j.organization_id = $2`, jobID, orgID).
		Scan(&repoID, &appID, &trigger, &ref, &commit, &status, &target, &pr); err != nil {
		return nil, "", err
	}
	switch {
	case trigger == Trigger:
		return nil, "a CodeGraph build", Reconcile(ctx, s.DB, &orgID)
	case target != nil || pr != nil:
		return nil, "not a repository branch scan", nil
	case status != "succeeded" && status != "partial":
		return nil, "scan " + status, nil
	case appID == nil:
		return nil, "repository has no application", nil
	}
	on, err := featureflags.Enabled(ctx, s.DB, orgID, "codegraph")
	if err != nil || !on {
		return nil, "codegraph flag off", err
	}
	st, err := loadSettings(ctx, s.DB, orgID)
	if err != nil || !st.AutoRebuild {
		return nil, "automatic rediscovery off", err
	}
	if online, err := graphWorkerOnline(ctx, s.DB, orgID); err != nil || !online {
		return nil, "no graph worker online", err
	}
	var latestAt *time.Time
	var latestCommit, latestStatus string
	_ = s.DB.QueryRow(ctx, `SELECT created_at, commit_sha, status FROM codegraph_snapshots WHERE repository_id = $1
		ORDER BY created_at DESC LIMIT 1`, repoID).Scan(&latestAt, &latestCommit, &latestStatus)
	if latestStatus == "queued" || latestStatus == "building" {
		return nil, "a build is queued or running", nil
	}
	if latestAt != nil && s.now().Sub(*latestAt) < time.Duration(st.MinIntervalMinutes)*time.Minute {
		return nil, "rate limited (minimum interval)", nil
	}
	if commit != "" && latestCommit == commit && (latestStatus == "ready" || latestStatus == "partial") {
		return nil, "commit unchanged", nil
	}
	var res BuildResult
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		res, err = queueBuild(ctx, tx, orgID, *appID, repoID, "scan", ref, nil)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	// Feedback loop 1 (new commit → rediscovery) in the monitoring feed.
	app, repo, snap := *appID, repoID, res.SnapshotID
	if _, err := monitoring.Record(ctx, s.DB, monitoring.Event{OrgID: orgID, ApplicationID: &app, RepositoryID: &repo,
		Type: monitoring.TypeRediscoveryQueued, Severity: "info",
		Title:         "CodeGraph rediscovery queued after a scan of commit " + shortSHA(commit),
		Summary:       "A " + trigger + " scan of " + ref + " finished; the CodeGraph of the repository is rebuilt from the new commit.",
		EvidenceLabel: monitoring.EvidenceVerified,
		Evidence:      map[string]any{"scan_job_id": jobID, "commit": commit, "previous_commit": latestCommit, "snapshot_id": res.SnapshotID},
		SubjectType:   "snapshot", SubjectID: &snap, Details: map[string]any{"trigger": trigger, "ref": ref}}); err != nil {
		s.Log.Warn("monitoring event not recorded", "err", err, "error_code", monitoring.CodeRecordFailed)
	}
	return &res, "", nil
}

// Reconcile settles snapshots whose discovery execution ended without a
// graph (failed, cancelled, lease expired, or the tool never ran) and marks
// running builds as building. It runs before snapshot reads and in the
// jobs runner.
func Reconcile(ctx context.Context, q db.Querier, orgID *uuid.UUID) error {
	// The commit is known once the execution completes (the worker reports
	// it with the completion, after the graph upload).
	_, err := q.Exec(ctx, `UPDATE codegraph_snapshots s SET commit_sha = j.commit_sha
		FROM scan_jobs j WHERE j.id = s.scan_job_id AND s.commit_sha = '' AND j.commit_sha <> ''
		  AND j.status IN ('succeeded', 'partial', 'failed', 'cancelled') AND ($1::uuid IS NULL OR s.organization_id = $1)`, orgID)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE codegraph_snapshots s SET status = 'building', started_at = COALESCE(s.started_at, j.started_at)
		FROM scan_jobs j WHERE j.id = s.scan_job_id AND s.status = 'queued' AND j.status = 'running'
		  AND ($1::uuid IS NULL OR s.organization_id = $1)`, orgID)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE codegraph_snapshots s SET status = 'failed', error_code = $2, finished_at = now(),
		error = left('the discovery execution ended (' || j.status || ') without a graph' ||
		        CASE WHEN j.error <> '' THEN ': ' || j.error ELSE '' END, 2000)
		FROM scan_jobs j WHERE j.id = s.scan_job_id AND s.status IN ('queued', 'building')
		  AND j.status IN ('succeeded', 'partial', 'failed', 'cancelled')
		  AND ($1::uuid IS NULL OR s.organization_id = $1)`, orgID, CodeNoGraph)
	if err != nil {
		return err
	}
	// The execution was deleted (retention): nothing will arrive.
	_, err = q.Exec(ctx, `UPDATE codegraph_snapshots s SET status = 'failed', error_code = $2, finished_at = now(),
		error = 'the discovery execution no longer exists'
		WHERE s.status IN ('queued', 'building') AND s.scan_job_id IS NULL AND ($1::uuid IS NULL OR s.organization_id = $1)`, orgID, CodeNoGraph)
	return err
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}
