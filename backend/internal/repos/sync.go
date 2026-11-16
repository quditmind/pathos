package repos

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

func (s *Service) registerSync(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/repositories/{id}/sync", s.syncRepository)
	mux.HandleFunc("GET /api/v1/repositories/{id}/sync-runs", s.listSyncRuns)
}

// SyncRun is one synchronization attempt (frontend type SyncRun).
type SyncRun struct {
	ID                uuid.UUID `json:"id"`
	Trigger           string    `json:"trigger"`
	Status            string    `json:"status"`
	Branch            string    `json:"branch"`
	PreviousCommitSHA string    `json:"previous_commit_sha"`
	CommitSHA         string    `json:"commit_sha"`
	Changed           bool      `json:"changed"`
	Error             string    `json:"error"`
	TriggeredBy       *UserRef  `json:"triggered_by"`
	StartedAt         time.Time `json:"started_at"`
	FinishedAt        time.Time `json:"finished_at"`
}

// syncTarget is what a sync needs to know about a repository.
type syncTarget struct {
	ID, OrgID     uuid.UUID
	ConnID        *uuid.UUID
	FullName      string
	ExternalID    string
	Org, Project  string
	ScanBranch    string
	DefaultBranch string
	LatestSHA     string
	SyncStatus    string
	PushedAt      *time.Time
}

func (t syncTarget) ref() scm.RepoRef {
	return scm.RepoRef{ExternalID: t.ExternalID, FullName: t.FullName, Organization: t.Org, Project: t.Project}
}

func (t syncTarget) branch() string {
	if t.ScanBranch != "" {
		return t.ScanBranch
	}
	return t.DefaultBranch
}

func loadSyncTarget(ctx context.Context, q db.Querier, orgID, repoID uuid.UUID) (syncTarget, error) {
	t := syncTarget{ID: repoID, OrgID: orgID}
	err := q.QueryRow(ctx, `SELECT scm_connection_id, full_name, external_id, scm_organization, scm_project, scan_branch, default_branch,
		latest_commit_sha, sync_status, last_pushed_at FROM repositories WHERE organization_id = $1 AND id = $2`, orgID, repoID).
		Scan(&t.ConnID, &t.FullName, &t.ExternalID, &t.Org, &t.Project, &t.ScanBranch, &t.DefaultBranch, &t.LatestSHA, &t.SyncStatus, &t.PushedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return t, errNotFound
	}
	return t, err
}

// syncStatusFor classifies a provider error.
func syncStatusFor(err error) string {
	switch {
	case errors.Is(err, scm.ErrNotFound):
		return "missing"
	case errors.Is(err, scm.ErrForbidden):
		return "permission_denied"
	}
	return "failed"
}

// SyncRepository refreshes one repository's metadata and head commit from
// its provider and records a sync run. Source code is not downloaded.
func (s *Service) SyncRepository(ctx context.Context, orgID, repoID uuid.UUID, trigger string, by *uuid.UUID) (SyncRun, error) {
	t, err := loadSyncTarget(ctx, s.DB, orgID, repoID)
	if err != nil {
		return SyncRun{}, err
	}
	if t.ConnID == nil {
		return SyncRun{}, httpx.Conflict("uploaded repositories are updated by uploading a new version")
	}
	c, err := s.getConn(ctx, s.DB, orgID, *t.ConnID)
	if err != nil {
		return SyncRun{}, err
	}
	run := SyncRun{ID: uuid.Must(uuid.NewV7()), Trigger: trigger, StartedAt: time.Now(), PreviousCommitSHA: t.LatestSHA}
	cl, err := s.client(ctx, c)
	if err == nil {
		cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err = s.syncWith(cctx, cl, t, &run, nil)
		cancel()
	}
	if err != nil {
		run.Status, run.Error = syncStatusFor(err), truncate(err.Error(), 500)
	}
	return run, s.saveSyncRun(ctx, t, run, by)
}

// syncWith fetches state for t. listed is the repository from a full
// listing when the caller already has it (scheduled reconciliation).
func (s *Service) syncWith(ctx context.Context, cl scm.FullClient, t syncTarget, run *SyncRun, listed *scm.RemoteRepo) error {
	var rr scm.RemoteRepo
	if listed != nil {
		rr = *listed
	} else {
		var err error
		if rr, err = cl.GetRepository(ctx, t.ref()); err != nil {
			return err
		}
	}
	vis := rr.Visibility
	if vis != "public" && vis != "internal" {
		vis = "private"
	}
	if _, err := s.DB.Exec(ctx, `
		UPDATE repositories SET full_name = $3, name = $4, url = $5, clone_url = $6,
		       default_branch = CASE WHEN $7 <> '' THEN $7 ELSE default_branch END,
		       visibility = $8, description = CASE WHEN $9 <> '' THEN $9 ELSE description END, remote_archived = $10,
		       last_pushed_at = COALESCE($11, last_pushed_at), size_bytes = COALESCE(NULLIF($12::bigint, 0), size_bytes),
		       scm_organization = CASE WHEN $13 <> '' THEN $13 ELSE scm_organization END,
		       scm_project = CASE WHEN $14 <> '' THEN $14 ELSE scm_project END
		WHERE organization_id = $1 AND id = $2`,
		t.OrgID, t.ID, rr.FullName, rr.Name, rr.URL, rr.CloneURL, rr.DefaultBranch, vis, truncate(rr.Description, 2000),
		rr.Archived, rr.PushedAt, rr.SizeBytes, rr.Organization, rr.Project); err != nil {
		return err
	}
	if rr.DefaultBranch != "" {
		t.DefaultBranch = rr.DefaultBranch
	}
	run.Branch = t.branch()
	ref := rr.Ref()
	if ref.ExternalID == "" {
		ref = t.ref()
	}
	// Skip the commit lookup when a listing shows no push since the last
	// known commit.
	unchanged := listed != nil && t.LatestSHA != "" && rr.PushedAt != nil && t.PushedAt != nil && !rr.PushedAt.After(*t.PushedAt)
	if unchanged {
		run.CommitSHA = t.LatestSHA
	} else {
		commit, err := cl.LatestCommit(ctx, ref, t.ScanBranch)
		if err != nil {
			return err
		}
		run.CommitSHA = commit.SHA
		if _, err := s.DB.Exec(ctx, `UPDATE repositories SET latest_commit_sha = $3, latest_commit_at = COALESCE($4, now())
			WHERE organization_id = $1 AND id = $2`, t.OrgID, t.ID, commit.SHA, commit.CommittedAt); err != nil {
			return err
		}
		if langs, err := cl.Languages(ctx, ref); err == nil && len(langs) > 0 {
			_, _ = s.DB.Exec(ctx, `UPDATE repositories SET languages = $3 WHERE organization_id = $1 AND id = $2`, t.OrgID, t.ID, langs)
		}
	}
	run.Changed = run.CommitSHA != t.LatestSHA
	run.Status = "ok"
	if rr.Archived {
		run.Status = "archived_upstream"
	}
	return nil
}

// saveSyncRun stores the run, updates the repository's sync state and
// raises a notification when a repository starts failing.
func (s *Service) saveSyncRun(ctx context.Context, t syncTarget, run SyncRun, by *uuid.UUID) error {
	ctx = context.WithoutCancel(ctx)
	run.FinishedAt = time.Now()
	return db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO repository_sync_runs (id, organization_id, repository_id, trigger, status, branch,
			previous_commit_sha, commit_sha, changed, error, triggered_by, started_at, finished_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			run.ID, t.OrgID, t.ID, run.Trigger, run.Status, run.Branch, run.PreviousCommitSHA, run.CommitSHA, run.Changed,
			run.Error, by, run.StartedAt, run.FinishedAt); err != nil {
			return err
		}
		ok := run.Status == "ok" || run.Status == "archived_upstream"
		if _, err := tx.Exec(ctx, `UPDATE repositories SET last_sync_at = $3, sync_status = $4, sync_error = $5,
			last_sync_ok_at = CASE WHEN $6 THEN $3 ELSE last_sync_ok_at END
			WHERE organization_id = $1 AND id = $2`, t.OrgID, t.ID, run.FinishedAt, run.Status, run.Error, ok); err != nil {
			return err
		}
		if !ok && t.SyncStatus != run.Status {
			if _, err := tx.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, subject_id, payload)
				VALUES ($1, 'repository.sync_failed', $2, jsonb_build_object('status', $3::text, 'error', $4::text))`,
				t.OrgID, t.ID, run.Status, run.Error); err != nil {
				return err
			}
		}
		return nil
	})
}

// recordPush applies a verified push webhook to the tracked branch.
func (s *Service) recordPush(ctx context.Context, orgID, repoID uuid.UUID, ev scm.WebhookEvent) {
	t, err := loadSyncTarget(ctx, s.DB, orgID, repoID)
	if err != nil || ev.CommitSHA == "" || strings.TrimPrefix(ev.Ref, "refs/heads/") != t.branch() {
		return
	}
	run := SyncRun{ID: uuid.Must(uuid.NewV7()), Trigger: "webhook", Status: "ok", Branch: t.branch(), StartedAt: time.Now(),
		PreviousCommitSHA: t.LatestSHA, CommitSHA: ev.CommitSHA, Changed: ev.CommitSHA != t.LatestSHA}
	if _, err := s.DB.Exec(ctx, `UPDATE repositories SET latest_commit_sha = $3, latest_commit_at = now(), last_pushed_at = now()
		WHERE organization_id = $1 AND id = $2`, orgID, repoID, ev.CommitSHA); err != nil {
		s.Log.Warn("webhook sync update failed", "repository_id", repoID, "err", err)
		return
	}
	if err := s.saveSyncRun(ctx, t, run, nil); err != nil {
		s.Log.Warn("webhook sync run not recorded", "repository_id", repoID, "err", err)
	}
}

func (s *Service) syncRepository(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, repo, err := s.loadRepoFor(r, authz.PermReposManage, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !repo.CanEdit {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	run, err := s.SyncRepository(ctx, p.OrganizationID, repo.ID, "manual", &p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "repository.sync", TargetType: "repository", TargetID: repo.ID.String(),
		Metadata: map[string]any{"name": repo.FullName, "status": run.Status, "commit_sha": run.CommitSHA, "changed": run.Changed}})
	out, err := s.getRepo(ctx, s.DB, p, repo.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	run.FinishedAt = time.Now()
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"run": run, "repository": out})
}

func (s *Service) listSyncRuns(w http.ResponseWriter, r *http.Request) {
	p, repo, err := s.loadRepoFor(r, authz.PermReposRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), `
		SELECT s.id, s.trigger, s.status, s.branch, s.previous_commit_sha, s.commit_sha, s.changed, s.error, s.started_at, s.finished_at,
		       (SELECT `+userJSON+` FROM users u WHERE u.id = s.triggered_by)
		FROM repository_sync_runs s WHERE s.organization_id = $1 AND s.repository_id = $2
		ORDER BY s.started_at DESC LIMIT 100`, p.OrganizationID, repo.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	runs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (SyncRun, error) {
		var run SyncRun
		var by []byte
		if err := row.Scan(&run.ID, &run.Trigger, &run.Status, &run.Branch, &run.PreviousCommitSHA, &run.CommitSHA, &run.Changed,
			&run.Error, &run.StartedAt, &run.FinishedAt, &by); err != nil {
			return run, err
		}
		return run, jsonPtr(by, &run.TriggeredBy)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if runs == nil {
		runs = []SyncRun{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": runs})
}
