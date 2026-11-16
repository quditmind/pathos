package repos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/platform/db"
	"pathos/internal/scm"
)

// importLease is extended by a heartbeat while an item runs.
const importLease = 3 * time.Minute

// importError is a classified processing failure.
type importError struct {
	Code      string
	Msg       string
	Transient bool // retry with backoff
	Attention bool // needs_attention instead of failed
}

func (e *importError) Error() string { return e.Code + ": " + e.Msg }

func permanent(code, msg string) error { return &importError{Code: code, Msg: msg} }
func attention(code, msg string) error { return &importError{Code: code, Msg: msg, Attention: true} }

// classifyProviderError maps SCM errors onto import error codes.
func classifyProviderError(err error) error {
	var ie *importError
	switch {
	case errors.As(err, &ie):
		return err
	case errors.Is(err, scm.ErrNotFound):
		return permanent("repository_not_found", "the repository does not exist or the connection cannot see it")
	case errors.Is(err, scm.ErrForbidden):
		return permanent("permission_denied", "the connection's credential lacks read permission on this repository")
	case errors.Is(err, scm.ErrAuth):
		return permanent("authentication_failed", err.Error())
	case errors.Is(err, scm.ErrTokenExpired):
		return attention("token_expired", "the connection's authorization expired; reconnect it, then retry")
	case errors.Is(err, scm.ErrBlockedAddress):
		return permanent("blocked_address", err.Error())
	case errors.Is(err, context.DeadlineExceeded):
		return &importError{Code: "timeout", Msg: "the provider did not answer in time", Transient: true}
	case scm.IsTransient(err):
		return &importError{Code: "provider_unavailable", Msg: truncate(err.Error(), 300), Transient: true}
	}
	return &importError{Code: "provider_error", Msg: truncate(err.Error(), 300), Transient: true}
}

// importItem is a claimed item.
type importItem struct {
	ID, OrgID, JobID uuid.UUID
	Source           string
	ConnID           *uuid.UUID
	RequestedBy      uuid.UUID
	Ref              sourceRef
	Name             string
	Values           AssetValues
	Attempts         int
	MaxAttempts      int
	AllowDuplicate   bool
	StartScan        bool
}

// RunImportWorkers processes import items until ctx ends (jobs role).
// owner identifies this process in leases.
func (s *Service) RunImportWorkers(ctx context.Context, n int, owner string) {
	if n < 1 {
		n = 1
	}
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			s.importLoop(ctx, id)
		}(fmt.Sprintf("%s/%d", owner, i))
	}
	// Recover items whose worker died.
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			if err := s.recoverImports(ctx); err != nil && ctx.Err() == nil {
				s.Log.Warn("import recovery failed", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
	wg.Wait()
}

func (s *Service) importLoop(ctx context.Context, owner string) {
	for ctx.Err() == nil {
		item, err := s.claimImport(ctx, owner)
		if err != nil {
			if !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
				s.Log.Warn("import claim failed", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		s.runImportItem(ctx, item, owner)
	}
}

// ProcessNextImport claims and processes one queued item (tests, tools).
// It reports whether an item was processed.
func (s *Service) ProcessNextImport(ctx context.Context) (bool, error) {
	item, err := s.claimImport(ctx, "inline")
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	s.runImportItem(ctx, item, "inline")
	return true, nil
}

func (s *Service) claimImport(ctx context.Context, owner string) (importItem, error) {
	var it importItem
	var ref, md []byte
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			UPDATE repository_import_items i SET status = 'validating', stage = 'validating', attempts = attempts + 1, lease_owner = $1,
			       lease_expires_at = now() + $2::interval, started_at = COALESCE(started_at, now()), progress = 5,
			       progress_message = 'Validating', error_code = '', error_message = '', updated_at = now()
			WHERE i.id = (
			  SELECT q.id FROM repository_import_items q JOIN repository_import_jobs j ON j.id = q.job_id
			  WHERE q.status = 'queued' AND q.next_attempt_at <= now() AND j.cancel_requested_at IS NULL
			  ORDER BY q.next_attempt_at, q.position FOR UPDATE OF q SKIP LOCKED LIMIT 1)
			RETURNING i.id, i.organization_id, i.job_id, i.source_ref, i.display_name, i.metadata, i.attempts, i.max_attempts, i.allow_duplicate`,
			owner, importLease.String()).Scan(&it.ID, &it.OrgID, &it.JobID, &ref, &it.Name, &md, &it.Attempts, &it.MaxAttempts, &it.AllowDuplicate)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `UPDATE repository_import_jobs SET started_at = COALESCE(started_at, now()) WHERE id = $1
			RETURNING source_type, scm_connection_id, requested_by, start_scan`, it.JobID).
			Scan(&it.Source, &it.ConnID, &it.RequestedBy, &it.StartScan); err != nil {
			return err
		}
		return refreshJobStatus(ctx, tx, it.JobID)
	})
	if err != nil {
		return it, err
	}
	if err := json.Unmarshal(ref, &it.Ref); err != nil {
		return it, err
	}
	return it, json.Unmarshal(md, &it.Values)
}

// recoverImports requeues items whose lease expired (crashed worker).
func (s *Service) recoverImports(ctx context.Context) error {
	rows, err := s.DB.Query(ctx, `
		UPDATE repository_import_items SET
		  status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
		  error_code = CASE WHEN attempts >= max_attempts THEN 'worker_lost' ELSE error_code END,
		  error_message = CASE WHEN attempts >= max_attempts THEN 'the import worker stopped while processing this item' ELSE error_message END,
		  completed_at = CASE WHEN attempts >= max_attempts THEN now() END,
		  next_attempt_at = now(), lease_owner = '', lease_expires_at = NULL, updated_at = now()
		WHERE status IN ('validating', 'importing', 'registering') AND lease_expires_at < now()
		RETURNING job_id`)
	if err != nil {
		return err
	}
	jobs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, j := range jobs {
		if err := refreshJobStatus(ctx, s.DB, j); err != nil {
			return err
		}
	}
	return nil
}

// stage records progress; it fails when the item was cancelled or its
// lease was lost, which stops processing at a stage boundary.
func (s *Service) stage(ctx context.Context, it importItem, owner, status string, progress int, msg string) error {
	tag, err := s.DB.Exec(ctx, `UPDATE repository_import_items SET status = $3, stage = $3, progress = $4, progress_message = $5,
		lease_expires_at = now() + $6::interval, updated_at = now()
		WHERE id = $1 AND lease_owner = $2 AND status IN ('validating', 'importing', 'registering')
		  AND NOT EXISTS (SELECT 1 FROM repository_import_jobs j WHERE j.id = job_id AND j.cancel_requested_at IS NOT NULL)`,
		it.ID, owner, status, progress, msg, importLease.String())
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return errCancelled
	}
	_ = refreshJobStatus(ctx, s.DB, it.JobID)
	return nil
}

var errCancelled = errors.New("import cancelled")

func (s *Service) runImportItem(parent context.Context, it importItem, owner string) {
	timeout := s.Limits.ImportTimeout
	if timeout <= 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	// Heartbeat: extend the lease and watch for cancellation.
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				var cancelled bool
				err := s.DB.QueryRow(ctx, `UPDATE repository_import_items i SET lease_expires_at = now() + $3::interval
					WHERE i.id = $1 AND i.lease_owner = $2
					RETURNING (SELECT j.cancel_requested_at IS NOT NULL FROM repository_import_jobs j WHERE j.id = i.job_id)`,
					it.ID, owner, importLease.String()).Scan(&cancelled)
				if err != nil || cancelled {
					cancel()
					return
				}
			}
		}
	}()
	log := s.Log.With("import_item_id", it.ID, "job_id", it.JobID, "source", it.Source)
	var res importResult
	var err error
	if it.Source == "upload" {
		res, err = s.processUpload(ctx, it, owner)
	} else {
		res, err = s.processSCM(ctx, it, owner)
	}
	bg := context.WithoutCancel(parent)
	if err == nil {
		s.finishItem(bg, it, owner, StatusCompleted, res, "", "")
		log.Info("import item completed", "repository_id", res.RepositoryID, "result", res.Result)
		if res.Result == "imported" || res.Result == "snapshot_added" {
			s.maybeScan(bg, it, res)
		}
		return
	}
	var ie *importError
	switch {
	case errors.Is(err, errCancelled), parent.Err() == nil && errors.Is(ctx.Err(), context.Canceled):
		s.finishItem(bg, it, owner, StatusCancelled, res, "cancelled", "cancelled before completion")
	case errors.Is(ctx.Err(), context.DeadlineExceeded) && parent.Err() == nil:
		s.finishItem(bg, it, owner, StatusFailed, res, "timeout", fmt.Sprintf("the import did not finish within %s", timeout))
	case parent.Err() != nil:
		// Shutting down: hand the item back without spending an attempt.
		_, _ = s.DB.Exec(bg, `UPDATE repository_import_items SET status = 'queued', attempts = GREATEST(attempts - 1, 0),
			lease_owner = '', lease_expires_at = NULL, progress_message = 'Interrupted; will resume', updated_at = now()
			WHERE id = $1 AND lease_owner = $2`, it.ID, owner)
		_ = refreshJobStatus(bg, s.DB, it.JobID)
	case errors.As(err, &ie) && ie.Transient && it.Attempts < it.MaxAttempts:
		delay := time.Duration(math.Pow(2, float64(it.Attempts))) * 15 * time.Second
		_, _ = s.DB.Exec(bg, `UPDATE repository_import_items SET status = 'queued', next_attempt_at = now() + $3::interval,
			lease_owner = '', lease_expires_at = NULL, error_code = $4, error_message = $5,
			progress_message = 'Retrying after a temporary error', updated_at = now()
			WHERE id = $1 AND lease_owner = $2`, it.ID, owner, delay.String(), ie.Code, truncate(ie.Msg, 1000))
		_ = refreshJobStatus(bg, s.DB, it.JobID)
		log.Warn("import item will be retried", "code", ie.Code, "in", delay)
	case errors.As(err, &ie):
		status := StatusFailed
		if ie.Attention {
			status = StatusNeedsAttention
		}
		s.finishItem(bg, it, owner, status, res, ie.Code, ie.Msg)
		log.Warn("import item stopped", "status", status, "code", ie.Code, "msg", ie.Msg)
	default:
		s.finishItem(bg, it, owner, StatusFailed, res, "internal_error", "an internal error occurred; see the server log")
		log.Error("import item failed", "err", err)
	}
}

// importResult is what processing produced.
type importResult struct {
	Result       string
	RepositoryID *uuid.UUID
	SnapshotID   *uuid.UUID
}

func (s *Service) finishItem(ctx context.Context, it importItem, owner, status string, res importResult, code, msg string) {
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		progress, pmsg := 100, map[string]string{StatusCompleted: "Completed", StatusFailed: "Failed", StatusCancelled: "Cancelled",
			StatusNeedsAttention: "Needs attention"}[status]
		if status != StatusCompleted {
			progress = 0
		}
		tag, err := tx.Exec(ctx, `UPDATE repository_import_items SET status = $3, result = $4, repository_id = COALESCE($5, repository_id),
			stage = CASE WHEN $3 = 'completed' THEN 'completed' ELSE stage END,
			snapshot_id = COALESCE($6, snapshot_id), error_code = $7, error_message = $8, progress = $9, progress_message = $10,
			lease_owner = '', lease_expires_at = NULL, completed_at = now(), updated_at = now()
			WHERE id = $1 AND lease_owner = $2`, it.ID, owner, status, res.Result, res.RepositoryID, res.SnapshotID, code,
			truncate(msg, 1000), progress, pmsg)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		if status == StatusFailed || status == StatusNeedsAttention {
			if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: it.OrgID, ActorID: &it.RequestedBy, Action: "repository_import.item_failed",
				Outcome: "failure", TargetType: "repository_import", TargetID: it.JobID.String(),
				Metadata: map[string]any{"item_id": it.ID, "name": it.Name, "code": code, "message": truncate(msg, 300)}}); err != nil {
				return err
			}
		}
		if err := refreshJobStatus(ctx, tx, it.JobID); err != nil {
			return err
		}
		// Notify once when the whole job has finished with failures.
		var jobStatus string
		var done bool
		if err := tx.QueryRow(ctx, `SELECT status, completed_at IS NOT NULL FROM repository_import_jobs WHERE id = $1`, it.JobID).
			Scan(&jobStatus, &done); err != nil {
			return err
		}
		if done && (jobStatus == StatusFailed || jobStatus == StatusNeedsAttention) {
			_, err = tx.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, subject_id, payload)
				SELECT $1, 'import.failed', $2, jsonb_build_object('status', $3::text, 'requested_by', $4::uuid)
				WHERE NOT EXISTS (SELECT 1 FROM notification_events WHERE event_key = 'import.failed' AND subject_id = $2
				                  AND created_at > (SELECT updated_at - interval '1 second' FROM repository_import_jobs WHERE id = $2 ))`,
				it.OrgID, it.JobID, jobStatus, it.RequestedBy)
		}
		return err
	})
	if err != nil {
		s.Log.Error("import item status not saved", "import_item_id", it.ID, "err", err)
	}
}

// maybeScan queues an onboarding scan when the job asked for it and the
// organization policy allows it (checked again now).
func (s *Service) maybeScan(ctx context.Context, it importItem, res importResult) {
	if !it.StartScan || s.EnqueueScan == nil || res.RepositoryID == nil {
		return
	}
	ap, err := s.loadPolicy(ctx, s.DB, it.OrgID)
	if err != nil || !ap.ScanOnImport {
		return
	}
	if err := s.EnqueueScan(ctx, it.OrgID, *res.RepositoryID, "onboarding", &it.RequestedBy); err != nil {
		s.Log.Warn("onboarding scan not queued", "repository_id", *res.RepositoryID, "err", err)
	}
}

// requester rebuilds the requesting user's authorization for registration
// (permissions may have changed since the job was created).
func (s *Service) requester(ctx context.Context, it importItem) (*authz.Principal, error) {
	u, err := identity.GetUser(ctx, s.DB, it.OrgID, it.RequestedBy)
	if err != nil {
		return nil, err
	}
	if u.Status != identity.StatusActive {
		return nil, identity.ErrDeactivated
	}
	grants, err := identity.LoadGrants(ctx, s.DB, u.ID)
	if err != nil {
		return nil, err
	}
	return &authz.Principal{UserID: u.ID, OrganizationID: u.OrganizationID, Email: u.Email, DisplayName: u.DisplayName, Grants: grants}, nil
}

// registerChecks re-validates metadata and authorization at registration
// time, so an asset is never created with metadata that has become invalid.
func (s *Service) registerChecks(ctx context.Context, it *importItem) error {
	p, err := s.requester(ctx, *it)
	if err != nil {
		return attention("requester_unavailable", "the requesting user is no longer active")
	}
	target, err := s.targetScope(ctx, p, it.Values.BusinessUnitID, it.Values.CountryID)
	if err == nil {
		err = s.Authz.Require(ctx, p, authz.PermReposManage, target)
	}
	if err != nil {
		return attention("permission_denied", "the requesting user no longer has repos.manage for the selected placement")
	}
	ap, err := s.loadPolicy(ctx, s.DB, it.OrgID)
	if err != nil {
		return err
	}
	// An application requested as "new" may already have been created by
	// an earlier item of the same job: use it.
	if na := it.Values.NewApplication; na != nil {
		var appID uuid.UUID
		if err := s.DB.QueryRow(ctx, `SELECT a.id FROM applications a WHERE a.organization_id = $1 AND lower(a.name) = lower($2) AND a.archived_at IS NULL
			AND EXISTS (SELECT 1 FROM repository_import_items i JOIN repositories r ON r.id = i.repository_id
			            WHERE i.job_id = $3 AND r.application_id = a.id)`, it.OrgID, na.Name, it.JobID).Scan(&appID); err == nil {
			it.Values.ApplicationID, it.Values.NewApplication = &appID, nil
		}
	}
	if fe := validateValues(ctx, s.DB, it.OrgID, ap, &it.Values, validateOpts{Creating: true}); len(fe) > 0 {
		parts := []string{}
		for k, v := range fe {
			parts = append(parts, k+": "+v)
		}
		return attention("validation_failed", "metadata is no longer valid ("+strings.Join(parts, "; ")+"); edit and import again")
	}
	return nil
}

// processSCM imports a Git or Azure DevOps repository.
func (s *Service) processSCM(ctx context.Context, it importItem, owner string) (importResult, error) {
	var res importResult
	if it.ConnID == nil {
		return res, permanent("invalid_item", "import item has no connection")
	}
	c, err := s.getConn(ctx, s.DB, it.OrgID, *it.ConnID)
	if err != nil {
		return res, permanent("connection_unavailable", "the SCM connection was deleted")
	}
	// Already imported (same connection, same repository): idempotent.
	if it.Ref.ExternalID != "" {
		var existing uuid.UUID
		if err := s.DB.QueryRow(ctx, `SELECT id FROM repositories WHERE scm_connection_id = $1 AND external_id = $2`, c.ID, it.Ref.ExternalID).
			Scan(&existing); err == nil {
			return importResult{Result: "already_imported", RepositoryID: &existing}, nil
		}
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		return res, classifyProviderError(err)
	}
	rr, err := cl.GetRepository(ctx, it.Ref.RepoRef)
	if err != nil {
		return res, classifyProviderError(err)
	}
	ref := rr.Ref()
	if ref.Organization == "" {
		ref.Organization = it.Ref.Organization
	}
	if ref.Project == "" {
		ref.Project = it.Ref.Project
	}
	var existing uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT id FROM repositories WHERE scm_connection_id = $1 AND external_id = $2`, c.ID, rr.ExternalID).
		Scan(&existing); err == nil {
		return importResult{Result: "already_imported", RepositoryID: &existing}, nil
	}
	if !it.AllowDuplicate && rr.CloneURL != "" {
		var dup uuid.UUID
		if err := s.DB.QueryRow(ctx, `SELECT id FROM repositories WHERE organization_id = $1 AND lower(clone_url) = lower($2)`,
			it.OrgID, rr.CloneURL).Scan(&dup); err == nil {
			res.RepositoryID = &dup
			return res, attention("duplicate", "this repository is already registered through another connection; retry with \"import anyway\" to register it twice")
		}
	}
	if err := s.stage(ctx, it, owner, StatusImporting, 35, "Reading branch and commit"); err != nil {
		return res, err
	}
	branch := it.Ref.Branch
	commit, err := cl.LatestCommit(ctx, ref, branch)
	if err != nil {
		if branch != "" && errors.Is(err, scm.ErrNotFound) {
			return res, permanent("invalid_branch", "branch "+branch+" does not exist")
		}
		if !(errors.Is(err, scm.ErrNotFound) && rr.DefaultBranch == "") {
			return res, classifyProviderError(err)
		}
		// Empty repository: register it without a commit.
	}
	if err := s.stage(ctx, it, owner, StatusImporting, 55, "Detecting languages"); err != nil {
		return res, err
	}
	langs, _ := cl.Languages(ctx, ref)
	if langs == nil {
		langs = map[string]int64{}
	}
	if err := s.stage(ctx, it, owner, StatusRegistering, 75, "Registering asset"); err != nil {
		return res, err
	}
	if err := s.registerChecks(ctx, &it); err != nil {
		return res, err
	}
	vis := rr.Visibility
	if vis != "public" && vis != "internal" {
		vis = "private"
	}
	var techs []string
	if rr.Language != "" {
		techs = []string{rr.Language}
	}
	id := uuid.Must(uuid.NewV7())
	result := "imported"
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `
			INSERT INTO repositories (id, organization_id, scm_connection_id, source_type, external_id, full_name, name, url, clone_url,
			  default_branch, scan_branch, visibility, description, technologies, remote_archived, last_pushed_at, imported_by,
			  scm_organization, scm_project, full_history, latest_commit_sha, latest_commit_at, size_bytes, languages,
			  last_sync_at, last_sync_ok_at, sync_status)
			VALUES ($1, $2, $3, 'scm', $4, $5, $6, $7, $8, $9, $10, $11, $12, COALESCE($13::text[], '{}'), $14, $15, $16,
			  $17, $18, $19, $20, $21, NULLIF($22::bigint, 0), $23, now(), now(), 'ok')
			ON CONFLICT (scm_connection_id, external_id) DO NOTHING`,
			id, it.OrgID, c.ID, rr.ExternalID, rr.FullName, rr.Name, rr.URL, rr.CloneURL, rr.DefaultBranch, branch, vis,
			truncate(rr.Description, 2000), techs, rr.Archived, rr.PushedAt, it.RequestedBy,
			ref.Organization, ref.Project, it.Ref.FullHistory, commit.SHA, commit.CommittedAt, rr.SizeBytes, langs)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			result = "already_imported"
			return tx.QueryRow(ctx, `SELECT id FROM repositories WHERE scm_connection_id = $1 AND external_id = $2`, c.ID, rr.ExternalID).Scan(&id)
		}
		if it.Values.Description == "" {
			it.Values.Description = truncate(rr.Description, 2000)
		}
		if err := writeValues(ctx, tx, it.OrgID, id, it.RequestedBy, &it.Values); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO repository_sync_runs (id, organization_id, repository_id, trigger, status, branch, commit_sha, changed, triggered_by)
			VALUES ($1, $2, $3, 'import', 'ok', $4, $5, true, $6)`, uuid.Must(uuid.NewV7()), it.OrgID, id, firstNonEmpty(branch, rr.DefaultBranch), commit.SHA, it.RequestedBy); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: it.OrgID, ActorID: &it.RequestedBy, Action: "repository.import",
			TargetType: "repository", TargetID: id.String(),
			Metadata: map[string]any{"name": rr.FullName, "import_job_id": it.JobID, "scm_connection_id": c.ID, "provider": c.Provider,
				"branch": firstNonEmpty(branch, rr.DefaultBranch), "commit_sha": commit.SHA, "metadata": it.Values}})
	})
	if err != nil {
		if db.IsUniqueViolation(err) {
			return res, permanent("name_clash", "another asset already uses this asset name")
		}
		if db.IsForeignKeyViolation(err) {
			return res, attention("validation_failed", "a referenced owner, team, unit, region or tag was deleted; edit and import again")
		}
		return res, err
	}
	return importResult{Result: result, RepositoryID: &id}, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
