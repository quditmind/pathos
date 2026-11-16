package repos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
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

// Import item and job statuses (spec section 9).
const (
	StatusQueued         = "queued"
	StatusValidating     = "validating"
	StatusImporting      = "importing"
	StatusRegistering    = "registering"
	StatusCompleted      = "completed"
	StatusFailed         = "failed"
	StatusCancelled      = "cancelled"
	StatusNeedsAttention = "needs_attention"
)

var (
	activeStatuses   = []string{"draft", "pending", StatusQueued, StatusValidating, StatusImporting, StatusRegistering}
	runningStatuses  = []string{StatusValidating, StatusImporting, StatusRegistering}
	retryableResults = []string{StatusFailed, StatusNeedsAttention, StatusCancelled}
)

// maxImportItems bounds one import job.
const maxImportItems = 200

func (s *Service) registerImports(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/repository-imports/validate", s.validateImportHandler)
	mux.HandleFunc("POST /api/v1/repository-imports", s.createImport)
	mux.HandleFunc("GET /api/v1/repository-imports", s.listImports)
	mux.HandleFunc("GET /api/v1/repository-imports/{id}", s.getImport)
	mux.HandleFunc("POST /api/v1/repository-imports/{id}/cancel", s.cancelImport)
	mux.HandleFunc("POST /api/v1/repository-imports/{id}/retry", s.retryImport)
}

// importItemRequest is one repository to import (frontend ImportItemRequest).
type importItemRequest struct {
	Ref                *scm.RepoRef `json:"ref"`
	UploadID           *uuid.UUID   `json:"upload_id"`
	TargetRepositoryID *uuid.UUID   `json:"target_repository_id"`
	Branch             string       `json:"branch"`
	FullHistory        bool         `json:"full_history"`
	DisplayName        *string      `json:"display_name"`
	AssetName          *string      `json:"asset_name"`
	AllowDuplicate     bool         `json:"allow_duplicate"`
}

type importJobRequest struct {
	Source          string              `json:"source"`
	SCMConnectionID *uuid.UUID          `json:"scm_connection_id"`
	IdempotencyKey  string              `json:"idempotency_key"`
	Metadata        AssetMetadata       `json:"metadata"`
	Items           []importItemRequest `json:"items"`
	StartScan       bool                `json:"start_scan"`
}

// sourceRef is stored per item (repository_import_items.source_ref).
type sourceRef struct {
	scm.RepoRef
	UploadID           *uuid.UUID `json:"upload_id,omitempty"`
	TargetRepositoryID *uuid.UUID `json:"target_repository_id,omitempty"`
	Branch             string     `json:"branch,omitempty"`
	FullHistory        bool       `json:"full_history,omitempty"`
}

// ItemProblem is a per-item validation finding.
type ItemProblem struct {
	Index        int        `json:"index"`
	Code         string     `json:"code"`
	Message      string     `json:"message"`
	RepositoryID *uuid.UUID `json:"repository_id,omitempty"`
}

// plannedItem is a validated item ready to be stored.
type plannedItem struct {
	ref     sourceRef
	name    string
	values  AssetValues
	dupOK   bool
	blocked bool // a problem that prevents creating the job
}

// planImport validates a request. Field errors concern the shared
// metadata; problems concern individual items. blocking reports whether
// the job may not be created.
func (s *Service) planImport(ctx context.Context, p *authz.Principal, req *importJobRequest) (*Connection, []plannedItem, FieldErrors, []ItemProblem, error) {
	var conn *Connection
	switch req.Source {
	case "upload":
		if req.SCMConnectionID != nil {
			return nil, nil, nil, nil, httpx.BadRequest("scm_connection_id does not apply to uploads")
		}
		if s.Sources == nil {
			return nil, nil, nil, nil, httpx.E(http.StatusServiceUnavailable, "uploads_unavailable", "local uploads are not configured on this server")
		}
	case "git", "devops":
		if req.SCMConnectionID == nil {
			return nil, nil, nil, nil, httpx.BadRequest("scm_connection_id is required")
		}
		c, err := s.getConn(ctx, s.DB, p.OrganizationID, *req.SCMConnectionID)
		if err != nil {
			return nil, nil, nil, nil, httpx.BadRequest("unknown SCM connection")
		}
		info, _ := providerInfo(c.Provider)
		if info.Category != req.Source && !(info.Category == "" && req.Source == "git") {
			return nil, nil, nil, nil, httpx.BadRequest(fmt.Sprintf("a %s connection cannot be used for a %s import", c.Provider, req.Source))
		}
		conn = &c
	default:
		return nil, nil, nil, nil, httpx.BadRequest("source must be upload, git or devops")
	}
	if len(req.Items) == 0 || len(req.Items) > maxImportItems {
		return nil, nil, nil, nil, httpx.BadRequest(fmt.Sprintf("select 1-%d repositories", maxImportItems))
	}
	ap, err := s.loadPolicy(ctx, s.DB, p.OrganizationID)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// New versions of existing uploaded repositories keep the asset's
	// metadata; authorization is checked per target repository.
	versionsOnly := req.Source == "upload"
	for _, it := range req.Items {
		versionsOnly = versionsOnly && it.TargetRepositoryID != nil
	}
	base := defaultValues()
	base.TagIDs = []uuid.UUID{}
	req.Metadata.Apply(&base)
	if req.Metadata.Environment == nil {
		base.Environment = ""
	}
	if req.Metadata.Criticality == nil {
		base.Criticality = ""
	}
	fe := FieldErrors{}
	if !versionsOnly {
		fe = validateValues(ctx, s.DB, p.OrganizationID, ap, &base, validateOpts{Creating: true})
		delete(fe, "asset_name") // checked per item below

		// Authorization: repos.manage at the target placement.
		target, err := s.targetScope(ctx, p, base.BusinessUnitID, base.CountryID)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if err := s.Authz.Require(ctx, p, authz.PermReposManage, target); err != nil {
			return nil, nil, nil, nil, err
		}
	} else if err := req.Metadata.mustBeEmpty(); err != nil {
		return nil, nil, nil, nil, err
	}

	var problems []ItemProblem
	if versionsOnly {
		// No new asset is created: names are kept.
		for i := range req.Items {
			req.Items[i].DisplayName, req.Items[i].AssetName = nil, nil
		}
	}
	planned := make([]plannedItem, 0, len(req.Items))
	seenRefs, seenNames := map[string]bool{}, map[string]bool{}
	for i, it := range req.Items {
		pi := plannedItem{values: base, dupOK: it.AllowDuplicate}
		pi.values.ComplianceScopes, pi.values.TagIDs = slices.Clone(base.ComplianceScopes), slices.Clone(base.TagIDs)
		problem := func(code, msg string, repoID *uuid.UUID, blocking bool) {
			if repoID != nil && *repoID == uuid.Nil {
				repoID = nil // exists, but not visible to the caller
			}
			problems = append(problems, ItemProblem{Index: i, Code: code, Message: msg, RepositoryID: repoID})
			pi.blocked = pi.blocked || blocking
		}
		if it.Branch != "" && !validBranch(it.Branch) {
			problem("invalid_branch", "invalid branch name", nil, true)
		}
		pi.ref.Branch, pi.ref.FullHistory = it.Branch, it.FullHistory
		switch req.Source {
		case "upload":
			if it.UploadID == nil || it.Ref != nil {
				problem("invalid_item", "each upload item needs an upload_id", nil, true)
				break
			}
			pi.ref.UploadID, pi.ref.TargetRepositoryID = it.UploadID, it.TargetRepositoryID
			name, dupRepo, msg, blocking := s.checkUploadItem(ctx, p, *it.UploadID, it.TargetRepositoryID)
			pi.name = name
			if msg != "" {
				code := "invalid_upload"
				if dupRepo != nil {
					code = "duplicate"
				}
				if !(code == "duplicate" && it.AllowDuplicate) {
					problem(code, msg, dupRepo, blocking)
				}
			}
			if seenRefs["u:"+it.UploadID.String()] {
				problem("duplicate_item", "the same upload is listed twice", nil, true)
			}
			seenRefs["u:"+it.UploadID.String()] = true
		default:
			if it.Ref == nil || (it.Ref.ExternalID == "" && it.Ref.FullName == "") || it.UploadID != nil || it.TargetRepositoryID != nil {
				problem("invalid_item", "each repository needs ref.external_id or ref.full_name", nil, true)
				break
			}
			for _, v := range []string{it.Ref.ExternalID, it.Ref.FullName, it.Ref.Organization, it.Ref.Project} {
				if len(v) > 300 {
					problem("invalid_item", "repository reference is too long", nil, true)
				}
			}
			pi.ref.RepoRef = *it.Ref
			pi.name = it.Ref.FullName
			if pi.name == "" {
				pi.name = it.Ref.ExternalID
			}
			key := "r:" + it.Ref.ExternalID + "/" + strings.ToLower(it.Ref.FullName)
			if seenRefs[key] {
				problem("duplicate_item", "the same repository is listed twice", nil, true)
			}
			seenRefs[key] = true
			if it.Ref.ExternalID != "" {
				var existing uuid.UUID
				if err := s.DB.QueryRow(ctx, `SELECT id FROM repositories WHERE organization_id = $1 AND scm_connection_id = $2 AND external_id = $3`,
					p.OrganizationID, conn.ID, it.Ref.ExternalID).Scan(&existing); err == nil {
					if !s.canRead(ctx, p, existing) {
						existing = uuid.Nil
					}
					problem("already_imported", "already imported; it will be skipped", &existing, false)
				}
			}
		}
		if it.DisplayName != nil {
			pi.values.DisplayName = strings.TrimSpace(*it.DisplayName)
		}
		if it.AssetName != nil {
			pi.values.AssetName = strings.TrimSpace(*it.AssetName)
		}
		if pi.values.DisplayName == "" && pi.name != "" {
			pi.values.DisplayName = truncate(pi.name, 200)
		}
		if pi.values.DisplayName != "" {
			pi.name = pi.values.DisplayName
		}
		if len(pi.values.DisplayName) > 200 || len(pi.values.AssetName) > 200 {
			problem("invalid_name", "names must be at most 200 characters", nil, true)
		}
		if an := strings.ToLower(pi.values.AssetName); an != "" {
			if seenNames[an] {
				problem("name_clash", "two items use the asset name "+pi.values.AssetName, nil, true)
			}
			seenNames[an] = true
			if it.TargetRepositoryID == nil {
				var clash bool
				_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM repositories WHERE organization_id = $1 AND lower(asset_name) = $2 AND archived_at IS NULL)`,
					p.OrganizationID, an).Scan(&clash)
				if clash {
					problem("name_clash", "another asset already uses the name "+pi.values.AssetName, nil, true)
				}
			}
		}
		planned = append(planned, pi)
	}
	if problems == nil {
		problems = []ItemProblem{}
	}
	return conn, planned, fe, problems, nil
}

func blocking(planned []plannedItem, fe FieldErrors) bool {
	if len(fe) > 0 {
		return true
	}
	for _, pi := range planned {
		if pi.blocked {
			return true
		}
	}
	return false
}

func (s *Service) validateImportHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var req importJobRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	_, planned, fe, problems, err := s.planImport(ctx, p, &req)
	if err != nil {
		var he *httpx.Error
		if errors.As(err, &he) && he.Status == http.StatusUnprocessableEntity {
			fe = he.Fields
		} else {
			s.fail(w, r, err)
			return
		}
	}
	if fe == nil {
		fe = FieldErrors{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"valid": !blocking(planned, fe), "fields": fe, "items": problems})
}

func (s *Service) createImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var req importJobRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	key := strings.TrimSpace(req.IdempotencyKey)
	if key == "" {
		key = r.Header.Get("Idempotency-Key")
	}
	if len(key) < 8 || len(key) > 100 {
		s.fail(w, r, httpx.BadRequest("idempotency_key (8-100 characters) is required"))
		return
	}
	// A repeated submission returns the job created by the first one.
	var existing uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT id FROM repository_import_jobs WHERE organization_id = $1 AND requested_by = $2 AND idempotency_key = $3`,
		p.OrganizationID, p.UserID, key).Scan(&existing); err == nil {
		job, err := s.loadImport(ctx, p, existing, true)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, job)
		return
	}
	conn, planned, fe, problems, err := s.planImport(ctx, p, &req)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := fe.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	if blocking(planned, fe) {
		msgs := []string{}
		for _, pr := range problems {
			if planned[pr.Index].blocked {
				msgs = append(msgs, fmt.Sprintf("item %d: %s", pr.Index+1, pr.Message))
			}
		}
		e := httpx.E(http.StatusUnprocessableEntity, "invalid_items", strings.Join(msgs, "; "))
		e.Details = map[string]any{"items": problems}
		s.fail(w, r, e)
		return
	}
	ap, err := s.loadPolicy(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	jobID := uuid.Must(uuid.NewV7())
	var connID *uuid.UUID
	if conn != nil {
		connID = &conn.ID
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO repository_import_jobs (id, organization_id, source_type, scm_connection_id, status,
			requested_by, idempotency_key, total_items, start_scan) VALUES ($1, $2, $3, $4, 'queued', $5, $6, $7, $8)`,
			jobID, p.OrganizationID, req.Source, connID, p.UserID, key, len(planned), req.StartScan && ap.ScanOnImport); err != nil {
			return err
		}
		for i, pi := range planned {
			ref, _ := json.Marshal(pi.ref)
			md, _ := json.Marshal(pi.values)
			if _, err := tx.Exec(ctx, `INSERT INTO repository_import_items (id, organization_id, job_id, position, source_ref, display_name,
				metadata, allow_duplicate) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
				uuid.Must(uuid.NewV7()), p.OrganizationID, jobID, i, ref, truncate(pi.name, 300), md, pi.dupOK); err != nil {
				if db.IsUniqueViolation(err) {
					return httpx.Conflict("an upload is already being imported by another job")
				}
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository_import.create", TargetType: "repository_import", TargetID: jobID.String(),
			Metadata: map[string]any{"source": req.Source, "items": len(planned), "scm_connection_id": connID}})
	})
	if err != nil {
		if db.IsUniqueViolation(err) {
			// Lost a race with an identical submission.
			if e2 := s.DB.QueryRow(ctx, `SELECT id FROM repository_import_jobs WHERE organization_id = $1 AND requested_by = $2 AND idempotency_key = $3`,
				p.OrganizationID, p.UserID, key).Scan(&existing); e2 == nil {
				job, e3 := s.loadImport(ctx, p, existing, true)
				if e3 == nil {
					httpx.WriteJSON(w, http.StatusOK, job)
					return
				}
			}
		}
		s.fail(w, r, err)
		return
	}
	job, err := s.loadImport(ctx, p, jobID, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, job)
}

// ImportItemView is the API form of an item (frontend ImportItem).
type ImportItemView struct {
	ID              uuid.UUID  `json:"id"`
	Position        int        `json:"position"`
	DisplayName     string     `json:"display_name"`
	Status          string     `json:"status"`
	Stage           string     `json:"stage"`
	Result          string     `json:"result"`
	Progress        int        `json:"progress"`
	ProgressMessage string     `json:"progress_message"`
	ErrorCode       string     `json:"error_code"`
	ErrorMessage    string     `json:"error_message"`
	Attempts        int        `json:"attempts"`
	MaxAttempts     int        `json:"max_attempts"`
	RepositoryID    *uuid.UUID `json:"repository_id"`
	SnapshotID      *uuid.UUID `json:"snapshot_id"`
	StartedAt       *time.Time `json:"started_at"`
	CompletedAt     *time.Time `json:"completed_at"`
	CanRetry        bool       `json:"can_retry"`
}

// ImportJobView is the API form of a job (frontend ImportJob).
type ImportJobView struct {
	ID                 uuid.UUID        `json:"id"`
	SourceType         string           `json:"source_type"`
	SCMConnectionID    *uuid.UUID       `json:"scm_connection_id"`
	SCMConnectionName  string           `json:"scm_connection_name"`
	Status             string           `json:"status"`
	RequestedBy        UserRef          `json:"requested_by"`
	TotalItems         int              `json:"total_items"`
	CompletedItems     int              `json:"completed_items"`
	FailedItems        int              `json:"failed_items"`
	AttentionItems     int              `json:"attention_items"`
	StartScan          bool             `json:"start_scan"`
	CreatedAt          time.Time        `json:"created_at"`
	StartedAt          *time.Time       `json:"started_at"`
	CompletedAt        *time.Time       `json:"completed_at"`
	Items              []ImportItemView `json:"items,omitempty"`
	CanCancel          bool             `json:"can_cancel"`
	CanRetry           bool             `json:"can_retry"`
	cancelRequested    bool
	activeItems        int
	retryableItemCount int
}

const importJobSelect = `
	SELECT j.id, j.source_type, j.scm_connection_id, COALESCE(c.name, ''), j.status, u.id, COALESCE(NULLIF(u.display_name, ''), u.email), u.email,
	       j.total_items, j.start_scan, j.created_at, j.started_at, j.completed_at, j.cancel_requested_at IS NOT NULL,
	       count(i.id) FILTER (WHERE i.status = 'completed'), count(i.id) FILTER (WHERE i.status = 'failed'),
	       count(i.id) FILTER (WHERE i.status = 'needs_attention'),
	       count(i.id) FILTER (WHERE i.status IN ('draft', 'pending', 'queued', 'validating', 'importing', 'registering')),
	       count(i.id) FILTER (WHERE i.status IN ('failed', 'needs_attention', 'cancelled'))
	FROM repository_import_jobs j
	JOIN users u ON u.id = j.requested_by
	LEFT JOIN scm_connections c ON c.id = j.scm_connection_id
	LEFT JOIN repository_import_items i ON i.job_id = j.id`

const importJobGroup = ` GROUP BY j.id, c.name, u.id`

func scanImportJob(row pgx.Row) (ImportJobView, error) {
	var j ImportJobView
	err := row.Scan(&j.ID, &j.SourceType, &j.SCMConnectionID, &j.SCMConnectionName, &j.Status, &j.RequestedBy.ID, &j.RequestedBy.Name,
		&j.RequestedBy.Email, &j.TotalItems, &j.StartScan, &j.CreatedAt, &j.StartedAt, &j.CompletedAt, &j.cancelRequested,
		&j.CompletedItems, &j.FailedItems, &j.AttentionItems, &j.activeItems, &j.retryableItemCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return j, errNotFound
	}
	return j, err
}

// canControlImport: the requester, or repos.manage organization-wide.
func canControlImport(p *authz.Principal, requester uuid.UUID) bool {
	return requester == p.UserID || p.HasOrgWide(authz.PermReposManage)
}

func (j *ImportJobView) finish(p *authz.Principal) {
	ctl := canControlImport(p, j.RequestedBy.ID)
	j.CanCancel = ctl && (j.activeItems > 0 && !j.cancelRequested || j.AttentionItems > 0)
	j.CanRetry = ctl && j.retryableItemCount > 0
	for i := range j.Items {
		j.Items[i].CanRetry = ctl && slices.Contains(retryableResults, j.Items[i].Status)
	}
}

func (s *Service) loadImport(ctx context.Context, p *authz.Principal, id uuid.UUID, withItems bool) (ImportJobView, error) {
	j, err := scanImportJob(s.DB.QueryRow(ctx, importJobSelect+` WHERE j.organization_id = $1 AND j.id = $2`+importJobGroup, p.OrganizationID, id))
	if err != nil {
		return j, err
	}
	if !canControlImport(p, j.RequestedBy.ID) && !p.HasOrgWide(authz.PermReposRead) {
		return j, errNotFound
	}
	if withItems {
		rows, err := s.DB.Query(ctx, `SELECT id, position, display_name, status, stage, result, progress, progress_message, error_code, error_message,
			attempts, max_attempts, repository_id, snapshot_id, started_at, completed_at
			FROM repository_import_items WHERE job_id = $1 ORDER BY position`, id)
		if err != nil {
			return j, err
		}
		j.Items, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (ImportItemView, error) {
			var it ImportItemView
			return it, row.Scan(&it.ID, &it.Position, &it.DisplayName, &it.Status, &it.Stage, &it.Result, &it.Progress, &it.ProgressMessage,
				&it.ErrorCode, &it.ErrorMessage, &it.Attempts, &it.MaxAttempts, &it.RepositoryID, &it.SnapshotID, &it.StartedAt, &it.CompletedAt)
		})
		if err != nil {
			return j, err
		}
	}
	j.finish(p)
	return j, nil
}

func (s *Service) listImports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposManage) && !p.HasOrgWide(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	where := []string{"j.organization_id = $1"}
	args := []any{p.OrganizationID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if q.Get("mine") == "true" || (!p.HasOrgWide(authz.PermReposManage) && !p.HasOrgWide(authz.PermReposRead)) {
		add("j.requested_by = ?", p.UserID)
	}
	switch q.Get("status") {
	case "", "all":
	case "active":
		add("j.status = ANY(?)", activeStatuses)
	case "finished":
		add("NOT (j.status = ANY(?))", activeStatuses)
	default:
		if !slices.Contains(append(slices.Clone(activeStatuses), StatusCompleted, StatusFailed, StatusCancelled, StatusNeedsAttention), q.Get("status")) {
			s.fail(w, r, httpx.BadRequest("invalid status"))
			return
		}
		add("j.status = ?", q.Get("status"))
	}
	if c := q.Get("cursor"); c != "" {
		ts, idStr, ok := strings.Cut(c, "|")
		t, err1 := time.Parse(time.RFC3339Nano, ts)
		id, err2 := uuid.Parse(idStr)
		if !ok || err1 != nil || err2 != nil {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		args = append(args, t, id)
		where = append(where, fmt.Sprintf("(j.created_at, j.id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	limit := 25
	args = append(args, limit)
	rows, err := s.DB.Query(ctx, importJobSelect+" WHERE "+strings.Join(where, " AND ")+importJobGroup+
		fmt.Sprintf(" ORDER BY j.created_at DESC, j.id DESC LIMIT $%d", len(args)), args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	jobs, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ImportJobView, error) { return scanImportJob(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if jobs == nil {
		jobs = []ImportJobView{}
	}
	for i := range jobs {
		jobs[i].finish(p)
	}
	var next *string
	if len(jobs) == limit {
		last := jobs[len(jobs)-1]
		c := last.CreatedAt.Format(time.RFC3339Nano) + "|" + last.ID.String()
		next = &c
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": jobs, "next_cursor": next})
}

func (s *Service) getImport(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	job, err := s.loadImport(r.Context(), p, id, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, job)
}

func (s *Service) controlledImport(w http.ResponseWriter, r *http.Request) (*authz.Principal, ImportJobView, bool) {
	p := s.Principal(r.Context())
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return nil, ImportJobView{}, false
	}
	job, err := s.loadImport(r.Context(), p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return nil, ImportJobView{}, false
	}
	if !canControlImport(p, job.RequestedBy.ID) {
		s.fail(w, r, authz.ErrForbidden)
		return nil, ImportJobView{}, false
	}
	return p, job, true
}

func (s *Service) cancelImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, job, ok := s.controlledImport(w, r)
	if !ok {
		return
	}
	if !job.CanCancel {
		s.fail(w, r, httpx.Conflict("nothing to cancel"))
		return
	}
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE repository_import_jobs SET cancel_requested_at = now(), updated_at = now() WHERE id = $1`, job.ID); err != nil {
			return err
		}
		// Waiting items stop now; running items stop at their next stage.
		if _, err := tx.Exec(ctx, `UPDATE repository_import_items SET status = 'cancelled', progress_message = 'Cancelled by '||$2::text,
			completed_at = now(), updated_at = now() WHERE job_id = $1 AND status IN ('draft', 'pending', 'queued', 'needs_attention')`, job.ID, p.Email); err != nil {
			return err
		}
		if err := refreshJobStatus(ctx, tx, job.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository_import.cancel", TargetType: "repository_import", TargetID: job.ID.String()})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.loadImport(ctx, p, job.ID, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type retryRequest struct {
	ItemIDs        []uuid.UUID `json:"item_ids"`
	AllowDuplicate bool        `json:"allow_duplicate"`
}

func (s *Service) retryImport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, job, ok := s.controlledImport(w, r)
	if !ok {
		return
	}
	var req retryRequest
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, &req); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	var n int64
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE repository_import_items SET status = 'queued', attempts = 0, next_attempt_at = now(),
			error_code = '', error_message = '', progress = 0, progress_message = 'Queued for retry', completed_at = NULL, stage = 'queued',
			allow_duplicate = allow_duplicate OR $3, updated_at = now()
			WHERE job_id = $1 AND status IN ('failed', 'needs_attention', 'cancelled') AND (cardinality($2::uuid[]) = 0 OR id = ANY($2))`,
			job.ID, nonNil(req.ItemIDs), req.AllowDuplicate)
		if err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("an upload in this job is already being imported by another job")
			}
			return err
		}
		if n = tag.RowsAffected(); n == 0 {
			return httpx.Conflict("no failed, cancelled or attention items to retry")
		}
		if _, err := tx.Exec(ctx, `UPDATE repository_import_jobs SET cancel_requested_at = NULL, completed_at = NULL, status = 'queued',
			updated_at = now() WHERE id = $1`, job.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository_import.retry", TargetType: "repository_import", TargetID: job.ID.String(),
			Metadata: map[string]any{"items": n, "allow_duplicate": req.AllowDuplicate}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.loadImport(ctx, p, job.ID, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// refreshJobStatus derives the job status from its items.
func refreshJobStatus(ctx context.Context, q db.Querier, jobID uuid.UUID) error {
	_, err := q.Exec(ctx, `
		WITH c AS (
		  SELECT count(*) FILTER (WHERE status IN ('validating', 'importing', 'registering')) AS running,
		         count(*) FILTER (WHERE status IN ('draft', 'pending', 'queued')) AS waiting,
		         count(*) FILTER (WHERE status = 'failed') AS failed,
		         count(*) FILTER (WHERE status = 'needs_attention') AS attention,
		         count(*) FILTER (WHERE status = 'cancelled') AS cancelled,
		         count(*) AS total,
		         max(CASE status WHEN 'registering' THEN 3 WHEN 'importing' THEN 2 WHEN 'validating' THEN 1 ELSE 0 END) AS stage
		  FROM repository_import_items WHERE job_id = $1)
		UPDATE repository_import_jobs j SET
		  status = CASE
		    WHEN c.running > 0 THEN (CASE c.stage WHEN 3 THEN 'registering' WHEN 2 THEN 'importing' ELSE 'validating' END)
		    WHEN c.waiting > 0 THEN 'queued'
		    WHEN c.failed > 0 THEN 'failed'
		    WHEN c.attention > 0 THEN 'needs_attention'
		    WHEN c.cancelled = c.total THEN 'cancelled'
		    ELSE 'completed' END,
		  completed_at = CASE WHEN c.running = 0 AND c.waiting = 0 THEN COALESCE(j.completed_at, now()) ELSE NULL END,
		  updated_at = now()
		FROM c WHERE j.id = $1`, jobID)
	return err
}
