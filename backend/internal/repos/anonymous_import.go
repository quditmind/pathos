package repos

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

type anonymousImportRequest struct {
	URL string `json:"url"`
	ImportItem
	DisplayName string `json:"display_name"`
	StartScan   bool   `json:"start_scan"`
	DryRun      bool   `json:"dry_run"`
}

// AnonymousImportResult is the response of POST /repositories/import-url.
type AnonymousImportResult struct {
	Status       string     `json:"status"` // imported | would_import
	RepositoryID *uuid.UUID `json:"repository_id,omitempty"`
	Anonymous    bool       `json:"anonymous"`
	Visibility   string     `json:"visibility"`
	ScanQueued   bool       `json:"scan_queued"`
	ScanError    string     `json:"scan_error,omitempty"`
	Repository   PublicRepo `json:"repository"`
}

func (s *Service) probe() *PublicProbe {
	if s.Public != nil {
		return s.Public
	}
	return &PublicProbe{HTTP: s.httpClient(), Net: s.Net}
}

// importAnonymous registers a public repository by URL without a token.
func (s *Service) importAnonymous(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if p == nil {
		s.fail(w, r, httpx.ErrUnauthenticated)
		return
	}
	if !p.HasAnywhere(authz.PermReposManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var req anonymousImportRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	item := merge(req.ImportItem, ImportItem{})
	if len(req.DisplayName) > 200 {
		s.fail(w, r, httpx.BadRequest("display_name: at most 200 characters"))
		return
	}
	ap, err := s.loadPolicy(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !ap.active(KindEnvironment, item.Environment) {
		s.fail(w, r, httpx.BadRequest("invalid environment "+item.Environment))
		return
	}
	if !slices.Contains(criticalities, item.Criticality) {
		s.fail(w, r, httpx.BadRequest("invalid criticality "+item.Criticality))
		return
	}
	if item.ScanBranch != "" && !validBranch(item.ScanBranch) {
		s.fail(w, r, httpx.BadRequest("invalid scan branch"))
		return
	}
	target, err := s.targetScope(ctx, p, item.BusinessUnitID, item.CountryID)
	if err == nil {
		err = s.Authz.Require(ctx, p, authz.PermReposManage, target)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The URL is checked before anything is written, and only public
	// repositories pass.
	pub, err := s.probe().Probe(ctx, req.URL)
	if err != nil {
		var he *httpx.Error
		if errors.As(err, &he) {
			s.Log.Info("anonymous import refused", "url_host", hostOf(req.URL), "error_code", he.ErrorCode, "reason", he.Code)
		}
		s.fail(w, r, err)
		return
	}
	res := AnonymousImportResult{Status: "would_import", Anonymous: true, Visibility: "public", Repository: pub}
	id, err := s.insertAnonymous(ctx, p, pub, item, req.DisplayName, req.DryRun)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if req.DryRun {
		httpx.WriteJSON(w, http.StatusOK, res)
		return
	}
	res.Status, res.RepositoryID = "imported", &id
	if req.StartScan && s.EnqueueScan != nil {
		if err := s.EnqueueScan(ctx, p.OrganizationID, id, "onboarding", &p.UserID); err != nil {
			res.ScanError = errMessage(err)
			if res.ScanError == "could not import (invalid application, business unit or country)" {
				res.ScanError = "the first scan could not be queued: " + truncate(err.Error(), 200)
			}
		} else {
			res.ScanQueued = true
		}
	}
	httpx.WriteJSON(w, http.StatusCreated, res)
}

func hostOf(raw string) string {
	u, err := parsePublicURL(raw, true)
	if err != nil || u.URL == nil {
		return ""
	}
	return u.URL.Hostname()
}

// insertAnonymous stores a public repository with source_type "git".
func (s *Service) insertAnonymous(ctx context.Context, p *authz.Principal, pub PublicRepo, item ImportItem, displayName string, dryRun bool) (uuid.UUID, error) {
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var existing uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM repositories WHERE organization_id = $1 AND source_type = 'git' AND archived_at IS NULL
		AND lower(clone_url) = lower($2)`, p.OrganizationID, pub.CloneURL).Scan(&existing)
	if err == nil {
		e := anonErr(http.StatusConflict, "already_imported", DiagAnonDuplicate, "this repository is already imported anonymously")
		e.Details = map[string]any{"repository_id": existing}
		return uuid.Nil, e
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, err
	}
	if err := validateTagSet(ctx, tx, p.OrganizationID, item.TagIDs); err != nil {
		return uuid.Nil, err
	}
	var techs []string
	if pub.Language != "" {
		techs = []string{pub.Language}
	}
	id := uuid.Must(uuid.NewV7())
	if _, err := tx.Exec(ctx, `
		INSERT INTO repositories (id, organization_id, scm_connection_id, source_type, source_provider, external_id, full_name, name, url, clone_url,
		  default_branch, scan_branch, visibility, description, technologies, application_id, business_unit_id, country_id,
		  environment, criticality, remote_archived, last_pushed_at, imported_by, scm_organization, scm_project, business_region_id,
		  display_name, last_sync_at, last_sync_ok_at, sync_status)
		VALUES ($1, $2, NULL, 'git', $3, $4, $5, $6, $7, $8, $9, $10, 'public', $11, COALESCE($12::text[], '{}'), $13, $14, $15, $16, $17, $18, $19, $20,
		  $21, $22, (SELECT region_id FROM countries WHERE id = $15), $23, now(), now(), 'ok')`,
		id, p.OrganizationID, pub.Provider, truncate(pub.ExternalID, 500), truncate(pub.FullName, 200), truncate(pub.Name, 200), pub.URL, pub.CloneURL,
		pub.DefaultBranch, item.ScanBranch, truncate(pub.Description, 2000), techs, item.ApplicationID, item.BusinessUnitID, item.CountryID,
		item.Environment, item.Criticality, pub.Archived, pub.PushedAt, p.UserID, pub.Organization, pub.Project, displayName); err != nil {
		if db.IsUniqueViolation(err) {
			return uuid.Nil, anonErr(http.StatusConflict, "already_imported", DiagAnonDuplicate,
				"this repository is already imported anonymously, or another asset uses this display name")
		}
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO repository_tags (organization_id, repository_id, tag_id)
		SELECT $1, $2, unnest($3::uuid[])`, p.OrganizationID, id, nonNil(item.TagIDs)); err != nil {
		return uuid.Nil, err
	}
	if dryRun {
		return uuid.Nil, nil
	}
	if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "repository.import", TargetType: "repository", TargetID: id.String(),
		Metadata: map[string]any{"source": "anonymous", "provider": pub.Provider, "url": pub.URL, "full_name": pub.FullName}}); err != nil {
		return uuid.Nil, err
	}
	return id, tx.Commit(ctx)
}

// syncAnonymous re-checks an anonymous repository: still public, default
// branch and description. A repository that is no longer public is marked
// permission_denied and is not scanned again (scans.Enqueue).
func (s *Service) syncAnonymous(ctx context.Context, t syncTarget, trigger string, by *uuid.UUID) (SyncRun, error) {
	run := SyncRun{ID: uuid.Must(uuid.NewV7()), Trigger: trigger, StartedAt: time.Now(), PreviousCommitSHA: t.LatestSHA}
	var urlStr string
	if err := s.DB.QueryRow(ctx, `SELECT url FROM repositories WHERE id = $1`, t.ID).Scan(&urlStr); err != nil {
		return run, err
	}
	pub, err := s.probe().Probe(ctx, urlStr)
	var he *httpx.Error
	switch {
	case err == nil:
		run.Status, run.Branch = "ok", firstNonEmptyStr(t.ScanBranch, pub.DefaultBranch)
		if pub.Archived {
			run.Status = "archived_upstream"
		}
		if _, err := s.DB.Exec(ctx, `UPDATE repositories SET default_branch = CASE WHEN $3 <> '' THEN $3 ELSE default_branch END,
			description = $4, remote_archived = $5, last_pushed_at = COALESCE($6, last_pushed_at), visibility = 'public', updated_at = now()
			WHERE organization_id = $1 AND id = $2`, t.OrgID, t.ID, pub.DefaultBranch, truncate(pub.Description, 2000), pub.Archived, pub.PushedAt); err != nil {
			return run, err
		}
	case errors.As(err, &he) && he.ErrorCode == DiagAnonNotPublic:
		run.Status, run.Error = "permission_denied", DiagAnonNotPublic+": "+he.Message
	default:
		run.Status, run.Error = "failed", truncate(err.Error(), 500)
	}
	return run, s.saveSyncRun(ctx, t, run, by)
}
