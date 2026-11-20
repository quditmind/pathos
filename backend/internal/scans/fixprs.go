package scans

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/depfix"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

// Automatic fix pull requests. When enabled for a repository, an
// authorized user asks for a pull request that upgrades a vulnerable
// dependency to its fixed version. A worker clones the repository and
// edits the manifest as text (internal/depfix; no package manager, build
// tool or repository code runs); the API then creates a branch under
// scm.FixBranchPrefix, commits the edited files and opens a pull/merge
// request. The finding keeps its status: only a later scan of the branch
// resolves it, whatever happens to the pull request.
//
// Requesting needs findings.triage and repos.manage on the repository:
// a fix PR both changes how a finding is handled and writes to the
// repository with the connection's credential.

// FixPRTargetFunc resolves the SCM writer, repository reference and target
// branch of a repository.
type FixPRTargetFunc func(ctx context.Context, orgID, repoID uuid.UUID) (scm.PullRequestWriter, scm.RepoRef, string, error)

// Fix PR statuses that block a new request for the same findings.
var fixPRActive = []string{"queued", "running", "creating", "open"}

const (
	fixLeaseDuration = 10 * time.Minute
	fixMaxAttempts   = 3
	maxFixResultBody = 40 << 20
	maxFixTotalBytes = 20 << 20
)

// FixPR is a fix pull request as returned by the API.
type FixPR struct {
	ID             uuid.UUID   `json:"id"`
	RepositoryID   uuid.UUID   `json:"repository_id"`
	RepositoryName string      `json:"repository_name"`
	Ecosystem      string      `json:"ecosystem"`
	PackageName    string      `json:"package_name"`
	CurrentVersion string      `json:"current_version"`
	TargetVersion  string      `json:"target_version"`
	Grouping       string      `json:"grouping"`
	Status         string      `json:"status"`
	Error          string      `json:"error"`
	BaseBranch     string      `json:"base_branch"`
	Branch         string      `json:"branch"`
	ChangedFiles   []string    `json:"changed_files"`
	PRNumber       string      `json:"pr_number"`
	PRURL          string      `json:"pr_url"`
	FindingIDs     []uuid.UUID `json:"finding_ids"`
	RequestedBy    string      `json:"requested_by"`
	CreatedAt      time.Time   `json:"created_at"`
	UpdatedAt      time.Time   `json:"updated_at"`
	StateCheckedAt *time.Time  `json:"state_checked_at"`
	// Kind is dependency (manifest upgrade) or ai_code (verified AI fix).
	Kind    string     `json:"kind"`
	AIFixID *uuid.UUID `json:"ai_fix_id"`
}

const fixPRCols = `x.id, x.repository_id, r.full_name, x.ecosystem, x.package_name, x.current_version, x.target_version, x.grouping,
	x.status, x.error, x.base_branch, x.branch, x.changed_files, x.pr_number, x.pr_url,
	COALESCE((SELECT array_agg(ff.finding_id ORDER BY ff.finding_id) FROM fix_pull_request_findings ff WHERE ff.fix_pull_request_id = x.id), '{}'),
	COALESCE(u.email, ''), x.created_at, x.updated_at, x.state_checked_at, x.kind, x.ai_fix_id
	FROM fix_pull_requests x JOIN repositories r ON r.id = x.repository_id LEFT JOIN users u ON u.id = x.requested_by`

func scanFixPR(row pgx.Row) (FixPR, error) {
	var f FixPR
	err := row.Scan(&f.ID, &f.RepositoryID, &f.RepositoryName, &f.Ecosystem, &f.PackageName, &f.CurrentVersion, &f.TargetVersion, &f.Grouping,
		&f.Status, &f.Error, &f.BaseBranch, &f.Branch, &f.ChangedFiles, &f.PRNumber, &f.PRURL, &f.FindingIDs,
		&f.RequestedBy, &f.CreatedAt, &f.UpdatedAt, &f.StateCheckedAt, &f.Kind, &f.AIFixID)
	return f, err
}

func (s *Service) registerFixPRs(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/repositories/{id}/fix-pr-settings", s.getFixSettings)
	mux.HandleFunc("PUT /api/v1/repositories/{id}/fix-pr-settings", s.putFixSettings)
	mux.HandleFunc("GET /api/v1/repositories/{id}/fix-prs", s.listRepoFixPRs)
	mux.HandleFunc("GET /api/v1/findings/{id}/fix-pr", s.findingFixPR)
	mux.HandleFunc("POST /api/v1/findings/{id}/fix-pr", s.requestFixPR)
	mux.HandleFunc("POST /api/v1/fix-prs/{id}/refresh", s.refreshFixPR)
}

// --- settings ------------------------------------------------------------------

type fixSettings struct {
	Enabled  bool   `json:"enabled"`
	Grouping string `json:"grouping"`
	Source   string `json:"source_type"`
	Provider string `json:"provider"`
}

func (s *Service) getFixSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermScansRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	var st fixSettings
	if err := s.DB.QueryRow(ctx, `SELECT r.fix_prs_enabled, r.fix_pr_grouping, r.source_type, COALESCE(c.provider, '')
		FROM repositories r LEFT JOIN scm_connections c ON c.id = r.scm_connection_id WHERE r.organization_id = $1 AND r.id = $2`,
		p.OrganizationID, id).Scan(&st.Enabled, &st.Grouping, &st.Source, &st.Provider); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (s *Service) putFixSettings(w http.ResponseWriter, r *http.Request) {
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
	var req struct {
		Enabled  bool   `json:"enabled"`
		Grouping string `json:"grouping"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Grouping != "finding" && req.Grouping != "package" {
		s.fail(w, r, httpx.BadRequest("grouping must be finding or package"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var source string
		if err := tx.QueryRow(ctx, `UPDATE repositories SET fix_prs_enabled = $3, fix_pr_grouping = $4 WHERE organization_id = $1 AND id = $2
			RETURNING source_type`, p.OrganizationID, id, req.Enabled, req.Grouping).Scan(&source); err != nil {
			return err
		}
		if req.Enabled && (source == "upload" || source == "git") {
			return httpx.BadRequest("uploaded repositories have no SCM connection to open pull requests in")
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.fix_prs", TargetType: "repository", TargetID: id.String(),
			Metadata: map[string]any{"enabled": req.Enabled, "grouping": req.Grouping}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.getFixSettings(w, r)
}

// --- eligibility ---------------------------------------------------------------

type fixFinding struct {
	ID, RepoID                       uuid.UUID
	Category, Status                 string
	Package, Version, Fixed, File    string
	Title, CVE, Severity             string
	TargetScan                       bool
	RepoEnabled                      bool
	RepoGrouping, RepoSource, RepoNm string
}

func (s *Service) loadFixFinding(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (fixFinding, error) {
	var f fixFinding
	err := q.QueryRow(ctx, `SELECT f.id, f.repository_id, f.category, f.status, f.package_name, f.package_version, f.fixed_version, f.file_path,
		f.title, f.cve, f.severity, f.scan_target_id IS NOT NULL, r.fix_prs_enabled, r.fix_pr_grouping, r.source_type, r.full_name
		FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE f.organization_id = $1 AND f.id = $2`, orgID, id).
		Scan(&f.ID, &f.RepoID, &f.Category, &f.Status, &f.Package, &f.Version, &f.Fixed, &f.File, &f.Title, &f.CVE, &f.Severity,
			&f.TargetScan, &f.RepoEnabled, &f.RepoGrouping, &f.RepoSource, &f.RepoNm)
	return f, err
}

// resolvePackage finds the finding's ecosystem and the package name in the
// form the manifest uses, from the repository's SBOM (package URLs) or,
// failing that, from the file the scanner reported.
func resolvePackage(ctx context.Context, q db.Querier, f fixFinding) (eco, name string) {
	rows, err := q.Query(ctx, `SELECT purl FROM sbom_components WHERE repository_id = $1 AND version = $2 AND purl <> '' LIMIT 500`, f.RepoID, f.Version)
	if err == nil {
		defer rows.Close()
		want := strings.ToLower(f.Package)
		for rows.Next() {
			var purl string
			if rows.Scan(&purl) != nil {
				continue
			}
			e, n, _ := depfix.FromPURL(purl)
			ln := strings.ToLower(n)
			if ln == want || (e == depfix.Maven && (strings.HasSuffix(ln, ":"+want) || strings.ReplaceAll(ln, ":", "/") == want)) {
				return e, n
			}
		}
	}
	return depfix.FromPath(f.File), f.Package
}

// FixEligibility tells the UI whether "Open fix PR" can be offered.
type FixEligibility struct {
	Eligible      bool           `json:"eligible"`
	Reason        string         `json:"reason,omitempty"`
	Ecosystem     string         `json:"ecosystem"`
	PackageName   string         `json:"package_name"`
	TargetVersion string         `json:"target_version"`
	Support       depfix.Support `json:"support"`
	Enabled       bool           `json:"enabled"`
	Grouping      string         `json:"grouping"`
	CanRequest    bool           `json:"can_request"`
	Requests      []FixPR        `json:"requests"`
}

func (s *Service) eligibility(ctx context.Context, f fixFinding) FixEligibility {
	e := FixEligibility{Enabled: f.RepoEnabled, Grouping: f.RepoGrouping, Requests: []FixPR{}}
	e.Ecosystem, e.PackageName = resolvePackage(ctx, s.DB, f)
	e.Support = depfix.Supported(e.Ecosystem)
	e.TargetVersion = depfix.PickTarget(f.Version, f.Fixed)
	switch {
	case f.Category != "sca":
		e.Reason = "fix pull requests are available for dependency (SCA) findings"
	case f.TargetScan:
		e.Reason = "this finding comes from a scan target, not from the repository's source"
	case f.RepoSource == "upload" || f.RepoSource == "git":
		e.Reason = "uploaded and anonymous repositories have no SCM connection to open pull requests in"
	case !f.RepoEnabled:
		e.Reason = "fix pull requests are not enabled for this repository (repository settings)"
	case f.Status != "open" && f.Status != "in_progress" && f.Status != "needs_review":
		e.Reason = "the finding is not open"
	case f.Package == "" || f.Version == "":
		e.Reason = "the scanner did not report the package and version"
	case f.Fixed == "":
		e.Reason = "no fixed version is known for this vulnerability"
	case e.TargetVersion == "":
		e.Reason = "the reported fixed version (" + f.Fixed + ") is not a version PATHOS can upgrade to"
	case !e.Support.Supported:
		e.Reason = "not supported: " + e.Support.Reason
	default:
		e.Eligible = true
	}
	return e
}

func (s *Service) findingFixPR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := s.loadFixFinding(ctx, s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsRead, f.RepoID); err != nil {
		s.fail(w, r, err)
		return
	}
	e := s.eligibility(ctx, f)
	e.CanRequest = s.canRequestFix(ctx, p, f.RepoID)
	rows, err := s.DB.Query(ctx, `SELECT `+fixPRCols+` WHERE x.organization_id = $1
		AND x.id IN (SELECT fix_pull_request_id FROM fix_pull_request_findings WHERE finding_id = $2) ORDER BY x.created_at DESC LIMIT 20`,
		p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	e.Requests, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (FixPR, error) { return scanFixPR(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, e)
}

func (s *Service) canRequestFix(ctx context.Context, p *authz.Principal, repoID uuid.UUID) bool {
	scope := authz.Scope{Type: authz.ScopeRepository, ID: repoID}
	return s.Authz.Require(ctx, p, authz.PermFindingsTriage, scope) == nil && s.Authz.Require(ctx, p, authz.PermReposManage, scope) == nil
}

// --- request -------------------------------------------------------------------

func (s *Service) requestFixPR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		TargetVersion string `json:"target_version"`
		Grouping      string `json:"grouping"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := s.loadFixFinding(ctx, s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsTriage, f.RepoID); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermReposManage, f.RepoID); err != nil {
		s.fail(w, r, err)
		return
	}
	e := s.eligibility(ctx, f)
	if !e.Eligible {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "fix_pr_not_available", e.Reason))
		return
	}
	target := e.TargetVersion
	if req.TargetVersion != "" {
		if !depfix.ValidVersion(req.TargetVersion) || depfix.Compare(req.TargetVersion, f.Version) <= 0 {
			s.fail(w, r, httpx.BadRequest("target_version must be a plain version above "+f.Version))
			return
		}
		target = req.TargetVersion
	}
	grouping := f.RepoGrouping
	if req.Grouping != "" {
		if req.Grouping != "finding" && req.Grouping != "package" {
			s.fail(w, r, httpx.BadRequest("grouping must be finding or package"))
			return
		}
		grouping = req.Grouping
	}
	fixID := uuid.Must(uuid.NewV7())
	var covered []uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		// Serialize requests per repository.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM repositories WHERE id = $1 FOR UPDATE`, f.RepoID); err != nil {
			return err
		}
		covered = []uuid.UUID{f.ID}
		if grouping == "package" {
			// Every open finding of the same package version in the
			// repository is fixed by the same upgrade.
			rows, err := tx.Query(ctx, `SELECT id FROM findings WHERE repository_id = $1 AND category = 'sca' AND scan_target_id IS NULL
				AND status IN ('open', 'in_progress', 'needs_review') AND lower(package_name) = lower($2) AND package_version = $3 AND id <> $4`,
				f.RepoID, f.Package, f.Version, f.ID)
			if err != nil {
				return err
			}
			more, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			if err != nil {
				return err
			}
			covered = append(covered, more...)
		}
		var existing string
		err := tx.QueryRow(ctx, `SELECT x.pr_url FROM fix_pull_requests x JOIN fix_pull_request_findings ff ON ff.fix_pull_request_id = x.id
			WHERE ff.finding_id = ANY($1) AND x.status = ANY($2) LIMIT 1`, covered, fixPRActive).Scan(&existing)
		switch {
		case err == nil:
			msg := "a fix pull request for this finding is already in progress"
			if existing != "" {
				msg += ": " + existing
			}
			return httpx.Conflict(msg)
		case !errors.Is(err, pgx.ErrNoRows):
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fix_pull_requests (id, organization_id, repository_id, ecosystem, package_name, current_version,
			target_version, manifest_hint, grouping, requested_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			fixID, p.OrganizationID, f.RepoID, e.Ecosystem, truncate(e.PackageName, 300), truncate(f.Version, 100), target,
			truncate(f.File, 1000), grouping, p.UserID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO fix_pull_request_findings (fix_pull_request_id, finding_id) SELECT $1, unnest($2::uuid[])`,
			fixID, covered); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "fix_pr.request", TargetType: "finding", TargetID: f.ID.String(),
			Metadata: map[string]any{"fix_pr_id": fixID.String(), "repository_id": f.RepoID.String(), "package": e.PackageName,
				"from": f.Version, "to": target, "ecosystem": e.Ecosystem, "grouping": grouping, "findings": len(covered)}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := scanFixPR(s.DB.QueryRow(ctx, `SELECT `+fixPRCols+` WHERE x.id = $1`, fixID))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, out)
}

func (s *Service) listRepoFixPRs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsRead, id); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT `+fixPRCols+` WHERE x.organization_id = $1 AND x.repository_id = $2 ORDER BY x.created_at DESC LIMIT 200`,
		p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (FixPR, error) { return scanFixPR(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Service) refreshFixPR(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var repoID uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT repository_id FROM fix_pull_requests WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id).
		Scan(&repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsTriage, repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	if s.FixPRTarget == nil {
		s.fail(w, r, httpx.E(http.StatusServiceUnavailable, "unavailable", "pull request tracking is not configured"))
		return
	}
	if err := TrackFixPR(ctx, s.DB, s.Log, s.FixPRTarget, id); err != nil {
		s.fail(w, r, httpx.E(http.StatusBadGateway, "scm_error", FixPRError(err)))
		return
	}
	out, err := scanFixPR(s.DB.QueryRow(ctx, `SELECT `+fixPRCols+` WHERE x.id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// FixPRError turns an SCM error into a message for users and the record.
func FixPRError(err error) string {
	switch {
	case errors.Is(err, scm.ErrTokenExpired):
		return "the connection's authorization expired or was revoked; reconnect the SCM connection"
	case errors.Is(err, scm.ErrAuth):
		return "the SCM rejected the connection's credential"
	case errors.Is(err, scm.ErrForbidden), errors.Is(err, scm.ErrNotFound):
		return "the connection's credential lacks permission to create branches and pull requests in this repository " +
			"(it needs write access: GitHub contents and pull requests write, GitLab Developer role with the api scope, " +
			"Bitbucket repository:write and pullrequest:write, Azure DevOps Code read & write)"
	case errors.Is(err, scm.ErrConflict):
		return "the branch or pull request already exists, or the target branch changed; request the fix again"
	case errors.Is(err, scm.ErrRateLimited):
		return "the SCM rate-limited PATHOS; try again later"
	}
	return truncate(err.Error(), 500)
}

// --- worker protocol -----------------------------------------------------------

// LeasedFix is a fix job as a worker receives it.
type LeasedFix struct {
	FixID          uuid.UUID       `json:"fix_id"`
	FullName       string          `json:"full_name"`
	CloneURL       string          `json:"clone_url"`
	Ref            string          `json:"ref"`
	Credential     *scm.Credential `json:"credential,omitempty"`
	Public         bool            `json:"public"`
	Ecosystem      string          `json:"ecosystem"`
	PackageName    string          `json:"package_name"`
	CurrentVersion string          `json:"current_version"`
	TargetVersion  string          `json:"target_version"`
	ManifestHint   string          `json:"manifest_hint"`
	TimeoutSeconds int             `json:"timeout_seconds"`
}

func requeueExpiredFixes(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, `UPDATE fix_pull_requests SET
		status = CASE WHEN attempts >= $1 THEN 'failed' ELSE 'queued' END,
		error = CASE WHEN attempts >= $1 THEN 'worker lease expired ' || attempts || ' times' ELSE error END,
		finished_at = CASE WHEN attempts >= $1 THEN now() ELSE NULL END,
		leased_by = NULL, lease_expires_at = NULL, updated_at = now()
		WHERE status = 'running' AND lease_expires_at < now()`, fixMaxAttempts)
	return err
}

func (s *Service) fixLease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := workerFrom(ctx)
	if err := requeueExpiredFixes(ctx, s.DB); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	var job LeasedFix
	var connID *uuid.UUID
	var repoID uuid.UUID
	var visibility, scanBranch, defBranch string
	err := s.DB.QueryRow(ctx, `
		UPDATE fix_pull_requests x SET status = 'running', leased_by = $2, lease_expires_at = now() + $3::interval,
		       attempts = attempts + 1, updated_at = now(), error = ''
		FROM repositories r
		WHERE r.id = x.repository_id AND x.id = (
		  SELECT q.id FROM fix_pull_requests q WHERE q.organization_id = $1 AND q.status = 'queued'
		  ORDER BY q.created_at FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING x.id, x.repository_id, r.full_name, r.clone_url, r.scm_connection_id, r.visibility, r.scan_branch, r.default_branch,
		  x.ecosystem, x.package_name, x.current_version, x.target_version, x.manifest_hint`,
		wk.orgID, wk.ID, fixLeaseDuration.String()).Scan(&job.FixID, &repoID, &job.FullName, &job.CloneURL, &connID, &visibility,
		&scanBranch, &defBranch, &job.Ecosystem, &job.PackageName, &job.CurrentVersion, &job.TargetVersion, &job.ManifestHint)
	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	job.Ref = scanBranch
	if job.Ref == "" {
		job.Ref = defBranch
	}
	job.Public = visibility == "public"
	job.TimeoutSeconds = int(fixLeaseDuration.Seconds()) - 60
	fail := func(msg string) {
		_, _ = s.DB.Exec(ctx, `UPDATE fix_pull_requests SET status = 'failed', error = $2, finished_at = now(), updated_at = now(),
			lease_expires_at = NULL WHERE id = $1`, job.FixID, truncate(msg, 1000))
		w.WriteHeader(http.StatusNoContent)
	}
	if connID == nil || job.CloneURL == "" {
		fail("the repository has no SCM connection")
		return
	}
	if s.CloneCredential != nil {
		cred, err := s.CloneCredential(ctx, wk.orgID, *connID)
		if err != nil {
			fail("could not obtain a clone credential: " + safeErr(err))
			return
		}
		job.Credential = &cred
	}
	s.Log.Info("fix pull request leased", "fix_pr_id", job.FixID, "repository", job.FullName, "worker", wk.Name)
	httpx.WriteJSON(w, http.StatusOK, job)
}

// FixResult is what a worker reports for a fix job.
type FixResult struct {
	Status     string    `json:"status"` // ok | not_supported | failed
	Error      string    `json:"error"`
	BaseCommit string    `json:"base_commit"`
	Files      []FixFile `json:"files"`
	Notes      []string  `json:"notes"`
}

// FixFile is one edited file.
type FixFile struct {
	Path          string `json:"path"`
	ContentBase64 string `json:"content_base64"`
}

var fixBranchUnsafe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// FixBranchName builds the branch for a fix request.
func FixBranchName(id uuid.UUID, ecosystem, pkg, target string) string {
	part := strings.Trim(fixBranchUnsafe.ReplaceAllString(strings.ToLower(pkg), "-"), "-.")
	if len(part) > 60 {
		part = part[:60]
	}
	b := scm.FixBranchPrefix + strings.Trim(fixBranchUnsafe.ReplaceAllString(ecosystem, "-"), "-.") + "-" + part + "-" +
		strings.Trim(fixBranchUnsafe.ReplaceAllString(target, "-"), "-.") + "-" + strings.ReplaceAll(id.String(), "-", "")[24:]
	b = strings.ReplaceAll(b, "..", ".")
	return b
}

func (s *Service) fixResult(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	wk := workerFrom(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	var status string
	var leasedBy *uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT status, leased_by FROM fix_pull_requests WHERE id = $1 AND organization_id = $2`, id, wk.orgID).
		Scan(&status, &leasedBy); err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	if status != "running" || leasedBy == nil || *leasedBy != wk.ID {
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusConflict, "lease_lost", "this fix job is not leased by this worker"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFixResultBody)
	var res FixResult
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid fix result"))
		return
	}
	finish := func(st, msg string) {
		_, _ = s.DB.Exec(ctx, `UPDATE fix_pull_requests SET status = $2, error = $3, finished_at = now(), updated_at = now(),
			leased_by = NULL, lease_expires_at = NULL WHERE id = $1`, id, st, truncate(msg, 1000))
		_ = s.auditFix(ctx, s.DB, wk.orgID, id, "fix_pr."+st, map[string]any{"error": truncate(msg, 500), "worker": wk.Name})
		w.WriteHeader(http.StatusNoContent)
	}
	switch res.Status {
	case "not_supported":
		finish("not_supported", res.Error)
		return
	case "failed":
		finish("failed", res.Error)
		return
	case "ok":
	default:
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid fix result status"))
		return
	}
	files, err := decodeFixFiles(res.Files)
	if err != nil {
		finish("failed", "worker result rejected: "+err.Error())
		return
	}
	if !scm.ValidCommit(res.BaseCommit) || len(res.BaseCommit) < 40 {
		finish("failed", "worker result rejected: invalid base commit")
		return
	}
	if _, err := s.DB.Exec(ctx, `UPDATE fix_pull_requests SET status = 'creating', base_commit = $2, leased_by = NULL, lease_expires_at = NULL,
		updated_at = now() WHERE id = $1`, id, res.BaseCommit); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	// The pull request is created in the background: the worker is done.
	go s.openFixPR(context.WithoutCancel(ctx), wk.orgID, id, res.BaseCommit, files, res.Notes)
	w.WriteHeader(http.StatusNoContent)
}

func decodeFixFiles(in []FixFile) ([]scm.FileChange, error) {
	if len(in) == 0 || len(in) > scm.MaxChangeFiles {
		return nil, fmt.Errorf("a fix changes 1 to %d files", scm.MaxChangeFiles)
	}
	total := 0
	out := make([]scm.FileChange, 0, len(in))
	for _, f := range in {
		if !scm.ValidRepoPath(f.Path) || strings.HasPrefix(f.Path, ".git/") || f.Path == ".git" {
			return nil, errors.New("invalid file path")
		}
		b, err := base64.StdEncoding.DecodeString(f.ContentBase64)
		if err != nil {
			return nil, errors.New("invalid file content")
		}
		total += len(b)
		if len(b) > scm.MaxChangeFileBytes || total > maxFixTotalBytes {
			return nil, errors.New("changed files are too large")
		}
		out = append(out, scm.FileChange{Path: f.Path, Content: b})
	}
	return out, nil
}

func (s *Service) auditFix(ctx context.Context, q db.Querier, orgID, id uuid.UUID, action string, meta map[string]any) error {
	return audit.Write(ctx, q, audit.Entry{OrganizationID: orgID, Action: action, TargetType: "fix_pull_request", TargetID: id.String(), Metadata: meta})
}

// openFixPR creates the branch, commit and pull request of a dependency
// upgrade.
func (s *Service) openFixPR(ctx context.Context, orgID, id uuid.UUID, base string, files []scm.FileChange, notes []string) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	var repoID uuid.UUID
	var eco, pkg, from, to string
	if err := s.DB.QueryRow(ctx, `SELECT repository_id, ecosystem, package_name, current_version, target_version FROM fix_pull_requests WHERE id = $1`, id).
		Scan(&repoID, &eco, &pkg, &from, &to); err != nil {
		s.failFixPR(ctx, orgID, id, "fix request not found")
		return
	}
	findings, err := s.fixFindingsSummary(ctx, id)
	if err != nil {
		s.failFixPR(ctx, orgID, id, "could not load the findings: "+safeErr(err))
		return
	}
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.Path
	}
	title := fmt.Sprintf("Upgrade %s from %s to %s (security fix)", pkg, from, to)
	s.publishFixPR(ctx, orgID, id, repoID, base, FixBranchName(id, eco, pkg, to), title, title+"\n\n"+fixCommitBody(findings), files,
		func(baseBranch string) string {
			return fixPRBody(pkg, from, to, eco, baseBranch, findings, paths, notes, s.PublicURL)
		})
}

func (s *Service) failFixPR(ctx context.Context, orgID, id uuid.UUID, msg string) {
	_, _ = s.DB.Exec(ctx, `UPDATE fix_pull_requests SET status = 'failed', error = $2, finished_at = now(), updated_at = now() WHERE id = $1`,
		id, truncate(msg, 1000))
	_ = s.auditFix(ctx, s.DB, orgID, id, "fix_pr.failed", map[string]any{"error": truncate(msg, 500)})
	s.Log.Warn("fix pull request failed", "fix_pr_id", id, "err", msg)
}

// publishFixPR creates the branch (from base), commits files and opens the
// pull request of fix request id, and records the outcome. The body is
// built once the target branch is known. Shared by dependency upgrades and
// verified AI fixes.
func (s *Service) publishFixPR(ctx context.Context, orgID, id, repoID uuid.UUID, base, branch, title, commitMessage string, files []scm.FileChange,
	body func(baseBranch string) string) {
	if s.FixPRTarget == nil {
		s.failFixPR(ctx, orgID, id, "pull request creation is not configured")
		return
	}
	writer, ref, baseBranch, err := s.FixPRTarget(ctx, orgID, repoID)
	if err != nil {
		s.failFixPR(ctx, orgID, id, err.Error())
		return
	}
	if !scm.ValidFixBranch(branch) {
		s.failFixPR(ctx, orgID, id, "could not build a valid branch name")
		return
	}
	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.Path
	}
	if err := writer.CreateBranch(ctx, ref, branch, base); err != nil {
		s.failFixPR(ctx, orgID, id, "creating branch "+branch+": "+FixPRError(err))
		return
	}
	commit, err := writer.CommitFiles(ctx, ref, branch, base, commitMessage, files)
	if err != nil {
		s.failFixPR(ctx, orgID, id, "committing to "+branch+": "+FixPRError(err))
		return
	}
	pr, err := writer.CreatePullRequest(ctx, ref, scm.PullRequestSpec{Branch: branch, BaseBranch: baseBranch, Title: title, Body: body(baseBranch)})
	if err != nil {
		s.failFixPR(ctx, orgID, id, "opening the pull request: "+FixPRError(err))
		return
	}
	link := pr.URL
	if !strings.HasPrefix(link, "https://") && !strings.HasPrefix(link, "http://") {
		link = ""
	}
	if _, err := s.DB.Exec(ctx, `UPDATE fix_pull_requests SET status = 'open', error = '', base_branch = $2, branch = $3, commit_sha = $4,
		changed_files = $5, pr_number = $6, pr_url = $7, state_checked_at = now(), updated_at = now() WHERE id = $1`,
		id, truncate(baseBranch, 255), branch, truncate(commit, 64), paths, truncate(pr.ID, 40), truncate(link, 1000)); err != nil {
		s.Log.Error("fix pull request not recorded", "fix_pr_id", id, "err", err)
		return
	}
	_ = s.auditFix(ctx, s.DB, orgID, id, "fix_pr.opened", map[string]any{"branch": branch, "pull_request": pr.ID, "url": link,
		"files": paths, "repository_id": repoID.String()})
	s.Log.Info("fix pull request opened", "fix_pr_id", id, "pull_request", pr.ID)
}

type fixFindingLine struct {
	ID                   uuid.UUID
	Title, CVE, Severity string
}

func (s *Service) fixFindingsSummary(ctx context.Context, id uuid.UUID) ([]fixFindingLine, error) {
	rows, err := s.DB.Query(ctx, `SELECT f.id, f.title, f.cve, f.severity FROM findings f
		JOIN fix_pull_request_findings ff ON ff.finding_id = f.id WHERE ff.fix_pull_request_id = $1
		ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity), f.cve`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (fixFindingLine, error) {
		var l fixFindingLine
		err := row.Scan(&l.ID, &l.Title, &l.CVE, &l.Severity)
		return l, err
	})
}

func fixCommitBody(fs []fixFindingLine) string {
	var b strings.Builder
	for i, f := range fs {
		if i == 20 {
			fmt.Fprintf(&b, "...and %d more\n", len(fs)-20)
			break
		}
		id := f.CVE
		if id == "" {
			id = f.Title
		}
		fmt.Fprintf(&b, "Fixes %s (%s)\n", truncate(id, 200), f.Severity)
	}
	b.WriteString("\nGenerated by PATHOS.")
	return b.String()
}

func fixPRBody(pkg, from, to, eco, baseBranch string, fs []fixFindingLine, paths, notes []string, publicURL string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "PATHOS opened this pull request to upgrade **%s** (%s) from `%s` to `%s`, a version that fixes the vulnerabilities below.\n\n",
		mdEscape(pkg), eco, mdEscape(from), mdEscape(to))
	b.WriteString("### Vulnerabilities\n\n")
	for i, f := range fs {
		if i == 50 {
			fmt.Fprintf(&b, "- …and %d more\n", len(fs)-50)
			break
		}
		line := mdEscape(truncate(f.Title, 200))
		if f.CVE != "" {
			line = mdEscape(f.CVE) + ": " + line
		}
		if publicURL != "" {
			line += fmt.Sprintf(" ([PATHOS](%s/findings?finding=%s))", strings.TrimRight(publicURL, "/"), f.ID)
		}
		fmt.Fprintf(&b, "- **%s** %s\n", f.Severity, line)
	}
	b.WriteString("\n### Changed files\n\n")
	for _, p := range paths {
		fmt.Fprintf(&b, "- `%s`\n", mdEscape(p))
	}
	for _, n := range notes {
		fmt.Fprintf(&b, "\n> %s\n", mdEscape(truncate(n, 500)))
	}
	fmt.Fprintf(&b, "\n### Before merging\n\n"+
		"- The manifest was edited as text; no package manager or build ran. Let CI build and test the change.\n"+
		"- A new version can change behaviour: review the package's release notes.\n"+
		"- PATHOS marks the findings fixed only when a later scan of `%s` no longer detects them, not when this pull request is merged.\n",
		mdEscape(baseBranch))
	return b.String()
}

var mdUnsafe = strings.NewReplacer("`", "'", "<", "&lt;", ">", "&gt;", "\n", " ", "\r", " ")

func mdEscape(s string) string { return mdUnsafe.Replace(s) }

// --- PR state tracking -----------------------------------------------------------

// TrackFixPR refreshes the state of one open fix pull request. Merged and
// closed pull requests are recorded; findings are not changed (a scan
// resolves them).
func TrackFixPR(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, target FixPRTargetFunc, id uuid.UUID) error {
	var orgID, repoID uuid.UUID
	var status, number string
	if err := pool.QueryRow(ctx, `SELECT organization_id, repository_id, status, pr_number FROM fix_pull_requests WHERE id = $1`, id).
		Scan(&orgID, &repoID, &status, &number); err != nil {
		return err
	}
	if status != "open" || number == "" {
		return nil
	}
	writer, ref, _, err := target(ctx, orgID, repoID)
	if err != nil {
		return err
	}
	pr, err := writer.GetPullRequest(ctx, ref, number)
	if err != nil {
		_, _ = pool.Exec(ctx, `UPDATE fix_pull_requests SET state_checked_at = now() WHERE id = $1`, id)
		return err
	}
	if pr.State == scm.PROpen {
		_, err = pool.Exec(ctx, `UPDATE fix_pull_requests SET state_checked_at = now() WHERE id = $1`, id)
		return err
	}
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE fix_pull_requests SET status = $2, state_checked_at = now(), updated_at = now(), finished_at = now()
			WHERE id = $1 AND status = 'open'`, id, pr.State)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		if log != nil {
			log.Info("fix pull request "+pr.State, "fix_pr_id", id, "pull_request", number)
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: orgID, Action: "fix_pr." + pr.State, TargetType: "fix_pull_request",
			TargetID: id.String(), Metadata: map[string]any{"pull_request": number, "repository_id": repoID.String()}})
	})
}

// RunFixPRTracker polls open fix pull requests (jobs role). Each is
// checked at most every interval.
func RunFixPRTracker(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, target FixPRTargetFunc, interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rows, err := pool.Query(ctx, `SELECT id FROM fix_pull_requests WHERE status = 'open'
			AND (state_checked_at IS NULL OR state_checked_at < now() - $1::interval) ORDER BY state_checked_at NULLS FIRST LIMIT 50`,
			interval.String())
		if err != nil {
			log.Warn("fix pull request tracking failed", "err", err)
			continue
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		if err != nil {
			continue
		}
		for _, id := range ids {
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			if err := TrackFixPR(cctx, pool, log, target, id); err != nil {
				log.Warn("fix pull request state not refreshed", "fix_pr_id", id, "err", FixPRError(err))
			}
			cancel()
		}
		// Requests stuck in "creating" (API restarted mid-creation) fail.
		_, _ = pool.Exec(ctx, `UPDATE fix_pull_requests SET status = 'failed', error = 'pull request creation was interrupted; request the fix again',
			finished_at = now(), updated_at = now() WHERE status = 'creating' AND updated_at < now() - interval '15 minutes'`)
		_ = requeueExpiredFixes(ctx, pool)
	}
}
