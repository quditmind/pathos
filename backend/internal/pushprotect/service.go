package pushprotect

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

// Service queues, runs and reports push scans.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// Diff returns the diff reader of a repository's SCM connection
	// (repos.Service.PushDiffReader). Only the jobs role needs it.
	Diff func(ctx context.Context, orgID, repoID uuid.UUID) (scm.DiffReader, scm.RepoRef, error)
}

// Providers whose push diffs PATHOS can read.
var supportedProviders = []string{scm.GitHub, scm.GitHubEnterprise, scm.GitLab}

const (
	maxAttempts  = 3
	staleRunning = 10 * time.Minute
	pollInterval = 5 * time.Second
	maxAlerts    = 500 // per push
)

// OnPush queues a push scan when the repository opted in. It is called for
// verified webhook events only (see repos.Service.OnEvent).
func (s *Service) OnPush(ctx context.Context, orgID, repoID uuid.UUID, ev scm.WebhookEvent) {
	if ev.Kind != "push" || !scm.ValidCommit(ev.CommitSHA) || (!scm.ZeroCommit(ev.Before) && !scm.ValidCommit(ev.Before)) {
		return
	}
	before := ev.Before
	if scm.ZeroCommit(before) {
		before = ""
	}
	tag, err := s.DB.Exec(ctx, `
		INSERT INTO push_secret_scans (id, organization_id, repository_id, ref, before_sha, after_sha)
		SELECT $1, r.organization_id, r.id, left($3, 255), $4, $5 FROM repositories r
		WHERE r.organization_id = $6 AND r.id = $2 AND r.push_secret_scan_enabled AND r.archived_at IS NULL
		ON CONFLICT (repository_id, after_sha, before_sha) DO NOTHING`,
		uuid.Must(uuid.NewV7()), repoID, ev.Ref, before, ev.CommitSHA, orgID)
	if err != nil {
		s.Log.Warn("push scan not queued", "repository_id", repoID, "err", err)
		return
	}
	if tag.RowsAffected() > 0 {
		s.Log.Info("push scan queued", "repository_id", repoID, "commit", ev.CommitSHA)
	}
}

// RunBackground processes queued push scans until ctx ends (jobs role).
func (s *Service) RunBackground(ctx context.Context) {
	t := time.NewTicker(pollInterval)
	defer t.Stop()
	for {
		for {
			ok, err := s.ProcessNext(ctx)
			if err != nil {
				s.Log.Warn("push scan failed", "err", err)
			}
			if !ok || ctx.Err() != nil {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type pushScan struct {
	ID, OrgID, RepoID uuid.UUID
	Ref               string
	Before, After     string
	Attempts          int
}

// ProcessNext leases and runs one queued push scan. It reports whether a
// scan was found.
func (s *Service) ProcessNext(ctx context.Context) (bool, error) {
	var ps pushScan
	err := s.DB.QueryRow(ctx, `
		UPDATE push_secret_scans p SET status = 'running', started_at = now(), attempts = p.attempts + 1
		WHERE p.id = (
		  SELECT q.id FROM push_secret_scans q
		  WHERE q.status = 'queued' OR (q.status = 'running' AND q.started_at < now() - $1::interval)
		  ORDER BY q.created_at FOR UPDATE SKIP LOCKED LIMIT 1)
		RETURNING p.id, p.organization_id, p.repository_id, p.ref, p.before_sha, p.after_sha, p.attempts`,
		staleRunning.String()).Scan(&ps.ID, &ps.OrgID, &ps.RepoID, &ps.Ref, &ps.Before, &ps.After, &ps.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if ps.Attempts > maxAttempts {
		s.finish(ctx, ps, "failed", "gave up after repeated failures", 0, nil)
		return true, nil
	}
	if s.Diff == nil {
		s.finish(ctx, ps, "failed", "push diffs are not available in this process", 0, nil)
		return true, nil
	}
	cctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	reader, ref, err := s.Diff(cctx, ps.OrgID, ps.RepoID)
	if err == nil {
		var d scm.PushDiff
		d, err = reader.PushDiff(cctx, ref, ps.Before, ps.After)
		if err == nil {
			files, alerts := scanDiff(d)
			s.finish(ctx, ps, "done", truncatedNote(d), files, alerts)
			return true, nil
		}
	}
	switch {
	case errors.Is(err, scm.ErrNotSupported):
		s.finish(ctx, ps, "not_supported", safeErr(err), 0, nil)
	case scm.IsTransient(err) && ps.Attempts < maxAttempts:
		_, _ = s.DB.Exec(ctx, `UPDATE push_secret_scans SET status = 'queued', error = $2 WHERE id = $1`, ps.ID, safeErr(err))
	default:
		s.finish(ctx, ps, "failed", safeErr(err), 0, nil)
	}
	return true, nil
}

func truncatedNote(d scm.PushDiff) string {
	if d.Truncated {
		return "large push: the combined diff was scanned and attributed to the head commit, or some files were too large to read"
	}
	return ""
}

// alert is one stored finding of a push scan (never the value).
type alert struct {
	Commit, Path string
	Match
}

func scanDiff(d scm.PushDiff) (int, []alert) {
	var out []alert
	files := 0
	for _, c := range d.Commits {
		for _, f := range c.Files {
			files++
			for _, m := range ScanPatch(f.Patch) {
				if len(out) >= maxAlerts {
					return files, out
				}
				out = append(out, alert{Commit: c.SHA, Path: f.Path, Match: m})
			}
		}
	}
	return files, out
}

// safeErr bounds provider error messages (they never contain credentials
// or response bodies; see internal/scm).
func safeErr(err error) string {
	msg := err.Error()
	if len(msg) > 500 {
		msg = msg[:500]
	}
	return msg
}

func (s *Service) finish(ctx context.Context, ps pushScan, status, msg string, files int, alerts []alert) {
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		stored := 0
		for _, a := range alerts {
			var line *int
			if a.Line > 0 {
				l := a.Line
				line = &l
			}
			tag, err := tx.Exec(ctx, `INSERT INTO pushed_secrets (id, organization_id, push_scan_id, repository_id, commit_sha, file_path, line, rule_id, description, match_digest)
				VALUES ($1, $2, $3, $4, $5, left($6, 1000), $7, $8, $9, $10) ON CONFLICT DO NOTHING`,
				uuid.Must(uuid.NewV7()), ps.OrgID, ps.ID, ps.RepoID, a.Commit, a.Path, line, a.RuleID, a.Description, a.Digest)
			if err != nil {
				return err
			}
			stored += int(tag.RowsAffected())
		}
		if _, err := tx.Exec(ctx, `UPDATE push_secret_scans SET status = $2, error = left($3, 1000), files_scanned = $4, alerts = $5, finished_at = now()
			WHERE id = $1`, ps.ID, status, msg, files, stored); err != nil {
			return err
		}
		if stored == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO notification_events (organization_id, event_key, repository_id, severity, subject_id, payload)
			VALUES ($1, 'secret.pushed', $2, 'critical', $3, jsonb_build_object('ref', $4::text, 'commit', $5::text, 'alerts', $6::int))`,
			ps.OrgID, ps.RepoID, ps.ID, ps.Ref, ps.After, stored); err != nil {
			return err
		}
		rules := map[string]int{}
		for _, a := range alerts {
			rules[a.RuleID]++
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: ps.OrgID, Action: "push_protection.secret_detected",
			TargetType: "repository", TargetID: ps.RepoID.String(),
			Metadata: map[string]any{"push_scan_id": ps.ID, "ref": ps.Ref, "commit": ps.After, "alerts": stored, "rules": rules}})
	})
	if err != nil {
		s.Log.Error("push scan result not stored", "push_scan_id", ps.ID, "err", err)
		return
	}
	s.Log.Info("push scan finished", "push_scan_id", ps.ID, "repository_id", ps.RepoID, "status", status, "files", files, "alerts", len(alerts))
}

// --- HTTP API ---

// Register mounts the push protection endpoints.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/repositories/{id}/push-protection", s.getSettings)
	mux.HandleFunc("PUT /api/v1/repositories/{id}/push-protection", s.putSettings)
	mux.HandleFunc("GET /api/v1/repositories/{id}/pushed-secrets", s.listAlerts)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) requireRepo(ctx context.Context, p *authz.Principal, perm authz.Permission, repoID uuid.UUID) error {
	if p == nil {
		return httpx.ErrUnauthenticated
	}
	err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: repoID})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, org.ErrScopeNotFound):
		return httpx.ErrNotFound
	case errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(perm):
		return httpx.ErrNotFound
	}
	return err
}

func repoID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return uuid.Nil, httpx.ErrNotFound
	}
	return id, nil
}

// Settings is a repository's push protection configuration.
type Settings struct {
	Enabled bool `json:"enabled"`
	// Supported: the repository's provider can report push diffs
	// (GitHub, GitHub Enterprise Server, GitLab).
	Supported bool   `json:"supported"`
	Provider  string `json:"provider"`
	Source    string `json:"source_type"`
}

func (s *Service) settings(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Settings, error) {
	var st Settings
	err := q.QueryRow(ctx, `SELECT r.push_secret_scan_enabled, COALESCE(c.provider, ''), r.source_type
		FROM repositories r LEFT JOIN scm_connections c ON c.id = r.scm_connection_id
		WHERE r.organization_id = $1 AND r.id = $2`, orgID, id).Scan(&st.Enabled, &st.Provider, &st.Source)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, httpx.ErrNotFound
	}
	for _, p := range supportedProviders {
		st.Supported = st.Supported || st.Provider == p
	}
	return st, err
}

func (s *Service) getSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := repoID(r)
	if err == nil {
		err = s.requireRepo(ctx, p, authz.PermScansRead, id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := s.settings(ctx, s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (s *Service) putSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := repoID(r)
	if err == nil {
		err = s.requireRepo(ctx, p, authz.PermReposManage, id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	var st Settings
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		cur, err := s.settings(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if req.Enabled && !cur.Supported {
			if cur.Source == "upload" {
				return httpx.BadRequest("uploaded repositories receive no pushes")
			}
			return httpx.BadRequest("push-event scanning is available for GitHub, GitHub Enterprise Server and GitLab; use the pre-receive hook for other servers")
		}
		if _, err := tx.Exec(ctx, `UPDATE repositories SET push_secret_scan_enabled = $3 WHERE organization_id = $1 AND id = $2`,
			p.OrganizationID, id, req.Enabled); err != nil {
			return err
		}
		st = cur
		st.Enabled = req.Enabled
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.push_protection", TargetType: "repository", TargetID: id.String(),
			Metadata: map[string]any{"enabled": req.Enabled}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// Alert is a pushed secret as listed (no value: only where and what kind).
type Alert struct {
	ID          uuid.UUID `json:"id"`
	PushScanID  uuid.UUID `json:"push_scan_id"`
	Ref         string    `json:"ref"`
	CommitSHA   string    `json:"commit_sha"`
	FilePath    string    `json:"file_path"`
	Line        *int      `json:"line"`
	RuleID      string    `json:"rule_id"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
}

// Scan is one push scan.
type Scan struct {
	ID           uuid.UUID  `json:"id"`
	Ref          string     `json:"ref"`
	BeforeSHA    string     `json:"before_sha"`
	AfterSHA     string     `json:"after_sha"`
	Status       string     `json:"status"`
	Error        string     `json:"error"`
	FilesScanned int        `json:"files_scanned"`
	Alerts       int        `json:"alerts"`
	CreatedAt    time.Time  `json:"created_at"`
	FinishedAt   *time.Time `json:"finished_at"`
}

func (s *Service) listAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := repoID(r)
	if err == nil {
		err = s.requireRepo(ctx, p, authz.PermFindingsRead, id)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := struct {
		Items []Alert `json:"items"`
		Scans []Scan  `json:"scans"`
	}{Items: []Alert{}, Scans: []Scan{}}
	rows, err := s.DB.Query(ctx, `SELECT a.id, a.push_scan_id, p.ref, a.commit_sha, a.file_path, a.line, a.rule_id, a.description, a.created_at
		FROM pushed_secrets a JOIN push_secret_scans p ON p.id = a.push_scan_id
		WHERE a.organization_id = $1 AND a.repository_id = $2 ORDER BY a.created_at DESC, a.file_path LIMIT 200`, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.ID, &a.PushScanID, &a.Ref, &a.CommitSHA, &a.FilePath, &a.Line, &a.RuleID, &a.Description, &a.CreatedAt); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		out.Items = append(out.Items, a)
	}
	rows.Close()
	rows, err = s.DB.Query(ctx, `SELECT id, ref, before_sha, after_sha, status, error, files_scanned, alerts, created_at, finished_at
		FROM push_secret_scans WHERE organization_id = $1 AND repository_id = $2 ORDER BY created_at DESC LIMIT 20`, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var sc Scan
		if err := rows.Scan(&sc.ID, &sc.Ref, &sc.BeforeSHA, &sc.AfterSHA, &sc.Status, &sc.Error, &sc.FilesScanned, &sc.Alerts, &sc.CreatedAt, &sc.FinishedAt); err != nil {
			s.fail(w, r, err)
			return
		}
		sc.Error = strings.TrimSpace(sc.Error)
		out.Scans = append(out.Scans, sc)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
