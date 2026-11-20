package rea

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/codegraph"
	"pathos/internal/featureflags"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
	"pathos/internal/scans"
)

// Flag is the feature flag of the module.
const Flag = "reverse_engineering"

// Service is the reverse-engineering API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// Graph serves binary graph views from the CodeGraph store.
	Graph *codegraph.Service
	// now is replaced in tests.
	now func() time.Time
}

// Register mounts the API (every route checks the feature flag).
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/rea/settings", s.getSettings)
	mux.HandleFunc("PUT /api/v1/rea/settings", s.putSettings)
	mux.HandleFunc("GET /api/v1/rea/tools", s.tools)
	mux.HandleFunc("GET /api/v1/rea/artifacts", s.artifacts)
	mux.HandleFunc("POST /api/v1/rea/artifacts/{id}/authorizations", s.authorize)
	mux.HandleFunc("DELETE /api/v1/rea/artifacts/{id}/authorizations/{aid}", s.revoke)
	mux.HandleFunc("POST /api/v1/rea/analyses", s.start)
	mux.HandleFunc("GET /api/v1/rea/analyses", s.listAnalyses)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}", s.getAnalysis)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}/functions", s.functions)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}/functions/{nid}", s.function)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}/strings", s.strings)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}/imports", s.imports)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}/sections", s.sections)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}/graph", s.graph)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}/graph/nodes/{nid}", s.graphNode)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}/diff", s.diff)
	mux.HandleFunc("POST /api/v1/rea/analyses/{id}/diff", s.recomputeDiff)
	mux.HandleFunc("GET /api/v1/rea/analyses/{id}/drafts", s.drafts)
	mux.HandleFunc("POST /api/v1/rea/drafts/{id}/create-finding", s.createFinding)
	mux.HandleFunc("POST /api/v1/rea/drafts/{id}/dismiss", s.dismissDraft)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound), codegraph.IsNotFound(err):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

// caller returns the principal after the flag check.
func (s *Service) caller(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	if err := featureflags.Require(r.Context(), s.DB, p.OrganizationID, Flag); err != nil {
		return nil, err
	}
	return p, nil
}

// requireRepo checks perm on a repository, hiding existence from callers
// without any access.
func (s *Service) requireRepo(ctx context.Context, p *authz.Principal, perm authz.Permission, repoID uuid.UUID) error {
	err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: repoID})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, org.ErrScopeNotFound):
		return errNotFound
	case errors.Is(err, authz.ErrForbidden) && !p.HasAnywhere(authz.PermFindingsRead):
		return errNotFound
	}
	return err
}

func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, errNotFound
	}
	return id, nil
}

// --- settings and tools ------------------------------------------------------

func (s *Service) getSettings(w http.ResponseWriter, r *http.Request) {
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermScannersRead) && !p.HasAnywhere(authz.PermFindingsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	st, err := loadSettings(r.Context(), s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (s *Service) putSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Authz.Require(ctx, p, authz.PermScannersManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}); err != nil {
		s.fail(w, r, err)
		return
	}
	var in Settings
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	sendCode, _, err := aiCodePolicy(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := in.validate(sendCode); err != nil {
		s.fail(w, r, err)
		return
	}
	prev, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO rea_settings (organization_id, enabled_tools, memory_mb, timeout_minutes, input_policy,
			decompiled_code_ai, updated_by, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, now())
			ON CONFLICT (organization_id) DO UPDATE SET enabled_tools = EXCLUDED.enabled_tools, memory_mb = EXCLUDED.memory_mb,
			timeout_minutes = EXCLUDED.timeout_minutes, input_policy = EXCLUDED.input_policy, decompiled_code_ai = EXCLUDED.decompiled_code_ai,
			updated_by = EXCLUDED.updated_by, updated_at = now()`,
			p.OrganizationID, in.EnabledTools, in.MemoryMB, in.TimeoutMinutes, in.InputPolicy, in.DecompiledCodeAI, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "rea.settings.update", TargetType: "rea_settings", TargetID: p.OrganizationID.String(), RequestID: httpx.RequestID(r),
			Metadata: map[string]any{"enabled_tools": in.EnabledTools, "memory_mb": in.MemoryMB, "timeout_minutes": in.TimeoutMinutes,
				"input_policy": in.InputPolicy, "previous_input_policy": prev.InputPolicy, "decompiled_code_ai": in.DecompiledCodeAI,
				"previous_decompiled_code_ai": prev.DecompiledCodeAI}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

var versionPartRe = regexp.MustCompile(`^([a-z0-9-]+) (\S+)$`)

// workerTools reads the newest online reverse-engineering worker's
// pathos-rea version line ("pathos-rea v; radare2 v; ghidra -; ...").
func workerTools(ctx context.Context, q db.Querier, orgID uuid.UUID) (online bool, installed map[string]string, err error) {
	var line string
	err = q.QueryRow(ctx, `SELECT COALESCE(scanners->>$3, '') FROM workers WHERE organization_id = $1 AND revoked_at IS NULL
		AND last_seen_at > now() - $2::interval AND scanners ? $3 ORDER BY last_seen_at DESC LIMIT 1`,
		orgID, scans.WorkerOnlineWindow.String(), scanners.PathosREA).Scan(&line)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, map[string]string{}, nil
	}
	if err != nil {
		return false, nil, err
	}
	return true, parseVersionLine(line), nil
}

// parseVersionLine reads "pathos-rea 3.0; radare2 6.2.6; ghidra -".
func parseVersionLine(line string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(line, ";") {
		m := versionPartRe.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil || m[2] == "-" {
			continue
		}
		out[m[1]] = text(m[2], 64)
	}
	return out
}

func (s *Service) tools(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermScannersRead) && !p.HasAnywhere(authz.PermFindingsRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	online, installed, err := workerTools(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]ToolInfo, len(Tools))
	for i, t := range Tools {
		t.Version, t.Installed = installed[t.Key], installed[t.Key] != ""
		for _, e := range st.EnabledTools {
			t.Enabled = t.Enabled || e == t.Key
		}
		out[i] = t
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"tools": out, "worker_online": online, "analyser_version": installed["pathos-rea"]})
}

// --- artifacts and the input policy ------------------------------------------

// ArtifactOut is an artifact of GET /rea/artifacts.
type ArtifactOut struct {
	TargetID       uuid.UUID  `json:"target_id"`
	Name           string     `json:"name"`
	FileName       string     `json:"file_name"`
	SHA256         string     `json:"sha256"`
	Size           int64      `json:"size"`
	Kind           string     `json:"kind"`
	RepositoryID   uuid.UUID  `json:"repository_id"`
	RepositoryName string     `json:"repository_name"`
	ApplicationID  *uuid.UUID `json:"application_id"`
	CreatedAt      time.Time  `json:"created_at"`
	Trust          Trust      `json:"trust"`
	LastAnalysis   *Analysis  `json:"last_analysis"`
}

const artifactSelect = `SELECT t.id, t.repository_id, r.application_id, t.kind, t.name, t.artifact_name, t.sbom_sha256, t.sbom_size,
	t.provenance_material, t.created_at, COALESCE(NULLIF(r.display_name, ''), r.full_name), t.enabled AND r.archived_at IS NULL
	FROM scan_targets t JOIN repositories r ON r.id = t.repository_id`

func scanArtifact(row pgx.Row) (artifactRow, error) {
	var a artifactRow
	var name, sha *string
	var size *int64
	err := row.Scan(&a.ID, &a.RepoID, &a.AppID, &a.Kind, &a.Name, &name, &sha, &size, &a.Provenance, &a.CreatedAt, &a.RepoName, &a.Enabled)
	if name != nil {
		a.FileName = *name
	}
	if sha != nil {
		a.SHA256 = *sha
	}
	if size != nil {
		a.Size = *size
	}
	return a, err
}

// artifact loads an artifact target and checks perm on its repository.
func (s *Service) artifact(ctx context.Context, p *authz.Principal, perm authz.Permission, id uuid.UUID) (artifactRow, error) {
	a, err := scanArtifact(s.DB.QueryRow(ctx, artifactSelect+` WHERE t.organization_id = $1 AND t.id = $2`, p.OrganizationID, id))
	if err != nil {
		return a, err
	}
	if err := s.requireRepo(ctx, p, perm, a.RepoID); err != nil {
		return a, err
	}
	if a.Kind != "artifact" && a.Kind != "mobile-app" {
		return a, httpx.E(http.StatusUnprocessableEntity, "rea_not_artifact", "reverse engineering analyses uploaded build artifacts and mobile app packages only").WithDiag(CodeNotArtifact)
	}
	return a, nil
}

func (s *Service) artifacts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	var repoID *uuid.UUID
	if v := q.Get("repository_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("repository_id must be a UUID"))
			return
		}
		repoID = &id
	}
	search := strings.TrimSpace(q.Get("q"))
	if len(search) > 200 {
		s.fail(w, r, httpx.BadRequest("q is too long"))
		return
	}
	limit, err := intParam(q.Get("limit"), 100, 1, 500)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	expr, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 5)
	rows, err := s.DB.Query(ctx, artifactSelect+` WHERE t.organization_id = $1 AND t.kind IN ('artifact', 'mobile-app')
		AND ($2::uuid IS NULL OR t.repository_id = $2) AND ($3 = '' OR t.name ILIKE '%' || $3 || '%' OR t.artifact_name ILIKE '%' || $3 || '%')
		AND `+expr+` ORDER BY t.created_at DESC LIMIT $4`, append([]any{p.OrganizationID, repoID, search, limit}, args...)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (artifactRow, error) { return scanArtifact(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]ArtifactOut, 0, len(list))
	for _, a := range list {
		t, err := evaluate(ctx, s.DB, p.OrganizationID, a, st.InputPolicy)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		ao := ArtifactOut{TargetID: a.ID, Name: a.Name, FileName: a.FileName, SHA256: a.SHA256, Size: a.Size, Kind: a.Kind,
			RepositoryID: a.RepoID, RepositoryName: a.RepoName, ApplicationID: a.AppID, CreatedAt: a.CreatedAt, Trust: t}
		last, err := scanAnalysis(s.DB.QueryRow(ctx, analysisSelect+` WHERE a.organization_id = $1 AND a.target_id = $2
			ORDER BY a.created_at DESC LIMIT 1`, p.OrganizationID, a.ID))
		switch {
		case err == nil:
			ao.LastAnalysis = &last
		case !errors.Is(err, pgx.ErrNoRows):
			s.fail(w, r, err)
			return
		}
		out = append(out, ao)
	}
	if err := reconcile(ctx, s.DB, p.OrganizationID); err != nil {
		s.Log.Warn("reverse-engineering status reconcile failed", "err", err)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"artifacts": out, "input_policy": st.InputPolicy})
}

func intParam(v string, def, lo, hi int) (int, error) {
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < lo || n > hi {
		return 0, httpx.BadRequest("a numeric parameter is out of range (" + strconv.Itoa(lo) + " to " + strconv.Itoa(hi) + ")")
	}
	return n, nil
}

type authorizeRequest struct {
	Reason string `json:"reason"`
}

// authorize records an "analyse untrusted artifact" authorisation: per
// artifact (bound to its SHA-256), with a reason, audited; only when the
// input policy allows authorisations.
func (s *Service) authorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.artifact(ctx, p, authz.PermREAAuthorize, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in authorizeRequest
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.Reason = strings.TrimSpace(in.Reason)
	if len(in.Reason) < 10 || len(in.Reason) > 1000 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "invalid_request", "give a reason of 10 to 1000 characters"))
		return
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if st.InputPolicy != PolicyOwnBuildsOrAuth {
		s.fail(w, r, httpx.E(http.StatusConflict, "rea_authorization_disabled",
			"the input policy is \"own builds only\": untrusted artifacts cannot be authorised").WithDiag(CodeAuthDisabled))
		return
	}
	if a.SHA256 == "" {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "rea_not_artifact", "the artifact has no recorded SHA-256").WithDiag(CodeNotArtifact))
		return
	}
	auth := AuthInfo{ID: uuid.Must(uuid.NewV7()), Reason: in.Reason, AuthorizedByEmail: p.Email, ArtifactSHA256: a.SHA256}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		// A new authorisation replaces the active one.
		if _, err := tx.Exec(ctx, `UPDATE rea_authorizations SET revoked_at = now(), revoked_by = $3
			WHERE organization_id = $1 AND target_id = $2 AND revoked_at IS NULL`, p.OrganizationID, a.ID, p.UserID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO rea_authorizations (id, organization_id, target_id, artifact_sha256, reason, authorized_by)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING created_at`, auth.ID, p.OrganizationID, a.ID, a.SHA256, in.Reason, p.UserID).
			Scan(&auth.CreatedAt); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "rea.artifact.authorize_untrusted", TargetType: "scan_target", TargetID: a.ID.String(), RequestID: httpx.RequestID(r),
			Metadata: map[string]any{"reason": in.Reason, "sha256": a.SHA256, "file_name": a.FileName, "repository_id": a.RepoID,
				"authorization_id": auth.ID}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	by := p.Email
	auth.AuthorizedBy = &by
	httpx.WriteJSON(w, http.StatusCreated, auth)
}

func (s *Service) revoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	aid, err := pathUUID(r, "aid")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	a, err := s.artifact(ctx, p, authz.PermREAAuthorize, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE rea_authorizations SET revoked_at = now(), revoked_by = $4
			WHERE organization_id = $1 AND target_id = $2 AND id = $3 AND revoked_at IS NULL`, p.OrganizationID, a.ID, aid, p.UserID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "rea.artifact.revoke_authorization", TargetType: "scan_target", TargetID: a.ID.String(), RequestID: httpx.RequestID(r),
			Metadata: map[string]any{"authorization_id": aid, "sha256": a.SHA256}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- starting an analysis ----------------------------------------------------

// SystemProfileName names the per-organization system profile of
// reverse-engineering executions (stored archived: never selectable).
const SystemProfileName = "Reverse engineering (system)"

// ensureSystemProfile returns the current version of the organization's
// reverse-engineering system profile, creating it on first use. Every
// profile version must list the mandatory scanners (database trigger); the
// lease runs only pathos-rea for "rea" executions.
func ensureSystemProfile(ctx context.Context, tx pgx.Tx, orgID uuid.UUID) (uuid.UUID, error) {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('rea-profile:' || $1::text, 0))`, orgID); err != nil {
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
		VALUES ($1, $2, $3, 'System profile of reverse-engineering analyses (not selectable).', now())`, pid, orgID, SystemProfileName); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO scan_profile_versions (id, organization_id, profile_id, version, timeout_seconds, sbom, change_note)
		VALUES ($1, $2, $3, 1, 14400, false, 'Reverse engineering, static tier')`, vid, orgID, pid); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO profile_scanners (profile_version_id, scanner_key, config)
		SELECT $1, key, '{}'::jsonb FROM scanner_catalog WHERE mandatory OR key = $2`, vid, scanners.PathosREA); err != nil {
		return uuid.Nil, err
	}
	if _, err := tx.Exec(ctx, `UPDATE scan_profiles SET current_version_id = $2 WHERE id = $1`, pid, vid); err != nil {
		return uuid.Nil, err
	}
	return vid, nil
}

type startRequest struct {
	TargetID  uuid.UUID `json:"target_id"`
	CommitSHA string    `json:"commit_sha"`
}

var commitRe = regexp.MustCompile(`^[0-9a-f]{7,64}$`)

// start queues an analysis after the input policy accepted the artifact.
func (s *Service) start(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in startRequest
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.CommitSHA = strings.ToLower(strings.TrimSpace(in.CommitSHA))
	if in.CommitSHA != "" && !commitRe.MatchString(in.CommitSHA) {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "invalid_request", "commit_sha must be a hexadecimal commit id"))
		return
	}
	a, err := s.artifact(ctx, p, authz.PermFindingsRead, in.TargetID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, perm := range []authz.Permission{authz.PermScansRun, authz.PermREARun} {
		if err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: a.RepoID}); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if !a.Enabled {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "rea_not_artifact", "the target is disabled or its repository is archived").WithDiag(CodeNotArtifact))
		return
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	trust, err := evaluate(ctx, s.DB, p.OrganizationID, a, st.InputPolicy)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if trust.Status == "untrusted" {
		// The done-when of M10: nothing that PATHOS cannot tie to the
		// organization's own builds is analysed without an authorisation.
		_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "rea.analysis.refused", Outcome: "failure", TargetType: "scan_target", TargetID: a.ID.String(), RequestID: httpx.RequestID(r),
			Metadata: map[string]any{"reason": trust.Reason, "sha256": a.SHA256, "input_policy": st.InputPolicy}})
		code, msg := CodeUntrusted, "artifact refused: "+trust.Reason+". By default only artifacts from your own builds (verified signature or provenance) are analysed"
		if trust.Provenance != nil && trust.Provenance.Status == "mismatch" || (trust.Authorization != nil && trust.Authorization.ArtifactSHA256 != a.SHA256) {
			code = CodeArtifactMismatch
		}
		status, legacy := http.StatusForbidden, "rea_untrusted_artifact"
		if code == CodeArtifactMismatch {
			status, legacy = http.StatusConflict, "rea_artifact_mismatch"
		}
		s.fail(w, r, httpx.E(status, legacy, msg).WithDiag(code))
		return
	}
	online, installed, err := workerTools(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !online {
		s.fail(w, r, httpx.E(http.StatusConflict, "rea_no_worker",
			"no reverse-engineering worker is online (worker-rea with its sandbox runner, Compose profile rea)").WithDiag(CodeNoWorker))
		return
	}
	var tools []string
	for _, t := range st.EnabledTools {
		if installed[t] != "" {
			tools = append(tools, t)
		}
	}
	if len(tools) == 0 {
		tools = []string{"radare2", "binwalk"}
	}
	cfg, _ := json.Marshal(map[string]any{"tools": tools, "memory_mb": st.MemoryMB, "timeout_seconds": st.TimeoutMinutes * 60,
		"max_functions": 20000, "max_strings": 20000, "max_code": 200})
	commit, commitSource := "", ""
	switch {
	case trust.Provenance != nil && trust.Provenance.Status == "verified" && trust.Provenance.Commit != "":
		commit, commitSource = trust.Provenance.Commit, "provenance"
	case in.CommitSHA != "":
		commit, commitSource = in.CommitSHA, "user"
	}
	var authID *uuid.UUID
	if trust.Basis == "authorization" && trust.Authorization != nil {
		authID = &trust.Authorization.ID
	}
	an := Analysis{ID: uuid.Must(uuid.NewV7()), TargetID: a.ID, ArtifactName: a.FileName, ArtifactSHA256: a.SHA256, RepositoryID: a.RepoID,
		RepositoryName: a.RepoName, ApplicationID: a.AppID, Status: "queued", TrustBasis: trust.Basis, CommitSHA: commit, CommitSource: commitSource,
		DiffStatus: "pending", Tools: map[string]ToolRun{}, Stats: map[string]any{}}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		vid, err := ensureSystemProfile(ctx, tx, p.OrganizationID)
		if err != nil {
			return err
		}
		q, err := scans.EnqueueREA(ctx, tx, p.OrganizationID, scans.REAEnqueue{TargetID: a.ID, ProfileVersionID: vid, Config: cfg,
			TimeoutSeconds: st.TimeoutMinutes*60 + 600, RequestedBy: &p.UserID})
		if err != nil {
			return err
		}
		if q.Coalesced {
			existing, err := scanAnalysis(tx.QueryRow(ctx, analysisSelect+` WHERE a.scan_job_id = $1`, q.JobID))
			if err == nil {
				an = existing
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		an.ScanJobID = &q.JobID
		if err := tx.QueryRow(ctx, `INSERT INTO rea_analyses (id, organization_id, target_id, repository_id, application_id, scan_job_id,
			artifact_name, artifact_sha256, trust_basis, authorization_id, trust_detail, commit_sha, commit_source, requested_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING created_at`,
			an.ID, p.OrganizationID, a.ID, a.RepoID, a.AppID, q.JobID, text(a.FileName, 255), a.SHA256, trust.Basis, authID, trustJSON(trust),
			commit, commitSource, p.UserID).Scan(&an.CreatedAt); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "rea.analysis.start", TargetType: "scan_target", TargetID: a.ID.String(), RequestID: httpx.RequestID(r),
			Metadata: map[string]any{"analysis_id": an.ID, "scan_job_id": q.JobID, "trust_basis": trust.Basis, "sha256": a.SHA256,
				"authorization_id": authID, "tools": tools, "commit_source": commitSource}})
	})
	if errors.Is(err, scans.ErrNotScannable) || errors.Is(err, scans.ErrScanPrerequisite) {
		err = httpx.E(http.StatusUnprocessableEntity, "rea_not_artifact", err.Error()).WithDiag(CodeNotArtifact)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusAccepted, map[string]any{"analysis": an, "trust": trust})
}
