package scans

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
)

func (s *Service) registerProfiles(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/scanners", s.listScanners)
	mux.HandleFunc("GET /api/v1/scan-profiles", s.listProfiles)
	mux.HandleFunc("POST /api/v1/scan-profiles", s.createProfile)
	mux.HandleFunc("GET /api/v1/scan-profiles/{id}", s.getProfile)
	mux.HandleFunc("PUT /api/v1/scan-profiles/{id}", s.updateProfile)
	mux.HandleFunc("POST /api/v1/scan-profiles/{id}/default", s.setDefaultProfile)
	mux.HandleFunc("DELETE /api/v1/scan-profiles/{id}", s.archiveProfile)
}

// ProfileScanner is one enabled scanner in a profile version.
type ProfileScanner struct {
	Key    string          `json:"key"`
	Config json.RawMessage `json:"config,omitempty"`
}

// ProfileSettings are the versioned settings of a profile.
type ProfileSettings struct {
	SeverityThreshold string           `json:"severity_threshold"`
	Exclusions        []string         `json:"exclusions"`
	TimeoutSeconds    int              `json:"timeout_seconds"`
	SBOM              bool             `json:"sbom"`
	FailOnCritical    bool             `json:"fail_on_critical"`
	RetentionDays     int              `json:"retention_days"`
	Scanners          []ProfileScanner `json:"scanners"`
}

// ProfileVersion is one immutable version.
type ProfileVersion struct {
	ID         uuid.UUID `json:"id"`
	Version    int       `json:"version"`
	ChangeNote string    `json:"change_note"`
	CreatedBy  *string   `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	ProfileSettings
}

// Profile is a scan profile with its current version.
type Profile struct {
	ID              uuid.UUID        `json:"id"`
	Name            string           `json:"name"`
	Description     string           `json:"description"`
	IsDefault       bool             `json:"is_default"`
	RepositoryCount int              `json:"repository_count"`
	Current         ProfileVersion   `json:"current"`
	History         []ProfileVersion `json:"history,omitempty"`
}

func (s *Service) listScanners(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermScannersRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	out := append(append(append([]scanners.Scanner{}, scanners.Catalog...), scanners.SyftUtility), scanners.Builtins...)
	// Declarative adapters registered by workers.
	// Only plugins an online, non-revoked worker currently provides.
	rows, err := s.DB.Query(r.Context(), `SELECT c.key, c.name, COALESCE(c.homepage, ''), COALESCE(c.notes, '') FROM scanner_catalog c
		WHERE c.worker_family = 'plugin' AND EXISTS (SELECT 1 FROM workers w WHERE w.revoked_at IS NULL AND w.scanners ? c.key
		  AND w.last_seen_at > now() - $1::interval)
		ORDER BY c.key`, WorkerOnlineWindow.String())
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var key, name, home, notes string
		if err := rows.Scan(&key, &name, &home, &notes); err != nil {
			s.fail(w, r, err)
			return
		}
		if sc, ok := scanners.ResolvePlugin(key); ok {
			sc.Name, sc.Homepage, sc.Notes = name, home, notes
			out = append(out, sc)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

const versionSelect = `
	SELECT v.id, v.version, v.change_note, COALESCE(NULLIF(u.display_name, ''), u.email), v.created_at,
	       v.severity_threshold, v.exclusions, v.timeout_seconds, v.sbom, v.fail_on_critical, v.retention_days,
	       COALESCE((SELECT json_agg(json_build_object('key', ps.scanner_key, 'config', ps.config) ORDER BY c.sort_order)
	                 FROM profile_scanners ps JOIN scanner_catalog c ON c.key = ps.scanner_key
	                 WHERE ps.profile_version_id = v.id), '[]')
	FROM scan_profile_versions v LEFT JOIN users u ON u.id = v.created_by`

func scanVersion(row pgx.Row) (ProfileVersion, error) {
	var v ProfileVersion
	var sc []byte
	err := row.Scan(&v.ID, &v.Version, &v.ChangeNote, &v.CreatedBy, &v.CreatedAt, &v.SeverityThreshold, &v.Exclusions,
		&v.TimeoutSeconds, &v.SBOM, &v.FailOnCritical, &v.RetentionDays, &sc)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, errNotFound
	}
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(sc, &v.Scanners)
	return v, err
}

func (s *Service) loadProfile(ctx context.Context, q db.Querier, orgID, id uuid.UUID, history bool) (Profile, error) {
	var p Profile
	var cur uuid.UUID
	err := q.QueryRow(ctx, `SELECT id, name, description, is_default, current_version_id,
		(SELECT count(*) FROM repositories r WHERE r.scan_profile_id = sp.id AND r.archived_at IS NULL)
		FROM scan_profiles sp WHERE organization_id = $1 AND id = $2 AND archived_at IS NULL`, orgID, id).
		Scan(&p.ID, &p.Name, &p.Description, &p.IsDefault, &cur, &p.RepositoryCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, errNotFound
	}
	if err != nil {
		return p, err
	}
	if p.Current, err = scanVersion(q.QueryRow(ctx, versionSelect+` WHERE v.id = $1`, cur)); err != nil {
		return p, err
	}
	if history {
		rows, err := q.Query(ctx, versionSelect+` WHERE v.profile_id = $1 ORDER BY v.version DESC LIMIT 50`, id)
		if err != nil {
			return p, err
		}
		p.History, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (ProfileVersion, error) { return scanVersion(row) })
		if err != nil {
			return p, err
		}
	}
	return p, nil
}

func (s *Service) listProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermScansRead) && !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT id FROM scan_profiles WHERE organization_id = $1 AND archived_at IS NULL
		ORDER BY is_default DESC, lower(name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]Profile, 0, len(ids))
	for _, id := range ids {
		pr, err := s.loadProfile(ctx, s.DB, p.OrganizationID, id, false)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		out = append(out, pr)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) getProfile(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermScansRead) && !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pr, err := s.loadProfile(r.Context(), s.DB, p.OrganizationID, id, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, pr)
}

type profileRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	ChangeNote  string  `json:"change_note"`
	ProfileSettings
}

// validate checks settings and normalizes scanners (mandatory ones added).
func (req *profileRequest) validate() error {
	st := &req.ProfileSettings
	if st.SeverityThreshold == "" {
		st.SeverityThreshold = "info"
	}
	if !slices.Contains(scanners.Severities, st.SeverityThreshold) {
		return httpx.BadRequest("severity_threshold must be one of critical, high, medium, low, info")
	}
	if st.TimeoutSeconds == 0 {
		st.TimeoutSeconds = 1800
	}
	if st.TimeoutSeconds < 60 || st.TimeoutSeconds > 14400 {
		return httpx.BadRequest("timeout_seconds must be between 60 and 14400")
	}
	if st.RetentionDays == 0 {
		st.RetentionDays = 90
	}
	if st.RetentionDays < 7 || st.RetentionDays > 3650 {
		return httpx.BadRequest("retention_days must be between 7 and 3650")
	}
	if len(st.Exclusions) > 100 {
		return httpx.BadRequest("at most 100 exclusions")
	}
	clean := []string{}
	for _, e := range st.Exclusions {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if len(e) > 200 || strings.Contains(e, "..") || strings.HasPrefix(e, "/") {
			return httpx.BadRequest("exclusions must be relative glob patterns (no '..', no leading '/')")
		}
		clean = append(clean, e)
	}
	st.Exclusions = clean
	seen := map[string]bool{}
	var out []ProfileScanner
	for _, ps := range st.Scanners {
		sc, ok := scanners.Lookup(ps.Key)
		if !ok {
			// Declarative adapters: known once a worker registered them
			// (the catalog foreign key rejects unregistered ones).
			sc, ok = scanners.ResolvePlugin(ps.Key)
		}
		if !ok {
			return httpx.BadRequest("unknown scanner " + ps.Key)
		}
		if !sc.AdapterAvailable {
			return httpx.BadRequest(sc.Name + " is catalogued but no worker image runs it yet")
		}
		if sc.TargetOnly {
			return httpx.BadRequest(sc.Name + " runs for scan targets (Scan targets page), not in repository profiles")
		}
		if sc.Decision == "restricted" {
			return httpx.BadRequest(sc.Name + " is license-restricted")
		}
		if seen[ps.Key] {
			continue
		}
		seen[ps.Key] = true
		if len(ps.Config) == 0 || string(ps.Config) == "null" {
			ps.Config = json.RawMessage("{}")
		}
		var obj map[string]any
		if err := json.Unmarshal(ps.Config, &obj); err != nil || len(ps.Config) > 4096 {
			return httpx.BadRequest("scanner config must be a JSON object up to 4 KB")
		}
		out = append(out, ps)
	}
	for _, sc := range scanners.Catalog {
		if sc.Mandatory && !seen[sc.Key] {
			// Mandatory scanners are locked on; add rather than reject.
			out = append([]ProfileScanner{{Key: sc.Key, Config: json.RawMessage("{}")}}, out...)
		}
	}
	if st.SBOM && seen[scanners.Grype] && !seen[scanners.Syft] {
		out = append(out, ProfileScanner{Key: scanners.Syft, Config: json.RawMessage("{}")})
	}
	if seen[scanners.Grype] && !st.SBOM {
		return httpx.BadRequest("Grype scans the SBOM: enable sbom or disable Grype")
	}
	st.Scanners = out
	return nil
}

func insertVersion(ctx context.Context, tx pgx.Tx, orgID, profileID uuid.UUID, version int, st ProfileSettings, note string, by *uuid.UUID) (uuid.UUID, error) {
	id := uuid.Must(uuid.NewV7())
	if _, err := tx.Exec(ctx, `INSERT INTO scan_profile_versions (id, organization_id, profile_id, version, severity_threshold,
		exclusions, timeout_seconds, sbom, fail_on_critical, retention_days, change_note, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		id, orgID, profileID, version, st.SeverityThreshold, nonNilStrings(st.Exclusions), st.TimeoutSeconds, st.SBOM,
		st.FailOnCritical, st.RetentionDays, note, by); err != nil {
		return id, err
	}
	for _, ps := range st.Scanners {
		if _, err := tx.Exec(ctx, `INSERT INTO profile_scanners (profile_version_id, scanner_key, config) VALUES ($1, $2, $3)`,
			id, ps.Key, []byte(ps.Config)); err != nil {
			return id, err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE scan_profiles SET current_version_id = $2, updated_at = now() WHERE id = $1`, profileID, id)
	return id, err
}

// DefaultSettings is the seeded "Default" profile: every core scanner.
func DefaultSettings() ProfileSettings {
	st := ProfileSettings{SeverityThreshold: "info", TimeoutSeconds: 1800, SBOM: true, RetentionDays: 90,
		Exclusions: []string{"node_modules/**", "vendor/**", "**/testdata/**"}}
	for _, sc := range scanners.Catalog {
		if sc.DefaultEnabled {
			st.Scanners = append(st.Scanners, ProfileScanner{Key: sc.Key, Config: json.RawMessage("{}")})
		}
	}
	st.Scanners = append(st.Scanners, ProfileScanner{Key: scanners.Syft, Config: json.RawMessage("{}")})
	return st
}

// EnsureDefaultProfile seeds the default profile for an organization.
func EnsureDefaultProfile(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) error {
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM scan_profiles WHERE organization_id = $1 AND archived_at IS NULL)`, orgID).Scan(&exists); err != nil || exists {
			return err
		}
		pid := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO scan_profiles (id, organization_id, name, description, is_default)
			VALUES ($1, $2, 'Default', 'All core scanners: secrets, SAST, SCA with SBOM, IaC', true)`, pid, orgID); err != nil {
			return err
		}
		_, err := insertVersion(ctx, tx, orgID, pid, 1, DefaultSettings(), "Initial version", nil)
		return err
	})
}

func (s *Service) createProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermProfilesManage, s.orgScope(p)); err != nil {
		s.fail(w, r, err)
		return
	}
	var req profileRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Name == nil || strings.TrimSpace(*req.Name) == "" || len(*req.Name) > 200 {
		s.fail(w, r, httpx.BadRequest("name is required (max 200 characters)"))
		return
	}
	if err := req.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	pid := uuid.Must(uuid.NewV7())
	var out Profile
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		desc := ""
		if req.Description != nil {
			desc = *req.Description
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scan_profiles (id, organization_id, name, description) VALUES ($1, $2, $3, $4)`,
			pid, p.OrganizationID, strings.TrimSpace(*req.Name), desc); err != nil {
			return err
		}
		if _, err := insertVersion(ctx, tx, p.OrganizationID, pid, 1, req.ProfileSettings, firstNonEmpty(req.ChangeNote, "Initial version"), &p.UserID); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan_profile.create", TargetType: "scan_profile", TargetID: pid.String(), Metadata: map[string]any{"name": *req.Name}}); err != nil {
			return err
		}
		var err error
		out, err = s.loadProfile(ctx, tx, p.OrganizationID, pid, true)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

// updateProfile replaces the settings by creating a new immutable version.
func (s *Service) updateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermProfilesManage, s.orgScope(p)); err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req profileRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := req.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	var out Profile
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		cur, err := s.loadProfile(ctx, tx, p.OrganizationID, id, false)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `SELECT 1 FROM scan_profiles WHERE id = $1 FOR UPDATE`, id); err != nil {
			return err
		}
		if req.Name != nil || req.Description != nil {
			if req.Name != nil && (strings.TrimSpace(*req.Name) == "" || len(*req.Name) > 200) {
				return httpx.BadRequest("name must be 1-200 characters")
			}
			if _, err := tx.Exec(ctx, `UPDATE scan_profiles SET name = COALESCE($2, name), description = COALESCE($3, description) WHERE id = $1`,
				id, trimPtr(req.Name), req.Description); err != nil {
				return err
			}
		}
		next := cur.Current.Version + 1
		if _, err := insertVersion(ctx, tx, p.OrganizationID, id, next, req.ProfileSettings, req.ChangeNote, &p.UserID); err != nil {
			return err
		}
		keys := make([]string, len(req.Scanners))
		for i, ps := range req.Scanners {
			keys[i] = ps.Key
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scan_profile.update", TargetType: "scan_profile", TargetID: id.String(),
			Metadata: map[string]any{"name": cur.Name, "version": next, "scanners": keys, "change_note": req.ChangeNote}}); err != nil {
			return err
		}
		out, err = s.loadProfile(ctx, tx, p.OrganizationID, id, true)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) setDefaultProfile(w http.ResponseWriter, r *http.Request) {
	s.profileAction(w, r, "scan_profile.set_default", func(ctx context.Context, tx pgx.Tx, orgID, id uuid.UUID) error {
		if _, err := tx.Exec(ctx, `UPDATE scan_profiles SET is_default = false WHERE organization_id = $1 AND is_default`, orgID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE scan_profiles SET is_default = true, updated_at = now() WHERE id = $1`, id)
		return err
	})
}

func (s *Service) archiveProfile(w http.ResponseWriter, r *http.Request) {
	s.profileAction(w, r, "scan_profile.archive", func(ctx context.Context, tx pgx.Tx, orgID, id uuid.UUID) error {
		var isDefault bool
		if err := tx.QueryRow(ctx, `SELECT is_default FROM scan_profiles WHERE id = $1`, id).Scan(&isDefault); err != nil {
			return err
		}
		if isDefault {
			return httpx.Conflict("make another profile the default before archiving this one")
		}
		if _, err := tx.Exec(ctx, `UPDATE repositories SET scan_profile_id = NULL WHERE scan_profile_id = $1`, id); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE scan_profiles SET archived_at = now(), updated_at = now() WHERE id = $1`, id)
		return err
	})
}

func (s *Service) profileAction(w http.ResponseWriter, r *http.Request, action string, fn func(context.Context, pgx.Tx, uuid.UUID, uuid.UUID) error) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermProfilesManage, s.orgScope(p)); err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		pr, err := s.loadProfile(ctx, tx, p.OrganizationID, id, false)
		if err != nil {
			return err
		}
		if err := fn(ctx, tx, p.OrganizationID, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: action, TargetType: "scan_profile", TargetID: id.String(), Metadata: map[string]any{"name": pr.Name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func trimPtr(p *string) *string {
	if p == nil {
		return nil
	}
	t := strings.TrimSpace(*p)
	return &t
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
