package repos

import (
	"bytes"
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
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

func (s *Service) registerRepositories(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/repositories", s.listRepositories)
	mux.HandleFunc("POST /api/v1/repositories/import", s.importRepositories)
	mux.HandleFunc("POST /api/v1/repositories/import-csv", s.importCSV)
	mux.HandleFunc("POST /api/v1/repositories/bulk-tags", s.bulkTags)
	mux.HandleFunc("GET /api/v1/repositories/{id}", s.getRepository)
	mux.HandleFunc("PATCH /api/v1/repositories/{id}", s.updateRepository)
	mux.HandleFunc("GET /api/v1/repositories/{id}/branches", s.listBranches)
	mux.HandleFunc("POST /api/v1/repositories/{id}/archive", s.archiveRepository)
	mux.HandleFunc("POST /api/v1/repositories/{id}/unarchive", s.unarchiveRepository)
	mux.HandleFunc("DELETE /api/v1/repositories/{id}", s.deleteRepository)
}

// Ref is a compact reference to a related entity.
type Ref struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
	Code string    `json:"code,omitempty"`
}

// TagRef is a tag attached to a repository.
type TagRef struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"name"`
	Color        string    `json:"color"`
	CategoryID   uuid.UUID `json:"category_id"`
	CategoryName string    `json:"category_name"`
}

// SnapshotSummary is the current source snapshot of an uploaded repository.
type SnapshotSummary struct {
	ID                uuid.UUID `json:"id"`
	CreatedAt         time.Time `json:"created_at"`
	ArchiveFilename   string    `json:"archive_filename"`
	ArchiveSHA256     string    `json:"archive_sha256"`
	SnapshotSHA256    string    `json:"snapshot_sha256"`
	FileCount         int       `json:"file_count"`
	UncompressedBytes int64     `json:"uncompressed_bytes"`
	MalwareScan       string    `json:"malware_scan"`
}

// Repository is the API representation (frontend type Repository).
type Repository struct {
	ID             uuid.UUID  `json:"id"`
	ConnectionID   *uuid.UUID `json:"scm_connection_id"`
	ConnectionName string     `json:"scm_connection_name"`
	Provider       string     `json:"provider"`
	SourceType     string     `json:"source_type"`
	SCMOrg         string     `json:"scm_organization"`
	SCMProject     string     `json:"scm_project"`
	ExternalID     string     `json:"external_id"`
	FullName       string     `json:"full_name"`
	Name           string     `json:"name"`
	URL            string     `json:"url"`
	DefaultBranch  string     `json:"default_branch"`
	ScanBranch     string     `json:"scan_branch"`
	Visibility     string     `json:"visibility"`
	Description    string     `json:"description"`
	Technologies   []string   `json:"technologies"`
	Application    *Ref       `json:"application"`
	BusinessUnit   *Ref       `json:"business_unit"`
	Country        *Ref       `json:"country"`
	Region         *Ref       `json:"region"`
	Environment    string     `json:"environment"`
	Criticality    string     `json:"criticality"`
	ScanEnabled    bool       `json:"scan_enabled"`
	ScanProfileID  *uuid.UUID `json:"scan_profile_id"`
	RemoteArchived bool       `json:"remote_archived"`
	LastPushedAt   *time.Time `json:"last_pushed_at"`
	ArchivedAt     *time.Time `json:"archived_at"`
	CreatedAt      time.Time  `json:"created_at"`
	Tags           []TagRef   `json:"tags"`

	DisplayName         string           `json:"display_name"`
	AssetName           string           `json:"asset_name"`
	BusinessPurpose     string           `json:"business_purpose"`
	ApplicationType     string           `json:"application_type"`
	BusinessOwner       *UserRef         `json:"business_owner"`
	TechnicalOwner      *UserRef         `json:"technical_owner"`
	ApplicationOwner    *UserRef         `json:"application_owner"`
	ResponsibleTeam     *Ref             `json:"responsible_team"`
	SupportingTeam      *Ref             `json:"supporting_team"`
	Department          *Ref             `json:"department"`
	CostCentre          string           `json:"cost_centre"`
	BusinessRegion      *Ref             `json:"business_region"`
	DataResidencyRegion *Ref             `json:"data_residency_region"`
	HostingRegion       string           `json:"hosting_region"`
	OperationalLocation string           `json:"operational_location"`
	DataClassification  string           `json:"data_classification"`
	InternetExposure    string           `json:"internet_exposure"`
	ComplianceScopes    []string         `json:"compliance_scopes"`
	LifecycleStatus     string           `json:"lifecycle_status"`
	GoLiveDate          *string          `json:"go_live_date"`
	RetirementDate      *string          `json:"retirement_date"`
	Color               string           `json:"color"`
	FullHistory         bool             `json:"full_history"`
	LatestCommitSHA     string           `json:"latest_commit_sha"`
	LatestCommitAt      *time.Time       `json:"latest_commit_at"`
	SizeBytes           *int64           `json:"size_bytes"`
	FileCount           *int             `json:"file_count"`
	Languages           map[string]int64 `json:"languages"`
	LastSyncAt          *time.Time       `json:"last_sync_at"`
	LastSyncOKAt        *time.Time       `json:"last_sync_ok_at"`
	SyncStatus          string           `json:"sync_status"`
	SyncError           string           `json:"sync_error"`
	CurrentSnapshot     *SnapshotSummary `json:"current_snapshot"`
	CanEdit             bool             `json:"can_edit"`
	CanManage           bool             `json:"can_manage"`
}

const userJSON = `json_build_object('id', u.id, 'name', COALESCE(NULLIF(u.display_name, ''), u.email), 'email', u.email)`

// repoSelectTmpl takes the can_manage expression and the ownership expression.
const repoSelectTmpl = `
	SELECT r.id, r.scm_connection_id, COALESCE(c.name, ''), COALESCE(c.provider, 'upload'), r.source_type, r.scm_organization, r.scm_project,
	       r.external_id, r.full_name, r.name, r.url,
	       r.default_branch, r.scan_branch, r.visibility, r.description, r.technologies,
	       a.id, a.name, b.id, b.name, co.id, co.name, co.code, rg.id, rg.name,
	       r.environment, r.criticality, r.scan_enabled, r.scan_profile_id, r.remote_archived, r.last_pushed_at, r.archived_at, r.created_at,
	       COALESCE((SELECT json_agg(json_build_object('id', t.id, 'name', t.name, 'color', t.color,
	                   'category_id', tc.id, 'category_name', tc.name) ORDER BY tc.name, t.name)
	                 FROM repository_tags rt JOIN tags t ON t.id = rt.tag_id JOIN tag_categories tc ON tc.id = t.category_id
	                 WHERE rt.repository_id = r.id), '[]'),
	       r.display_name, r.asset_name, r.business_purpose, r.application_type,
	       (SELECT ` + userJSON + ` FROM users u WHERE u.id = r.business_owner_id),
	       (SELECT ` + userJSON + ` FROM users u WHERE u.id = r.technical_owner_id),
	       (SELECT ` + userJSON + ` FROM users u WHERE u.id = r.application_owner_id),
	       (SELECT json_build_object('id', t.id, 'name', t.name) FROM teams t WHERE t.id = r.responsible_team_id),
	       (SELECT json_build_object('id', t.id, 'name', t.name) FROM teams t WHERE t.id = r.supporting_team_id),
	       (SELECT json_build_object('id', d.id, 'name', d.name) FROM business_units d WHERE d.id = r.department_id),
	       r.cost_centre,
	       (SELECT json_build_object('id', x.id, 'name', x.name, 'code', x.code) FROM regions x WHERE x.id = r.business_region_id),
	       (SELECT json_build_object('id', x.id, 'name', x.name, 'code', x.code) FROM regions x WHERE x.id = r.data_residency_region_id),
	       r.hosting_region, r.operational_location, r.data_classification, r.internet_exposure,
	       COALESCE((SELECT array_agg(s.scope_key ORDER BY s.scope_key) FROM repository_compliance_scopes s WHERE s.repository_id = r.id), '{}'),
	       r.lifecycle_status, r.go_live_date, r.retirement_date, r.color, r.full_history,
	       r.latest_commit_sha, r.latest_commit_at, r.size_bytes, r.file_count, r.languages,
	       r.last_sync_at, r.last_sync_ok_at, r.sync_status, r.sync_error,
	       (SELECT json_build_object('id', ss.id, 'created_at', ss.created_at, 'archive_filename', ss.archive_filename,
	               'archive_sha256', ss.archive_sha256, 'snapshot_sha256', ss.snapshot_sha256, 'file_count', ss.file_count,
	               'uncompressed_bytes', ss.uncompressed_bytes, 'malware_scan', ss.malware_scan)
	          FROM source_snapshots ss WHERE ss.id = r.current_snapshot_id),
	       COALESCE((%[1]s), false), COALESCE((%[1]s) OR (%[2]s), false)
	FROM repositories r
	LEFT JOIN scm_connections c ON c.id = r.scm_connection_id
	LEFT JOIN applications a ON a.id = r.application_id
	LEFT JOIN business_units b ON b.id = r.business_unit_id
	LEFT JOIN countries co ON co.id = r.country_id
	LEFT JOIN regions rg ON rg.id = co.region_id`

// ownerSQL is true when the user ($n) owns the repository row r.
func ownerSQL(n int) string {
	u := "$" + strconv.Itoa(n)
	return "COALESCE(r.business_owner_id = " + u + " OR r.technical_owner_id = " + u + " OR r.application_owner_id = " + u +
		" OR r.responsible_team_id IN (SELECT tm.team_id FROM team_members tm WHERE tm.user_id = " + u + "), false)"
}

// repoQuery returns the SELECT (without WHERE) for principal p and its
// arguments: $1 = organization, $2 = user, then the manage-scope arguments.
func repoQuery(p *authz.Principal) (string, []any) {
	args := []any{p.OrganizationID, p.UserID}
	mexpr, margs := org.ScopeSQL(authz.FilterFor(p, authz.PermReposManage), "r.id", "r.business_unit_id", "r.country_id", 3)
	args = append(args, margs...)
	return fmt.Sprintf(repoSelectTmpl, mexpr, ownerSQL(2)), args
}

func ref(id *uuid.UUID, name *string) *Ref {
	if id == nil {
		return nil
	}
	return &Ref{ID: *id, Name: *name}
}

func jsonPtr[T any](b []byte, dst **T) error {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	*dst = &v
	return nil
}

func scanRepo(row pgx.Row) (Repository, error) {
	var r Repository
	var appID, buID, coID, rgID *uuid.UUID
	var appName, buName, coName, coCode, rgName *string
	var tags, bo, to, ao, rt, st, dep, brg, drg, snap []byte
	var golive, retire *time.Time
	err := row.Scan(&r.ID, &r.ConnectionID, &r.ConnectionName, &r.Provider, &r.SourceType, &r.SCMOrg, &r.SCMProject,
		&r.ExternalID, &r.FullName, &r.Name, &r.URL,
		&r.DefaultBranch, &r.ScanBranch, &r.Visibility, &r.Description, &r.Technologies,
		&appID, &appName, &buID, &buName, &coID, &coName, &coCode, &rgID, &rgName,
		&r.Environment, &r.Criticality, &r.ScanEnabled, &r.ScanProfileID, &r.RemoteArchived, &r.LastPushedAt, &r.ArchivedAt, &r.CreatedAt, &tags,
		&r.DisplayName, &r.AssetName, &r.BusinessPurpose, &r.ApplicationType, &bo, &to, &ao, &rt, &st, &dep,
		&r.CostCentre, &brg, &drg, &r.HostingRegion, &r.OperationalLocation, &r.DataClassification, &r.InternetExposure,
		&r.ComplianceScopes, &r.LifecycleStatus, &golive, &retire, &r.Color, &r.FullHistory,
		&r.LatestCommitSHA, &r.LatestCommitAt, &r.SizeBytes, &r.FileCount, &r.Languages,
		&r.LastSyncAt, &r.LastSyncOKAt, &r.SyncStatus, &r.SyncError, &snap, &r.CanManage, &r.CanEdit)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, errNotFound
	}
	if err != nil {
		return r, err
	}
	r.Application, r.BusinessUnit, r.Region = ref(appID, appName), ref(buID, buName), ref(rgID, rgName)
	if coID != nil {
		r.Country = &Ref{ID: *coID, Name: *coName, Code: *coCode}
	}
	if r.Technologies == nil {
		r.Technologies = []string{}
	}
	if r.ComplianceScopes == nil {
		r.ComplianceScopes = []string{}
	}
	if r.Languages == nil {
		r.Languages = map[string]int64{}
	}
	r.GoLiveDate, r.RetirementDate = dateString(golive), dateString(retire)
	if r.ArchivedAt != nil {
		r.CanEdit = r.CanManage // archived assets are read-only for owners
	}
	for _, j := range []struct {
		b   []byte
		set func([]byte) error
	}{
		{bo, func(b []byte) error { return jsonPtr(b, &r.BusinessOwner) }},
		{to, func(b []byte) error { return jsonPtr(b, &r.TechnicalOwner) }},
		{ao, func(b []byte) error { return jsonPtr(b, &r.ApplicationOwner) }},
		{rt, func(b []byte) error { return jsonPtr(b, &r.ResponsibleTeam) }},
		{st, func(b []byte) error { return jsonPtr(b, &r.SupportingTeam) }},
		{dep, func(b []byte) error { return jsonPtr(b, &r.Department) }},
		{brg, func(b []byte) error { return jsonPtr(b, &r.BusinessRegion) }},
		{drg, func(b []byte) error { return jsonPtr(b, &r.DataResidencyRegion) }},
		{snap, func(b []byte) error { return jsonPtr(b, &r.CurrentSnapshot) }},
	} {
		if err := j.set(j.b); err != nil {
			return r, err
		}
	}
	err = json.Unmarshal(tags, &r.Tags)
	return r, err
}

// getRepo loads one repository as seen by p.
func (s *Service) getRepo(ctx context.Context, q db.Querier, p *authz.Principal, id uuid.UUID) (Repository, error) {
	sel, args := repoQuery(p)
	args = append(args, id)
	return scanRepo(q.QueryRow(ctx, sel+fmt.Sprintf(` WHERE r.organization_id = $1 AND r.id = $%d`, len(args)), args...))
}

// criticalities are fixed; their labels and colours are configurable.
var criticalities = []string{"low", "medium", "high", "critical"}

func uuidParam(r *http.Request, name string) (*uuid.UUID, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil, httpx.BadRequest("invalid " + name)
	}
	return &id, nil
}

// repoSort is a keyset-paginated sort order.
type repoSort struct {
	expr, cast string
	desc       bool
}

var repoSorts = map[string]repoSort{
	"name":         {"lower(COALESCE(NULLIF(r.display_name, ''), r.full_name))", "text", false},
	"created_at":   {"r.created_at", "timestamptz", false},
	"criticality":  {"(CASE r.criticality WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END)", "int", false},
	"last_sync_at": {"COALESCE(r.last_sync_at, 'epoch'::timestamptz)", "timestamptz", false},
}

// repoListFilter appends WHERE conditions for the shared list/insights
// filters. It returns an error for malformed parameters.
func repoListFilter(r *http.Request, where *[]string, args *[]any) error {
	q := r.URL.Query()
	add := func(cond string, v any) {
		*args = append(*args, v)
		*where = append(*where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(*args))))
	}
	switch q.Get("status") {
	case "", "active":
		*where = append(*where, "r.archived_at IS NULL")
	case "archived":
		*where = append(*where, "r.archived_at IS NOT NULL")
	case "all":
	default:
		return httpx.BadRequest("status must be active, archived or all")
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		add("(lower(r.full_name) LIKE ? OR lower(r.description) LIKE ? OR lower(r.display_name) LIKE ? OR lower(r.asset_name) LIKE ?)",
			"%"+escapeLike(strings.ToLower(v))+"%")
	}
	for param, col := range map[string]string{
		"scm_connection_id": "r.scm_connection_id", "application_id": "r.application_id", "country_id": "r.country_id",
		"business_owner_id": "r.business_owner_id", "technical_owner_id": "r.technical_owner_id",
		"business_region_id": "r.business_region_id", "responsible_team_id": "r.responsible_team_id",
	} {
		id, err := uuidParam(r, param)
		if err != nil {
			return err
		}
		if id != nil {
			add(col+" = ?", *id)
		}
	}
	if id, err := uuidParam(r, "business_unit_id"); err != nil {
		return err
	} else if id != nil {
		add(`r.business_unit_id IN (WITH RECURSIVE d AS (SELECT id FROM business_units WHERE id = ?
			UNION ALL SELECT b.id FROM business_units b JOIN d ON b.parent_id = d.id) SELECT id FROM d)`, *id)
	}
	if id, err := uuidParam(r, "region_id"); err != nil {
		return err
	} else if id != nil {
		add("co.region_id = ?", *id)
	}
	if id, err := uuidParam(r, "tag_id"); err != nil {
		return err
	} else if id != nil {
		add("EXISTS (SELECT 1 FROM repository_tags rt WHERE rt.repository_id = r.id AND rt.tag_id = ?)", *id)
	}
	if v := q.Get("criticality"); v != "" {
		if !slices.Contains(criticalities, v) {
			return httpx.BadRequest("invalid criticality")
		}
		add("r.criticality = ?", v)
	}
	for param, col := range map[string]string{
		"environment": "r.environment", "data_classification": "r.data_classification", "lifecycle_status": "r.lifecycle_status",
		"internet_exposure": "r.internet_exposure", "source_type": "r.source_type", "application_type": "r.application_type",
		"hosting_region": "r.hosting_region",
	} {
		if v := q.Get(param); v != "" {
			if len(v) > 63 {
				return httpx.BadRequest("invalid " + param)
			}
			add(col+" = ?", v)
		}
	}
	if v := q.Get("sync_status"); v != "" {
		if !slices.Contains([]string{"never", "ok", "failed", "missing", "permission_denied", "archived_upstream"}, v) {
			return httpx.BadRequest("invalid sync_status")
		}
		add("r.sync_status = ?", v)
	}
	if v := q.Get("provider"); v != "" {
		if v == "upload" {
			*where = append(*where, "r.source_type = 'upload'")
		} else {
			add("c.provider = ?", v)
		}
	}
	if v := q.Get("compliance"); v != "" {
		add("EXISTS (SELECT 1 FROM repository_compliance_scopes s WHERE s.repository_id = r.id AND s.scope_key = ?)", v)
	}
	switch q.Get("missing_owner") {
	case "":
	case "business":
		*where = append(*where, "r.business_owner_id IS NULL")
	case "technical":
		*where = append(*where, "r.technical_owner_id IS NULL")
	case "any":
		*where = append(*where, "(r.business_owner_id IS NULL OR r.technical_owner_id IS NULL)")
	default:
		return httpx.BadRequest("missing_owner must be business, technical or any")
	}
	if q.Get("owner") == "none" {
		*where = append(*where, "r.application_id IS NULL")
	}
	return nil
}

// readScope returns the visibility condition for repos.read: the caller's
// scopes plus repositories they own.
func readScope(p *authz.Principal, args *[]any) (string, bool) {
	f := authz.FilterFor(p, authz.PermReposRead)
	if f.None() {
		return "", false
	}
	expr, scopeArgs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", len(*args)+1)
	*args = append(*args, scopeArgs...)
	return "(" + expr + " OR " + ownerSQL(2) + ")", true
}

func (s *Service) listRepositories(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	q := r.URL.Query()
	limit := 50
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 200 {
			s.fail(w, r, httpx.BadRequest("limit must be between 1 and 200"))
			return
		}
		limit = n
	}
	sortKey := q.Get("sort")
	if sortKey == "" {
		sortKey = "name"
	}
	srt, ok := repoSorts[strings.TrimPrefix(sortKey, "-")]
	if !ok {
		s.fail(w, r, httpx.BadRequest("sort must be name, created_at, criticality or last_sync_at (prefix - for descending)"))
		return
	}
	srt.desc = strings.HasPrefix(sortKey, "-")

	sel, args := repoQuery(p)
	where := []string{"r.organization_id = $1"}
	scope, ok := readScope(p, &args)
	if !ok {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	where = append(where, scope)
	if err := repoListFilter(r, &where, &args); err != nil {
		s.fail(w, r, err)
		return
	}
	cmp, dir := ">", "ASC"
	if srt.desc {
		cmp, dir = "<", "DESC"
	}
	if c := q.Get("cursor"); c != "" {
		key, idStr, ok := strings.Cut(c, "|")
		id, err := uuid.Parse(idStr)
		if !ok || err != nil {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		args = append(args, key, id)
		where = append(where, fmt.Sprintf("(%s, r.id) %s ($%d::%s, $%d)", srt.expr, cmp, len(args)-1, srt.cast, len(args)))
	}
	args = append(args, limit)
	sql := strings.Replace(sel, "\n\tFROM repositories r", fmt.Sprintf(", (%s)::text\n\tFROM repositories r", srt.expr), 1) +
		" WHERE " + strings.Join(where, " AND ") +
		fmt.Sprintf(" ORDER BY %s %s, r.id %s LIMIT $%d", srt.expr, dir, dir, len(args))
	rows, err := s.DB.Query(ctx, sql, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var keys []string
	repos, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Repository, error) {
		var key string
		repo, err := scanRepo(sortKeyRow{row, &key})
		keys = append(keys, key)
		return repo, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if repos == nil {
		repos = []Repository{}
	}
	var next *string
	if len(repos) == limit {
		c := keys[len(keys)-1] + "|" + repos[len(repos)-1].ID.String()
		next = &c
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": repos, "next_cursor": next})
}

// sortKeyRow appends the sort key column to a scan.
type sortKeyRow struct {
	pgx.Row
	key *string
}

func (s sortKeyRow) Scan(dest ...any) error { return s.Row.Scan(append(dest, s.key)...) }

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// isOwner reports whether p owns repository id (business, technical or
// application owner, or member of its responsible team).
func (s *Service) isOwner(ctx context.Context, p *authz.Principal, id uuid.UUID) bool {
	var ok bool
	_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM repositories r WHERE r.organization_id = $1 AND r.id = $3 AND `+ownerSQL(2)+`)`,
		p.OrganizationID, p.UserID, id).Scan(&ok)
	return ok
}

// loadRepoFor loads a repository after checking perm. Owners of a
// repository pass repos.read checks for it, and repos.manage checks when
// ownerEdit is set (descriptive and ownership metadata only).
func (s *Service) loadRepoFor(r *http.Request, perm authz.Permission, ownerEdit ...bool) (*authz.Principal, Repository, error) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		return p, Repository{}, err
	}
	// Check permission first so existence is not leaked to unauthorized users.
	if err := s.requireRepo(ctx, p, perm, id); err != nil {
		ownerOK := p.HasAnywhere(authz.PermReposRead) && (perm == authz.PermReposRead || len(ownerEdit) > 0 && ownerEdit[0]) && s.isOwner(ctx, p, id)
		if !ownerOK {
			if errors.Is(err, org.ErrScopeNotFound) {
				return p, Repository{}, errNotFound
			}
			if errors.Is(err, authz.ErrForbidden) && !p.HasAnywhere(perm) && !p.HasAnywhere(authz.PermReposRead) {
				return p, Repository{}, err
			}
			if errors.Is(err, authz.ErrForbidden) && s.canRead(ctx, p, id) {
				return p, Repository{}, err // visible, but not allowed: 403
			}
			return p, Repository{}, errNotFound
		}
	}
	repo, err := s.getRepo(ctx, s.DB, p, id)
	return p, repo, err
}

func (s *Service) canRead(ctx context.Context, p *authz.Principal, id uuid.UUID) bool {
	return s.requireRepo(ctx, p, authz.PermReposRead, id) == nil || s.isOwner(ctx, p, id)
}

func (s *Service) getRepository(w http.ResponseWriter, r *http.Request) {
	_, repo, err := s.loadRepoFor(r, authz.PermReposRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, repo)
}

// optUUID distinguishes "absent" from explicit null in PATCH bodies.
type optUUID struct {
	Set bool
	Val *uuid.UUID
}

func (o *optUUID) UnmarshalJSON(b []byte) error {
	o.Set = true
	if bytes.Equal(b, []byte("null")) {
		return nil
	}
	var id uuid.UUID
	if err := json.Unmarshal(b, &id); err != nil {
		return err
	}
	o.Val = &id
	return nil
}

type repoPatch struct {
	AssetMetadata
	ScanEnabled  *bool     `json:"scan_enabled"`
	ScanBranch   *string   `json:"scan_branch"`
	Technologies *[]string `json:"technologies"`
	FullHistory  *bool     `json:"full_history"`
}

// ownerEditable are the AssetValues fields an asset owner without
// repos.manage may change (descriptive and ownership metadata).
var ownerEditable = []string{
	"display_name", "description", "application_type", "business_purpose",
	"business_owner_id", "technical_owner_id", "application_owner_id", "responsible_team_id", "supporting_team_id",
	"cost_centre", "hosting_region", "operational_location", "data_classification", "internet_exposure",
	"compliance_scopes", "tag_ids", "color", "lifecycle_status", "go_live_date", "retirement_date",
}

func validTechnologies(t []string) ([]string, error) {
	if len(t) > 30 {
		return nil, httpx.BadRequest("at most 30 technologies")
	}
	out := make([]string, 0, len(t))
	for _, v := range t {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 50 {
			return nil, httpx.BadRequest("technologies must be 1-50 characters each")
		}
		if !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out, nil
}

func validBranch(b string) bool {
	if len(b) > 255 || strings.HasPrefix(b, "-") || strings.Contains(b, "..") {
		return false
	}
	for _, c := range b {
		if c < 0x21 || c == 0x7f || strings.ContainsRune(`~^:?*[\`, c) {
			return false
		}
	}
	return true
}

func (s *Service) updateRepository(w http.ResponseWriter, r *http.Request) {
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
	var req repoPatch
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.ScanBranch != nil && *req.ScanBranch != "" && !validBranch(*req.ScanBranch) {
		s.fail(w, r, httpx.BadRequest("invalid branch name"))
		return
	}
	var techs []string
	if req.Technologies != nil {
		if techs, err = validTechnologies(*req.Technologies); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	ap, err := s.loadPolicy(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	old, err := currentValues(ctx, s.DB, p.OrganizationID, repo.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cur := old
	cur.ComplianceScopes, cur.TagIDs = slices.Clone(old.ComplianceScopes), slices.Clone(old.TagIDs)
	changed := req.AssetMetadata.Apply(&cur)

	if !repo.CanManage {
		// Asset owners: descriptive and ownership metadata only.
		for _, f := range changed {
			if !slices.Contains(ownerEditable, f) {
				s.fail(w, r, httpx.E(http.StatusForbidden, "forbidden", "changing "+f+" requires repos.manage for this repository"))
				return
			}
		}
		if req.ScanEnabled != nil || req.ScanBranch != nil || req.FullHistory != nil {
			s.fail(w, r, httpx.E(http.StatusForbidden, "forbidden", "scan settings require repos.manage for this repository"))
			return
		}
	}
	if fe := validateValues(ctx, s.DB, p.OrganizationID, ap, &cur, validateOpts{Changed: changed, Previous: &old, ExcludeRepo: &repo.ID}); len(fe) > 0 {
		s.fail(w, r, fe.Err())
		return
	}
	// Moving placement or creating an application needs repos.manage at
	// the destination too.
	if slices.Contains(changed, "business_unit_id") || slices.Contains(changed, "country_id") || cur.NewApplication != nil {
		target, err := s.targetScope(ctx, p, cur.BusinessUnitID, cur.CountryID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if err := s.Authz.Require(ctx, p, authz.PermReposManage, target); err != nil {
			s.fail(w, r, err)
			return
		}
	}

	var out Repository
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if len(changed) > 0 {
			if err := writeValues(ctx, tx, p.OrganizationID, repo.ID, p.UserID, &cur); err != nil {
				return err
			}
		}
		other := map[string]any{}
		sets := []string{"updated_at = now()"}
		args := []any{repo.ID}
		set := func(col string, v any) {
			args = append(args, v)
			sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
			other[col] = v
		}
		if req.ScanEnabled != nil {
			set("scan_enabled", *req.ScanEnabled)
		}
		if req.ScanBranch != nil {
			set("scan_branch", *req.ScanBranch)
		}
		if req.Technologies != nil {
			set("technologies", techs)
		}
		if req.FullHistory != nil {
			set("full_history", *req.FullHistory)
		}
		if len(other) > 0 {
			if _, err := tx.Exec(ctx, "UPDATE repositories SET "+strings.Join(sets, ", ")+" WHERE id = $1", args...); err != nil {
				return err
			}
		}
		diff := diffValues(old, cur)
		for k, v := range other {
			diff[k] = map[string]any{"new": v}
		}
		action := "repository.update"
		if !repo.CanManage {
			action = "repository.update_as_owner"
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: action, TargetType: "repository", TargetID: repo.ID.String(),
			Metadata: map[string]any{"name": repo.FullName, "changed": diff}}); err != nil {
			return err
		}
		out, err = s.getRepo(ctx, tx, p, repo.ID)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func idOf(r *Ref) *uuid.UUID {
	if r == nil {
		return nil
	}
	return &r.ID
}

// setTags replaces a repository's tags, enforcing category rules.
func (s *Service) setTags(ctx context.Context, tx pgx.Tx, orgID, repoID uuid.UUID, tagIDs []uuid.UUID) error {
	if err := validateTagSet(ctx, tx, orgID, tagIDs); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM repository_tags WHERE repository_id = $1 AND tag_id <> ALL($2::uuid[])`, repoID, nonNil(tagIDs)); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `INSERT INTO repository_tags (organization_id, repository_id, tag_id)
		SELECT $1, $2, unnest($3::uuid[]) ON CONFLICT DO NOTHING`, orgID, repoID, nonNil(tagIDs))
	return err
}

func nonNil(ids []uuid.UUID) []uuid.UUID {
	if ids == nil {
		return []uuid.UUID{}
	}
	return ids
}

// validateTagSet checks that the tags exist, that single-value categories
// have at most one tag, and that every mandatory category is covered.
func validateTagSet(ctx context.Context, q db.Querier, orgID uuid.UUID, tagIDs []uuid.UUID) error {
	if len(tagIDs) > 50 {
		return httpx.BadRequest("at most 50 tags per repository")
	}
	var found int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM tags WHERE organization_id = $1 AND id = ANY($2::uuid[])`, orgID, nonNil(tagIDs)).Scan(&found); err != nil {
		return err
	}
	if found != len(slices.Compact(slices.SortedFunc(slices.Values(tagIDs), func(a, b uuid.UUID) int { return bytes.Compare(a[:], b[:]) }))) {
		return httpx.BadRequest("unknown tag")
	}
	rows, err := q.Query(ctx, `
		SELECT tc.name, tc.is_mandatory, tc.allow_multiple,
		       count(t.id) FILTER (WHERE t.id = ANY($2::uuid[]))
		FROM tag_categories tc LEFT JOIN tags t ON t.category_id = tc.id
		WHERE tc.organization_id = $1
		GROUP BY tc.id`, orgID, nonNil(tagIDs))
	if err != nil {
		return err
	}
	defer rows.Close()
	var missing, multi []string
	for rows.Next() {
		var name string
		var mandatory, multiple bool
		var n int
		if err := rows.Scan(&name, &mandatory, &multiple, &n); err != nil {
			return err
		}
		if mandatory && n == 0 {
			missing = append(missing, name)
		}
		if !multiple && n > 1 {
			multi = append(multi, name)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(missing) > 0 {
		slices.Sort(missing)
		return httpx.E(http.StatusUnprocessableEntity, "mandatory_tags_missing", "a tag is required in: "+strings.Join(missing, ", "))
	}
	if len(multi) > 0 {
		return httpx.BadRequest("only one tag allowed in: " + strings.Join(multi, ", "))
	}
	return nil
}

func (s *Service) listBranches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, repo, err := s.loadRepoFor(r, authz.PermReposRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if repo.ConnectionID == nil {
		s.fail(w, r, httpx.Conflict("uploaded repositories have no branches; upload a new version instead"))
		return
	}
	c, err := s.getConn(ctx, s.DB, p.OrganizationID, *repo.ConnectionID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cl, err := s.client(ctx, c)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	branches, err := cl.ListBranches(ctx, scm.RemoteRepo{ExternalID: repo.ExternalID, FullName: repo.FullName})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	slices.Sort(branches)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": branches, "default_branch": repo.DefaultBranch})
}

func (s *Service) setArchived(w http.ResponseWriter, r *http.Request, archive bool) {
	ctx := r.Context()
	p, repo, err := s.loadRepoFor(r, authz.PermReposManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if archive == (repo.ArchivedAt != nil) {
		s.fail(w, r, httpx.Conflict(map[bool]string{true: "repository is already archived", false: "repository is not archived"}[archive]))
		return
	}
	action := map[bool]string{true: "repository.archive", false: "repository.unarchive"}[archive]
	var out Repository
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE repositories SET archived_at = CASE WHEN $2 THEN now() END, updated_at = now() WHERE id = $1`, repo.ID, archive); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: action, TargetType: "repository", TargetID: repo.ID.String(), Metadata: map[string]any{"name": repo.FullName}}); err != nil {
			return err
		}
		out, err = s.getRepo(ctx, tx, p, repo.ID)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) archiveRepository(w http.ResponseWriter, r *http.Request) {
	s.setArchived(w, r, true)
}
func (s *Service) unarchiveRepository(w http.ResponseWriter, r *http.Request) {
	s.setArchived(w, r, false)
}

// deleteRepository permanently removes an archived repository.
func (s *Service) deleteRepository(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, repo, err := s.loadRepoFor(r, authz.PermReposManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if repo.ArchivedAt == nil {
		s.fail(w, r, httpx.Conflict("archive the repository before deleting it"))
		return
	}
	var snapshotKeys []string
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT object_key FROM source_snapshots WHERE repository_id = $1`, repo.ID)
		if err != nil {
			return err
		}
		if snapshotKeys, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE repositories SET current_snapshot_id = NULL WHERE id = $1`, repo.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE scope_type = 'repository' AND scope_id = $1`, repo.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM repositories WHERE id = $1`, repo.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.delete", TargetType: "repository", TargetID: repo.ID.String(),
			Metadata: map[string]any{"name": repo.FullName, "source_type": repo.SourceType, "snapshots_deleted": len(snapshotKeys)}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(snapshotKeys) > 0 && s.Sources != nil {
		if err := s.Sources.Delete(context.WithoutCancel(ctx), snapshotKeys...); err != nil {
			s.Log.Warn("snapshot objects of a deleted repository were not removed", "repository_id", repo.ID, "err", err)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

type bulkTagsRequest struct {
	RepositoryIDs []uuid.UUID `json:"repository_ids"`
	Add           []uuid.UUID `json:"add"`
	Remove        []uuid.UUID `json:"remove"`
}

// bulkTags adds/removes tags on many repositories atomically.
func (s *Service) bulkTags(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req bulkTagsRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.RepositoryIDs) == 0 || len(req.RepositoryIDs) > 500 || len(req.Add)+len(req.Remove) == 0 {
		s.fail(w, r, httpx.BadRequest("select 1-500 repositories and at least one tag to add or remove"))
		return
	}
	for _, id := range req.RepositoryIDs {
		if err := s.requireRepo(ctx, p, authz.PermReposManage, id); err != nil {
			if errors.Is(err, org.ErrScopeNotFound) {
				err = httpx.BadRequest("unknown repository " + id.String())
			}
			s.fail(w, r, err)
			return
		}
	}
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		for _, id := range req.RepositoryIDs {
			var current []uuid.UUID
			rows, err := tx.Query(ctx, `SELECT tag_id FROM repository_tags WHERE repository_id = $1`, id)
			if err != nil {
				return err
			}
			current, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			if err != nil {
				return err
			}
			next := slices.DeleteFunc(slices.Clone(current), func(t uuid.UUID) bool { return slices.Contains(req.Remove, t) })
			for _, t := range req.Add {
				if !slices.Contains(next, t) {
					next = append(next, t)
				}
			}
			if err := s.setTags(ctx, tx, p.OrganizationID, id, next); err != nil {
				var he *httpx.Error
				if errors.As(err, &he) {
					he.Message = fmt.Sprintf("repository %s: %s", id, he.Message)
				}
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.bulk_tag", TargetType: "repository",
			Metadata: map[string]any{"repositories": len(req.RepositoryIDs), "add": req.Add, "remove": req.Remove}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"updated": len(req.RepositoryIDs)})
}
