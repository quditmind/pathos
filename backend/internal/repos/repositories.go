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

// Repository is the API representation.
type Repository struct {
	ID             uuid.UUID  `json:"id"`
	ConnectionID   uuid.UUID  `json:"scm_connection_id"`
	ConnectionName string     `json:"scm_connection_name"`
	Provider       string     `json:"provider"`
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
	RemoteArchived bool       `json:"remote_archived"`
	LastPushedAt   *time.Time `json:"last_pushed_at"`
	ArchivedAt     *time.Time `json:"archived_at"`
	CreatedAt      time.Time  `json:"created_at"`
	Tags           []TagRef   `json:"tags"`
}

const repoSelect = `
	SELECT r.id, r.scm_connection_id, c.name, c.provider, r.external_id, r.full_name, r.name, r.url,
	       r.default_branch, r.scan_branch, r.visibility, r.description, r.technologies,
	       a.id, a.name, b.id, b.name, co.id, co.name, co.code, rg.id, rg.name,
	       r.environment, r.criticality, r.scan_enabled, r.remote_archived, r.last_pushed_at, r.archived_at, r.created_at,
	       COALESCE((SELECT json_agg(json_build_object('id', t.id, 'name', t.name, 'color', t.color,
	                   'category_id', tc.id, 'category_name', tc.name) ORDER BY tc.name, t.name)
	                 FROM repository_tags rt JOIN tags t ON t.id = rt.tag_id JOIN tag_categories tc ON tc.id = t.category_id
	                 WHERE rt.repository_id = r.id), '[]')
	FROM repositories r
	JOIN scm_connections c ON c.id = r.scm_connection_id
	LEFT JOIN applications a ON a.id = r.application_id
	LEFT JOIN business_units b ON b.id = r.business_unit_id
	LEFT JOIN countries co ON co.id = r.country_id
	LEFT JOIN regions rg ON rg.id = co.region_id`

func ref(id *uuid.UUID, name *string) *Ref {
	if id == nil {
		return nil
	}
	return &Ref{ID: *id, Name: *name}
}

func scanRepo(row pgx.Row) (Repository, error) {
	var r Repository
	var appID, buID, coID, rgID *uuid.UUID
	var appName, buName, coName, coCode, rgName *string
	var tags []byte
	err := row.Scan(&r.ID, &r.ConnectionID, &r.ConnectionName, &r.Provider, &r.ExternalID, &r.FullName, &r.Name, &r.URL,
		&r.DefaultBranch, &r.ScanBranch, &r.Visibility, &r.Description, &r.Technologies,
		&appID, &appName, &buID, &buName, &coID, &coName, &coCode, &rgID, &rgName,
		&r.Environment, &r.Criticality, &r.ScanEnabled, &r.RemoteArchived, &r.LastPushedAt, &r.ArchivedAt, &r.CreatedAt, &tags)
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
	err = json.Unmarshal(tags, &r.Tags)
	return r, err
}

func (s *Service) getRepo(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Repository, error) {
	return scanRepo(q.QueryRow(ctx, repoSelect+` WHERE r.organization_id = $1 AND r.id = $2`, orgID, id))
}

var (
	environments  = []string{"production", "staging", "development", "test", "other"}
	criticalities = []string{"low", "medium", "high", "critical"}
)

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

func (s *Service) listRepositories(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermReposRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
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
	where := []string{"r.organization_id = $1"}
	args := []any{p.OrganizationID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	scopeExpr, scopeArgs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", len(args)+1)
	args = append(args, scopeArgs...)
	where = append(where, scopeExpr)

	switch q.Get("status") {
	case "", "active":
		where = append(where, "r.archived_at IS NULL")
	case "archived":
		where = append(where, "r.archived_at IS NOT NULL")
	case "all":
	default:
		s.fail(w, r, httpx.BadRequest("status must be active, archived or all"))
		return
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		add("(lower(r.full_name) LIKE ? OR lower(r.description) LIKE ?)", "%"+escapeLike(strings.ToLower(v))+"%")
	}
	for param, col := range map[string]string{"scm_connection_id": "r.scm_connection_id", "application_id": "r.application_id", "country_id": "r.country_id"} {
		id, err := uuidParam(r, param)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if id != nil {
			add(col+" = ?", *id)
		}
	}
	if id, err := uuidParam(r, "business_unit_id"); err != nil {
		s.fail(w, r, err)
		return
	} else if id != nil {
		add(`r.business_unit_id IN (WITH RECURSIVE d AS (SELECT id FROM business_units WHERE id = ?
			UNION ALL SELECT b.id FROM business_units b JOIN d ON b.parent_id = d.id) SELECT id FROM d)`, *id)
	}
	if id, err := uuidParam(r, "region_id"); err != nil {
		s.fail(w, r, err)
		return
	} else if id != nil {
		add("co.region_id = ?", *id)
	}
	if id, err := uuidParam(r, "tag_id"); err != nil {
		s.fail(w, r, err)
		return
	} else if id != nil {
		add("EXISTS (SELECT 1 FROM repository_tags rt WHERE rt.repository_id = r.id AND rt.tag_id = ?)", *id)
	}
	if v := q.Get("criticality"); v != "" {
		if !slices.Contains(criticalities, v) {
			s.fail(w, r, httpx.BadRequest("invalid criticality"))
			return
		}
		add("r.criticality = ?", v)
	}
	if v := q.Get("environment"); v != "" {
		if !slices.Contains(environments, v) {
			s.fail(w, r, httpx.BadRequest("invalid environment"))
			return
		}
		add("r.environment = ?", v)
	}
	if q.Get("owner") == "none" {
		where = append(where, "r.application_id IS NULL")
	}
	if c := q.Get("cursor"); c != "" {
		key, idStr, ok := strings.Cut(c, "|")
		id, err := uuid.Parse(idStr)
		if !ok || err != nil {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		args = append(args, key, id)
		where = append(where, fmt.Sprintf("(lower(r.full_name), r.id) > ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit)
	sql := repoSelect + " WHERE " + strings.Join(where, " AND ") +
		fmt.Sprintf(" ORDER BY lower(r.full_name), r.id LIMIT $%d", len(args))
	rows, err := s.DB.Query(ctx, sql, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	repos, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Repository, error) { return scanRepo(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if repos == nil {
		repos = []Repository{}
	}
	var next *string
	if len(repos) == limit {
		last := repos[len(repos)-1]
		c := strings.ToLower(last.FullName) + "|" + last.ID.String()
		next = &c
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": repos, "next_cursor": next})
}

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (s *Service) loadRepoFor(r *http.Request, perm authz.Permission) (*authz.Principal, Repository, error) {
	p := s.Principal(r.Context())
	id, err := pathID(r)
	if err != nil {
		return p, Repository{}, err
	}
	// Check permission first so existence is not leaked to unauthorized users.
	if err := s.requireRepo(r.Context(), p, perm, id); err != nil {
		if errors.Is(err, org.ErrScopeNotFound) {
			return p, Repository{}, errNotFound
		}
		if errors.Is(err, authz.ErrForbidden) && !p.HasAnywhere(perm) {
			return p, Repository{}, err
		}
		return p, Repository{}, errNotFound
	}
	repo, err := s.getRepo(r.Context(), s.DB, p.OrganizationID, id)
	return p, repo, err
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
	ApplicationID  optUUID      `json:"application_id"`
	BusinessUnitID optUUID      `json:"business_unit_id"`
	CountryID      optUUID      `json:"country_id"`
	Environment    *string      `json:"environment"`
	Criticality    *string      `json:"criticality"`
	ScanEnabled    *bool        `json:"scan_enabled"`
	ScanBranch     *string      `json:"scan_branch"`
	Technologies   *[]string    `json:"technologies"`
	TagIDs         *[]uuid.UUID `json:"tag_ids"`
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
	p, repo, err := s.loadRepoFor(r, authz.PermReposManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req repoPatch
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Environment != nil && !slices.Contains(environments, *req.Environment) {
		s.fail(w, r, httpx.BadRequest("environment must be one of "+strings.Join(environments, ", ")))
		return
	}
	if req.Criticality != nil && !slices.Contains(criticalities, *req.Criticality) {
		s.fail(w, r, httpx.BadRequest("criticality must be one of "+strings.Join(criticalities, ", ")))
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
	// Moving placement needs repos.manage at the destination too.
	if req.BusinessUnitID.Set || req.CountryID.Set {
		bu, co := idOf(repo.BusinessUnit), idOf(repo.Country)
		if req.BusinessUnitID.Set {
			bu = req.BusinessUnitID.Val
		}
		if req.CountryID.Set {
			co = req.CountryID.Val
		}
		target, err := s.targetScope(ctx, p, bu, co)
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
		sets := []string{"updated_at = now()"}
		args := []any{repo.ID}
		set := func(col string, v any) {
			args = append(args, v)
			sets = append(sets, fmt.Sprintf("%s = $%d", col, len(args)))
		}
		changed := map[string]any{}
		if req.ApplicationID.Set {
			set("application_id", req.ApplicationID.Val)
			changed["application_id"] = req.ApplicationID.Val
		}
		if req.BusinessUnitID.Set {
			set("business_unit_id", req.BusinessUnitID.Val)
			changed["business_unit_id"] = req.BusinessUnitID.Val
		}
		if req.CountryID.Set {
			set("country_id", req.CountryID.Val)
			changed["country_id"] = req.CountryID.Val
		}
		if req.Environment != nil {
			set("environment", *req.Environment)
			changed["environment"] = *req.Environment
		}
		if req.Criticality != nil {
			set("criticality", *req.Criticality)
			changed["criticality"] = *req.Criticality
		}
		if req.ScanEnabled != nil {
			set("scan_enabled", *req.ScanEnabled)
			changed["scan_enabled"] = *req.ScanEnabled
		}
		if req.ScanBranch != nil {
			set("scan_branch", *req.ScanBranch)
			changed["scan_branch"] = *req.ScanBranch
		}
		if req.Technologies != nil {
			set("technologies", techs)
			changed["technologies"] = techs
		}
		if _, err := tx.Exec(ctx, "UPDATE repositories SET "+strings.Join(sets, ", ")+" WHERE id = $1", args...); err != nil {
			return err
		}
		if req.TagIDs != nil {
			if err := s.setTags(ctx, tx, p.OrganizationID, repo.ID, *req.TagIDs); err != nil {
				return err
			}
			changed["tag_ids"] = *req.TagIDs
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.update", TargetType: "repository", TargetID: repo.ID.String(),
			Metadata: map[string]any{"name": repo.FullName, "changed": changed}}); err != nil {
			return err
		}
		out, err = s.getRepo(ctx, tx, p.OrganizationID, repo.ID)
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
	c, err := s.getConn(ctx, s.DB, p.OrganizationID, repo.ConnectionID)
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
		out, err = s.getRepo(ctx, tx, p.OrganizationID, repo.ID)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) archiveRepository(w http.ResponseWriter, r *http.Request)   { s.setArchived(w, r, true) }
func (s *Service) unarchiveRepository(w http.ResponseWriter, r *http.Request) { s.setArchived(w, r, false) }

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
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM role_assignments WHERE scope_type = 'repository' AND scope_id = $1`, repo.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM repositories WHERE id = $1`, repo.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "repository.delete", TargetType: "repository", TargetID: repo.ID.String(), Metadata: map[string]any{"name": repo.FullName}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
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
