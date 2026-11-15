package repos

import (
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

func (s *Service) registerTags(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/tag-categories", s.listTagCategories)
	mux.HandleFunc("POST /api/v1/tag-categories", s.createTagCategory)
	mux.HandleFunc("PATCH /api/v1/tag-categories/{id}", s.updateTagCategory)
	mux.HandleFunc("DELETE /api/v1/tag-categories/{id}", s.deleteTagCategory)
	mux.HandleFunc("POST /api/v1/tag-categories/{id}/tags", s.createTag)
	mux.HandleFunc("DELETE /api/v1/tags/{id}", s.deleteTag)
}

var tagColors = []string{"slate", "blue", "green", "amber", "red", "purple", "teal", "pink"}

// Tag is a tag inside a category.
type Tag struct {
	ID              uuid.UUID `json:"id"`
	Name            string    `json:"name"`
	Color           string    `json:"color"`
	RepositoryCount int       `json:"repository_count"`
}

// TagCategory groups tags; mandatory categories must be covered on every
// repository import and edit.
type TagCategory struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	IsMandatory   bool      `json:"is_mandatory"`
	AllowMultiple bool      `json:"allow_multiple"`
	Tags          []Tag     `json:"tags"`
	// NonCompliant counts active repositories missing a tag in a mandatory
	// category (they must be fixed at their next edit).
	NonCompliant int `json:"noncompliant_repositories"`
}

func (s *Service) listTagCategories(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(r.Context(), `
		SELECT tc.id, tc.name, tc.description, tc.is_mandatory, tc.allow_multiple,
		       COALESCE((SELECT json_agg(json_build_object('id', t.id, 'name', t.name, 'color', t.color,
		                   'repository_count', (SELECT count(*) FROM repository_tags rt WHERE rt.tag_id = t.id)) ORDER BY lower(t.name))
		                 FROM tags t WHERE t.category_id = tc.id), '[]'),
		       CASE WHEN tc.is_mandatory THEN (SELECT count(*) FROM repositories r
		            WHERE r.organization_id = tc.organization_id AND r.archived_at IS NULL
		              AND NOT EXISTS (SELECT 1 FROM repository_tags rt JOIN tags t ON t.id = rt.tag_id
		                              WHERE rt.repository_id = r.id AND t.category_id = tc.id)) ELSE 0 END
		FROM tag_categories tc WHERE tc.organization_id = $1 ORDER BY lower(tc.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	cats, err := pgx.CollectRows(rows, pgx.RowToStructByPos[TagCategory])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if cats == nil {
		cats = []TagCategory{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": cats})
}

type categoryRequest struct {
	Name          *string `json:"name"`
	Description   *string `json:"description"`
	IsMandatory   *bool   `json:"is_mandatory"`
	AllowMultiple *bool   `json:"allow_multiple"`
}

func (s *Service) createTagCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermReposManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req categoryRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	name := str(req.Name)
	if name == "" || len(name) > 100 || strings.Contains(name, ":") {
		s.fail(w, r, httpx.BadRequest("name must be 1-100 characters and must not contain ':'"))
		return
	}
	id := uuid.Must(uuid.NewV7())
	mandatory, multiple := req.IsMandatory != nil && *req.IsMandatory, req.AllowMultiple == nil || *req.AllowMultiple
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tag_categories (id, organization_id, name, description, is_mandatory, allow_multiple)
			VALUES ($1, $2, $3, $4, $5, $6)`, id, p.OrganizationID, name, str(req.Description), mandatory, multiple); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "tag_category.create", TargetType: "tag_category", TargetID: id.String(),
			Metadata: map[string]any{"name": name, "is_mandatory": mandatory}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, TagCategory{ID: id, Name: name, Description: str(req.Description), IsMandatory: mandatory, AllowMultiple: multiple, Tags: []Tag{}})
}

func (s *Service) updateTagCategory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermReposManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req categoryRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Name != nil && (str(req.Name) == "" || len(str(req.Name)) > 100 || strings.Contains(*req.Name, ":")) {
		s.fail(w, r, httpx.BadRequest("name must be 1-100 characters and must not contain ':'"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var name *string
		if req.Name != nil {
			n := str(req.Name)
			name = &n
		}
		tag, err := tx.Exec(ctx, `UPDATE tag_categories SET name = COALESCE($3, name), description = COALESCE($4, description),
			is_mandatory = COALESCE($5, is_mandatory), allow_multiple = COALESCE($6, allow_multiple), updated_at = now()
			WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id, name, req.Description, req.IsMandatory, req.AllowMultiple)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "tag_category.update", TargetType: "tag_category", TargetID: id.String(),
			Metadata: map[string]any{"is_mandatory": req.IsMandatory, "allow_multiple": req.AllowMultiple}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) deleteTagCategory(w http.ResponseWriter, r *http.Request) {
	s.deleteTaxonomy(w, r, "tag_categories", "tag_category")
}

func (s *Service) deleteTag(w http.ResponseWriter, r *http.Request) {
	s.deleteTaxonomy(w, r, "tags", "tag")
}

// deleteTaxonomy removes a category (with its tags) or a tag; repository
// tag links are removed by cascade.
func (s *Service) deleteTaxonomy(w http.ResponseWriter, r *http.Request, table, kind string) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermReposManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var name string
		// table is one of two constants, never user input.
		if err := tx.QueryRow(ctx, `DELETE FROM `+table+` WHERE organization_id = $1 AND id = $2 RETURNING name`, p.OrganizationID, id).Scan(&name); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: kind + ".delete", TargetType: kind, TargetID: id.String(), Metadata: map[string]any{"name": name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type tagRequest struct {
	Name  string `json:"name"`
	Color string `json:"color"`
}

func (s *Service) createTag(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermReposManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	catID, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req tagRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 || strings.ContainsAny(req.Name, ":;") {
		s.fail(w, r, httpx.BadRequest("name must be 1-100 characters without ':' or ';'"))
		return
	}
	if req.Color == "" {
		req.Color = "slate"
	}
	if !slices.Contains(tagColors, req.Color) {
		s.fail(w, r, httpx.BadRequest("color must be one of "+strings.Join(tagColors, ", ")))
		return
	}
	id := uuid.Must(uuid.NewV7())
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO tags (id, organization_id, category_id, name, color) VALUES ($1, $2, $3, $4, $5)`,
			id, p.OrganizationID, catID, req.Name, req.Color); err != nil {
			if db.IsForeignKeyViolation(err) {
				return errNotFound
			}
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "tag.create", TargetType: "tag", TargetID: id.String(), Metadata: map[string]any{"name": req.Name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, Tag{ID: id, Name: req.Name, Color: req.Color})
}
