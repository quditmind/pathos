package org

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
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Handlers serves the organization structure API.
type Handlers struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/organization", h.getOrg)
	mux.HandleFunc("GET /api/v1/regions", h.listRegions)
	mux.HandleFunc("GET /api/v1/business-units", h.listBUs)
	mux.HandleFunc("POST /api/v1/business-units", h.createBU)
	mux.HandleFunc("GET /api/v1/audit-logs", h.listAudit)
}

func (h *Handlers) require(r *http.Request, perm authz.Permission) (*authz.Principal, error) {
	p := h.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	// Organization structure is visible to anyone who can read it at any scope:
	// names of regions and BUs are needed to render scoped data.
	if perm == authz.PermOrgRead {
		if !p.HasAnywhere(perm) {
			return nil, httpx.ErrForbidden
		}
		return p, nil
	}
	if err := h.Authz.Require(r.Context(), p, perm, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}); err != nil {
		return nil, httpx.ErrForbidden
	}
	return p, nil
}

type Organization struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *Handlers) getOrg(w http.ResponseWriter, r *http.Request) {
	p := h.Principal(r.Context())
	var o Organization
	err := h.DB.QueryRow(r.Context(), `SELECT id, name, slug, created_at FROM organizations WHERE id = $1`, p.OrganizationID).
		Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt)
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, o)
}

type Country struct {
	ID   uuid.UUID `json:"id"`
	Code string    `json:"code"`
	Name string    `json:"name"`
}

type Region struct {
	ID        uuid.UUID `json:"id"`
	Code      string    `json:"code"`
	Name      string    `json:"name"`
	Countries []Country `json:"countries"`
}

func (h *Handlers) listRegions(w http.ResponseWriter, r *http.Request) {
	p, err := h.require(r, authz.PermOrgRead)
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	rows, err := h.DB.Query(r.Context(), `
		SELECT r.id, r.code, r.name,
		       COALESCE(json_agg(json_build_object('id', c.id, 'code', c.code, 'name', c.name) ORDER BY c.name)
		                FILTER (WHERE c.id IS NOT NULL), '[]')
		FROM regions r LEFT JOIN countries c ON c.region_id = r.id
		WHERE r.organization_id = $1
		GROUP BY r.id ORDER BY r.name`, p.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	regions, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Region, error) {
		var rg Region
		err := row.Scan(&rg.ID, &rg.Code, &rg.Name, &rg.Countries)
		return rg, err
	})
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": regions})
}

type BusinessUnit struct {
	ID          uuid.UUID  `json:"id"`
	ParentID    *uuid.UUID `json:"parent_id"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (h *Handlers) listBUs(w http.ResponseWriter, r *http.Request) {
	p, err := h.require(r, authz.PermOrgRead)
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	rows, err := h.DB.Query(r.Context(), `
		SELECT id, parent_id, name, description, created_at FROM business_units
		WHERE organization_id = $1 AND archived_at IS NULL ORDER BY lower(name)`, p.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	bus, err := pgx.CollectRows(rows, pgx.RowToStructByPos[BusinessUnit])
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	if bus == nil {
		bus = []BusinessUnit{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": bus})
}

type createBURequest struct {
	Name        string     `json:"name"`
	ParentID    *uuid.UUID `json:"parent_id"`
	Description string     `json:"description"`
}

func (h *Handlers) createBU(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := h.require(r, authz.PermOrgManage)
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	var req createBURequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 200 || len(req.Description) > 2000 {
		httpx.WriteError(w, r, h.Log, httpx.BadRequest("name is required (max 200 characters); description max 2000"))
		return
	}
	bu := BusinessUnit{ID: uuid.Must(uuid.NewV7()), ParentID: req.ParentID, Name: req.Name, Description: req.Description}
	err = db.InTx(ctx, h.DB, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO business_units (id, organization_id, parent_id, name, description)
			VALUES ($1, $2, $3, $4, $5) RETURNING created_at`, bu.ID, p.OrganizationID, bu.ParentID, bu.Name, bu.Description).Scan(&bu.CreatedAt)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "business_unit.create", TargetType: "business_unit", TargetID: bu.ID.String(), Metadata: map[string]any{"name": bu.Name}})
	})
	switch {
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("a business unit with this name already exists under the same parent")
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("parent business unit does not exist")
	}
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, bu)
}

func (h *Handlers) listAudit(w http.ResponseWriter, r *http.Request) {
	p, err := h.require(r, authz.PermAuditRead)
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	q := r.URL.Query()
	params := audit.ListParams{OrganizationID: p.OrganizationID, Action: q.Get("action"),
		TargetType: q.Get("target_type"), TargetID: q.Get("target_id"), Limit: 50}
	if a := q.Get("actor_id"); a != "" {
		id, err := uuid.Parse(a)
		if err != nil {
			httpx.WriteError(w, r, h.Log, httpx.BadRequest("invalid actor_id"))
			return
		}
		params.ActorID = &id
	}
	if c := q.Get("cursor"); c != "" {
		ts, idStr, ok := strings.Cut(c, "|")
		t, terr := time.Parse(time.RFC3339Nano, ts)
		id, ierr := uuid.Parse(idStr)
		if !ok || terr != nil || ierr != nil {
			httpx.WriteError(w, r, h.Log, httpx.BadRequest("invalid cursor"))
			return
		}
		params.Before, params.BeforeID = &t, &id
	}
	recs, err := audit.List(r.Context(), h.DB, params)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	if recs == nil {
		recs = []audit.Record{}
	}
	var next *string
	if len(recs) == params.Limit {
		last := recs[len(recs)-1]
		c := last.CreatedAt.Format(time.RFC3339Nano) + "|" + last.ID.String()
		next = &c
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": recs, "next_cursor": next})
}
