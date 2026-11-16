package repos

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

func (s *Service) registerApplications(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/applications", s.listApplications)
	mux.HandleFunc("POST /api/v1/applications", s.createApplication)
	mux.HandleFunc("PATCH /api/v1/applications/{id}", s.updateApplication)
	mux.HandleFunc("POST /api/v1/applications/{id}/archive", s.archiveApplication)
}

// UserRef is a compact user reference.
type UserRef struct {
	ID    uuid.UUID `json:"id"`
	Name  string    `json:"name"`
	Email string    `json:"email"`
}

// Application groups repositories into a business asset.
type Application struct {
	ID            uuid.UUID `json:"id"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	BusinessUnit  *Ref      `json:"business_unit"`
	Owner         *UserRef  `json:"owner"`
	SecurityOwner *UserRef  `json:"security_owner"`
	Criticality   string    `json:"criticality"`
	// ExternalRef is the organization's application identifier (e.g. a CMDB ID).
	ExternalRef     string     `json:"external_ref"`
	RepositoryCount int        `json:"repository_count"`
	ArchivedAt      *time.Time `json:"archived_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

const appSelect = `
	SELECT a.id, a.name, a.description, b.id, b.name,
	       o.id, COALESCE(NULLIF(o.display_name, ''), o.email), o.email,
	       so.id, COALESCE(NULLIF(so.display_name, ''), so.email), so.email,
	       a.criticality, a.external_ref,
	       (SELECT count(*) FROM repositories r WHERE r.application_id = a.id AND r.archived_at IS NULL),
	       a.archived_at, a.created_at
	FROM applications a
	LEFT JOIN business_units b ON b.id = a.business_unit_id
	LEFT JOIN users o ON o.id = a.owner_user_id
	LEFT JOIN users so ON so.id = a.security_owner_user_id`

func userRef(id *uuid.UUID, name, email *string) *UserRef {
	if id == nil {
		return nil
	}
	return &UserRef{ID: *id, Name: *name, Email: *email}
}

func scanApp(row pgx.Row) (Application, error) {
	var a Application
	var buID, oID, soID *uuid.UUID
	var buName, oName, oEmail, soName, soEmail *string
	err := row.Scan(&a.ID, &a.Name, &a.Description, &buID, &buName, &oID, &oName, &oEmail, &soID, &soName, &soEmail,
		&a.Criticality, &a.ExternalRef, &a.RepositoryCount, &a.ArchivedAt, &a.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, errNotFound
	}
	a.BusinessUnit = ref(buID, buName)
	a.Owner, a.SecurityOwner = userRef(oID, oName, oEmail), userRef(soID, soName, soEmail)
	return a, err
}

func (s *Service) getApp(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (Application, error) {
	return scanApp(q.QueryRow(ctx, appSelect+` WHERE a.organization_id = $1 AND a.id = $2`, orgID, id))
}

// listApplications returns applications the caller can see: all with an
// org-wide grant; otherwise those placed in a granted business unit or
// containing a visible repository.
func (s *Service) listApplications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermReposRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	scope, scopeArgs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 3)
	buScope, _ := org.ScopeSQL(authz.Filter{All: f.All, BusinessUnits: f.BusinessUnits}, "NULL::uuid", "a.business_unit_id", "NULL::uuid", 3)
	if f.All {
		buScope = "true"
	} else if len(f.BusinessUnits) == 0 {
		buScope = "false"
	}
	archived := "a.archived_at IS NULL"
	if r.URL.Query().Get("status") == "archived" {
		archived = "a.archived_at IS NOT NULL"
	}
	// buScope reuses scope's placeholders ($3-$5) when present.
	args := append([]any{p.OrganizationID, "%" + escapeLike(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))) + "%"}, scopeArgs...)
	rows, err := s.DB.Query(ctx, appSelect+` WHERE a.organization_id = $1 AND `+archived+` AND lower(a.name) LIKE $2
		AND (`+buScope+` OR EXISTS (SELECT 1 FROM repositories r WHERE r.application_id = a.id AND `+scope+`))
		ORDER BY lower(a.name) LIMIT 500`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	apps, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Application, error) { return scanApp(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if apps == nil {
		apps = []Application{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": apps})
}

type appRequest struct {
	Name            *string `json:"name"`
	Description     *string `json:"description"`
	BusinessUnitID  optUUID `json:"business_unit_id"`
	OwnerUserID     optUUID `json:"owner_user_id"`
	SecurityOwnerID optUUID `json:"security_owner_user_id"`
	Criticality     *string `json:"criticality"`
	ExternalRef     *string `json:"external_ref"`
}

func (req *appRequest) validate(create bool) error {
	if create && (req.Name == nil || strings.TrimSpace(*req.Name) == "") {
		return httpx.BadRequest("name is required")
	}
	if req.Name != nil && (strings.TrimSpace(*req.Name) == "" || len(*req.Name) > 200) {
		return httpx.BadRequest("name must be 1-200 characters")
	}
	if req.Description != nil && len(*req.Description) > 2000 {
		return httpx.BadRequest("description must be at most 2000 characters")
	}
	if req.ExternalRef != nil {
		v := strings.TrimSpace(*req.ExternalRef)
		if len(v) > 100 || strings.ContainsAny(v, "\x00\r\n") {
			return httpx.BadRequest("external_ref must be at most 100 characters")
		}
		req.ExternalRef = &v
	}
	if req.Criticality != nil && !slices.Contains(criticalities, *req.Criticality) {
		return httpx.BadRequest("invalid criticality")
	}
	return nil
}

func (s *Service) appScope(p *authz.Principal, bu *uuid.UUID) authz.Scope {
	if bu != nil {
		return authz.Scope{Type: authz.ScopeBusinessUnit, ID: *bu}
	}
	return s.orgScope(p)
}

func (s *Service) createApplication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req appRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := req.validate(true); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Authz.Require(ctx, p, authz.PermReposManage, s.appScope(p, req.BusinessUnitID.Val)); err != nil {
		if errors.Is(err, org.ErrScopeNotFound) {
			err = httpx.BadRequest("business unit does not exist")
		}
		s.fail(w, r, err)
		return
	}
	crit := "medium"
	if req.Criticality != nil {
		crit = *req.Criticality
	}
	id := uuid.Must(uuid.NewV7())
	var app Application
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO applications (id, organization_id, name, description, business_unit_id,
			owner_user_id, security_owner_user_id, criticality, external_ref) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
			id, p.OrganizationID, strings.TrimSpace(*req.Name), str(req.Description), req.BusinessUnitID.Val,
			req.OwnerUserID.Val, req.SecurityOwnerID.Val, crit, str(req.ExternalRef)); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "application.create", TargetType: "application", TargetID: id.String(), Metadata: map[string]any{"name": *req.Name}}); err != nil {
			return err
		}
		var err error
		app, err = s.getApp(ctx, tx, p.OrganizationID, id)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, app)
}

func (s *Service) loadAppFor(r *http.Request) (*authz.Principal, Application, error) {
	p := s.Principal(r.Context())
	id, err := pathID(r)
	if err != nil {
		return p, Application{}, err
	}
	app, err := s.getApp(r.Context(), s.DB, p.OrganizationID, id)
	if err != nil {
		return p, app, err
	}
	err = s.Authz.Require(r.Context(), p, authz.PermReposManage, s.appScope(p, idOf(app.BusinessUnit)))
	return p, app, err
}

func (s *Service) updateApplication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, app, err := s.loadAppFor(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req appRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := req.validate(false); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.BusinessUnitID.Set {
		if err := s.Authz.Require(ctx, p, authz.PermReposManage, s.appScope(p, req.BusinessUnitID.Val)); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE applications SET
			name = COALESCE($2, name), description = COALESCE($3, description),
			business_unit_id = CASE WHEN $4 THEN $5 ELSE business_unit_id END,
			owner_user_id = CASE WHEN $6 THEN $7 ELSE owner_user_id END,
			security_owner_user_id = CASE WHEN $8 THEN $9 ELSE security_owner_user_id END,
			criticality = COALESCE($10, criticality), external_ref = COALESCE($11, external_ref), updated_at = now()
			WHERE id = $1`, app.ID, req.Name, req.Description,
			req.BusinessUnitID.Set, req.BusinessUnitID.Val, req.OwnerUserID.Set, req.OwnerUserID.Val,
			req.SecurityOwnerID.Set, req.SecurityOwnerID.Val, req.Criticality, req.ExternalRef)
		if err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "application.update", TargetType: "application", TargetID: app.ID.String(), Metadata: map[string]any{"name": app.Name}}); err != nil {
			return err
		}
		app, err = s.getApp(ctx, tx, p.OrganizationID, app.ID)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, app)
}

func (s *Service) archiveApplication(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, app, err := s.loadAppFor(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE repositories SET application_id = NULL, updated_at = now() WHERE application_id = $1`, app.ID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE applications SET archived_at = now(), updated_at = now() WHERE id = $1`, app.ID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "application.archive", TargetType: "application", TargetID: app.ID.String(),
			Metadata: map[string]any{"name": app.Name, "repositories_unlinked": app.RepositoryCount}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
