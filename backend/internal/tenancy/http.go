package tenancy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/identity"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/tenant"
)

// Caller identifies the signed-in person of a browser session.
type Caller struct {
	Subject string
	Email   string
}

// Handlers serves the installation administration API
// (/api/v1/installation/*). Every route requires a browser session (not an API
// token) whose subject is a installation administrator, and multi-tenancy to
// be enabled. The routes manage organizations only; they never return an
// organization's data beyond its name, slug, status and two counts.
type Handlers struct {
	DB  *pgxpool.Pool
	Log *slog.Logger
	// Caller returns the session's person (nil for API tokens and
	// unauthenticated requests).
	Caller func(context.Context) *Caller
	// Seed seeds a new organization's defaults.
	Seed SeedFunc
	// DeleteArtifacts and DeleteSources remove object-storage keys of a
	// deleted organization (nil: nothing stored outside PostgreSQL).
	DeleteArtifacts func(ctx context.Context, keys []string) error
	DeleteSources   func(ctx context.Context, keys []string) error
	// DefaultOrgID is the organization named by PATHOS_ORG_SLUG; it
	// cannot be suspended or deleted.
	DefaultOrgID uuid.UUID
}

func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/installation/organizations", h.list)
	mux.HandleFunc("POST /api/v1/installation/organizations", h.create)
	mux.HandleFunc("POST /api/v1/installation/organizations/{id}/suspend", h.suspend)
	mux.HandleFunc("POST /api/v1/installation/organizations/{id}/resume", h.resume)
	mux.HandleFunc("DELETE /api/v1/installation/organizations/{id}", h.delete)
	mux.HandleFunc("GET /api/v1/installation/admins", h.listAdmins)
	mux.HandleFunc("GET /api/v1/installation/audit-logs", h.listAudit)
}

var errMultiTenantOff = httpx.E(http.StatusNotFound, "multi_tenancy_disabled", "multi-tenancy is not enabled on this installation")

// require authorizes a installation administrator.
func (h *Handlers) require(r *http.Request) (*Caller, error) {
	ctx := r.Context()
	c := h.Caller(ctx)
	if c == nil {
		return nil, httpx.ErrForbidden
	}
	on, err := MultiTenant(ctx, h.DB)
	if err != nil {
		return nil, err
	}
	if !on {
		return nil, errMultiTenantOff
	}
	ok, err := IsInstallationAdmin(ctx, h.DB, c.Subject)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, httpx.ErrForbidden
	}
	return c, nil
}

func (h *Handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		err = httpx.ErrNotFound
	case errors.Is(err, ErrSlugTaken):
		err = httpx.Conflict("an organization with this slug already exists")
	}
	httpx.WriteError(w, r, h.Log, err)
}

func (h *Handlers) audit(r *http.Request, c *Caller, action string, orgID *uuid.UUID, outcome string, md map[string]any) {
	if err := WriteInstallationAudit(r.Context(), h.DB, InstallationAuditEntry{ActorSubject: c.Subject, ActorEmail: c.Email, Action: action,
		OrganizationID: orgID, Outcome: outcome, Metadata: md}); err != nil {
		h.Log.Error("installation audit write failed", "action", action, "err", err)
	}
}

func (h *Handlers) list(w http.ResponseWriter, r *http.Request) {
	if _, err := h.require(r); err != nil {
		h.fail(w, r, err)
		return
	}
	orgs, err := ListOrganizations(r.Context(), h.DB)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": orgs})
}

type createRequest struct {
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	AdminEmail string `json:"admin_email"`
}

func (h *Handlers) create(w http.ResponseWriter, r *http.Request) {
	c, err := h.require(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var req createRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	req.Name, req.Slug = strings.TrimSpace(req.Name), strings.ToLower(strings.TrimSpace(req.Slug))
	if len(req.Name) == 0 || len(req.Name) > 200 {
		h.fail(w, r, httpx.BadRequest("name must be 1 to 200 characters"))
		return
	}
	if !ValidSlug(req.Slug) {
		h.fail(w, r, httpx.BadRequest("slug must be 1 to 63 lowercase letters, digits and hyphens"))
		return
	}
	if req.AdminEmail != "" && (len(req.AdminEmail) > 320 || !strings.Contains(req.AdminEmail, "@")) {
		h.fail(w, r, httpx.BadRequest("admin_email is not a valid email address"))
		return
	}
	o, admin, err := CreateOrganization(r.Context(), h.DB, req.Name, req.Slug, req.AdminEmail, h.Seed)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	md := map[string]any{"name": o.Name, "slug": o.Slug}
	if admin != nil {
		md["invited_admin"] = admin.Email
		// The organization's own audit log records the invitation too.
		_ = audit.Write(tenant.WithOrg(r.Context(), o.ID), h.DB, audit.Entry{OrganizationID: o.ID, ActorEmail: c.Email,
			Action: "organization.create", TargetType: "organization", TargetID: o.ID.String(),
			Metadata: map[string]any{"by_installation_admin": true, "invited_admin": admin.Email}})
	}
	h.audit(r, c, "organization.create", &o.ID, audit.Success, md)
	resp := map[string]any{"organization": o}
	if admin != nil {
		resp["invited_admin"] = admin
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

type suspendRequest struct {
	Reason string `json:"reason"`
}

func (h *Handlers) target(w http.ResponseWriter, r *http.Request) (*Caller, Organization, bool) {
	c, err := h.require(r)
	if err != nil {
		h.fail(w, r, err)
		return nil, Organization{}, false
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		h.fail(w, r, httpx.ErrNotFound)
		return nil, Organization{}, false
	}
	o, err := GetOrganization(r.Context(), h.DB, id)
	if err != nil {
		h.fail(w, r, err)
		return nil, Organization{}, false
	}
	return c, o, true
}

func (h *Handlers) suspend(w http.ResponseWriter, r *http.Request) {
	c, o, ok := h.target(w, r)
	if !ok {
		return
	}
	var req suspendRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	if len(req.Reason) > 500 {
		h.fail(w, r, httpx.BadRequest("reason must be at most 500 characters"))
		return
	}
	if o.ID == h.DefaultOrgID {
		h.fail(w, r, httpx.E(http.StatusConflict, "default_organization", "the default organization (PATHOS_ORG_SLUG) cannot be suspended"))
		return
	}
	o, err := SetStatus(r.Context(), h.DB, o.ID, StatusSuspended, strings.TrimSpace(req.Reason))
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit(r, c, "organization.suspend", &o.ID, audit.Success, map[string]any{"slug": o.Slug, "reason": o.SuspendedReason})
	httpx.WriteJSON(w, http.StatusOK, o)
}

func (h *Handlers) resume(w http.ResponseWriter, r *http.Request) {
	c, o, ok := h.target(w, r)
	if !ok {
		return
	}
	o, err := SetStatus(r.Context(), h.DB, o.ID, StatusActive, "")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.audit(r, c, "organization.resume", &o.ID, audit.Success, map[string]any{"slug": o.Slug})
	httpx.WriteJSON(w, http.StatusOK, o)
}

type deleteRequest struct {
	ConfirmSlug string `json:"confirm_slug"`
}

func (h *Handlers) delete(w http.ResponseWriter, r *http.Request) {
	c, o, ok := h.target(w, r)
	if !ok {
		return
	}
	var req deleteRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	switch {
	case o.ID == h.DefaultOrgID:
		h.fail(w, r, httpx.E(http.StatusConflict, "default_organization", "the default organization (PATHOS_ORG_SLUG) cannot be deleted"))
		return
	case o.Status != StatusSuspended:
		h.fail(w, r, httpx.E(http.StatusConflict, "not_suspended", "suspend the organization before deleting it"))
		return
	case req.ConfirmSlug != o.Slug:
		h.fail(w, r, httpx.BadRequest("confirm_slug must equal the organization's slug"))
		return
	}
	ctx := r.Context()
	artifacts, sources, err := ObjectKeys(ctx, h.DB, o.ID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	// Objects first: if the deletion of rows then fails, nothing points
	// at missing objects for long (the organization is suspended), and
	// a retry removes the rest.
	objErr := ""
	if h.DeleteArtifacts != nil && len(artifacts) > 0 {
		if err := deleteBatches(ctx, artifacts, h.DeleteArtifacts); err != nil {
			objErr = err.Error()
		}
	}
	if h.DeleteSources != nil && len(sources) > 0 {
		if err := deleteBatches(ctx, sources, h.DeleteSources); err != nil {
			objErr = err.Error()
		}
	}
	if objErr != "" {
		h.Log.Error("organization delete: object storage cleanup failed", "organization_id", o.ID, "err", objErr)
		h.audit(r, c, "organization.delete", &o.ID, audit.Failure, map[string]any{"slug": o.Slug, "stage": "objects"})
		h.fail(w, r, httpx.E(http.StatusBadGateway, "object_storage_error", "stored objects could not be deleted; nothing was removed from the database, try again"))
		return
	}
	n, err := DeleteOrganization(ctx, h.DB, o.ID)
	if err != nil {
		h.audit(r, c, "organization.delete", &o.ID, audit.Failure, map[string]any{"slug": o.Slug, "stage": "rows"})
		h.fail(w, r, err)
		return
	}
	h.audit(r, c, "organization.delete", &o.ID, audit.Success, map[string]any{"slug": o.Slug, "name": o.Name, "rows": n,
		"objects": len(artifacts) + len(sources)})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"deleted": true, "rows": n, "objects": len(artifacts) + len(sources)})
}

func deleteBatches(ctx context.Context, keys []string, del func(context.Context, []string) error) error {
	for i := 0; i < len(keys); i += 500 {
		if err := del(ctx, keys[i:min(i+500, len(keys))]); err != nil {
			return err
		}
	}
	return nil
}

func (h *Handlers) listAdmins(w http.ResponseWriter, r *http.Request) {
	if _, err := h.require(r); err != nil {
		h.fail(w, r, err)
		return
	}
	admins, err := ListInstallationAdmins(r.Context(), h.DB)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": admins})
}

func (h *Handlers) listAudit(w http.ResponseWriter, r *http.Request) {
	if _, err := h.require(r); err != nil {
		h.fail(w, r, err)
		return
	}
	items, err := ListInstallationAudit(r.Context(), h.DB, 200)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// --- memberships of the signed-in person -----------------------------------

// MembershipsResponse is GET /api/v1/me/organizations.
type MembershipsResponse struct {
	MultiTenant       bool         `json:"multi_tenant"`
	InstallationAdmin bool         `json:"installation_admin"`
	Active            uuid.UUID    `json:"active_organization_id"`
	Items             []Membership `json:"items"`
}

// MyMemberships lists the organizations subject can switch to (active
// organizations where the membership is active).
func MyMemberships(ctx context.Context, q db.Querier, subject string, active uuid.UUID) (MembershipsResponse, error) {
	resp := MembershipsResponse{Active: active, Items: []Membership{}}
	var err error
	if resp.MultiTenant, err = MultiTenant(ctx, q); err != nil {
		return resp, err
	}
	ms, err := Memberships(ctx, q, subject)
	if err != nil {
		return resp, err
	}
	for _, m := range ms {
		if m.UserStatus == identity.StatusActive && (m.Status == StatusActive || m.OrganizationID == active) {
			resp.Items = append(resp.Items, m)
		}
	}
	if resp.MultiTenant {
		if resp.InstallationAdmin, err = IsInstallationAdmin(ctx, q, subject); err != nil {
			return resp, err
		}
	}
	return resp, nil
}
