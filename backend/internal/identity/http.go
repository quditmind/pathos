package identity

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/mail"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// SessionRevoker ends all sessions of a user.
type SessionRevoker interface {
	RevokeUser(ctx context.Context, userID uuid.UUID) (int, error)
}

// Handlers serves the user, role and role-assignment API.
type Handlers struct {
	DB          *pgxpool.Pool
	Authz       *authz.Authorizer
	Sessions    SessionRevoker
	Provisioner Provisioner // optional
	Log         *slog.Logger
	Principal   func(context.Context) *authz.Principal
	CSRFToken   func(context.Context) string
}

// Register mounts the routes on mux. All routes require authentication,
// which the caller enforces.
func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/me", h.me)
	mux.HandleFunc("GET /api/v1/users", h.listUsers)
	mux.HandleFunc("POST /api/v1/users", h.createUser)
	mux.HandleFunc("GET /api/v1/users/{id}", h.getUser)
	mux.HandleFunc("POST /api/v1/users/{id}/deactivate", h.deactivate)
	mux.HandleFunc("POST /api/v1/users/{id}/reactivate", h.reactivate)
	mux.HandleFunc("GET /api/v1/users/{id}/mfa", h.mfaStatus)
	mux.HandleFunc("POST /api/v1/users/{id}/require-mfa", h.requireMFA)
	mux.HandleFunc("POST /api/v1/users/{id}/recovery-codes", h.requireRecoveryCodes)
	mux.HandleFunc("GET /api/v1/me/mfa", h.myMFA)
	mux.HandleFunc("POST /api/v1/me/recovery-codes", h.myRecoveryCodes)
	mux.HandleFunc("GET /api/v1/users/{id}/role-assignments", h.listAssignments)
	mux.HandleFunc("POST /api/v1/users/{id}/role-assignments", h.createAssignment)
	mux.HandleFunc("DELETE /api/v1/role-assignments/{id}", h.deleteAssignment)
	mux.HandleFunc("GET /api/v1/roles", h.listRoles)
	mux.HandleFunc("GET /api/v1/permissions", h.listPermissions)
}

func (h *Handlers) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		p := h.Principal(r.Context())
		if p != nil {
			_ = audit.Write(r.Context(), h.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action: "authz.denied", Outcome: audit.Denied, Metadata: map[string]any{"method": r.Method, "path": r.URL.Path}})
		}
		err = httpx.ErrForbidden
	case errors.Is(err, ErrNotFound):
		err = httpx.ErrNotFound
	case errors.Is(err, ErrConflict):
		err = httpx.Conflict(strings.TrimPrefix(err.Error(), "conflict: "))
	}
	httpx.WriteError(w, r, h.Log, err)
}

func (h *Handlers) orgScope(p *authz.Principal) authz.Scope {
	return authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}
}

func (h *Handlers) require(r *http.Request, perm authz.Permission) (*authz.Principal, error) {
	p := h.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	if err := h.Authz.Require(r.Context(), p, perm, h.orgScope(p)); err != nil {
		return nil, err
	}
	return p, nil
}

func pathUUID(r *http.Request, name string) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue(name))
	if err != nil {
		return uuid.Nil, httpx.ErrNotFound
	}
	return id, nil
}

// --- me -------------------------------------------------------------------

type meResponse struct {
	User        User               `json:"user"`
	Permissions []authz.Permission `json:"permissions"`
	// OrgWide lists permissions held at organization scope (for UI decisions).
	OrgWide     []authz.Permission `json:"org_wide_permissions"`
	Assignments []Assignment       `json:"role_assignments"`
	CSRFToken   string             `json:"csrf_token"`
}

func (h *Handlers) me(w http.ResponseWriter, r *http.Request) {
	p := h.Principal(r.Context())
	u, err := GetUser(r.Context(), h.DB, p.OrganizationID, p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	as, err := ListAssignments(r.Context(), h.DB, p.OrganizationID, p.UserID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var orgWide []authz.Permission
	for _, perm := range p.EffectivePermissions() {
		if p.HasOrgWide(perm) {
			orgWide = append(orgWide, perm)
		}
	}
	resp := meResponse{User: u, Permissions: p.EffectivePermissions(), OrgWide: orgWide, Assignments: as}
	if h.CSRFToken != nil {
		resp.CSRFToken = h.CSRFToken(r.Context())
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

// --- users ----------------------------------------------------------------

type listUsersResponse struct {
	Items      []User  `json:"items"`
	NextCursor *string `json:"next_cursor"`
}

func (h *Handlers) listUsers(w http.ResponseWriter, r *http.Request) {
	p, err := h.require(r, authz.PermUsersRead)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	params := ListParams{Query: strings.TrimSpace(q.Get("q")), Status: q.Get("status")}
	if params.Status != "" && params.Status != StatusInvited && params.Status != StatusActive && params.Status != StatusDeactivated {
		h.fail(w, r, httpx.BadRequest("status must be invited, active or deactivated"))
		return
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 200 {
			h.fail(w, r, httpx.BadRequest("limit must be between 1 and 200"))
			return
		}
		params.Limit = n
	}
	if params.Limit == 0 {
		params.Limit = 50
	}
	if c := q.Get("cursor"); c != "" {
		// Cursor is "<email>|<id>" of the last row.
		i := strings.LastIndexByte(c, '|')
		id, err := uuid.Parse(c[i+1:])
		if i < 0 || err != nil {
			h.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		params.AfterKey, params.AfterID = c[:i], &id
	}
	users, err := ListUsers(r.Context(), h.DB, p.OrganizationID, params)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	resp := listUsersResponse{Items: users}
	if resp.Items == nil {
		resp.Items = []User{}
	}
	if len(users) == params.Limit {
		last := users[len(users)-1]
		c := last.Email + "|" + last.ID.String()
		resp.NextCursor = &c
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func (h *Handlers) getUser(w http.ResponseWriter, r *http.Request) {
	p, err := h.require(r, authz.PermUsersRead)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	u, err := GetUser(r.Context(), h.DB, p.OrganizationID, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

type roleRequest struct {
	RoleKey   string          `json:"role_key"`
	ScopeType authz.ScopeType `json:"scope_type"`
	ScopeID   *uuid.UUID      `json:"scope_id"`
}

type createUserRequest struct {
	Email       string        `json:"email"`
	DisplayName string        `json:"display_name"`
	Roles       []roleRequest `json:"roles"`
}

type createUserResponse struct {
	User        User         `json:"user"`
	Assignments []Assignment `json:"role_assignments"`
	// Provisioning reports what happened in the identity provider.
	Provisioning provisioningResult `json:"provisioning"`
}

type provisioningResult struct {
	Status  string `json:"status"` // created | linked_existing | skipped | failed
	Message string `json:"message,omitempty"`
}

func validEmail(e string) bool {
	a, err := mail.ParseAddress(e)
	return err == nil && a.Address == e && len(e) <= 254
}

func (h *Handlers) createUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := h.require(r, authz.PermUsersManage)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	var req createUserRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.DisplayName = strings.TrimSpace(req.DisplayName)
	if !validEmail(req.Email) {
		h.fail(w, r, httpx.BadRequest("a valid email address is required"))
		return
	}
	if len(req.DisplayName) > 200 {
		h.fail(w, r, httpx.BadRequest("display_name must be at most 200 characters"))
		return
	}
	if len(req.Roles) > 20 {
		h.fail(w, r, httpx.BadRequest("at most 20 role assignments per request"))
		return
	}

	var resp createUserResponse
	err = db.InTx(ctx, h.DB, func(tx pgx.Tx) error {
		u, err := CreateUser(ctx, tx, User{OrganizationID: p.OrganizationID, Email: req.Email, DisplayName: req.DisplayName})
		if err != nil {
			return err
		}
		resp.User = u
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "user.invite", TargetType: "user", TargetID: u.ID.String(), Metadata: map[string]any{"email": u.Email}}); err != nil {
			return err
		}
		for _, rr := range req.Roles {
			a, err := h.grant(ctx, tx, p, u.ID, rr)
			if err != nil {
				return err
			}
			resp.Assignments = append(resp.Assignments, a)
		}
		return nil
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if resp.Assignments == nil {
		resp.Assignments = []Assignment{}
	}

	// Provision in the IdP after commit: an IdP failure leaves a valid
	// invited user that can be linked on first login.
	resp.Provisioning = provisioningResult{Status: "skipped", Message: "Keycloak provisioning is not configured; create the account in Keycloak or enable self-registration"}
	if h.Provisioner != nil {
		sub, created, perr := h.Provisioner.EnsureUser(ctx, resp.User.Email, resp.User.DisplayName)
		switch {
		case sub == "":
			resp.Provisioning = provisioningResult{Status: "failed", Message: "identity provider account could not be created"}
			h.Log.Error("keycloak provisioning failed", "err", perr, "user_id", resp.User.ID)
		default:
			if err := SetKeycloakSubject(ctx, h.DB, p.OrganizationID, resp.User.ID, sub); err != nil {
				if db.IsUniqueViolation(err) {
					resp.Provisioning = provisioningResult{Status: "failed", Message: "the Keycloak account is already linked to another PATHOS user"}
				} else {
					h.fail(w, r, err)
					return
				}
				break
			}
			resp.Provisioning.Status = "created"
			resp.Provisioning.Message = "invitation email sent"
			if !created {
				resp.Provisioning = provisioningResult{Status: "linked_existing", Message: "linked to an existing Keycloak account"}
			}
			if perr != nil {
				resp.Provisioning.Message = "account created, but the invitation email could not be sent; check SMTP settings in Keycloak"
				h.Log.Warn("keycloak invitation email failed", "err", perr, "user_id", resp.User.ID)
			}
		}
		_ = audit.Write(ctx, h.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "user.provision", TargetType: "user", TargetID: resp.User.ID.String(),
			Outcome:  map[bool]string{true: audit.Success, false: audit.Failure}[resp.Provisioning.Status != "failed"],
			Metadata: map[string]any{"status": resp.Provisioning.Status}})
	}
	httpx.WriteJSON(w, http.StatusCreated, resp)
}

func (h *Handlers) deactivate(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusDeactivated)
}
func (h *Handlers) reactivate(w http.ResponseWriter, r *http.Request) {
	h.setStatus(w, r, StatusActive)
}

func (h *Handlers) setStatus(w http.ResponseWriter, r *http.Request, status string) {
	ctx := r.Context()
	p, err := h.require(r, authz.PermUsersManage)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if status == StatusDeactivated && id == p.UserID {
		h.fail(w, r, httpx.BadRequest("you cannot deactivate your own account"))
		return
	}
	var u User
	err = db.InTx(ctx, h.DB, func(tx pgx.Tx) error {
		cur, err := GetUserForUpdate(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if status == StatusDeactivated {
			if cur.Status == StatusDeactivated {
				return httpx.Conflict("user is already deactivated")
			}
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('pathos.super_admins'))`); err != nil {
				return err
			}
			n, err := CountActiveOrgSuperAdmins(ctx, tx, p.OrganizationID, &id, nil)
			if err != nil {
				return err
			}
			if n == 0 {
				return httpx.Conflict("cannot deactivate the last active super administrator")
			}
		} else {
			if cur.Status != StatusDeactivated {
				return httpx.Conflict("user is not deactivated")
			}
			// Reactivated users that never logged in return to invited.
			if cur.KeycloakSubject == nil || cur.LastLoginAt == nil {
				status = StatusInvited
			}
		}
		u, err = SetStatus(ctx, tx, p.OrganizationID, id, status)
		if err != nil {
			return err
		}
		action := "user.deactivate"
		if status != StatusDeactivated {
			action = "user.reactivate"
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: action, TargetType: "user", TargetID: id.String(), Metadata: map[string]any{"email": u.Email}})
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if status == StatusDeactivated {
		// Immediate revocation of PATHOS sessions; the IdP account is disabled
		// too so the user cannot start a new login.
		if n, err := h.Sessions.RevokeUser(ctx, id); err != nil {
			h.Log.Error("session revocation failed", "err", err, "user_id", id)
		} else {
			h.Log.Info("sessions revoked", "user_id", id, "count", n)
		}
	}
	if h.Provisioner != nil && u.KeycloakSubject != nil {
		enabled := status != StatusDeactivated
		if err := h.Provisioner.SetEnabled(ctx, *u.KeycloakSubject, enabled); err != nil {
			h.Log.Warn("keycloak enable/disable failed", "err", err, "user_id", id)
		}
		if !enabled {
			_ = h.Provisioner.Logout(ctx, *u.KeycloakSubject)
		}
	}
	httpx.WriteJSON(w, http.StatusOK, u)
}

// --- roles & assignments --------------------------------------------------

func (h *Handlers) listRoles(w http.ResponseWriter, r *http.Request) {
	p, err := h.require(r, authz.PermRolesRead)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	roles, err := ListRoles(r.Context(), h.DB, p.OrganizationID)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": roles})
}

func (h *Handlers) listPermissions(w http.ResponseWriter, r *http.Request) {
	if _, err := h.require(r, authz.PermRolesRead); err != nil {
		h.fail(w, r, err)
		return
	}
	perms, err := ListPermissions(r.Context(), h.DB)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": perms})
}

func (h *Handlers) listAssignments(w http.ResponseWriter, r *http.Request) {
	p, err := h.require(r, authz.PermRolesRead)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if _, err := GetUser(r.Context(), h.DB, p.OrganizationID, id); err != nil {
		h.fail(w, r, err)
		return
	}
	as, err := ListAssignments(r.Context(), h.DB, p.OrganizationID, id)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if as == nil {
		as = []Assignment{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": as})
}

// grant validates and creates one role assignment inside tx.
func (h *Handlers) grant(ctx context.Context, tx pgx.Tx, p *authz.Principal, userID uuid.UUID, rr roleRequest) (Assignment, error) {
	if !rr.ScopeType.Valid() {
		return Assignment{}, httpx.BadRequest("scope_type must be organization, region, business_unit or repository")
	}
	scope := authz.Scope{Type: rr.ScopeType}
	if rr.ScopeType == authz.ScopeOrganization {
		scope.ID = p.OrganizationID
		if rr.ScopeID != nil && *rr.ScopeID != p.OrganizationID {
			return Assignment{}, httpx.BadRequest("scope_id must be the organization id for organization scope")
		}
	} else {
		if rr.ScopeID == nil {
			return Assignment{}, httpx.BadRequest("scope_id is required")
		}
		scope.ID = *rr.ScopeID
	}
	ok, err := org.ScopeExists(ctx, tx, p.OrganizationID, scope)
	if err != nil {
		return Assignment{}, err
	}
	if !ok {
		return Assignment{}, httpx.BadRequest("scope does not exist")
	}
	role, err := GetRoleByKey(ctx, tx, p.OrganizationID, rr.RoleKey)
	if errors.Is(err, ErrNotFound) {
		return Assignment{}, httpx.BadRequest("unknown role " + strconv.Quote(rr.RoleKey))
	}
	if err != nil {
		return Assignment{}, err
	}
	// Org-only roles granted at a narrower scope would silently grant nothing
	// for those permissions; reject super_admin outside organization scope.
	if role.Key == authz.RoleSuperAdmin && scope.Type != authz.ScopeOrganization {
		return Assignment{}, httpx.BadRequest("super_admin can only be granted at organization scope")
	}
	can, err := h.Authz.CanGrantRole(ctx, p, role.Permissions, scope)
	if err != nil {
		return Assignment{}, err
	}
	if !can {
		return Assignment{}, authz.ErrForbidden
	}
	aid, err := CreateAssignment(ctx, tx, p.OrganizationID, userID, role.ID, scope, &p.UserID)
	if err != nil {
		return Assignment{}, err
	}
	if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "role_assignment.create", TargetType: "user", TargetID: userID.String(),
		Metadata: map[string]any{"assignment_id": aid, "role": role.Key, "scope_type": scope.Type, "scope_id": scope.ID}}); err != nil {
		return Assignment{}, err
	}
	return GetAssignment(ctx, tx, p.OrganizationID, aid)
}

func (h *Handlers) createAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := h.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermRolesAssign) {
		h.fail(w, r, authz.ErrForbidden)
		return
	}
	var req roleRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		h.fail(w, r, err)
		return
	}
	var a Assignment
	err = db.InTx(ctx, h.DB, func(tx pgx.Tx) error {
		u, err := GetUserForUpdate(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if u.Status == StatusDeactivated {
			return httpx.Conflict("cannot assign roles to a deactivated user")
		}
		a, err = h.grant(ctx, tx, p, id, req)
		return err
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, a)
}

func (h *Handlers) deleteAssignment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := h.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		h.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, h.DB, func(tx pgx.Tx) error {
		a, err := GetAssignment(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		role, err := GetRoleByKey(ctx, tx, p.OrganizationID, a.RoleKey)
		if err != nil {
			return err
		}
		// Revoking needs the same authority as granting.
		can, err := h.Authz.CanGrantRole(ctx, p, role.Permissions, authz.Scope{Type: a.ScopeType, ID: a.ScopeID})
		if err != nil {
			return err
		}
		if !can {
			return authz.ErrForbidden
		}
		if role.Key == authz.RoleSuperAdmin && a.ScopeType == authz.ScopeOrganization {
			if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('pathos.super_admins'))`); err != nil {
				return err
			}
			n, err := CountActiveOrgSuperAdmins(ctx, tx, p.OrganizationID, nil, &a.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return httpx.Conflict("cannot remove the last active super administrator")
			}
		}
		if err := DeleteAssignment(ctx, tx, p.OrganizationID, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "role_assignment.delete", TargetType: "user", TargetID: a.UserID.String(),
			Metadata: map[string]any{"assignment_id": a.ID, "role": a.RoleKey, "scope_type": a.ScopeType, "scope_id": a.ScopeID}})
	})
	if err != nil {
		h.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// mfaUser loads a user and the MFA manager, or explains why MFA cannot be
// managed (no Keycloak provisioning, or a user not linked to Keycloak yet).
func (h *Handlers) mfaUser(r *http.Request, perm authz.Permission) (*authz.Principal, User, MFAManager, error) {
	p, err := h.require(r, perm)
	if err != nil {
		return nil, User{}, nil, err
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		return nil, User{}, nil, err
	}
	u, err := GetUser(r.Context(), h.DB, p.OrganizationID, id)
	if err != nil {
		return nil, User{}, nil, err
	}
	m, ok := h.Provisioner.(MFAManager)
	if !ok || h.Provisioner == nil {
		return nil, User{}, nil, httpx.E(http.StatusConflict, "mfa_unavailable", "MFA is managed in Keycloak; Keycloak provisioning is not configured")
	}
	if u.KeycloakSubject == nil {
		return nil, User{}, nil, httpx.E(http.StatusConflict, "mfa_unavailable", "this user has no Keycloak account yet")
	}
	return p, u, m, nil
}

func (h *Handlers) mfaStatus(w http.ResponseWriter, r *http.Request) {
	_, u, m, err := h.mfaUser(r, authz.PermUsersRead)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	st, err := m.MFAStatus(r.Context(), *u.KeycloakSubject)
	if err != nil {
		h.Log.Warn("MFA status lookup failed", "user_id", u.ID, "err", err)
		h.fail(w, r, httpx.E(http.StatusBadGateway, "idp_error", "could not read the MFA status from Keycloak"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// requireMFA makes the user enrol an authenticator at the next sign-in.
func (h *Handlers) requireMFA(w http.ResponseWriter, r *http.Request) {
	p, u, m, err := h.mfaUser(r, authz.PermUsersManage)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	changed, err := m.RequireMFA(r.Context(), *u.KeycloakSubject)
	if err != nil {
		h.Log.Warn("require MFA failed", "user_id", u.ID, "err", err)
		h.fail(w, r, httpx.E(http.StatusBadGateway, "idp_error", "could not update the user in Keycloak"))
		return
	}
	_ = audit.Write(r.Context(), h.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "user.require_mfa", TargetType: "user", TargetID: u.ID.String(), Metadata: map[string]any{"changed": changed}})
	st, err := m.MFAStatus(r.Context(), *u.KeycloakSubject)
	if err != nil {
		h.fail(w, r, httpx.E(http.StatusBadGateway, "idp_error", "could not read the MFA status from Keycloak"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"changed": changed, "mfa": st})
}

// requireRecoveryCodes makes a user generate new recovery codes at the next
// sign-in (an administrator helping someone who used or lost theirs).
func (h *Handlers) requireRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	p, u, m, err := h.mfaUser(r, authz.PermUsersManage)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.recoveryCodes(w, r, p, u, m, "user.require_recovery_codes")
}

func (h *Handlers) recoveryCodes(w http.ResponseWriter, r *http.Request, p *authz.Principal, u User, m MFAManager, action string) {
	rc, ok := m.(RecoveryCodeManager)
	if !ok {
		h.fail(w, r, httpx.E(http.StatusConflict, "mfa_unavailable", "the identity provider does not issue recovery codes"))
		return
	}
	changed, err := rc.RequireRecoveryCodes(r.Context(), *u.KeycloakSubject)
	if err != nil {
		h.Log.Warn("require recovery codes failed", "user_id", u.ID, "err", err)
		h.fail(w, r, httpx.E(http.StatusBadGateway, "idp_error", "could not update the user in Keycloak"))
		return
	}
	_ = audit.Write(r.Context(), h.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: action, TargetType: "user", TargetID: u.ID.String(), Metadata: map[string]any{"changed": changed}})
	st, err := m.MFAStatus(r.Context(), *u.KeycloakSubject)
	if err != nil {
		h.fail(w, r, httpx.E(http.StatusBadGateway, "idp_error", "could not read the MFA status from Keycloak"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"changed": changed, "mfa": st})
}

// myUser is the signed-in user's own MFA context (no permission needed).
func (h *Handlers) myUser(r *http.Request) (*authz.Principal, User, MFAManager, error) {
	p := h.Principal(r.Context())
	if p == nil {
		return nil, User{}, nil, authz.ErrForbidden
	}
	u, err := GetUser(r.Context(), h.DB, p.OrganizationID, p.UserID)
	if err != nil {
		return nil, User{}, nil, err
	}
	m, ok := h.Provisioner.(MFAManager)
	if !ok || h.Provisioner == nil {
		return nil, User{}, nil, httpx.E(http.StatusConflict, "mfa_unavailable", "MFA is managed in Keycloak; Keycloak provisioning is not configured")
	}
	if u.KeycloakSubject == nil {
		return nil, User{}, nil, httpx.E(http.StatusConflict, "mfa_unavailable", "your account is not linked to Keycloak")
	}
	return p, u, m, nil
}

func (h *Handlers) myMFA(w http.ResponseWriter, r *http.Request) {
	_, u, m, err := h.myUser(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	st, err := m.MFAStatus(r.Context(), *u.KeycloakSubject)
	if err != nil {
		h.fail(w, r, httpx.E(http.StatusBadGateway, "idp_error", "could not read the MFA status from Keycloak"))
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// myRecoveryCodes lets users generate their own recovery codes; Keycloak
// shows them once, at the next sign-in.
func (h *Handlers) myRecoveryCodes(w http.ResponseWriter, r *http.Request) {
	p, u, m, err := h.myUser(r)
	if err != nil {
		h.fail(w, r, err)
		return
	}
	h.recoveryCodes(w, r, p, u, m, "user.recovery_codes")
}
