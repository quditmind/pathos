package auth

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"pathos/internal/audit"
	"pathos/internal/identity"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/tenant"
	"pathos/internal/tenancy"
)

// subjectOf returns the signed-in person's OIDC subject: from the
// principal, or (session of a suspended organization) from the session's
// users row.
func (s *Service) subjectOf(ctx context.Context) (string, *Session, error) {
	sess := SessionFrom(ctx)
	if p := PrincipalFrom(ctx); p != nil {
		return p.Subject, sess, nil
	}
	if sess == nil {
		return "", nil, httpx.ErrUnauthenticated
	}
	u, err := identity.GetUser(tenant.WithOrg(ctx, sess.OrgID), s.DB, sess.OrgID, sess.UserID)
	if err != nil {
		return "", nil, httpx.ErrUnauthenticated
	}
	if u.KeycloakSubject == nil {
		return "", sess, nil
	}
	return *u.KeycloakSubject, sess, nil
}

// HandleMyOrganizations serves GET /api/v1/me/organizations: the
// organizations the signed-in person can switch to, the active one, and
// whether they are a installation administrator.
func (s *Service) HandleMyOrganizations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, sess, err := s.subjectOf(ctx)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	active := uuid.Nil
	if p := PrincipalFrom(ctx); p != nil {
		active = p.OrganizationID
	} else if sess != nil {
		active = sess.OrgID
	}
	resp, err := tenancy.MyMemberships(ctx, s.DB, sub, active)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type switchRequest struct {
	OrganizationID uuid.UUID `json:"organization_id"`
}

// HandleSwitchOrganization serves POST /api/v1/me/organization: it starts
// a new session (new cookie and CSRF token) in another organization the
// person belongs to. The target must be an active organization with an
// active membership of the same subject; the old session ends.
func (s *Service) HandleSwitchOrganization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sub, sess, err := s.subjectOf(ctx)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if sess == nil {
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusForbidden, "session_required", "switching organization needs a browser session"))
		return
	}
	var req switchRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if sub == "" {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	ms, err := tenancy.Memberships(ctx, s.DB, sub)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	var target *tenancy.Membership
	for i := range ms {
		m := ms[i]
		if m.OrganizationID == req.OrganizationID && m.Status == tenancy.StatusActive && m.UserStatus == identity.StatusActive {
			target = &m
		}
	}
	if target == nil {
		// Same answer for "does not exist" and "not a member".
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	token, _, err := s.Sessions.Create(ctx, target.UserID, target.OrganizationID, sess.IDToken)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if c, err := r.Cookie(s.SessionCookieName()); err == nil {
		_ = s.Sessions.Delete(ctx, c.Value, sess.UserID)
	}
	s.setSessionCookie(w, token)
	from := sess.OrgID
	_ = audit.Write(tenant.WithOrg(ctx, from), s.DB, audit.Entry{OrganizationID: from, ActorID: &sess.UserID,
		// No target id: one organization's audit log never names another.
		Action: "auth.switch_organization", Metadata: map[string]any{"direction": "out"}})
	_ = audit.Write(tenant.WithOrg(ctx, target.OrganizationID), s.DB, audit.Entry{OrganizationID: target.OrganizationID, ActorID: &target.UserID,
		Action: "auth.switch_organization", TargetType: "organization", TargetID: target.OrganizationID.String(),
		Metadata: map[string]any{"direction": "in"}})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"active_organization_id": target.OrganizationID})
}
