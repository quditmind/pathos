package auth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/platform/config"
	"pathos/internal/platform/db"
	"pathos/internal/platform/diag"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/tenant"
	"pathos/internal/tenancy"
)

// Service wires OIDC login, sessions and request authentication.
type Service struct {
	Cfg      *config.Config
	DB       *pgxpool.Pool
	Sessions *SessionStore
	Log      *slog.Logger
	// OrgID is the default organization (PATHOS_ORG_SLUG): the only one
	// in a single-organization install.
	OrgID uuid.UUID
	// MultiTenant maps logins to organizations from memberships,
	// invitations and the organization claim (docs/MULTI_TENANCY.md).
	MultiTenant bool
	// HTTPClient is used for discovery, JWKS and token calls.
	HTTPClient *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	endSess  string
}

func (s *Service) secureCookies() bool { return s.Cfg.PublicURL.Scheme == "https" }

// SessionCookieName uses the __Host- prefix over HTTPS, which pins the
// cookie to this host, path / and Secure.
func (s *Service) SessionCookieName() string {
	if s.secureCookies() {
		return "__Host-pathos_session"
	}
	return "pathos_session"
}

func (s *Service) flowCookieName() string {
	if s.secureCookies() {
		return "__Host-pathos_oidc"
	}
	return "pathos_oidc"
}

func (s *Service) redirectURL() string { return s.Cfg.PublicURL.String() + "/api/auth/callback" }

// ensureProvider lazily performs OIDC discovery, so the API can start
// before Keycloak is ready.
func (s *Service) ensureProvider(ctx context.Context) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.provider != nil {
		return s.provider, s.verifier, nil
	}
	ctx = s.clientCtx(ctx)
	if s.Cfg.OIDC.DiscoveryURL != s.Cfg.OIDC.Issuer {
		// Discovery happens over the internal network, while tokens carry the
		// public issuer. go-oidc still verifies every token's issuer against
		// Cfg.OIDC.Issuer.
		ctx = oidc.InsecureIssuerURLContext(ctx, s.Cfg.OIDC.Issuer)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, s.Cfg.OIDC.DiscoveryURL)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}
	var extra struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = p.Claims(&extra)
	s.provider = p
	s.verifier = p.Verifier(&oidc.Config{ClientID: s.Cfg.OIDC.ClientID})
	s.endSess = extra.EndSession
	return p, s.verifier, nil
}

func (s *Service) clientCtx(ctx context.Context) context.Context {
	if s.HTTPClient != nil {
		return oidc.ClientContext(ctx, s.HTTPClient)
	}
	return ctx
}

func (s *Service) oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.Cfg.OIDC.ClientID,
		ClientSecret: s.Cfg.OIDC.ClientSecret,
		RedirectURL:  s.redirectURL(),
		Endpoint:     p.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

// SafeReturnTo accepts only same-origin relative paths.
func SafeReturnTo(s string) string {
	if s == "" || !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, `/\`) ||
		strings.ContainsAny(s, "\r\n\t") || strings.HasPrefix(s, "/api/") {
		return "/"
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return s
}

// HandleLogin starts the Authorization Code + PKCE flow.
func (s *Service) HandleLogin(w http.ResponseWriter, r *http.Request) {
	p, _, err := s.ensureProvider(r.Context())
	if err != nil {
		s.Log.Error("login unavailable", "err", err)
		httpx.WriteError(w, r, s.Log, httpx.E(http.StatusServiceUnavailable, "idp_unavailable", "identity provider is not reachable, try again shortly"))
		return
	}
	state, nonce, verifier := RandomToken(32), RandomToken(32), oauth2.GenerateVerifier()
	if err := s.Sessions.putFlow(r.Context(), state, loginFlow{Verifier: verifier, Nonce: nonce, ReturnTo: SafeReturnTo(r.URL.Query().Get("return_to"))}); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	// The flow cookie binds the callback to this browser (login CSRF).
	// #nosec G124 -- HttpOnly and SameSite set; Secure is on except for http development URLs (secureCookies)
	http.SetCookie(w, &http.Cookie{
		Name: s.flowCookieName(), Value: state, Path: "/", MaxAge: 600,
		HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode,
	})
	authURL := s.oauthConfig(p).AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

type idClaims struct {
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	Nonce             string `json:"nonce"`
}

// loginFailed sends the browser back to the login page with the reason
// and its error catalogue code (?error=<reason>&code=PTH-AUTH-…).
func (s *Service) loginFailed(w http.ResponseWriter, r *http.Request, reason string) {
	code := diag.ForLegacy("login:" + reason)
	if code == "" {
		code = diag.Fallback
	}
	s.Log.Warn("sign-in failed", "reason", reason, "request_id", httpx.RequestID(r), "error_code", code)
	http.Redirect(w, r, s.Cfg.PublicURL.String()+"/login?error="+url.QueryEscape(reason)+"&code="+url.QueryEscape(code), http.StatusFound)
}

// HandleCallback completes the login, provisions the user and creates the
// session.
func (s *Service) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	// #nosec G124 -- HttpOnly and SameSite set; Secure is on except for http development URLs (secureCookies)
	http.SetCookie(w, &http.Cookie{Name: s.flowCookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode})

	if e := q.Get("error"); e != "" {
		s.Log.Warn("idp returned error", "error", e)
		s.loginFailed(w, r, "idp_error")
		return
	}
	state := q.Get("state")
	c, err := r.Cookie(s.flowCookieName())
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(state)) != 1 {
		s.loginFailed(w, r, "invalid_state")
		return
	}
	flow, err := s.Sessions.takeFlow(ctx, state)
	if err != nil {
		s.loginFailed(w, r, "expired")
		return
	}
	p, verifier, err := s.ensureProvider(ctx)
	if err != nil {
		s.loginFailed(w, r, "idp_unavailable")
		return
	}
	tok, err := s.oauthConfig(p).Exchange(s.clientCtx(ctx), q.Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		s.Log.Warn("code exchange failed", "err", err)
		s.loginFailed(w, r, "exchange_failed")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	idt, err := verifier.Verify(ctx, rawID)
	if err != nil {
		s.Log.Warn("id token verification failed", "err", err)
		s.loginFailed(w, r, "invalid_token")
		return
	}
	var cl idClaims
	if err := idt.Claims(&cl); err != nil || subtle.ConstantTimeCompare([]byte(cl.Nonce), []byte(flow.Nonce)) != 1 {
		s.loginFailed(w, r, "invalid_token")
		return
	}
	name := cl.Name
	if name == "" {
		name = cl.PreferredUsername
	}
	li := identity.LoginIdentity{Subject: idt.Subject, Email: cl.Email, EmailVerified: cl.EmailVerified, Name: name}

	var res identity.ProvisionResult
	var activeOrg uuid.UUID
	if s.MultiTenant {
		var raw map[string]any
		_ = idt.Claims(&raw)
		res, activeOrg, err = s.ProvisionMemberships(ctx, li, raw[s.Cfg.OrgClaim])
	} else {
		activeOrg = s.OrgID
		res, err = s.provisionIn(tenant.WithOrg(ctx, s.OrgID), s.OrgID, li, s.Cfg.BootstrapAdminEmail)
	}
	if err != nil {
		reason := "provisioning_failed"
		switch {
		case errors.Is(err, identity.ErrDeactivated):
			reason = "deactivated"
		case errors.Is(err, errNoOrganization):
			reason = "no_organization"
		}
		s.Log.Warn("login rejected", "reason", reason, "err", err)
		_ = audit.Write(tenant.WithOrg(ctx, s.OrgID), s.DB, audit.Entry{OrganizationID: s.OrgID, ActorEmail: strings.ToLower(cl.Email),
			Action: "auth.login", Outcome: audit.Denied, Metadata: map[string]any{"reason": reason}})
		s.loginFailed(w, r, reason)
		return
	}
	if s.MultiTenant && s.Cfg.InstallationAdminEmail != "" && cl.EmailVerified && strings.EqualFold(cl.Email, s.Cfg.InstallationAdminEmail) {
		if granted, err := tenancy.GrantInstallationAdmin(ctx, s.DB, idt.Subject, cl.Email, "PATHOS_INSTALLATION_ADMIN_EMAIL"); err != nil {
			s.Log.Error("installation administrator bootstrap failed", "err", err)
		} else if granted {
			_ = tenancy.WriteInstallationAudit(ctx, s.DB, tenancy.InstallationAuditEntry{ActorSubject: idt.Subject, ActorEmail: strings.ToLower(cl.Email),
				Action: "installation_admin.bootstrap", Metadata: map[string]any{"email": strings.ToLower(cl.Email)}})
		}
	}

	// Rotate: drop any session presented with this request.
	if old, err := r.Cookie(s.SessionCookieName()); err == nil {
		if sess, err := s.Sessions.Get(ctx, old.Value); err == nil {
			_ = s.Sessions.Delete(ctx, old.Value, sess.UserID)
		}
	}
	token, _, err := s.Sessions.Create(ctx, res.User.ID, activeOrg, rawID)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	s.setSessionCookie(w, token)
	http.Redirect(w, r, s.Cfg.PublicURL.String()+flow.ReturnTo, http.StatusFound)
}

var errNoOrganization = errors.New("identity: no active membership in any organization")

// provisionIn provisions (finds, links or JIT-creates) the login in one
// organization and records the login in that organization's audit log.
func (s *Service) provisionIn(ctx context.Context, orgID uuid.UUID, li identity.LoginIdentity, bootstrapEmail string) (identity.ProvisionResult, error) {
	var res identity.ProvisionResult
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		res, err = identity.ProvisionOnLogin(ctx, tx, orgID, li, bootstrapEmail)
		if err != nil {
			return err
		}
		uid := res.User.ID
		md := map[string]any{"jit_created": res.Created, "linked_invite": res.Linked}
		if res.GrantedSuperAdmin {
			md["bootstrap_super_admin"] = true
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: orgID, ActorID: &uid, ActorEmail: res.User.Email,
			Action: "auth.login", TargetType: "user", TargetID: uid.String(), Metadata: md})
	})
	return res, err
}

// ProvisionMemberships maps a login to organizations (multi-tenancy):
//   - organizations where the subject already has a users row;
//   - organizations with a pending invitation for the email, when the IdP
//     verified the email;
//   - active organizations named in the organization claim (JIT
//     membership without roles, like a first login in a single-organization
//     install);
//   - the default organization for the bootstrap and installation
//     administrator emails (verified).
//
// Suspended organizations and deactivated memberships are skipped. The
// session starts in the default organization when the person belongs to
// it, else in the first organization by name. The bootstrap administrator
// email applies to the default organization only.
func (s *Service) ProvisionMemberships(ctx context.Context, li identity.LoginIdentity, claim any) (identity.ProvisionResult, uuid.UUID, error) {
	var none identity.ProvisionResult
	if li.Subject == "" {
		return none, uuid.Nil, errors.New("identity: subject claim is required")
	}
	candidates := map[uuid.UUID]bool{}
	ms, err := tenancy.Memberships(ctx, s.DB, li.Subject)
	if err != nil {
		return none, uuid.Nil, err
	}
	for _, m := range ms {
		if m.Status == tenancy.StatusActive && m.UserStatus != identity.StatusDeactivated {
			candidates[m.OrganizationID] = true
		}
	}
	if li.EmailVerified && li.Email != "" {
		invites, err := tenancy.PendingInvites(ctx, s.DB, li.Email)
		if err != nil {
			return none, uuid.Nil, err
		}
		for _, id := range invites {
			candidates[id] = true
		}
	}
	// The bootstrap administrator and the installation administrator join
	// the default organization at their first verified sign-in, so a fresh
	// multi-tenant install can be administered.
	for _, boot := range []string{s.Cfg.BootstrapAdminEmail, s.Cfg.InstallationAdminEmail} {
		if boot != "" && li.EmailVerified && strings.EqualFold(strings.TrimSpace(li.Email), boot) {
			if o, err := tenancy.GetOrganization(ctx, s.DB, s.OrgID); err == nil && o.Status == tenancy.StatusActive {
				candidates[s.OrgID] = true
			}
		}
	}
	claimed, err := tenancy.OrganizationsBySlug(ctx, s.DB, tenancy.SlugsFromClaim(claim, s.Cfg.OrgGroupPrefix))
	if err != nil {
		return none, uuid.Nil, err
	}
	for _, id := range claimed {
		candidates[id] = true
	}
	// Deterministic order: default organization first, then by id.
	ids := make([]uuid.UUID, 0, len(candidates))
	for id := range candidates {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, func(a, b uuid.UUID) int {
		switch {
		case a == s.OrgID:
			return -1
		case b == s.OrgID:
			return 1
		}
		return strings.Compare(a.String(), b.String())
	})
	var first identity.ProvisionResult
	active := uuid.Nil
	for _, orgID := range ids {
		boot := ""
		if orgID == s.OrgID {
			boot = s.Cfg.BootstrapAdminEmail
		}
		res, err := s.provisionIn(tenant.WithOrg(ctx, orgID), orgID, li, boot)
		if err != nil {
			s.Log.Warn("login: membership skipped", "organization_id", orgID, "err", err)
			continue
		}
		if active == uuid.Nil {
			first, active = res, orgID
		}
	}
	if active == uuid.Nil {
		return none, uuid.Nil, errNoOrganization
	}
	return first, active, nil
}

func (s *Service) setSessionCookie(w http.ResponseWriter, token string) {
	// #nosec G124 -- HttpOnly and SameSite set; Secure is on except for http development URLs (secureCookies)
	http.SetCookie(w, &http.Cookie{
		Name: s.SessionCookieName(), Value: token, Path: "/",
		MaxAge:   int(s.Sessions.AbsoluteTTL.Seconds()),
		HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode,
	})
}

// HandleLogout ends the PATHOS session and returns the IdP logout URL the
// browser should navigate to.
func (s *Service) HandleLogout(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sess := SessionFrom(ctx)
	p := PrincipalFrom(ctx)
	c, _ := r.Cookie(s.SessionCookieName())
	if sess != nil && c != nil {
		_ = s.Sessions.Delete(ctx, c.Value, sess.UserID)
	}
	if p != nil {
		_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "auth.logout", TargetType: "user", TargetID: p.UserID.String()})
	}
	// #nosec G124 -- HttpOnly and SameSite set; Secure is on except for http development URLs (secureCookies)
	http.SetCookie(w, &http.Cookie{Name: s.SessionCookieName(), Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode})

	logoutURL := s.Cfg.PublicURL.String() + "/login?logged_out=1"
	if _, _, err := s.ensureProvider(ctx); err == nil && s.endSess != "" {
		v := url.Values{"post_logout_redirect_uri": {logoutURL}, "client_id": {s.Cfg.OIDC.ClientID}}
		if sess != nil && sess.IDToken != "" {
			v.Set("id_token_hint", sess.IDToken)
		}
		logoutURL = s.endSess + "?" + v.Encode()
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"logout_url": logoutURL})
}

type ctxKey int

const (
	principalKey ctxKey = iota
	sessionKey
	suspendedKey
)

var errOrgSuspended = httpx.E(http.StatusForbidden, "organization_suspended",
	"this organization is suspended; switch to another organization or contact your installation administrator")

// PrincipalFrom returns the authenticated principal, or nil.
func PrincipalFrom(ctx context.Context) *authz.Principal {
	p, _ := ctx.Value(principalKey).(*authz.Principal)
	return p
}

// SessionFrom returns the current session, or nil.
func SessionFrom(ctx context.Context) *Session {
	s, _ := ctx.Value(sessionKey).(*Session)
	return s
}

// WithPrincipal stores p in ctx (used by tests and internal callers) and,
// like the authentication middleware, scopes ctx to p's organization.
func WithPrincipal(ctx context.Context, p *authz.Principal) context.Context {
	if p != nil && p.OrganizationID != uuid.Nil {
		ctx = tenant.WithOrg(ctx, p.OrganizationID)
	}
	return context.WithValue(ctx, principalKey, p)
}

// Authenticate loads the session and principal for every request. Requests
// without a valid session continue unauthenticated; RequireAuth rejects them.
// Unsafe methods require a valid CSRF token and a same-origin Origin header.
func (s *Service) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = audit.WithMeta(ctx, audit.Meta{IP: httpx.ClientIP(r), UserAgent: r.UserAgent(), RequestID: httpx.RequestID(r)})
		c, err := r.Cookie(s.SessionCookieName())
		// The REST API accepts personal API tokens; other endpoints that take
		// bearer tokens (the MCP server) authenticate them themselves.
		if err != nil && strings.HasPrefix(r.URL.Path, "/api/") {
			if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
				// Personal API token (no cookie, so no CSRF exposure).
				p, tokenID, terr := s.tokenPrincipal(ctx, strings.TrimSpace(bearer), r)
				if terr != nil {
					httpx.WriteError(w, r, s.Log, terr)
					return
				}
				m := audit.MetaFrom(ctx)
				m.APIToken = tokenID.String()
				ctx = context.WithValue(audit.WithMeta(ctx, m), principalKey, p)
				// Every query of the request is scoped to the token's
				// organization (row-level security).
				ctx = tenant.WithOrg(ctx, p.OrganizationID)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		if err == nil {
			sess, err := s.Sessions.Get(ctx, c.Value)
			switch {
			case err == nil:
				p, perr := s.loadPrincipal(ctx, sess)
				if perr == nil {
					ctx = context.WithValue(ctx, principalKey, p)
					ctx = context.WithValue(ctx, sessionKey, sess)
					// Every query of the request is scoped to the
					// session's active organization (row-level security).
					ctx = tenant.WithOrg(ctx, p.OrganizationID)
				} else if errors.Is(perr, tenancy.ErrSuspended) {
					// The session stays usable for switching to another
					// organization and signing out only.
					ctx = context.WithValue(ctx, sessionKey, sess)
					ctx = context.WithValue(ctx, suspendedKey, true)
				} else if errors.Is(perr, identity.ErrDeactivated) || errors.Is(perr, identity.ErrNotFound) {
					_ = s.Sessions.Delete(ctx, c.Value, sess.UserID)
				} else {
					httpx.WriteError(w, r, s.Log, perr)
					return
				}
			case !errors.Is(err, ErrNoSession):
				httpx.WriteError(w, r, s.Log, err)
				return
			}
		}
		if !safeMethod(r.Method) {
			if err := s.checkCSRF(r, SessionFrom(ctx)); err != nil {
				httpx.WriteError(w, r, s.Log, err)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

func (s *Service) checkCSRF(r *http.Request, sess *Session) error {
	if origin := r.Header.Get("Origin"); origin != "" {
		pub := s.Cfg.PublicURL
		if origin != pub.Scheme+"://"+pub.Host {
			return httpx.ErrCSRF
		}
	}
	if sess == nil {
		// Unauthenticated unsafe requests are rejected by RequireAuth;
		// nothing to protect here.
		return nil
	}
	tok := r.Header.Get("X-CSRF-Token")
	if tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(sess.CSRF)) != 1 {
		return httpx.ErrCSRF
	}
	return nil
}

// loadPrincipal loads the user and grants of a session or token, scoped to
// its organization. A suspended organization yields tenancy.ErrSuspended.
func (s *Service) loadPrincipal(ctx context.Context, sess *Session) (*authz.Principal, error) {
	ctx = tenant.WithOrg(ctx, sess.OrgID)
	var status string
	if err := s.DB.QueryRow(ctx, `SELECT status FROM organizations WHERE id = $1`, sess.OrgID).Scan(&status); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrNotFound
		}
		return nil, err
	}
	if status != tenancy.StatusActive {
		return nil, tenancy.ErrSuspended
	}
	u, err := identity.GetUser(ctx, s.DB, sess.OrgID, sess.UserID)
	if err != nil {
		return nil, err
	}
	if u.Status != identity.StatusActive {
		return nil, identity.ErrDeactivated
	}
	grants, err := identity.LoadGrants(ctx, s.DB, u.ID)
	if err != nil {
		return nil, err
	}
	p := &authz.Principal{UserID: u.ID, OrganizationID: u.OrganizationID, Email: u.Email, DisplayName: u.DisplayName, Grants: grants}
	if u.KeycloakSubject != nil {
		p.Subject = *u.KeycloakSubject
	}
	return p, nil
}

// RequireAuth rejects unauthenticated requests.
func (s *Service) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if PrincipalFrom(r.Context()) == nil {
			if suspended, _ := r.Context().Value(suspendedKey).(bool); suspended {
				httpx.WriteError(w, r, s.Log, errOrgSuspended)
				return
			}
			httpx.WriteError(w, r, s.Log, httpx.ErrUnauthenticated)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Token scopes for the REST API (MCP has its own scope).
const (
	TokenScopeRead  = "api:read"
	TokenScopeWrite = "api:write"
	tokenPrefix     = "pathos_pat_"
)

// tokenDenied lists API areas a token can never use: a token must not be
// able to mint tokens, change sign-in or MFA, or end sessions.
var tokenDenied = []string{"/api/v1/me/tokens", "/api/auth/", "/api/v1/me/recovery-codes", "/api/v1/me/mfa"}

// tokenPrincipal resolves a personal API token. Read tokens allow safe
// methods only. The owner's current role assignments apply, so a token
// never carries more than its owner has; deactivated owners' tokens stop
// working at once.
func (s *Service) tokenPrincipal(ctx context.Context, tok string, r *http.Request) (*authz.Principal, uuid.UUID, error) {
	bad := httpx.E(http.StatusUnauthorized, "invalid_token", "invalid, expired or revoked API token")
	if !strings.HasPrefix(tok, tokenPrefix) || len(tok) > 200 {
		return nil, uuid.Nil, bad
	}
	for _, p := range tokenDenied {
		if strings.HasPrefix(r.URL.Path, p) {
			return nil, uuid.Nil, httpx.E(http.StatusForbidden, "token_not_allowed", "API tokens cannot be used for this endpoint; sign in instead")
		}
	}
	sum := sha256.Sum256([]byte(tok))
	var tokenID, userID, orgID uuid.UUID
	var scopes []string
	// The token's organization is not known yet: look the hash up across
	// organizations (system scope), then load the principal scoped to the
	// token's organization.
	err := s.DB.QueryRow(tenant.WithSystem(ctx), `UPDATE api_tokens SET last_used_at = now()
		WHERE token_sha256 = $1 AND revoked_at IS NULL AND expires_at > now() AND scopes && ARRAY[$2, $3]::text[]
		RETURNING id, user_id, organization_id, scopes`, hex.EncodeToString(sum[:]), TokenScopeRead, TokenScopeWrite).
		Scan(&tokenID, &userID, &orgID, &scopes)
	if err != nil {
		return nil, uuid.Nil, bad
	}
	if !safeMethod(r.Method) && !slices.Contains(scopes, TokenScopeWrite) {
		return nil, uuid.Nil, httpx.E(http.StatusForbidden, "token_read_only", "this API token is read-only")
	}
	p, err := s.loadPrincipal(ctx, &Session{UserID: userID, OrgID: orgID})
	if errors.Is(err, tenancy.ErrSuspended) {
		return nil, uuid.Nil, errOrgSuspended
	}
	if err != nil {
		return nil, uuid.Nil, bad
	}
	return p, tokenID, nil
}
