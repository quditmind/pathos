package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
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
	"pathos/internal/platform/httpx"
)

// Service wires OIDC login, sessions and request authentication.
type Service struct {
	Cfg      *config.Config
	DB       *pgxpool.Pool
	Sessions *SessionStore
	Log      *slog.Logger
	OrgID    uuid.UUID
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

func (s *Service) loginFailed(w http.ResponseWriter, r *http.Request, reason string) {
	http.Redirect(w, r, s.Cfg.PublicURL.String()+"/login?error="+url.QueryEscape(reason), http.StatusFound)
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

	var res identity.ProvisionResult
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		res, err = identity.ProvisionOnLogin(ctx, tx, s.OrgID, identity.LoginIdentity{
			Subject: idt.Subject, Email: cl.Email, EmailVerified: cl.EmailVerified, Name: name,
		}, s.Cfg.BootstrapAdminEmail)
		if err != nil {
			return err
		}
		uid := res.User.ID
		md := map[string]any{"jit_created": res.Created, "linked_invite": res.Linked}
		if res.GrantedSuperAdmin {
			md["bootstrap_super_admin"] = true
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: s.OrgID, ActorID: &uid, ActorEmail: res.User.Email,
			Action: "auth.login", TargetType: "user", TargetID: uid.String(), Metadata: md})
	})
	if err != nil {
		reason := "provisioning_failed"
		if errors.Is(err, identity.ErrDeactivated) {
			reason = "deactivated"
		}
		s.Log.Warn("login rejected", "reason", reason, "err", err)
		_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: s.OrgID, ActorEmail: strings.ToLower(cl.Email),
			Action: "auth.login", Outcome: audit.Denied, Metadata: map[string]any{"reason": reason}})
		s.loginFailed(w, r, reason)
		return
	}

	// Rotate: drop any session presented with this request.
	if old, err := r.Cookie(s.SessionCookieName()); err == nil {
		if sess, err := s.Sessions.Get(ctx, old.Value); err == nil {
			_ = s.Sessions.Delete(ctx, old.Value, sess.UserID)
		}
	}
	token, _, err := s.Sessions.Create(ctx, res.User.ID, s.OrgID, rawID)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	s.setSessionCookie(w, token)
	http.Redirect(w, r, s.Cfg.PublicURL.String()+flow.ReturnTo, http.StatusFound)
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
)

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

// WithPrincipal stores p in ctx (used by tests and internal callers).
func WithPrincipal(ctx context.Context, p *authz.Principal) context.Context {
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
		if err == nil {
			sess, err := s.Sessions.Get(ctx, c.Value)
			switch {
			case err == nil:
				p, perr := s.loadPrincipal(ctx, sess)
				if perr == nil {
					ctx = context.WithValue(ctx, principalKey, p)
					ctx = context.WithValue(ctx, sessionKey, sess)
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

func (s *Service) loadPrincipal(ctx context.Context, sess *Session) (*authz.Principal, error) {
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
	return &authz.Principal{UserID: u.ID, OrganizationID: u.OrganizationID, Email: u.Email, DisplayName: u.DisplayName, Grants: grants}, nil
}

// RequireAuth rejects unauthenticated requests.
func (s *Service) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if PrincipalFrom(r.Context()) == nil {
			httpx.WriteError(w, r, s.Log, httpx.ErrUnauthenticated)
			return
		}
		next.ServeHTTP(w, r)
	})
}
