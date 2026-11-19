package repos

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
	"pathos/internal/secrets"
)

func (s *Service) registerOAuth(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/scm-providers", s.listProviders)
	mux.HandleFunc("GET /api/v1/scm-oauth-apps", s.listOAuthApps)
	mux.HandleFunc("POST /api/v1/scm-oauth-apps", s.createOAuthApp)
	mux.HandleFunc("PATCH /api/v1/scm-oauth-apps/{id}", s.updateOAuthApp)
	mux.HandleFunc("DELETE /api/v1/scm-oauth-apps/{id}", s.deleteOAuthApp)
	mux.HandleFunc("POST /api/v1/scm-connections/oauth/start", s.startOAuth)
	mux.HandleFunc("GET /api/v1/scm-oauth/callback", s.oauthCallback)
}

// oauthStateTTL bounds the time between consent start and callback.
const oauthStateTTL = 10 * time.Minute

func (s *Service) redirectURI() string { return s.PublicURL + "/api/v1/scm-oauth/callback" }

// accountFrom extracts the identity from a Check message.
func accountFrom(msg string) string {
	for _, p := range []string{"authenticated as ", "connected as ", "connected to "} {
		if i := strings.Index(strings.ToLower(msg), p); i >= 0 {
			return strings.TrimSpace(msg[i+len(p):])
		}
	}
	return msg
}

func (s *Service) listProviders(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermReposRead) && !p.HasOrgWide(authz.PermSCMManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	items := scm.Providers()
	if s.connectorsOn(r.Context(), p.OrganizationID) {
		items = scm.ConnectorCatalog()
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

// OAuthAppView is the API form of an OAuth application (no secret).
type OAuthAppView struct {
	ID              uuid.UUID `json:"id"`
	Provider        string    `json:"provider"`
	Name            string    `json:"name"`
	BaseURL         string    `json:"base_url"`
	TenantID        string    `json:"tenant_id"`
	ClientID        string    `json:"client_id"`
	Scopes          string    `json:"scopes"`
	RedirectURI     string    `json:"redirect_uri"`
	ConnectionCount int       `json:"connection_count"`
	CreatedAt       time.Time `json:"created_at"`
	secretID        uuid.UUID
}

const oauthAppCols = `a.id, a.provider, a.name, a.base_url, a.tenant_id, a.client_id, a.scopes, a.created_at, a.secret_id,
	(SELECT count(*) FROM scm_connections c WHERE c.oauth_app_id = a.id AND c.archived_at IS NULL)`

func (s *Service) scanOAuthApp(row pgx.Row) (OAuthAppView, error) {
	var a OAuthAppView
	err := row.Scan(&a.ID, &a.Provider, &a.Name, &a.BaseURL, &a.TenantID, &a.ClientID, &a.Scopes, &a.CreatedAt, &a.secretID, &a.ConnectionCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, errNotFound
	}
	a.RedirectURI = s.redirectURI()
	return a, err
}

func (s *Service) getOAuthAppView(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (OAuthAppView, error) {
	return s.scanOAuthApp(q.QueryRow(ctx, `SELECT `+oauthAppCols+` FROM scm_oauth_apps a
		WHERE a.organization_id = $1 AND a.id = $2 AND a.archived_at IS NULL`, orgID, id))
}

// oauthApp loads an application including its decrypted client secret.
func (s *Service) oauthApp(ctx context.Context, q db.Querier, orgID, id uuid.UUID) (*scm.OAuthApp, error) {
	// Archived apps still serve existing connections until they are
	// reconnected elsewhere, so no archived_at filter here.
	var a OAuthAppView
	err := q.QueryRow(ctx, `SELECT a.provider, a.base_url, a.tenant_id, a.client_id, a.scopes, a.secret_id
		FROM scm_oauth_apps a WHERE a.organization_id = $1 AND a.id = $2`, orgID, id).
		Scan(&a.Provider, &a.BaseURL, &a.TenantID, &a.ClientID, &a.Scopes, &a.secretID)
	if err != nil {
		return nil, err
	}
	secret, err := s.Secrets.Reveal(ctx, q, orgID, a.secretID, secrets.KindSCM)
	if err != nil {
		return nil, err
	}
	return &scm.OAuthApp{Provider: a.Provider, BaseURL: a.BaseURL, TenantID: a.TenantID, ClientID: a.ClientID,
		ClientSecret: secret, Scopes: a.Scopes}, nil
}

func (s *Service) listOAuthApps(w http.ResponseWriter, r *http.Request) {
	p, err := s.requireOrg(r, authz.PermSCMManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT `+oauthAppCols+` FROM scm_oauth_apps a
		WHERE a.organization_id = $1 AND a.archived_at IS NULL ORDER BY lower(a.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	apps, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (OAuthAppView, error) { return s.scanOAuthApp(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if apps == nil {
		apps = []OAuthAppView{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": apps, "redirect_uri": s.redirectURI()})
}

type oauthAppRequest struct {
	Provider     *string `json:"provider"`
	Name         *string `json:"name"`
	BaseURL      *string `json:"base_url"`
	TenantID     *string `json:"tenant_id"`
	ClientID     *string `json:"client_id"`
	ClientSecret *string `json:"client_secret"`
	Scopes       *string `json:"scopes"`
}

var oauthProviders = []string{scm.GitHub, scm.GitHubEnterprise, scm.GitLab, scm.Bitbucket, scm.AzureDevOps}

func (s *Service) validateOAuthApp(provider string, req *oauthAppRequest) error {
	if req.Name != nil {
		if n := str(req.Name); n == "" || len(n) > 200 {
			return httpx.BadRequest("name must be 1-200 characters")
		}
	}
	if req.ClientID != nil {
		if c := str(req.ClientID); c == "" || len(c) > 300 {
			return httpx.BadRequest("client_id must be 1-300 characters")
		}
	}
	if req.ClientSecret != nil && len(str(req.ClientSecret)) > 4000 {
		return httpx.BadRequest("client_secret is too long")
	}
	if req.TenantID != nil {
		t := str(req.TenantID)
		if len(t) > 100 || strings.ContainsAny(t, "/?#@ ") {
			return httpx.BadRequest("tenant_id must be a tenant GUID, domain, 'organizations' or 'common'")
		}
		if t != "" && provider != scm.AzureDevOps {
			return httpx.BadRequest("tenant_id applies to Azure DevOps (Microsoft Entra ID) only")
		}
	}
	if req.Scopes != nil && len(str(req.Scopes)) > 500 {
		return httpx.BadRequest("scopes must be at most 500 characters")
	}
	if req.BaseURL != nil && str(req.BaseURL) != "" {
		if provider != scm.GitHubEnterprise && provider != scm.GitLab {
			return httpx.BadRequest("base_url applies to GitHub Enterprise and self-managed GitLab only")
		}
		u, err := s.Net.ValidateBaseURL(str(req.BaseURL))
		if err != nil {
			return httpx.BadRequest(err.Error())
		}
		b := strings.TrimRight(u.String(), "/")
		req.BaseURL = &b
	}
	return nil
}

func (s *Service) createOAuthApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermSCMManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req oauthAppRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	provider := str(req.Provider)
	if !containsStr(oauthProviders, provider) {
		s.fail(w, r, httpx.BadRequest("provider must be one of "+strings.Join(oauthProviders, ", ")))
		return
	}
	if req.Name == nil || req.ClientID == nil || str(req.ClientSecret) == "" {
		s.fail(w, r, httpx.BadRequest("name, client_id and client_secret are required"))
		return
	}
	if err := s.validateOAuthApp(provider, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if provider == scm.GitHubEnterprise && str(req.BaseURL) == "" {
		s.fail(w, r, httpx.BadRequest("base_url is required for GitHub Enterprise"))
		return
	}
	tenant := str(req.TenantID)
	if provider == scm.AzureDevOps && tenant == "" {
		tenant = "organizations"
	}
	id := uuid.Must(uuid.NewV7())
	var out OAuthAppView
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		secID, err := s.Secrets.Create(ctx, tx, p.OrganizationID, secrets.KindSCM, "oauth-app:"+str(req.Name), []byte(str(req.ClientSecret)), &p.UserID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scm_oauth_apps (id, organization_id, provider, name, base_url, tenant_id, client_id, secret_id, scopes, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			id, p.OrganizationID, provider, str(req.Name), str(req.BaseURL), tenant, str(req.ClientID), secID, str(req.Scopes), p.UserID); err != nil {
			return err
		}
		if out, err = s.getOAuthAppView(ctx, tx, p.OrganizationID, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_oauth_app.create", TargetType: "scm_oauth_app", TargetID: id.String(),
			Metadata: map[string]any{"name": out.Name, "provider": provider, "client_id": out.ClientID, "base_url": out.BaseURL}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (s *Service) updateOAuthApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermSCMManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req oauthAppRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Provider != nil {
		s.fail(w, r, httpx.BadRequest("provider cannot be changed"))
		return
	}
	var out OAuthAppView
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		cur, err := s.getOAuthAppView(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if err := s.validateOAuthApp(cur.Provider, &req); err != nil {
			return err
		}
		changed := []string{}
		if str(req.ClientSecret) != "" {
			if err := s.Secrets.Update(ctx, tx, p.OrganizationID, cur.secretID, secrets.KindSCM, []byte(str(req.ClientSecret))); err != nil {
				return err
			}
			changed = append(changed, "client_secret")
		}
		trim := func(v *string) *string {
			if v == nil {
				return nil
			}
			t := strings.TrimSpace(*v)
			return &t
		}
		if _, err := tx.Exec(ctx, `UPDATE scm_oauth_apps SET name = COALESCE($3, name), base_url = COALESCE($4, base_url),
			tenant_id = COALESCE($5, tenant_id), client_id = COALESCE($6, client_id), scopes = COALESCE($7, scopes), updated_at = now()
			WHERE organization_id = $1 AND id = $2`,
			p.OrganizationID, id, trim(req.Name), trim(req.BaseURL), trim(req.TenantID), trim(req.ClientID), trim(req.Scopes)); err != nil {
			return err
		}
		for k, v := range map[string]*string{"name": req.Name, "base_url": req.BaseURL, "tenant_id": req.TenantID, "client_id": req.ClientID, "scopes": req.Scopes} {
			if v != nil {
				changed = append(changed, k)
			}
		}
		if out, err = s.getOAuthAppView(ctx, tx, p.OrganizationID, id); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_oauth_app.update", TargetType: "scm_oauth_app", TargetID: id.String(), Metadata: map[string]any{"changed": changed}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) deleteOAuthApp(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermSCMManage)
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
		cur, err := s.getOAuthAppView(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if cur.ConnectionCount > 0 {
			return httpx.Conflict("delete the connections that use this OAuth application first")
		}
		if _, err := tx.Exec(ctx, `UPDATE scm_oauth_apps SET archived_at = now(), updated_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		if err := s.Secrets.Update(ctx, tx, p.OrganizationID, cur.secretID, secrets.KindSCM, []byte("revoked")); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_oauth_app.delete", TargetType: "scm_oauth_app", TargetID: id.String(), Metadata: map[string]any{"name": cur.Name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type oauthStartRequest struct {
	OAuthAppID   uuid.UUID  `json:"oauth_app_id"`
	Name         string     `json:"name"`
	Owner        string     `json:"owner"`
	ConnectionID *uuid.UUID `json:"connection_id"`
	ReturnTo     string     `json:"return_to"`
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// safeReturnTo accepts same-origin absolute paths only.
func safeReturnTo(v string) string {
	const def = "/admin/scm"
	if v == "" || len(v) > 300 || !strings.HasPrefix(v, "/") || strings.HasPrefix(v, "//") || strings.Contains(v, "\\") {
		return def
	}
	for _, c := range v {
		if c < 0x20 || c == 0x7f {
			return def // browsers drop tabs and newlines: "/\t/evil" would become "//evil"
		}
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "" || u.Host != "" || u.User != nil || strings.HasPrefix(u.Path, "//") {
		return def
	}
	return v
}

func (s *Service) startOAuth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermSCMManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req oauthStartRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	view, err := s.getOAuthAppView(ctx, s.DB, p.OrganizationID, req.OAuthAppID)
	if err != nil {
		s.fail(w, r, httpx.BadRequest("unknown OAuth application"))
		return
	}
	name, owner := strings.TrimSpace(req.Name), strings.TrimSpace(req.Owner)
	if req.ConnectionID != nil {
		c, err := s.getConn(ctx, s.DB, p.OrganizationID, *req.ConnectionID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if c.AuthType != scm.AuthOAuth || c.OAuthAppID == nil || *c.OAuthAppID != view.ID {
			s.fail(w, r, httpx.BadRequest("reconnect must use the OAuth application the connection was created with"))
			return
		}
		name = c.Name
	} else if name == "" || len(name) > 200 || len(owner) > 200 {
		s.fail(w, r, httpx.BadRequest("name is required (max 200 characters)"))
		return
	}
	ex, err := scm.OAuthFor(view.Provider)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	app, err := s.oauthApp(ctx, s.DB, p.OrganizationID, view.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	state, verifier := randomToken(32), randomToken(48)
	challengeSum := sha256.Sum256([]byte(verifier))
	authURL, err := ex.AuthorizeURL(*app, s.redirectURI(), state, base64.RawURLEncoding.EncodeToString(challengeSum[:]))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.DB.Exec(ctx, `DELETE FROM scm_oauth_states WHERE expires_at < now()`); err != nil {
		s.fail(w, r, err)
		return
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO scm_oauth_states (state_sha256, organization_id, user_id, oauth_app_id, pkce_verifier,
		connection_name, owner, connection_id, return_to, expires_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		sha256Hex(state), p.OrganizationID, p.UserID, view.ID, verifier, name, owner, req.ConnectionID, safeReturnTo(req.ReturnTo),
		time.Now().Add(oauthStateTTL)); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"authorize_url": authURL})
}

// oauthCallback completes the authorization-code flow. It is a browser
// navigation, so every outcome is a redirect back into the SPA.
func (s *Service) oauthCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	q := r.URL.Query()
	fail := func(returnTo, msg string) {
		u := safeReturnTo(returnTo)
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		http.Redirect(w, r, u+sep+"oauth=error&message="+url.QueryEscape(truncate(msg, 300)), http.StatusSeeOther)
	}
	state := q.Get("state")
	if state == "" || len(state) > 200 {
		fail("", "missing or invalid state")
		return
	}
	var st struct {
		appID, userID   uuid.UUID
		verifier, name  string
		owner, returnTo string
		connID          *uuid.UUID
	}
	err := s.DB.QueryRow(ctx, `DELETE FROM scm_oauth_states WHERE state_sha256 = $1 AND organization_id = $2 AND expires_at > now()
		RETURNING oauth_app_id, user_id, pkce_verifier, connection_name, owner, return_to, connection_id`,
		sha256Hex(state), p.OrganizationID).Scan(&st.appID, &st.userID, &st.verifier, &st.name, &st.owner, &st.returnTo, &st.connID)
	if err != nil {
		fail("", "the authorization request expired or was already used; start again")
		return
	}
	// The state is bound to the user who started the flow.
	if st.userID != p.UserID || !p.HasOrgWide(authz.PermSCMManage) {
		_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_connection.oauth_callback", Outcome: "denied", TargetType: "scm_oauth_app", TargetID: st.appID.String()})
		fail(st.returnTo, "this authorization was started by another user")
		return
	}
	if e := q.Get("error"); e != "" {
		msg := q.Get("error_description")
		if msg == "" {
			msg = e
		}
		fail(st.returnTo, "the provider declined the authorization: "+msg)
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 2000 {
		fail(st.returnTo, "the provider did not return an authorization code")
		return
	}
	app, err := s.oauthApp(ctx, s.DB, p.OrganizationID, st.appID)
	if err != nil {
		fail(st.returnTo, "the OAuth application no longer exists")
		return
	}
	ex, err := scm.OAuthFor(app.Provider)
	if err != nil {
		fail(st.returnTo, err.Error())
		return
	}
	xctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	tok, err := ex.Exchange(xctx, s.httpClient(), *app, s.redirectURI(), code, st.verifier)
	cancel()
	if err != nil {
		fail(st.returnTo, "token exchange failed: "+err.Error())
		return
	}
	// #nosec G117 -- serialized only to be envelope-encrypted into the secrets store
	secret, _ := json.Marshal(tok)

	var connID uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if st.connID != nil {
			c, err := s.getConn(ctx, tx, p.OrganizationID, *st.connID)
			if err != nil {
				return err
			}
			if err := s.Secrets.Update(ctx, tx, p.OrganizationID, c.secretID, secrets.KindSCM, secret); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE scm_connections SET token_expires_at = $2, status = 'untested', status_message = '', updated_at = now()
				WHERE id = $1`, c.ID, tok.ExpiresAt); err != nil {
				return err
			}
			connID = c.ID
			return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action: "scm_connection.reconnect", TargetType: "scm_connection", TargetID: c.ID.String(), Metadata: map[string]any{"name": c.Name}})
		}
		base := app.BaseURL
		if base == "" {
			if info, ok := providerInfo(app.Provider); ok {
				base = info.DefaultBaseURL
			}
		}
		if base == "" {
			return errors.New("no base URL for provider " + app.Provider)
		}
		connID = uuid.Must(uuid.NewV7())
		secID, err := s.Secrets.Create(ctx, tx, p.OrganizationID, secrets.KindSCM, "scm:"+st.name, secret, &p.UserID)
		if err != nil {
			return err
		}
		whID, err := s.Secrets.Create(ctx, tx, p.OrganizationID, secrets.KindWebhook, "webhook:"+st.name, []byte(randomSecret()), &p.UserID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, owner,
			secret_id, webhook_secret_id, created_by, oauth_app_id, token_expires_at)
			VALUES ($1, $2, $3, $4, $5, 'oauth', $6, $7, $8, $9, $10, $11)`,
			connID, p.OrganizationID, st.name, app.Provider, base, st.owner, secID, whID, p.UserID, st.appID, tok.ExpiresAt); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_connection.create", TargetType: "scm_connection", TargetID: connID.String(),
			Metadata: map[string]any{"name": st.name, "provider": app.Provider, "auth_type": "oauth", "oauth_app_id": st.appID}})
	})
	if err != nil {
		msg := "could not save the connection"
		if db.IsUniqueViolation(err) {
			msg = "a connection with this name already exists"
		}
		fail(st.returnTo, msg)
		return
	}
	if c, err := s.getConn(ctx, s.DB, p.OrganizationID, connID); err == nil {
		s.check(ctx, c)
	}
	u := st.returnTo
	sep := "?"
	if strings.Contains(u, "?") {
		sep = "&"
	}
	http.Redirect(w, r, u+sep+"oauth=success&connection="+connID.String(), http.StatusSeeOther)
}

// tokenStore persists refreshed OAuth tokens. Refreshes are serialized by
// a row lock on the connection, and the stored token is re-read under the
// lock, so concurrent API and jobs processes never spend the same
// (rotating) refresh token twice.
type tokenStore struct {
	s    *Service
	conn Connection
	app  *scm.OAuthApp
	// seen is the access token last handed to the client; a different
	// stored token means another process already refreshed.
	seen string
}

func (t *tokenStore) Current(ctx context.Context) (scm.OAuthToken, error) {
	var tok scm.OAuthToken
	raw, err := t.s.Secrets.Reveal(ctx, t.s.DB, t.conn.orgID, t.conn.secretID, secrets.KindSCM)
	if err != nil {
		return tok, err
	}
	if err = json.Unmarshal(raw, &tok); err == nil {
		t.seen = tok.AccessToken
	}
	return tok, err
}

// RefreshLocked is called by the provider client when the token it holds
// is expired or was rejected. Unless another process refreshed meanwhile,
// it refreshes and persists the new token.
func (t *tokenStore) RefreshLocked(ctx context.Context, refresh func(context.Context, scm.OAuthToken) (scm.OAuthToken, error)) (scm.OAuthToken, error) {
	return t.refresh(ctx, 0, refresh)
}

// refresh runs under the connection row lock. With skew > 0 (proactive
// refresh) it refreshes only tokens expiring within skew; with skew == 0
// (on demand) it refreshes unless the stored token changed since the
// client last saw it.
func (t *tokenStore) refresh(ctx context.Context, skew time.Duration, refresh func(context.Context, scm.OAuthToken) (scm.OAuthToken, error)) (scm.OAuthToken, error) {
	var out scm.OAuthToken
	var refreshErr error
	err := db.InTx(ctx, t.s.DB, func(tx pgx.Tx) error {
		var expires *time.Time
		if err := tx.QueryRow(ctx, `SELECT token_expires_at FROM scm_connections WHERE id = $1 AND archived_at IS NULL FOR UPDATE`,
			t.conn.ID).Scan(&expires); err != nil {
			return err
		}
		raw, err := t.s.Secrets.Reveal(ctx, tx, t.conn.orgID, t.conn.secretID, secrets.KindSCM)
		if err != nil {
			return err
		}
		var cur scm.OAuthToken
		if err := json.Unmarshal(raw, &cur); err != nil {
			return err
		}
		if skew > 0 && !cur.Expired(time.Now(), skew) || skew == 0 && t.seen != "" && cur.AccessToken != t.seen {
			out = cur // still valid, or refreshed concurrently by another process
			t.seen = cur.AccessToken
			return nil
		}
		next, err := refresh(ctx, cur)
		if err != nil {
			refreshErr = err
			return nil
		}
		if next.RefreshToken == "" {
			next.RefreshToken = cur.RefreshToken // providers that do not rotate
		}
		// #nosec G117 -- serialized only to be envelope-encrypted into the secrets store
		b, _ := json.Marshal(next)
		if err := t.s.Secrets.Update(ctx, tx, t.conn.orgID, t.conn.secretID, secrets.KindSCM, b); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE scm_connections SET token_expires_at = $2, updated_at = now() WHERE id = $1`, t.conn.ID, next.ExpiresAt); err != nil {
			return err
		}
		out = next
		t.seen = next.AccessToken
		return nil
	})
	if err != nil {
		return out, err
	}
	if refreshErr != nil {
		if errors.Is(refreshErr, scm.ErrTokenExpired) {
			_, _ = t.s.DB.Exec(context.WithoutCancel(ctx), `UPDATE scm_connections SET status = 'expired', status_message = $2, last_checked_at = now()
				WHERE id = $1`, t.conn.ID, truncate(refreshErr.Error(), 500))
		}
		return out, refreshErr
	}
	return out, nil
}

// RefreshExpiringTokens proactively refreshes OAuth tokens that expire
// within window (jobs role, every few minutes).
func (s *Service) RefreshExpiringTokens(ctx context.Context, window time.Duration) {
	rows, err := s.DB.Query(ctx, `SELECT `+connCols+` FROM scm_connections c
		WHERE c.archived_at IS NULL AND c.auth_type = 'oauth' AND c.status <> 'expired'
		  AND c.token_expires_at IS NOT NULL AND c.token_expires_at < now() + $1::interval`, window.String())
	if err != nil {
		s.Log.Error("token refresh: list connections", "err", err)
		return
	}
	conns, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Connection, error) { return s.scanConn(row) })
	if err != nil {
		s.Log.Error("token refresh: list connections", "err", err)
		return
	}
	for _, c := range conns {
		if c.OAuthAppID == nil {
			continue
		}
		app, err := s.oauthApp(ctx, s.DB, c.orgID, *c.OAuthAppID)
		if err != nil {
			s.Log.Warn("token refresh: load OAuth app", "connection_id", c.ID, "err", err)
			continue
		}
		ex, err := scm.OAuthFor(app.Provider)
		if err != nil {
			continue
		}
		ts := &tokenStore{s: s, conn: c, app: app}
		rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		_, err = ts.refresh(rctx, window, func(ctx context.Context, cur scm.OAuthToken) (scm.OAuthToken, error) {
			if cur.RefreshToken == "" {
				return scm.OAuthToken{}, scm.ErrTokenExpired
			}
			return ex.Refresh(ctx, s.httpClient(), *app, cur)
		})
		cancel()
		if err != nil {
			s.Log.Warn("token refresh failed", "connection_id", c.ID, "err", err)
			continue
		}
		s.Log.Info("OAuth token refreshed", "connection_id", c.ID)
	}
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
