package repos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"slices"
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

func (s *Service) registerConnections(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/scm-connections", s.listConnections)
	mux.HandleFunc("POST /api/v1/scm-connections", s.createConnection)
	mux.HandleFunc("GET /api/v1/scm-connections/{id}", s.getConnection)
	mux.HandleFunc("PATCH /api/v1/scm-connections/{id}", s.updateConnection)
	mux.HandleFunc("DELETE /api/v1/scm-connections/{id}", s.deleteConnection)
	mux.HandleFunc("POST /api/v1/scm-connections/{id}/test", s.testConnection)
	mux.HandleFunc("POST /api/v1/scm-connections/{id}/webhook-secret", s.rotateWebhookSecret)
	mux.HandleFunc("GET /api/v1/scm-connections/{id}/discover", s.discover)
	mux.HandleFunc("POST /api/v1/scm-connections/{id}/resync", s.resyncConnection)
	mux.HandleFunc("GET /api/v1/scm-connections/{id}/organizations", s.remoteOrganizations)
	mux.HandleFunc("GET /api/v1/scm-connections/{id}/projects", s.remoteProjects)
	mux.HandleFunc("GET /api/v1/scm-connections/{id}/remote-repositories", s.remoteRepositories)
	mux.HandleFunc("GET /api/v1/scm-connections/{id}/remote-repositories/details", s.remoteRepositoryDetails)
	s.registerOAuth(mux)
}

func pathID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return uuid.Nil, httpx.ErrNotFound
	}
	return id, nil
}

func (s *Service) listConnections(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	// Connection names are needed to render repositories, so anyone who can
	// read repositories can list connections (credentials are never exposed).
	if !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(r.Context(), `SELECT `+connCols+` FROM scm_connections c
		WHERE c.organization_id = $1 AND c.archived_at IS NULL ORDER BY lower(c.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	conns, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Connection, error) { return s.scanConn(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if conns == nil {
		conns = []Connection{}
	}
	if !p.HasOrgWide(authz.PermSCMManage) {
		for i := range conns {
			conns[i].WebhookURL = ""
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": conns})
}

func (s *Service) getConnection(w http.ResponseWriter, r *http.Request) {
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
	c, err := s.getConn(r.Context(), s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

type connectionRequest struct {
	Name           *string `json:"name"`
	Provider       string  `json:"provider"`
	BaseURL        *string `json:"base_url"`
	AuthType       string  `json:"auth_type"`
	Owner          *string `json:"owner"`
	Token          *string `json:"token"`       // PAT
	PrivateKey     *string `json:"private_key"` // GitHub App PEM
	AppID          *int64  `json:"github_app_id"`
	InstallationID *int64  `json:"github_installation_id"`
	// Bitbucket API token: Atlassian account e-mail.
	Username *string `json:"username"`
	// Azure DevOps service principal.
	TenantID       *string `json:"tenant_id"`
	ClientID       *string `json:"client_id"`
	ClientSecret   *string `json:"client_secret"`
	CertificatePEM *string `json:"certificate_pem"`
	PrivateKeyPEM  *string `json:"private_key_pem"`
	// Azure DevOps: organizations to discover (required for service principals).
	Organizations *[]string `json:"organizations"`
}

var orgNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)

func validOrganizations(in []string) ([]string, error) {
	out := []string{}
	for _, o := range in {
		o = strings.TrimSpace(o)
		if o == "" {
			continue
		}
		if !orgNameRe.MatchString(o) {
			return nil, httpx.BadRequest("invalid organization name " + o)
		}
		if !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	if len(out) > 100 {
		return nil, httpx.BadRequest("at most 100 organizations")
	}
	return out, nil
}

// credentialFor builds the stored secret for a non-OAuth auth type from
// the request, validating the method's required fields.
func credentialFor(provider, authType string, req connectionRequest) ([]byte, error) {
	switch authType {
	case scm.AuthPAT:
		if str(req.Token) == "" {
			return nil, httpx.BadRequest("token is required")
		}
		return []byte(str(req.Token)), nil
	case scm.AuthGitHubApp:
		if provider != scm.GitHub && provider != scm.GitHubEnterprise {
			return nil, httpx.BadRequest("GitHub App authentication is only available for GitHub")
		}
		if _, err := scm.ParseRSAPrivateKey([]byte(str(req.PrivateKey))); err != nil {
			return nil, httpx.BadRequest(err.Error())
		}
		return []byte(str(req.PrivateKey)), nil
	case scm.AuthAPIToken:
		if provider != scm.Bitbucket {
			return nil, httpx.BadRequest("API token authentication is only available for Bitbucket")
		}
		if str(req.Username) == "" || str(req.Token) == "" {
			return nil, httpx.BadRequest("username (Atlassian account e-mail) and token are required")
		}
		return json.Marshal(scm.APITokenCredential{Username: str(req.Username), Token: str(req.Token)})
	case scm.AuthServicePrincipal:
		if provider != scm.AzureDevOps {
			return nil, httpx.BadRequest("service principal authentication is only available for Azure DevOps Services")
		}
		sp := scm.ServicePrincipalCredential{TenantID: str(req.TenantID), ClientID: str(req.ClientID),
			ClientSecret: str(req.ClientSecret), CertificatePEM: str(req.CertificatePEM), PrivateKeyPEM: str(req.PrivateKeyPEM)}
		if sp.TenantID == "" || sp.ClientID == "" {
			return nil, httpx.BadRequest("tenant_id and client_id are required")
		}
		if (sp.ClientSecret == "") == (sp.CertificatePEM == "") {
			return nil, httpx.BadRequest("provide either client_secret or certificate_pem with private_key_pem")
		}
		if sp.CertificatePEM != "" && sp.PrivateKeyPEM == "" {
			return nil, httpx.BadRequest("private_key_pem is required with certificate_pem")
		}
		return json.Marshal(sp)
	case scm.AuthOAuth:
		return nil, httpx.BadRequest("OAuth connections are created with POST /api/v1/scm-connections/oauth/start")
	}
	return nil, httpx.BadRequest("auth_type must be pat, github_app, api_token, service_principal or oauth")
}

// providerDefaults returns the catalog entry for a provider.
func providerInfo(provider string) (scm.ProviderInfo, bool) {
	for _, p := range scm.Providers() {
		if p.Key == provider {
			return p, true
		}
	}
	return scm.ProviderInfo{}, false
}

func authMethodAllowed(provider, authType string) bool {
	p, ok := providerInfo(provider)
	if !ok {
		return false
	}
	for _, m := range p.AuthMethods {
		if m.Key == authType {
			return true
		}
	}
	return false
}

func randomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

func (s *Service) createConnection(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.requireOrg(r, authz.PermSCMManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req connectionRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	name, owner := str(req.Name), str(req.Owner)
	if name == "" || len(name) > 200 || len(owner) > 200 {
		s.fail(w, r, httpx.BadRequest("name is required (max 200 characters)"))
		return
	}
	info, ok := providerInfo(req.Provider)
	if !ok {
		s.fail(w, r, httpx.BadRequest("unknown provider"))
		return
	}
	if !authMethodAllowed(req.Provider, req.AuthType) {
		s.fail(w, r, httpx.BadRequest("auth_type "+req.AuthType+" is not available for "+info.Label))
		return
	}
	base := str(req.BaseURL)
	if base == "" {
		base = scm.DefaultBaseURL(req.Provider, owner)
	}
	if base == "" {
		base = info.DefaultBaseURL
	}
	if base == "" {
		s.fail(w, r, httpx.BadRequest("base_url is required for this provider"))
		return
	}
	u, err := s.Net.ValidateBaseURL(base)
	if err != nil {
		s.fail(w, r, httpx.BadRequest(err.Error()))
		return
	}
	base = strings.TrimRight(u.String(), "/")
	if req.Provider == scm.AzureDevOps && owner != "" && strings.HasSuffix(strings.ToLower(base), "/"+strings.ToLower(owner)) {
		owner = "" // owner was the organization, already part of the base URL
	}
	orgs := []string{}
	if req.Organizations != nil {
		if orgs, err = validOrganizations(*req.Organizations); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if req.AuthType == scm.AuthGitHubApp && (req.AppID == nil || req.InstallationID == nil || *req.AppID <= 0 || *req.InstallationID <= 0) {
		s.fail(w, r, httpx.BadRequest("github_app_id and github_installation_id are required"))
		return
	}
	if req.AuthType == scm.AuthServicePrincipal && len(orgs) == 0 && strings.EqualFold(strings.TrimRight(base, "/"), "https://dev.azure.com") {
		s.fail(w, r, httpx.BadRequest("list the Azure DevOps organizations the service principal was added to"))
		return
	}
	secret, err := credentialFor(req.Provider, req.AuthType, req)
	if err != nil {
		s.fail(w, r, err)
		return
	}

	id := uuid.Must(uuid.NewV7())
	var c Connection
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		secID, err := s.Secrets.Create(ctx, tx, p.OrganizationID, secrets.KindSCM, "scm:"+name, secret, &p.UserID)
		if err != nil {
			return err
		}
		whID, err := s.Secrets.Create(ctx, tx, p.OrganizationID, secrets.KindWebhook, "webhook:"+name, []byte(randomSecret()), &p.UserID)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO scm_connections (id, organization_id, name, provider, base_url, auth_type, owner,
			  github_app_id, github_installation_id, secret_id, webhook_secret_id, created_by, organizations)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			id, p.OrganizationID, name, req.Provider, base, req.AuthType, owner, req.AppID, req.InstallationID, secID, whID, p.UserID, orgs); err != nil {
			return err
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_connection.create", TargetType: "scm_connection", TargetID: id.String(),
			Metadata: map[string]any{"name": name, "provider": req.Provider, "base_url": base, "auth_type": req.AuthType}}); err != nil {
			return err
		}
		c, err = s.getConn(ctx, tx, p.OrganizationID, id)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Test right away so the UI can show the result; failures are stored,
	// not fatal.
	c = s.check(ctx, c)
	httpx.WriteJSON(w, http.StatusCreated, c)
}

// check tests a connection and records the outcome.
func (s *Service) check(ctx context.Context, c Connection) Connection {
	status, msg := "ok", ""
	cl, err := s.client(ctx, c)
	if err == nil {
		ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		msg, err = cl.Check(ctx)
		cancel()
	}
	if err != nil {
		status, msg = "error", err.Error()
	}
	now := time.Now()
	if errors.Is(err, scm.ErrTokenExpired) {
		status = "expired"
	}
	account := c.Account
	if status == "ok" {
		account = accountFrom(msg)
	}
	_, _ = s.DB.Exec(ctx, `UPDATE scm_connections SET status = $2, status_message = $3, last_checked_at = $4, account = $5, updated_at = now() WHERE id = $1`,
		c.ID, status, truncate(msg, 500), now, truncate(account, 200))
	c.Status, c.StatusMessage, c.LastCheckedAt, c.Account = status, truncate(msg, 500), &now, truncate(account, 200)
	return c
}

func (s *Service) testConnection(w http.ResponseWriter, r *http.Request) {
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
	c, err := s.getConn(r.Context(), s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, s.check(r.Context(), c))
}

// updateConnection renames, re-scopes or rotates credentials.
func (s *Service) updateConnection(w http.ResponseWriter, r *http.Request) {
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
	var req connectionRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Provider != "" || req.AuthType != "" || req.BaseURL != nil {
		s.fail(w, r, httpx.BadRequest("provider, auth_type and base_url cannot be changed; create a new connection"))
		return
	}
	var c Connection
	changed := []string{}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		cur, err := s.getConn(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if req.Name != nil {
			if n := str(req.Name); n == "" || len(n) > 200 {
				return httpx.BadRequest("name must be 1-200 characters")
			}
			if _, err := tx.Exec(ctx, `UPDATE scm_connections SET name = $2, updated_at = now() WHERE id = $1`, id, str(req.Name)); err != nil {
				return err
			}
			changed = append(changed, "name")
		}
		if req.Owner != nil {
			if _, err := tx.Exec(ctx, `UPDATE scm_connections SET owner = $2, updated_at = now() WHERE id = $1`, id, str(req.Owner)); err != nil {
				return err
			}
			changed = append(changed, "owner")
		}
		if req.Organizations != nil {
			orgs, err := validOrganizations(*req.Organizations)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE scm_connections SET organizations = $2, updated_at = now() WHERE id = $1`, id, orgs); err != nil {
				return err
			}
			changed = append(changed, "organizations")
		}
		var newSecret []byte
		rotating := req.Token != nil || req.PrivateKey != nil || req.Username != nil || req.TenantID != nil ||
			req.ClientID != nil || req.ClientSecret != nil || req.CertificatePEM != nil || req.PrivateKeyPEM != nil
		if rotating {
			if cur.AuthType == scm.AuthOAuth {
				return httpx.BadRequest("OAuth connections are renewed with Reconnect (POST /api/v1/scm-connections/oauth/start with connection_id)")
			}
			if newSecret, err = credentialFor(cur.Provider, cur.AuthType, req); err != nil {
				return err
			}
		}
		if len(newSecret) > 0 {
			if err := s.Secrets.Update(ctx, tx, p.OrganizationID, cur.secretID, secrets.KindSCM, newSecret); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE scm_connections SET status = 'untested', status_message = '', token_expires_at = NULL WHERE id = $1`, id); err != nil {
				return err
			}
			changed = append(changed, "credential")
		}
		if req.AppID != nil || req.InstallationID != nil {
			if cur.AuthType != "github_app" {
				return httpx.BadRequest("app IDs apply only to GitHub App connections")
			}
			if _, err := tx.Exec(ctx, `UPDATE scm_connections SET github_app_id = COALESCE($2, github_app_id),
				github_installation_id = COALESCE($3, github_installation_id), updated_at = now() WHERE id = $1`, id, req.AppID, req.InstallationID); err != nil {
				return err
			}
			changed = append(changed, "github_app")
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_connection.update", TargetType: "scm_connection", TargetID: id.String(),
			Metadata: map[string]any{"changed": changed}}); err != nil {
			return err
		}
		c, err = s.getConn(ctx, tx, p.OrganizationID, id)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (s *Service) deleteConnection(w http.ResponseWriter, r *http.Request) {
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
	revoked := "not_applicable"
	if c, err := s.getConn(ctx, s.DB, p.OrganizationID, id); err == nil && c.RepositoryCount == 0 {
		// Best effort: invalidate OAuth tokens at the provider before the
		// stored credential is destroyed.
		if cl, err := s.client(ctx, c); err == nil {
			rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			if err := cl.Revoke(rctx); err != nil {
				revoked = "failed: " + truncate(err.Error(), 200)
			} else if c.AuthType == scm.AuthOAuth {
				revoked = "revoked"
			}
			cancel()
		}
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		c, err := s.getConn(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if c.RepositoryCount > 0 {
			return httpx.Conflict("archive or delete the connection's repositories first")
		}
		// Keep the row (historical repositories reference it) but destroy
		// the credentials.
		if _, err := tx.Exec(ctx, `UPDATE scm_connections SET archived_at = now(), status = 'revoked', token_expires_at = NULL, updated_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		if err := s.Secrets.Update(ctx, tx, p.OrganizationID, c.secretID, secrets.KindSCM, []byte("revoked")); err != nil {
			return err
		}
		if err := s.Secrets.Update(ctx, tx, p.OrganizationID, c.webhookSecretID, secrets.KindWebhook, []byte("revoked")); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_connection.delete", TargetType: "scm_connection", TargetID: id.String(),
			Metadata: map[string]any{"name": c.Name, "provider": c.Provider, "auth_type": c.AuthType, "provider_revocation": revoked}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// rotateWebhookSecret generates a new webhook secret and returns it once.
func (s *Service) rotateWebhookSecret(w http.ResponseWriter, r *http.Request) {
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
	secret := randomSecret()
	var c Connection
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		c, err = s.getConn(ctx, tx, p.OrganizationID, id)
		if err != nil {
			return err
		}
		if err := s.Secrets.Update(ctx, tx, p.OrganizationID, c.webhookSecretID, secrets.KindWebhook, []byte(secret)); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_connection.rotate_webhook_secret", TargetType: "scm_connection", TargetID: id.String()})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Shown once; configure it in the SCM webhook settings.
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"webhook_url": c.WebhookURL, "webhook_secret": secret})
}

// DiscoveredRepo is a remote repository plus import state.
type DiscoveredRepo struct {
	scm.RemoteRepo
	ImportedID *uuid.UUID `json:"imported_id"`
}

func (s *Service) listRemote(ctx context.Context, c Connection) ([]scm.RemoteRepo, error) {
	cl, err := s.client(ctx, c)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	return cl.ListRepositories(ctx)
}

// discover lists remote repositories with their import state. Requires
// repos.manage somewhere (importers choose placement later).
func (s *Service) discover(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.getConn(ctx, s.DB, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	remote, err := s.listRemote(ctx, c)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT external_id, id FROM repositories WHERE scm_connection_id = $1`, c.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	imported := map[string]uuid.UUID{}
	for rows.Next() {
		var ext string
		var rid uuid.UUID
		if err := rows.Scan(&ext, &rid); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		imported[ext] = rid
	}
	rows.Close()
	out := make([]DiscoveredRepo, 0, len(remote))
	for _, rr := range remote {
		d := DiscoveredRepo{RemoteRepo: rr}
		if rid, ok := imported[rr.ExternalID]; ok {
			d.ImportedID = &rid
		}
		out = append(out, d)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "truncated": len(remote) >= scm.MaxRepositories})
}
