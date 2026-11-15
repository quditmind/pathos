package repos

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
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
	switch req.Provider {
	case scm.GitHub, scm.GitHubEnterprise, scm.AzureDevOps, scm.AzureDevOpsServer:
	default:
		s.fail(w, r, httpx.BadRequest("provider must be github, github_enterprise, azure_devops or azure_devops_server"))
		return
	}
	base := str(req.BaseURL)
	if base == "" {
		base = scm.DefaultBaseURL(req.Provider, owner)
	}
	if base == "" {
		s.fail(w, r, httpx.BadRequest("base_url is required for this provider (Azure DevOps Services: set owner to the organization name)"))
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

	var secret []byte
	switch req.AuthType {
	case "pat":
		if str(req.Token) == "" {
			s.fail(w, r, httpx.BadRequest("token is required"))
			return
		}
		secret = []byte(str(req.Token))
	case "github_app":
		if req.Provider != scm.GitHub && req.Provider != scm.GitHubEnterprise {
			s.fail(w, r, httpx.BadRequest("GitHub App authentication is only available for GitHub"))
			return
		}
		if req.AppID == nil || req.InstallationID == nil || *req.AppID <= 0 || *req.InstallationID <= 0 {
			s.fail(w, r, httpx.BadRequest("github_app_id and github_installation_id are required"))
			return
		}
		if _, err := scm.ParseRSAPrivateKey([]byte(str(req.PrivateKey))); err != nil {
			s.fail(w, r, httpx.BadRequest(err.Error()))
			return
		}
		secret = []byte(str(req.PrivateKey))
	default:
		s.fail(w, r, httpx.BadRequest("auth_type must be pat or github_app"))
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
			  github_app_id, github_installation_id, secret_id, webhook_secret_id, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
			id, p.OrganizationID, name, req.Provider, base, req.AuthType, owner, req.AppID, req.InstallationID, secID, whID, p.UserID); err != nil {
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
	_, _ = s.DB.Exec(ctx, `UPDATE scm_connections SET status = $2, status_message = $3, last_checked_at = $4, updated_at = now() WHERE id = $1`,
		c.ID, status, msg, now)
	c.Status, c.StatusMessage, c.LastCheckedAt = status, msg, &now
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
		var newSecret []byte
		switch {
		case req.Token != nil && cur.AuthType == "pat":
			newSecret = []byte(str(req.Token))
		case req.PrivateKey != nil && cur.AuthType == "github_app":
			if _, err := scm.ParseRSAPrivateKey([]byte(str(req.PrivateKey))); err != nil {
				return httpx.BadRequest(err.Error())
			}
			newSecret = []byte(str(req.PrivateKey))
		case req.Token != nil || req.PrivateKey != nil:
			return httpx.BadRequest("credential type does not match the connection's auth_type")
		}
		if len(newSecret) > 0 {
			if err := s.Secrets.Update(ctx, tx, p.OrganizationID, cur.secretID, secrets.KindSCM, newSecret); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE scm_connections SET status = 'untested', status_message = '' WHERE id = $1`, id); err != nil {
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
		if _, err := tx.Exec(ctx, `UPDATE scm_connections SET archived_at = now(), updated_at = now() WHERE id = $1`, id); err != nil {
			return err
		}
		if err := s.Secrets.Update(ctx, tx, p.OrganizationID, c.secretID, secrets.KindSCM, []byte("revoked")); err != nil {
			return err
		}
		if err := s.Secrets.Update(ctx, tx, p.OrganizationID, c.webhookSecretID, secrets.KindWebhook, []byte("revoked")); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "scm_connection.delete", TargetType: "scm_connection", TargetID: id.String(), Metadata: map[string]any{"name": c.Name}})
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
