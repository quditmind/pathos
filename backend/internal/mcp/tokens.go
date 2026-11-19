// Package mcp provides personal API tokens, the PATHOS MCP server
// (interactive AI review with the user's own assistant) and the registry
// of MCP servers approved for use with PATHOS data.
package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/ai"
	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/identity"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/platform/tenant"
)

// Service holds the MCP dependencies.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	AI        *ai.Service
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	PublicURL string
}

// TokenPrefix identifies PATHOS personal access tokens (and lets secret
// scanners recognise leaked ones).
const TokenPrefix = "pathos_pat_"

// ScopeMCP allows use of the MCP endpoint only.
const ScopeMCP = "mcp"

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

// Register mounts the session-authenticated API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/me/tokens", s.listTokens)
	mux.HandleFunc("POST /api/v1/me/tokens", s.createToken)
	mux.HandleFunc("DELETE /api/v1/me/tokens/{id}", s.revokeToken)
	s.registerRegistry(mux)
}

// Token is a personal API token (the secret is shown once at creation).
type Token struct {
	ID         uuid.UUID  `json:"id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	Scopes     []string   `json:"scopes"`
	ExpiresAt  time.Time  `json:"expires_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

func (s *Service) listTokens(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	rows, err := s.DB.Query(r.Context(), `SELECT id, name, prefix, scopes, expires_at, last_used_at, revoked_at, created_at
		FROM api_tokens WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100`, p.UserID)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Token])
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if out == nil {
		out = []Token{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "mcp_url": s.PublicURL + "/mcp"})
}

type tokenRequest struct {
	Name string `json:"name"`
	Days int    `json:"days"`
	// Scopes: "mcp" (default), "api:read" (REST API, read-only),
	// "api:write" (REST API, read and write).
	Scopes []string `json:"scopes"`
}

var validScopes = []string{ScopeMCP, "api:read", "api:write"}

func (s *Service) createToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermFindingsRead) {
		httpx.WriteError(w, r, s.Log, httpx.ErrForbidden)
		return
	}
	var req tokenRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("name is required (max 100 characters)"))
		return
	}
	if req.Days == 0 {
		req.Days = 30
	}
	if req.Days < 1 || req.Days > 90 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("days must be between 1 and 90"))
		return
	}
	if len(req.Scopes) == 0 {
		req.Scopes = []string{ScopeMCP}
	}
	slices.Sort(req.Scopes)
	req.Scopes = slices.Compact(req.Scopes)
	for _, sc := range req.Scopes {
		if !slices.Contains(validScopes, sc) {
			httpx.WriteError(w, r, s.Log, httpx.BadRequest("scopes must be mcp, api:read or api:write"))
			return
		}
	}
	var active int
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()`, p.UserID).Scan(&active)
	if active >= 10 {
		httpx.WriteError(w, r, s.Log, httpx.Conflict("at most 10 active tokens per user; revoke one first"))
		return
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	secret := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	t := Token{ID: uuid.Must(uuid.NewV7()), Name: req.Name, Prefix: secret[:len(TokenPrefix)+6], Scopes: req.Scopes,
		ExpiresAt: time.Now().Add(time.Duration(req.Days) * 24 * time.Hour), CreatedAt: time.Now()}
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO api_tokens (id, organization_id, user_id, name, prefix, token_sha256, scopes, expires_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, t.ID, p.OrganizationID, p.UserID, t.Name, t.Prefix, hashToken(secret), t.Scopes, t.ExpiresAt); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "api_token.create", TargetType: "api_token", TargetID: t.ID.String(), Metadata: map[string]any{"name": t.Name, "days": req.Days, "scopes": t.Scopes}})
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"token": t, "secret": secret, "mcp_url": s.PublicURL + "/mcp", "api_url": s.PublicURL + "/api/v1"})
}

func (s *Service) revokeToken(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE api_tokens SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, id, p.UserID)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpx.ErrNotFound
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "api_token.revoke", TargetType: "api_token", TargetID: id.String()})
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

var errBadToken = errors.New("invalid, expired or revoked token")

// authenticate resolves a bearer token to a principal. The user's current
// role assignments apply (a token never carries more than its owner has),
// and deactivated users' tokens stop working immediately.
func (s *Service) authenticate(ctx context.Context, header string) (*authz.Principal, uuid.UUID, error) {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	tok = strings.TrimSpace(tok)
	if !ok || !strings.HasPrefix(tok, TokenPrefix) || len(tok) > 200 {
		return nil, uuid.Nil, errBadToken
	}
	var tokenID, userID, orgID uuid.UUID
	var orgStatus string
	// The token's organization is not known before the token is: system
	// scope for the hash lookup only; everything after is scoped to the
	// token's organization.
	err := s.DB.QueryRow(tenant.WithSystem(ctx), `UPDATE api_tokens t SET last_used_at = now()
		WHERE token_sha256 = $1 AND revoked_at IS NULL AND expires_at > now() AND $2 = ANY(scopes)
		RETURNING id, user_id, organization_id, (SELECT o.status FROM organizations o WHERE o.id = t.organization_id)`,
		hashToken(tok), ScopeMCP).Scan(&tokenID, &userID, &orgID, &orgStatus)
	if err != nil || orgStatus != "active" {
		return nil, uuid.Nil, errBadToken
	}
	ctx = tenant.WithOrg(ctx, orgID)
	u, err := identity.GetUser(ctx, s.DB, orgID, userID)
	if err != nil || u.Status != identity.StatusActive {
		return nil, uuid.Nil, errBadToken
	}
	grants, err := identity.LoadGrants(ctx, s.DB, userID)
	if err != nil {
		return nil, uuid.Nil, err
	}
	p := &authz.Principal{UserID: u.ID, OrganizationID: orgID, Email: u.Email, DisplayName: u.DisplayName, Grants: grants}
	if u.KeycloakSubject != nil {
		p.Subject = *u.KeycloakSubject
	}
	return p, tokenID, nil
}
