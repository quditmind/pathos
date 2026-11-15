package mcp

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// The registry records which MCP servers may be used with PATHOS data and
// which of their tools are allowed. The built-in PATHOS server is seeded
// approved, with its tools allowed; administrators can disable it or any
// tool. Requests for other servers start as pending.

const builtInName = "PATHOS"

// EnsureBuiltIn seeds the PATHOS MCP server entry.
func EnsureBuiltIn(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID, publicURL string) error {
	return db.InTx(ctx, pool, func(tx pgx.Tx) error {
		var id uuid.UUID
		err := tx.QueryRow(ctx, `SELECT id FROM mcp_servers WHERE organization_id = $1 AND built_in`, orgID).Scan(&id)
		if err == nil {
			return nil
		}
		id = uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO mcp_servers (id, organization_id, name, description, transport, endpoint, status, data_access, built_in, decided_at)
			VALUES ($1, $2, $3, 'Interactive finding review from your own AI assistant (personal API token)', 'streamable_http', $4, 'approved', 'findings_redacted', true, now())`,
			id, orgID, builtInName, strings.TrimRight(publicURL, "/")+"/mcp"); err != nil {
			return err
		}
		for _, t := range []struct{ name, access string }{{"list_pending_findings", "read"}, {"get_finding_evidence", "read"}, {"submit_review", "write"}} {
			if _, err := tx.Exec(ctx, `INSERT INTO mcp_tool_permissions (organization_id, server_id, tool, access, allowed) VALUES ($1, $2, $3, $4, true)`,
				orgID, id, t.name, t.access); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Service) serverEnabled(ctx context.Context, orgID uuid.UUID) bool {
	var ok bool
	_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mcp_servers WHERE organization_id = $1 AND built_in AND status = 'approved')`, orgID).Scan(&ok)
	return ok
}

func (s *Service) allowedTools(ctx context.Context, orgID uuid.UUID) map[string]bool {
	out := map[string]bool{}
	rows, err := s.DB.Query(ctx, `SELECT t.tool FROM mcp_tool_permissions t JOIN mcp_servers m ON m.id = t.server_id
		WHERE m.organization_id = $1 AND m.built_in AND t.allowed`, orgID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		if rows.Scan(&t) == nil {
			out[t] = true
		}
	}
	return out
}

func (s *Service) registerRegistry(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/mcp-servers", s.listServers)
	mux.HandleFunc("POST /api/v1/mcp-servers", s.requestServer)
	mux.HandleFunc("POST /api/v1/mcp-servers/{id}/decision", s.decideServer)
	mux.HandleFunc("PUT /api/v1/mcp-servers/{id}/tools", s.setTools)
	mux.HandleFunc("DELETE /api/v1/mcp-servers/{id}", s.deleteServer)
}

// ToolPermission is one tool's allow-list entry.
type ToolPermission struct {
	Tool    string `json:"tool"`
	Access  string `json:"access"`
	Allowed bool   `json:"allowed"`
}

// Server is a registry entry.
type Server struct {
	ID           uuid.UUID        `json:"id"`
	Name         string           `json:"name"`
	Description  string           `json:"description"`
	Transport    string           `json:"transport"`
	Endpoint     string           `json:"endpoint"`
	Status       string           `json:"status"`
	DataAccess   string           `json:"data_access"`
	BuiltIn      bool             `json:"built_in"`
	RequestedBy  *string          `json:"requested_by"`
	DecidedBy    *string          `json:"decided_by"`
	DecidedAt    *time.Time       `json:"decided_at"`
	DecisionNote string           `json:"decision_note"`
	Tools        []ToolPermission `json:"tools"`
	CreatedAt    time.Time        `json:"created_at"`
}

func (s *Service) listServers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermAIReview) && !p.HasOrgWide(authz.PermMCPManage) {
		httpx.WriteError(w, r, s.Log, httpx.ErrForbidden)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT m.id, m.name, m.description, m.transport, m.endpoint, m.status, m.data_access, m.built_in,
		COALESCE(NULLIF(u1.display_name, ''), u1.email), COALESCE(NULLIF(u2.display_name, ''), u2.email), m.decided_at, m.decision_note,
		COALESCE((SELECT json_agg(json_build_object('tool', t.tool, 'access', t.access, 'allowed', t.allowed) ORDER BY t.tool)
		          FROM mcp_tool_permissions t WHERE t.server_id = m.id), '[]'), m.created_at
		FROM mcp_servers m LEFT JOIN users u1 ON u1.id = m.requested_by LEFT JOIN users u2 ON u2.id = m.decided_by
		WHERE m.organization_id = $1 ORDER BY m.built_in DESC, m.name`, p.OrganizationID)
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Server])
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if out == nil {
		out = []Server{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

type serverRequest struct {
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Transport   string           `json:"transport"`
	Endpoint    string           `json:"endpoint"`
	DataAccess  string           `json:"data_access"`
	Tools       []ToolPermission `json:"tools"`
}

func validTools(ts []ToolPermission) error {
	if len(ts) > 100 {
		return httpx.BadRequest("at most 100 tools")
	}
	for _, t := range ts {
		if strings.TrimSpace(t.Tool) == "" || len(t.Tool) > 200 || (t.Access != "read" && t.Access != "write") {
			return httpx.BadRequest("each tool needs a name and access read or write")
		}
	}
	return nil
}

// requestServer registers an MCP server. Users with ai.review create a
// pending request; mcp.manage holders may approve it in the same step.
func (s *Service) requestServer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermAIReview) && !p.HasOrgWide(authz.PermMCPManage) {
		httpx.WriteError(w, r, s.Log, httpx.ErrForbidden)
		return
	}
	var req serverRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	req.Name, req.Endpoint = strings.TrimSpace(req.Name), strings.TrimSpace(req.Endpoint)
	if req.Name == "" || len(req.Name) > 200 || req.Endpoint == "" || len(req.Endpoint) > 1000 || len(req.Description) > 2000 {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("name and endpoint are required"))
		return
	}
	switch req.Transport {
	case "streamable_http":
		if u, err := url.Parse(req.Endpoint); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			httpx.WriteError(w, r, s.Log, httpx.BadRequest("streamable_http endpoints must be https URLs without credentials"))
			return
		}
	case "stdio":
	default:
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("transport must be stdio or streamable_http"))
		return
	}
	if req.DataAccess == "" {
		req.DataAccess = "none"
	}
	if req.DataAccess != "none" && req.DataAccess != "findings_redacted" && req.DataAccess != "findings_full" {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("invalid data_access"))
		return
	}
	if err := validTools(req.Tools); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO mcp_servers (id, organization_id, name, description, transport, endpoint, data_access, requested_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, id, p.OrganizationID, req.Name, req.Description, req.Transport, req.Endpoint, req.DataAccess, p.UserID); err != nil {
			return err
		}
		for _, t := range req.Tools {
			// Requested tools start disallowed until an administrator allows them.
			if _, err := tx.Exec(ctx, `INSERT INTO mcp_tool_permissions (organization_id, server_id, tool, access, allowed) VALUES ($1, $2, $3, $4, false)
				ON CONFLICT DO NOTHING`, p.OrganizationID, id, strings.TrimSpace(t.Tool), t.Access); err != nil {
				return err
			}
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "mcp_server.request", TargetType: "mcp_server", TargetID: id.String(), Metadata: map[string]any{"name": req.Name, "transport": req.Transport}})
	})
	if err != nil {
		if db.IsUniqueViolation(err) {
			err = httpx.Conflict("an MCP server with this name exists")
		}
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id, "status": "pending"})
}

func (s *Service) adminAction(w http.ResponseWriter, r *http.Request, fn func(context.Context, pgx.Tx, *authz.Principal, uuid.UUID) (string, map[string]any, error)) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermMCPManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}); err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrForbidden)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		httpx.WriteError(w, r, s.Log, httpx.ErrNotFound)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mcp_servers WHERE id = $1 AND organization_id = $2)`, id, p.OrganizationID).Scan(&exists); err != nil || !exists {
			return httpx.ErrNotFound
		}
		action, md, err := fn(ctx, tx, p, id)
		if err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: action, TargetType: "mcp_server", TargetID: id.String(), Metadata: md})
	})
	if err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) decideServer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Status string `json:"status"`
		Note   string `json:"note"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if req.Status != "approved" && req.Status != "rejected" && req.Status != "disabled" {
		httpx.WriteError(w, r, s.Log, httpx.BadRequest("status must be approved, rejected or disabled"))
		return
	}
	s.adminAction(w, r, func(ctx context.Context, tx pgx.Tx, p *authz.Principal, id uuid.UUID) (string, map[string]any, error) {
		_, err := tx.Exec(ctx, `UPDATE mcp_servers SET status = $2, decided_by = $3, decided_at = now(), decision_note = $4 WHERE id = $1`,
			id, req.Status, p.UserID, req.Note)
		return "mcp_server." + req.Status, map[string]any{"note": req.Note}, err
	})
}

func (s *Service) setTools(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tools []ToolPermission `json:"tools"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	if err := validTools(req.Tools); err != nil {
		httpx.WriteError(w, r, s.Log, err)
		return
	}
	s.adminAction(w, r, func(ctx context.Context, tx pgx.Tx, p *authz.Principal, id uuid.UUID) (string, map[string]any, error) {
		if _, err := tx.Exec(ctx, `DELETE FROM mcp_tool_permissions WHERE server_id = $1`, id); err != nil {
			return "", nil, err
		}
		allowed := []string{}
		for _, t := range req.Tools {
			if _, err := tx.Exec(ctx, `INSERT INTO mcp_tool_permissions (organization_id, server_id, tool, access, allowed) VALUES ($1, $2, $3, $4, $5)
				ON CONFLICT DO NOTHING`, p.OrganizationID, id, strings.TrimSpace(t.Tool), t.Access, t.Allowed); err != nil {
				return "", nil, err
			}
			if t.Allowed {
				allowed = append(allowed, t.Tool)
			}
		}
		return "mcp_server.set_tools", map[string]any{"allowed": allowed}, nil
	})
}

func (s *Service) deleteServer(w http.ResponseWriter, r *http.Request) {
	s.adminAction(w, r, func(ctx context.Context, tx pgx.Tx, p *authz.Principal, id uuid.UUID) (string, map[string]any, error) {
		tag, err := tx.Exec(ctx, `DELETE FROM mcp_servers WHERE id = $1 AND NOT built_in`, id)
		if err == nil && tag.RowsAffected() == 0 {
			err = httpx.Conflict("the built-in PATHOS server can be disabled but not deleted")
		}
		return "mcp_server.delete", nil, err
	})
}
