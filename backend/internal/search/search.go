// Package search implements global search (the ⌘K command palette).
// Each entity type is searched only if the caller may read it, and results
// are capped per type.
package search

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

type Handlers struct {
	DB        *pgxpool.Pool
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/search", h.search)
}

// Result is one search hit.
type Result struct {
	Type     string `json:"type"` // repository | application | user | business_unit | region | country
	ID       string `json:"id"`
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	Href     string `json:"href"`
}

const perType = 5

func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

func (h *Handlers) search(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := h.Principal(ctx)
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if utf8.RuneCountInString(q) < 2 {
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": []Result{}})
		return
	}
	if utf8.RuneCountInString(q) > 100 {
		httpx.WriteError(w, r, h.Log, httpx.BadRequest("query must be at most 100 characters"))
		return
	}
	like := "%" + escapeLike(strings.ToLower(q)) + "%"
	out := []Result{}

	type src struct {
		ok  bool
		sql string
	}
	sources := []src{
		{p.HasOrgWide(authz.PermUsersRead), `
			SELECT 'user', id::text, COALESCE(NULLIF(display_name, ''), email), email || ' · ' || status,
			       '/admin/users?user=' || id::text
			FROM users WHERE organization_id = $1 AND (email LIKE $2 OR lower(display_name) LIKE $2)
			ORDER BY email LIMIT $3`},
		{p.HasAnywhere(authz.PermOrgRead), `
			SELECT 'business_unit', id::text, name, 'Business unit', '/admin/organization'
			FROM business_units WHERE organization_id = $1 AND archived_at IS NULL AND lower(name) LIKE $2
			ORDER BY name LIMIT $3`},
		{p.HasAnywhere(authz.PermOrgRead), `
			SELECT 'region', id::text, name, 'Region · ' || code, '/admin/organization'
			FROM regions WHERE organization_id = $1 AND (lower(name) LIKE $2 OR lower(code) LIKE $2)
			ORDER BY name LIMIT $3`},
		{p.HasAnywhere(authz.PermOrgRead), `
			SELECT 'country', c.id::text, c.name, 'Country · ' || c.code || ' · ' || r.name, '/admin/organization'
			FROM countries c JOIN regions r ON r.id = c.region_id
			WHERE c.organization_id = $1 AND (lower(c.name) LIKE $2 OR lower(c.code) LIKE $2)
			ORDER BY c.name LIMIT $3`},
	}
	// Repositories and applications, filtered to the caller's repos.read scope.
	if f := authz.FilterFor(p, authz.PermReposRead); !f.None() {
		scope, args := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 4)
		base := []any{p.OrganizationID, like, perType}
		for _, sql := range []string{`
			SELECT 'repository', r.id::text, r.full_name, r.repository_key || ' · ' || r.criticality || ' · ' || r.environment,
			       '/repositories?repo=' || r.id::text
			FROM repositories r WHERE r.organization_id = $1 AND r.archived_at IS NULL AND (lower(r.full_name) LIKE $2 OR lower(r.repository_key) LIKE $2) AND ` + scope + `
			ORDER BY lower(r.full_name) LIMIT $3`, `
			SELECT 'application', a.id::text, a.name, 'Application · ' || a.criticality, '/applications?app=' || a.id::text
			FROM applications a WHERE a.organization_id = $1 AND a.archived_at IS NULL AND lower(a.name) LIKE $2
			  AND EXISTS (SELECT 1 FROM repositories r WHERE r.application_id = a.id AND ` + scope + `)
			ORDER BY lower(a.name) LIMIT $3`} {
			if f.All {
				// Applications without repositories are still visible org-wide.
				sql = strings.Replace(sql, "AND EXISTS (SELECT 1 FROM repositories r WHERE r.application_id = a.id AND true)", "", 1)
			}
			rows, err := h.DB.Query(ctx, sql, append(base, args...)...)
			if err != nil {
				httpx.WriteError(w, r, h.Log, err)
				return
			}
			res, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Result])
			if err != nil {
				httpx.WriteError(w, r, h.Log, err)
				return
			}
			out = append(out, res...)
		}
	}
	for _, s := range sources {
		if !s.ok {
			continue
		}
		rows, err := h.DB.Query(ctx, s.sql, p.OrganizationID, like, perType)
		if err != nil {
			httpx.WriteError(w, r, h.Log, err)
			return
		}
		res, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Result])
		if err != nil {
			httpx.WriteError(w, r, h.Log, err)
			return
		}
		out = append(out, res...)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}
