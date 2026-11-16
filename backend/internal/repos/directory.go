package repos

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
)

func (s *Service) registerDirectory(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/directory/users", s.directoryUsers)
	mux.HandleFunc("GET /api/v1/directory/teams", s.directoryTeams)
}

// directoryArgs authorizes owner pickers: anyone who can register or edit
// assets (repos.manage anywhere) or own them (repos.read) may look up
// active users and teams by name. Only id, name and e-mail are returned.
func (s *Service) directoryArgs(w http.ResponseWriter, r *http.Request) (*authz.Principal, string, int, bool) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermReposRead) && !p.HasAnywhere(authz.PermReposManage) {
		s.fail(w, r, authz.ErrForbidden)
		return nil, "", 0, false
	}
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 || n > 100 {
			s.fail(w, r, httpx.BadRequest("limit must be between 1 and 100"))
			return nil, "", 0, false
		}
		limit = n
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len(q) > 100 {
		s.fail(w, r, httpx.BadRequest("q is too long"))
		return nil, "", 0, false
	}
	return p, "%" + escapeLike(strings.ToLower(q)) + "%", limit, true
}

func (s *Service) directoryUsers(w http.ResponseWriter, r *http.Request) {
	p, like, limit, ok := s.directoryArgs(w, r)
	if !ok {
		return
	}
	// ids= resolves specific users (e.g. owners already set on an asset).
	var ids []uuid.UUID
	for _, v := range strings.Split(r.URL.Query().Get("ids"), ",") {
		if id, err := uuid.Parse(strings.TrimSpace(v)); err == nil && len(ids) < 100 {
			ids = append(ids, id)
		}
	}
	rows, err := s.DB.Query(r.Context(), `
		SELECT id, COALESCE(NULLIF(display_name, ''), email), email FROM users
		WHERE organization_id = $1 AND status <> 'deactivated'
		  AND (cardinality($4::uuid[]) > 0 AND id = ANY($4) OR cardinality($4::uuid[]) = 0
		       AND (lower(display_name) LIKE $2 OR email LIKE $2))
		ORDER BY lower(COALESCE(NULLIF(display_name, ''), email)) LIMIT $3`, p.OrganizationID, like, limit, nonNil(ids))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (UserRef, error) {
		var u UserRef
		return u, row.Scan(&u.ID, &u.Name, &u.Email)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []UserRef{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Service) directoryTeams(w http.ResponseWriter, r *http.Request) {
	p, like, limit, ok := s.directoryArgs(w, r)
	if !ok {
		return
	}
	rows, err := s.DB.Query(r.Context(), `
		SELECT t.id, t.name, (SELECT count(*) FROM team_members m WHERE m.team_id = t.id)
		FROM teams t WHERE t.organization_id = $1 AND lower(t.name) LIKE $2
		ORDER BY lower(t.name) LIMIT $3`, p.OrganizationID, like, limit)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type team struct {
		ID          uuid.UUID `json:"id"`
		Name        string    `json:"name"`
		MemberCount int       `json:"member_count"`
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (team, error) {
		var t team
		return t, row.Scan(&t.ID, &t.Name, &t.MemberCount)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []team{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items})
}
