package compliance

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

// Service serves compliance views over the caller's findings.
type Service struct {
	DB        *pgxpool.Pool
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/compliance/frameworks", s.list)
	mux.HandleFunc("GET /api/v1/compliance/frameworks/{key}", s.get)
}

// ControlStatus is a control with the open findings mapped to it.
type ControlStatus struct {
	Control
	// Status: failing (open critical or high findings), attention (other
	// open findings), passing (none) or not_applicable (no repository in
	// scope).
	Status       string         `json:"status"`
	Open         int            `json:"open_findings"`
	BySeverity   map[string]int `json:"by_severity"`
	Repositories int            `json:"repositories"`
}

// Summary is a framework with its control results.
type Summary struct {
	Key            string          `json:"key"`
	Name           string          `json:"name"`
	Version        string          `json:"version"`
	ScopeKey       string          `json:"scope_key"`
	Description    string          `json:"description"`
	RepositoriesIn int             `json:"repositories_in_scope"`
	Failing        int             `json:"failing"`
	Attention      int             `json:"attention"`
	Passing        int             `json:"passing"`
	Controls       []ControlStatus `json:"controls,omitempty"`
}

func (s *Service) evaluate(ctx context.Context, p *authz.Principal, f Framework, withControls bool) (Summary, error) {
	out := Summary{Key: f.Key, Name: f.Name, Version: f.Version, ScopeKey: f.ScopeKey, Description: f.Description}
	filter := authz.FilterFor(p, authz.PermFindingsRead)
	scope, sargs := org.ScopeSQL(filter, "r.id", "r.business_unit_id", "r.country_id", 2)
	base := append([]any{p.OrganizationID}, sargs...)
	// Repositories in the framework's scope that the caller can see.
	args := append([]any{}, base...)
	ph := func(v any) string { args = append(args, v); return "$" + strconv.Itoa(len(args)) }
	inScope := "true"
	if f.ScopeKey != "" {
		inScope = "EXISTS (SELECT 1 FROM repository_compliance_scopes cs WHERE cs.repository_id = r.id AND cs.scope_key = " + ph(f.ScopeKey) + ")"
	}
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM repositories r WHERE r.organization_id = $1 AND r.archived_at IS NULL AND `+scope+` AND `+inScope,
		args...).Scan(&out.RepositoriesIn); err != nil {
		return out, err
	}
	for _, c := range f.Controls {
		args = append([]any{}, base...)
		cs := ControlStatus{Control: c, BySeverity: map[string]int{}}
		rows, err := s.DB.Query(ctx, `SELECT f.severity, count(*), count(DISTINCT f.repository_id) FROM findings f JOIN repositories r ON r.id = f.repository_id
			WHERE f.organization_id = $1 AND r.archived_at IS NULL AND `+scope+` AND f.status IN ('open', 'in_progress', 'needs_review')
			  AND `+ScopeSQL(f, ph)+` AND `+MatchSQL(c, ph)+` GROUP BY f.severity`, args...)
		if err != nil {
			return out, err
		}
		for rows.Next() {
			var sev string
			var n, repos int
			if err := rows.Scan(&sev, &n, &repos); err != nil {
				rows.Close()
				return out, err
			}
			cs.BySeverity[sev] = n
			cs.Open += n
			cs.Repositories = max(cs.Repositories, repos)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return out, err
		}
		switch {
		case out.RepositoriesIn == 0:
			cs.Status = "not_applicable"
		case cs.BySeverity["critical"]+cs.BySeverity["high"] > 0:
			cs.Status = "failing"
			out.Failing++
		case cs.Open > 0:
			cs.Status = "attention"
			out.Attention++
		default:
			cs.Status = "passing"
			out.Passing++
		}
		if withControls {
			out.Controls = append(out.Controls, cs)
		}
	}
	return out, nil
}

func (s *Service) principal(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil || authz.FilterFor(p, authz.PermFindingsRead).None() {
		return nil, authz.ErrForbidden
	}
	return p, nil
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, authz.ErrForbidden) {
		err = httpx.ErrForbidden
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := make([]Summary, 0, len(Frameworks))
	for _, f := range Frameworks {
		sum, err := s.evaluate(r.Context(), p, f, false)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		items = append(items, sum)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items,
		"note": "Indicative mapping of open findings to controls; it is evidence for an assessment, not a compliance verdict."})
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	p, err := s.principal(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, ok := Lookup(r.PathValue("key"))
	if !ok {
		s.fail(w, r, httpx.ErrNotFound)
		return
	}
	sum, err := s.evaluate(r.Context(), p, f, true)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, sum)
}
