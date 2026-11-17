// Package reporting serves the executive dashboard and custom reports.
// Every figure is computed from the caller's findings in scope; nothing is
// estimated or invented.
package reporting

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

// Service serves reporting endpoints.
type Service struct {
	DB        *pgxpool.Pool
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/executive", s.executive)
	s.registerReports(mux)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

// Executive is the executive dashboard.
type Executive struct {
	GeneratedAt   time.Time           `json:"generated_at"`
	Days          int                 `json:"days"`
	Scope         string              `json:"scope"`
	Open          map[string]int      `json:"open_by_severity"`
	OpenKEV       int                 `json:"open_actively_exploited"`
	OpenCritRisk  int                 `json:"open_critical_risk"`
	Overdue       int                 `json:"open_past_sla"`
	New           int                 `json:"new_in_period"`
	Fixed         int                 `json:"fixed_in_period"`
	MTTR          map[string]*float64 `json:"mean_days_to_fix"`
	SLACompliance *float64            `json:"fixed_within_sla_percent"`
	Repositories  int                 `json:"repositories"`
	Scanned30     int                 `json:"repositories_scanned_30_days"`
	Trend         []TrendPoint        `json:"trend"`
	Applications  []GroupRisk         `json:"top_applications"`
	Units         []GroupRisk         `json:"business_units"`
}

// TrendPoint is one week of the trend.
type TrendPoint struct {
	Week  string `json:"week"`
	New   int    `json:"new"`
	Fixed int    `json:"fixed"`
	Open  int    `json:"open_at_end"`
}

// GroupRisk summarizes open findings of an application or business unit.
type GroupRisk struct {
	ID       *string `json:"id"`
	Name     string  `json:"name"`
	Critical int     `json:"critical"`
	High     int     `json:"high"`
	Open     int     `json:"open"`
	KEV      int     `json:"kev"`
	MaxRisk  *int    `json:"max_risk"`
}

const openCond = `f.status IN ('open', 'in_progress', 'needs_review')`

func round1(v *float64) *float64 {
	if v == nil {
		return nil
	}
	x := float64(int(*v*10+0.5)) / 10
	return &x
}

func (s *Service) executive(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if p == nil || f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	days := 90
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil {
		days = v
	}
	if days != 30 && days != 90 && days != 180 && days != 365 {
		s.fail(w, r, httpx.BadRequest("days must be 30, 90, 180 or 365"))
		return
	}
	cond, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 3)
	args := append([]any{p.OrganizationID, days}, sargs...)
	from := ` FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE f.organization_id = $1 AND r.archived_at IS NULL AND ` + cond
	ex := Executive{GeneratedAt: time.Now().UTC(), Days: days, Scope: "Organization", MTTR: map[string]*float64{}}
	if !p.HasOrgWide(authz.PermFindingsRead) {
		ex.Scope = "Repositories you can access"
	}
	var c, h, m, l int
	var mc, mh, mm, ml, sla *float64
	// #nosec G202 -- cond is built from placeholders
	err := s.DB.QueryRow(ctx, `SELECT
		  count(*) FILTER (WHERE `+openCond+` AND f.severity = 'critical'), count(*) FILTER (WHERE `+openCond+` AND f.severity = 'high'),
		  count(*) FILTER (WHERE `+openCond+` AND f.severity = 'medium'), count(*) FILTER (WHERE `+openCond+` AND f.severity = 'low'),
		  count(*) FILTER (WHERE `+openCond+` AND f.kev), count(*) FILTER (WHERE `+openCond+` AND f.risk_score >= 75),
		  count(*) FILTER (WHERE `+openCond+` AND f.sla_due_at < now()),
		  count(*) FILTER (WHERE f.first_seen_at >= now() - make_interval(days => $2)),
		  count(*) FILTER (WHERE f.status = 'fixed' AND f.resolved_at >= now() - make_interval(days => $2)),
		  (avg(EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at)) / 86400) FILTER (WHERE f.status = 'fixed' AND f.resolved_at >= now() - make_interval(days => $2) AND f.severity = 'critical'))::float8,
		  (avg(EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at)) / 86400) FILTER (WHERE f.status = 'fixed' AND f.resolved_at >= now() - make_interval(days => $2) AND f.severity = 'high'))::float8,
		  (avg(EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at)) / 86400) FILTER (WHERE f.status = 'fixed' AND f.resolved_at >= now() - make_interval(days => $2) AND f.severity = 'medium'))::float8,
		  (avg(EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at)) / 86400) FILTER (WHERE f.status = 'fixed' AND f.resolved_at >= now() - make_interval(days => $2) AND f.severity = 'low'))::float8,
		  (100.0 * avg(CASE WHEN f.sla_due_at IS NULL OR f.resolved_at <= f.sla_due_at THEN 1 ELSE 0 END)
		     FILTER (WHERE f.status = 'fixed' AND f.resolved_at >= now() - make_interval(days => $2)))::float8`+from, args...).
		Scan(&c, &h, &m, &l, &ex.OpenKEV, &ex.OpenCritRisk, &ex.Overdue, &ex.New, &ex.Fixed, &mc, &mh, &mm, &ml, &sla)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ex.Open = map[string]int{"critical": c, "high": h, "medium": m, "low": l}
	ex.MTTR = map[string]*float64{"critical": round1(mc), "high": round1(mh), "medium": round1(mm), "low": round1(ml)}
	ex.SLACompliance = round1(sla)
	// #nosec G202 -- cond is built from placeholders
	if err := s.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE EXISTS (SELECT 1 FROM scan_jobs j WHERE j.repository_id = r.id
		  AND j.status IN ('succeeded', 'partial') AND j.finished_at >= now() - interval '30 days'))
		FROM repositories r WHERE r.organization_id = $1 AND r.archived_at IS NULL AND $2::int > 0 AND `+cond, args...).Scan(&ex.Repositories, &ex.Scanned30); err != nil {
		s.fail(w, r, err)
		return
	}
	// Weekly trend: new and fixed per week, and findings open at week end
	// (first seen before it and not resolved by then).
	// #nosec G202 -- cond is built from placeholders
	rows, err := s.DB.Query(ctx, `WITH weeks AS (
		  SELECT generate_series(date_trunc('week', now() - make_interval(days => $2)), date_trunc('week', now()), interval '1 week') AS w)
		SELECT to_char(w, 'YYYY-MM-DD'),
		  (SELECT count(*)`+from+` AND f.first_seen_at >= w AND f.first_seen_at < w + interval '1 week'),
		  (SELECT count(*)`+from+` AND f.status = 'fixed' AND f.resolved_at >= w AND f.resolved_at < w + interval '1 week'),
		  (SELECT count(*)`+from+` AND f.first_seen_at < w + interval '1 week' AND f.status NOT IN ('false_positive')
		     AND (f.resolved_at IS NULL OR f.resolved_at >= w + interval '1 week') AND (f.status <> 'accepted_risk'))
		FROM weeks ORDER BY w`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ex.Trend, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (TrendPoint, error) {
		var t TrendPoint
		return t, r.Scan(&t.Week, &t.New, &t.Fixed, &t.Open)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	group := func(idExpr, nameExpr, join string) ([]GroupRisk, error) {
		// #nosec G202 -- expressions are constants; cond is built from placeholders
		rows, err := s.DB.Query(ctx, `SELECT `+idExpr+`::text, `+nameExpr+`,
			  count(*) FILTER (WHERE f.severity = 'critical'), count(*) FILTER (WHERE f.severity = 'high'), count(*), count(*) FILTER (WHERE f.kev),
			  max(f.risk_score)
			FROM findings f JOIN repositories r ON r.id = f.repository_id `+join+`
			WHERE f.organization_id = $1 AND r.archived_at IS NULL AND $2::int > 0 AND `+openCond+` AND `+cond+`
			GROUP BY 1, 2 ORDER BY 3 DESC, 4 DESC, 7 DESC NULLS LAST LIMIT 10`, args...)
		if err != nil {
			return nil, err
		}
		return pgx.CollectRows(rows, func(r pgx.CollectableRow) (GroupRisk, error) {
			var g GroupRisk
			return g, r.Scan(&g.ID, &g.Name, &g.Critical, &g.High, &g.Open, &g.KEV, &g.MaxRisk)
		})
	}
	if ex.Applications, err = group("a.id", "COALESCE(a.name, 'No application')", "LEFT JOIN applications a ON a.id = r.application_id"); err != nil {
		s.fail(w, r, err)
		return
	}
	if ex.Units, err = group("b.id", "COALESCE(b.name, 'No business unit')", "LEFT JOIN business_units b ON b.id = r.business_unit_id"); err != nil {
		s.fail(w, r, err)
		return
	}
	for _, g := range []*[]GroupRisk{&ex.Applications, &ex.Units} {
		if *g == nil {
			*g = []GroupRisk{}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, ex)
}
