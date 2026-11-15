package dashboard

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

// Handlers serves /api/v1/dashboard/*.
type Handlers struct {
	DB        *pgxpool.Pool
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	Now       func() time.Time
}

func (h *Handlers) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/dashboard", h.summary)
}

// Filters are the dashboard filter-bar values.
type Filters struct {
	Days           int        `json:"days"`
	RegionID       *uuid.UUID `json:"region_id,omitempty"`
	CountryID      *uuid.UUID `json:"country_id,omitempty"`
	BusinessUnitID *uuid.UUID `json:"business_unit_id,omitempty"`
}

func (f Filters) geo() bool { return f.RegionID != nil || f.CountryID != nil || f.BusinessUnitID != nil }

// Point is one sparkline/series value.
type Point struct {
	Date  string  `json:"date"`
	Value float64 `json:"value"`
}

// KPI is one rendered card.
type KPI struct {
	Key         string   `json:"key"`
	Label       string   `json:"label"`
	Group       string   `json:"group"`
	Description string   `json:"description"`
	Unit        Unit     `json:"unit"`
	Polarity    Polarity `json:"polarity"`
	Drill       string   `json:"drill"`
	// Status: ok | not_yet_available | restricted
	Status    string   `json:"status"`
	Phase     int      `json:"phase"`
	Value     *float64 `json:"value"`
	Previous  *float64 `json:"previous"`
	Sparkline []Point  `json:"sparkline,omitempty"`
	// OrgWide is set when geo filters are active but this KPI is not
	// geo-scoped, so the UI can label it.
	OrgWide bool `json:"org_wide,omitempty"`
}

// Category is one labelled value in a bar or donut chart.
type Category struct {
	Label string  `json:"label"`
	Value float64 `json:"value"`
}

// Series is one chart series.
type Series struct {
	Name   string  `json:"name"`
	Points []Point `json:"points"`
}

// Chart is one rendered chart panel.
type Chart struct {
	Key    string   `json:"key"`
	Title  string   `json:"title"`
	Kind   string   `json:"kind"`
	Status string   `json:"status"`
	Phase  int      `json:"phase"`
	Drill  string   `json:"drill"`
	Series []Series `json:"series,omitempty"`
	// Categories is used by bar and donut charts.
	Categories []Category `json:"categories,omitempty"`
}

type Response struct {
	Filters     Filters   `json:"filters"`
	PeriodStart time.Time `json:"period_start"`
	PeriodEnd   time.Time `json:"period_end"`
	Groups      []string  `json:"groups"`
	KPIs        []KPI     `json:"kpis"`
	Charts      []Chart   `json:"charts"`
}

func parseUUIDParam(r *http.Request, name string) (*uuid.UUID, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return nil, nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil, httpx.BadRequest("invalid " + name)
	}
	return &id, nil
}

// ParseFilters validates filter query parameters.
func ParseFilters(r *http.Request) (Filters, error) {
	f := Filters{Days: 30}
	if d := r.URL.Query().Get("days"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || (n != 7 && n != 30 && n != 90 && n != 365) {
			return f, httpx.BadRequest("days must be 7, 30, 90 or 365")
		}
		f.Days = n
	}
	var err error
	if f.RegionID, err = parseUUIDParam(r, "region_id"); err != nil {
		return f, err
	}
	if f.CountryID, err = parseUUIDParam(r, "country_id"); err != nil {
		return f, err
	}
	if f.BusinessUnitID, err = parseUUIDParam(r, "business_unit_id"); err != nil {
		return f, err
	}
	return f, nil
}

func (h *Handlers) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

// visible reports whether p may see a value gated by perm. Org-only
// permissions need an org-wide grant; others need the permission anywhere
// (values are then filtered to the caller's scope in SQL).
func visible(p *authz.Principal, perm authz.Permission) bool {
	if info, ok := authz.LookupPermission(perm); ok && info.OrgOnly {
		return p.HasOrgWide(perm)
	}
	return p.HasAnywhere(perm)
}

func (h *Handlers) summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := h.Principal(ctx)
	if !p.HasAnywhere(authz.PermDashboardRead) {
		httpx.WriteError(w, r, h.Log, httpx.ErrForbidden)
		return
	}
	f, err := ParseFilters(r)
	if err != nil {
		httpx.WriteError(w, r, h.Log, err)
		return
	}
	end := h.now().UTC()
	start := end.AddDate(0, 0, -f.Days)
	resp := Response{Filters: f, PeriodStart: start, PeriodEnd: end, Groups: Groups}

	q := &queries{db: h.DB, org: p.OrganizationID, start: start, end: end}
	q.repoWhere, q.repoArgs = repoFilter(p, f)
	for _, def := range KPIs {
		k := KPI{Key: def.Key, Label: def.Label, Group: def.Group, Description: def.Description, Unit: def.Unit,
			Polarity: def.Polarity, Drill: def.Drill, Phase: def.Phase, OrgWide: f.geo() && !def.GeoScoped}
		switch {
		case def.Phase > CurrentPhase:
			k.Status = "not_yet_available"
		case !visible(p, def.Requires):
			k.Status = "restricted"
		default:
			k.Status = "ok"
			if err := q.kpi(ctx, &k); err != nil {
				httpx.WriteError(w, r, h.Log, err)
				return
			}
		}
		resp.KPIs = append(resp.KPIs, k)
	}
	for _, def := range Charts {
		c := Chart{Key: def.Key, Title: def.Title, Kind: def.Kind, Phase: def.Phase, Drill: def.Drill}
		switch {
		case def.Phase > CurrentPhase:
			c.Status = "not_yet_available"
		case !visible(p, def.Requires):
			c.Status = "restricted"
		default:
			c.Status = "ok"
			if err := q.chart(ctx, &c); err != nil {
				httpx.WriteError(w, r, h.Log, err)
				return
			}
		}
		resp.Charts = append(resp.Charts, c)
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

type queries struct {
	db         *pgxpool.Pool
	org        uuid.UUID
	start, end time.Time
	// repoWhere restricts repositories (alias r, countries alias co) to the
	// caller's scope and the geo filters; placeholders start at $2.
	repoWhere string
	repoArgs  []any
}

// repoFilter combines the caller's repos.read scope with the dashboard's
// region / country / business unit filters.
func repoFilter(p *authz.Principal, f Filters) (string, []any) {
	scope, args := org.ScopeSQL(authz.FilterFor(p, authz.PermReposRead), "r.id", "r.business_unit_id", "r.country_id", 2)
	where := []string{"r.archived_at IS NULL", scope}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args)+1)))
	}
	if f.RegionID != nil {
		add("co.region_id = ?", *f.RegionID)
	}
	if f.CountryID != nil {
		add("r.country_id = ?", *f.CountryID)
	}
	if f.BusinessUnitID != nil {
		add(`r.business_unit_id IN (WITH RECURSIVE d AS (SELECT id FROM business_units WHERE id = ?
			UNION ALL SELECT b.id FROM business_units b JOIN d ON b.parent_id = d.id) SELECT id FROM d)`, *f.BusinessUnitID)
	}
	return strings.Join(where, " AND "), args
}

func (q *queries) repoCount(ctx context.Context, extra string) (int64, error) {
	var n int64
	err := q.db.QueryRow(ctx, `SELECT count(*) FROM repositories r LEFT JOIN countries co ON co.id = r.country_id
		WHERE r.organization_id = $1 AND `+q.repoWhere+extra, append([]any{q.org}, q.repoArgs...)...).Scan(&n)
	return n, err
}

func f64(v int64) *float64 { x := float64(v); return &x }

func (q *queries) kpi(ctx context.Context, k *KPI) error {
	prevStart := q.start.Add(-q.end.Sub(q.start))
	switch k.Key {
	case "repositories":
		n, err := q.repoCount(ctx, "")
		k.Value = f64(n)
		return err
	case "unowned_repositories":
		n, err := q.repoCount(ctx, " AND r.application_id IS NULL")
		k.Value = f64(n)
		return err
	case "applications":
		var n int64
		err := q.db.QueryRow(ctx, `SELECT count(DISTINCT r.application_id) FROM repositories r LEFT JOIN countries co ON co.id = r.country_id
			WHERE r.organization_id = $1 AND r.application_id IS NOT NULL AND `+q.repoWhere, append([]any{q.org}, q.repoArgs...)...).Scan(&n)
		k.Value = f64(n)
		return err
	case "active_users":
		var now, before int64
		err := q.db.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE status = 'active'),
			       count(*) FILTER (WHERE last_login_at IS NOT NULL AND created_at < $2
			                        AND (deactivated_at IS NULL OR deactivated_at >= $2))
			FROM users WHERE organization_id = $1`, q.org, q.start).Scan(&now, &before)
		if err != nil {
			return err
		}
		k.Value, k.Previous = f64(now), f64(before)
		spark, err := q.daily(ctx, `
			SELECT d::date, (SELECT count(*) FROM users u WHERE u.organization_id = $1 AND u.last_login_at IS NOT NULL
			                   AND u.created_at < d + interval '1 day'
			                   AND (u.deactivated_at IS NULL OR u.deactivated_at >= d + interval '1 day'))
			FROM generate_series($2::date, $3::date, interval '1 day') d ORDER BY 1`)
		k.Sparkline = spark
		return err
	case "pending_invitations":
		var n int64
		err := q.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE organization_id = $1 AND status = 'invited'`, q.org).Scan(&n)
		k.Value = f64(n)
		return err
	case "security_events":
		var cur, prev int64
		err := q.db.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE created_at >= $2),
			       count(*) FILTER (WHERE created_at < $2)
			FROM audit_logs WHERE organization_id = $1 AND outcome IN ('denied', 'failure')
			  AND created_at >= $3 AND created_at < $4`, q.org, q.start, prevStart, q.end).Scan(&cur, &prev)
		if err != nil {
			return err
		}
		k.Value, k.Previous = f64(cur), f64(prev)
		spark, err := q.daily(ctx, `
			SELECT d::date, count(a.id) FROM generate_series($2::date, $3::date, interval '1 day') d
			LEFT JOIN audit_logs a ON a.organization_id = $1 AND a.outcome IN ('denied', 'failure')
			  AND a.created_at >= d AND a.created_at < d + interval '1 day'
			GROUP BY 1 ORDER BY 1`)
		k.Sparkline = spark
		return err
	}
	return nil
}

func (q *queries) daily(ctx context.Context, sql string) ([]Point, error) {
	rows, err := q.db.Query(ctx, sql, q.org, q.start, q.end)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Point, error) {
		var d time.Time
		var v int64
		err := r.Scan(&d, &v)
		return Point{Date: d.Format("2006-01-02"), Value: float64(v)}, err
	})
}

func (q *queries) chart(ctx context.Context, c *Chart) error {
	switch c.Key {
	case "repos_by_criticality":
		rows, err := q.db.Query(ctx, `SELECT r.criticality, count(*) FROM repositories r LEFT JOIN countries co ON co.id = r.country_id
			WHERE r.organization_id = $1 AND `+q.repoWhere+` GROUP BY 1
			ORDER BY array_position(ARRAY['critical','high','medium','low'], r.criticality)`, append([]any{q.org}, q.repoArgs...)...)
		if err != nil {
			return err
		}
		c.Categories, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Category, error) {
			var cat Category
			var n int64
			err := r.Scan(&cat.Label, &n)
			cat.Value = float64(n)
			return cat, err
		})
		return err
	case "sign_ins":
		ok, err := q.daily(ctx, `
			SELECT d::date, count(a.id) FROM generate_series($2::date, $3::date, interval '1 day') d
			LEFT JOIN audit_logs a ON a.organization_id = $1 AND a.action = 'auth.login' AND a.outcome = 'success'
			  AND a.created_at >= d AND a.created_at < d + interval '1 day'
			GROUP BY 1 ORDER BY 1`)
		if err != nil {
			return err
		}
		denied, err := q.daily(ctx, `
			SELECT d::date, count(a.id) FROM generate_series($2::date, $3::date, interval '1 day') d
			LEFT JOIN audit_logs a ON a.organization_id = $1 AND a.action = 'auth.login' AND a.outcome <> 'success'
			  AND a.created_at >= d AND a.created_at < d + interval '1 day'
			GROUP BY 1 ORDER BY 1`)
		if err != nil {
			return err
		}
		c.Series = []Series{{Name: "Successful", Points: ok}, {Name: "Rejected", Points: denied}}
	case "admin_activity":
		rows, err := q.db.Query(ctx, `
			SELECT split_part(action, '.', 1) AS category, count(*)
			FROM audit_logs
			WHERE organization_id = $1 AND created_at >= $2 AND created_at < $3
			  AND action NOT LIKE 'auth.%' AND action <> 'authz.denied' AND outcome = 'success'
			GROUP BY 1 ORDER BY 2 DESC LIMIT 8`, q.org, q.start, q.end)
		if err != nil {
			return err
		}
		c.Categories, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Category, error) {
			var cat Category
			var n int64
			err := r.Scan(&cat.Label, &n)
			cat.Value = float64(n)
			return cat, err
		})
		return err
	}
	return nil
}
