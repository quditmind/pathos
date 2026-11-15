package dashboard

import (
	"context"
	"fmt"
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

	q := &queries{db: h.DB, org: p.OrganizationID, start: start, end: end, p: p, f: f}
	q.repoWhere, q.repoArgs = repoFilter(p, f, authz.PermReposRead)
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
	p         *authz.Principal
	f         Filters
}

// scoped returns the repository filter for perm with $1 = organization.
func (q *queries) scoped(perm authz.Permission) (string, []any) {
	w, a := repoFilter(q.p, q.f, perm)
	return w, append([]any{q.org}, a...)
}

func (q *queries) count(ctx context.Context, perm authz.Permission, sql string) (float64, error) {
	w, args := q.scoped(perm)
	var n float64
	err := q.db.QueryRow(ctx, strings.ReplaceAll(sql, "{scope}", w), args...).Scan(&n)
	return n, err
}

const openStatuses = "f.status IN ('open', 'in_progress', 'needs_review')"
const findingsFrom = ` FROM findings f JOIN repositories r ON r.id = f.repository_id LEFT JOIN countries co ON co.id = r.country_id
	WHERE f.organization_id = $1 AND {scope} AND ` + openStatuses

// repoFilter combines the caller's repos.read scope with the dashboard's
// region / country / business unit filters.
func repoFilter(p *authz.Principal, f Filters, perm authz.Permission) (string, []any) {
	scope, args := org.ScopeSQL(authz.FilterFor(p, perm), "r.id", "r.business_unit_id", "r.country_id", 2)
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
	setF := func(v float64, err error) error {
		if err == nil {
			k.Value = &v
		}
		return err
	}
	switch k.Key {
	case "ai_reviews", "ai_false_positive_rate", "pending_human_review":
		w, args := q.scoped(authz.PermFindingsRead)
		args = append(args, q.start)
		var total, fp, pending float64
		err := q.db.QueryRow(ctx, fmt.Sprintf(`SELECT count(*) FILTER (WHERE ar.created_at >= $%[1]d),
			  count(*) FILTER (WHERE ar.created_at >= $%[1]d AND ar.verdict = 'false_positive'),
			  count(*) FILTER (WHERE ar.status = 'pending_approval')
			FROM ai_reviews ar JOIN findings f ON f.id = ar.finding_id JOIN repositories r ON r.id = f.repository_id
			LEFT JOIN countries co ON co.id = r.country_id WHERE ar.organization_id = $1 AND `+w, len(args)), args...).Scan(&total, &fp, &pending)
		if err != nil {
			return err
		}
		switch k.Key {
		case "ai_reviews":
			k.Value = &total
		case "pending_human_review":
			k.Value = &pending
		default:
			rate := 0.0
			if total > 0 {
				rate = float64(int(1000*fp/total)) / 10
			}
			k.Value = &rate
		}
		return nil
	case "open_findings":
		return setF(q.count(ctx, authz.PermFindingsRead, `SELECT count(*)`+findingsFrom))
	case "critical_findings":
		return setF(q.count(ctx, authz.PermFindingsRead, `SELECT count(*)`+findingsFrom+` AND f.severity = 'critical'`))
	case "high_findings":
		return setF(q.count(ctx, authz.PermFindingsRead, `SELECT count(*)`+findingsFrom+` AND f.severity = 'high'`))
	case "secrets_exposed":
		return setF(q.count(ctx, authz.PermFindingsRead, `SELECT count(*)`+findingsFrom+` AND f.category = 'secrets'`))
	case "vulnerable_dependencies":
		return setF(q.count(ctx, authz.PermFindingsRead, `SELECT count(DISTINCT lower(f.package_name || '@' || f.package_version))`+findingsFrom+` AND f.category = 'sca' AND f.package_name <> ''`))
	case "risk_score":
		w, args := q.scoped(authz.PermFindingsRead)
		var score float64
		err := q.db.QueryRow(ctx, `SELECT COALESCE(round((
			  SELECT sum(CASE f.severity WHEN 'critical' THEN 10 WHEN 'high' THEN 5 WHEN 'medium' THEN 2 WHEN 'low' THEN 0.5 ELSE 0 END)
			  FROM findings f JOIN repositories r ON r.id = f.repository_id LEFT JOIN countries co ON co.id = r.country_id
			  WHERE f.organization_id = $1 AND `+w+` AND `+openStatuses+`)::numeric
			/ NULLIF((SELECT count(*) FROM repositories r LEFT JOIN countries co ON co.id = r.country_id
			          WHERE r.organization_id = $1 AND `+w+`), 0), 1), 0)`, args...).Scan(&score)
		return setF(score, err)
	case "scan_coverage":
		w, args := q.scoped(authz.PermReposRead)
		args = append(args, q.start)
		var pct float64
		err := q.db.QueryRow(ctx, fmt.Sprintf(`SELECT COALESCE(round(100.0 * count(*) FILTER (WHERE EXISTS (
			  SELECT 1 FROM scan_jobs j WHERE j.repository_id = r.id AND j.status IN ('succeeded', 'partial') AND j.finished_at >= $%d))
			/ NULLIF(count(*), 0), 1), 0)
			FROM repositories r LEFT JOIN countries co ON co.id = r.country_id
			WHERE r.organization_id = $1 AND r.scan_enabled AND `+w, len(args)), args...).Scan(&pct)
		return setF(pct, err)
	case "scans_completed", "scan_success_rate":
		w, args := q.scoped(authz.PermScansRead)
		prevStart := q.start.Add(-q.end.Sub(q.start))
		args = append(args, q.start, prevStart)
		n := len(args)
		var cur, curOK, prev, prevOK float64
		err := q.db.QueryRow(ctx, fmt.Sprintf(`SELECT
			  count(*) FILTER (WHERE j.finished_at >= $%[1]d),
			  count(*) FILTER (WHERE j.finished_at >= $%[1]d AND j.status IN ('succeeded', 'partial')),
			  count(*) FILTER (WHERE j.finished_at < $%[1]d),
			  count(*) FILTER (WHERE j.finished_at < $%[1]d AND j.status IN ('succeeded', 'partial'))
			FROM scan_jobs j JOIN repositories r ON r.id = j.repository_id LEFT JOIN countries co ON co.id = r.country_id
			WHERE j.organization_id = $1 AND `+w+` AND j.status IN ('succeeded', 'partial', 'failed') AND j.finished_at >= $%[2]d`, n-1, n),
			args...).Scan(&cur, &curOK, &prev, &prevOK)
		if err != nil {
			return err
		}
		if k.Key == "scans_completed" {
			k.Value, k.Previous = &cur, &prev
			return nil
		}
		rate := func(ok, all float64) *float64 {
			if all == 0 {
				return nil
			}
			v := float64(int(1000*ok/all)) / 10
			return &v
		}
		k.Value, k.Previous = rate(curOK, cur), rate(prevOK, prev)
		if k.Value == nil {
			z := 0.0
			k.Value = &z
		}
		return nil
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
	case "severity_distribution":
		w, args := q.scoped(authz.PermFindingsRead)
		rows, err := q.db.Query(ctx, `SELECT f.severity, count(*) FROM findings f JOIN repositories r ON r.id = f.repository_id
			LEFT JOIN countries co ON co.id = r.country_id WHERE f.organization_id = $1 AND `+w+` AND `+openStatuses+`
			GROUP BY 1 ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity)`, args...)
		if err != nil {
			return err
		}
		c.Categories, err = collectCategories(rows)
		return err
	case "top_repositories":
		w, args := q.scoped(authz.PermFindingsRead)
		rows, err := q.db.Query(ctx, `SELECT r.full_name,
			  sum(CASE f.severity WHEN 'critical' THEN 10 WHEN 'high' THEN 5 WHEN 'medium' THEN 2 WHEN 'low' THEN 0.5 ELSE 0 END)::bigint
			FROM findings f JOIN repositories r ON r.id = f.repository_id LEFT JOIN countries co ON co.id = r.country_id
			WHERE f.organization_id = $1 AND `+w+` AND `+openStatuses+`
			GROUP BY r.full_name HAVING sum(CASE f.severity WHEN 'critical' THEN 10 WHEN 'high' THEN 5 WHEN 'medium' THEN 2 WHEN 'low' THEN 0.5 ELSE 0 END) > 0
			ORDER BY 2 DESC LIMIT 8`, args...)
		if err != nil {
			return err
		}
		c.Categories, err = collectCategories(rows)
		return err
	case "scanner_activity":
		w, args := q.scoped(authz.PermScansRead)
		args = append(args, q.start)
		rows, err := q.db.Query(ctx, fmt.Sprintf(`SELECT sr.scanner_key, count(*) FROM scan_results sr
			JOIN scan_jobs j ON j.id = sr.scan_job_id JOIN repositories r ON r.id = j.repository_id LEFT JOIN countries co ON co.id = r.country_id
			WHERE j.organization_id = $1 AND `+w+` AND sr.created_at >= $%d GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, len(args)), args...)
		if err != nil {
			return err
		}
		c.Categories, err = collectCategories(rows)
		return err
	case "findings_trend":
		w, args := q.scoped(authz.PermFindingsRead)
		args = append(args, q.start, q.end)
		n := len(args)
		for _, sev := range []string{"critical", "high", "medium", "low"} {
			rows, err := q.db.Query(ctx, fmt.Sprintf(`SELECT d::date, (SELECT count(*) FROM findings f JOIN repositories r ON r.id = f.repository_id
				  LEFT JOIN countries co ON co.id = r.country_id
				  WHERE f.organization_id = $1 AND `+w+` AND f.severity = '%s'
				    AND f.status NOT IN ('false_positive', 'accepted_risk')
				    AND f.first_seen_at < d + interval '1 day' AND (f.resolved_at IS NULL OR f.resolved_at >= d + interval '1 day'))
				FROM generate_series($%d::date, $%d::date, interval '1 day') d ORDER BY 1`, sev, n-1, n), args...)
			if err != nil {
				return err
			}
			pts, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Point, error) {
				var d time.Time
				var v int64
				err := r.Scan(&d, &v)
				return Point{Date: d.Format("2006-01-02"), Value: float64(v)}, err
			})
			if err != nil {
				return err
			}
			c.Series = append(c.Series, Series{Name: sev, Points: pts})
		}
		return nil
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

func collectCategories(rows pgx.Rows) ([]Category, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Category, error) {
		var cat Category
		var n int64
		err := r.Scan(&cat.Label, &n)
		cat.Value = float64(n)
		return cat, err
	})
}
