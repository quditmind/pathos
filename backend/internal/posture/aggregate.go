package posture

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
	"pathos/internal/risk"
)

// Dimensions a posture can be grouped by: the repository column holding the
// group, and how to label it.
var dimensions = map[string]struct {
	col, labelSQL string
}{
	"application":   {"r.application_id", `SELECT id, name FROM applications WHERE id = ANY($1)`},
	"business_unit": {"r.business_unit_id", `SELECT id, name FROM business_units WHERE id = ANY($1)`},
	"team":          {"r.responsible_team_id", `SELECT id, name FROM teams WHERE id = ANY($1)`},
	"owner": {"COALESCE(r.application_owner_id, r.technical_owner_id, r.business_owner_id)",
		`SELECT id, COALESCE(NULLIF(display_name, ''), email) FROM users WHERE id = ANY($1)`},
	"region": {"r.business_region_id", `SELECT id, name FROM regions WHERE id = ANY($1)`},
}

// Group is the posture of one group of repositories.
type Group struct {
	ID    *uuid.UUID `json:"id"`
	Label string     `json:"label"`
	// Repositories in the caller's scope (active, not archived).
	Repositories int            `json:"repositories"`
	Open         map[string]int `json:"open"` // by severity
	OpenTotal    int            `json:"open_total"`
	KEV          int            `json:"kev_open"`
	SLABreached  int            `json:"sla_breached"`
	// HighRisk counts open findings with a contextual risk ≥ 50.
	HighRisk int      `json:"high_risk_open"`
	MaxRisk  *float64 `json:"max_risk"`
	AvgRisk  *float64 `json:"avg_risk"`
	// RiskScore is the group's rollup (see rollup) and its band.
	RiskScore float64     `json:"risk_score"`
	RiskBand  string      `json:"risk_band"`
	RiskBasis RiskFactors `json:"risk_basis"`
	// Remediation over the window: findings fixed, mean time to remediate
	// (days) and the share fixed within their SLA.
	Fixed         int        `json:"fixed"`
	MTTRDays      *float64   `json:"mttr_days"`
	SLACompliance *float64   `json:"sla_compliance"`
	LastScanAt    *time.Time `json:"last_scan_at"`
	// Coverage is the share of repositories with a successful SAST, SCA and
	// secrets scan in the last 30 days (each category counts a third).
	Coverage *float64 `json:"coverage"`
}

// RiskFactors explains a rollup.
type RiskFactors struct {
	MaxFindingRisk float64 `json:"max_finding_risk"`
	OtherHighRisk  int     `json:"other_high_risk_findings"`
	Uplift         float64 `json:"uplift"`
}

// rollup is the risk of a group: its riskiest open finding, raised by one
// point for every other open finding with a risk of at least 50 (at most
// 15 points), capped at 100. A group with one critical issue and a group
// with twenty both rank high, the second slightly higher; many low-risk
// findings never add up to a high risk.
func rollup(maxRisk *float64, highRisk int) (float64, RiskFactors) {
	if maxRisk == nil {
		return 0, RiskFactors{}
	}
	f := RiskFactors{MaxFindingRisk: *maxRisk}
	if *maxRisk >= 50 && highRisk > 1 {
		f.OtherHighRisk = highRisk - 1
	}
	f.Uplift = float64(min(15, f.OtherHighRisk))
	return min(100, f.MaxFindingRisk+f.Uplift), f
}

// groups computes the posture of every group of repositories in scope.
// extra filters repositories (alias r) with its own args.
func (s *Service) groups(ctx context.Context, p *authz.Principal, dim string, days int, extra string, extraArgs ...any) ([]Group, error) {
	d, ok := dimensions[dim]
	if !ok {
		return nil, httpx.BadRequest("by must be application, business_unit, team, owner or region")
	}
	cond, args, err := scope(p, authz.PermFindingsRead, 3)
	if err != nil {
		return nil, err
	}
	args = append([]any{p.OrganizationID, days}, args...)
	if extra != "" {
		cond += " AND " + fmt.Sprintf(extra, len(args)+1)
		args = append(args, extraArgs...)
	}
	// #nosec G201 -- d.col comes from the fixed dimensions table; cond is built from placeholders
	q := fmt.Sprintf(`
	WITH rs AS (
	  SELECT r.id, %s AS k FROM repositories r
	  WHERE r.organization_id = $1 AND r.archived_at IS NULL AND %s),
	g AS (SELECT k, count(*) AS repos FROM rs GROUP BY k),
	fo AS (
	  SELECT rs.k,
	         count(*) FILTER (WHERE f.severity = 'critical') AS c, count(*) FILTER (WHERE f.severity = 'high') AS h,
	         count(*) FILTER (WHERE f.severity = 'medium') AS m, count(*) FILTER (WHERE f.severity = 'low') AS l,
	         count(*) FILTER (WHERE f.severity = 'info') AS i, count(*) FILTER (WHERE f.kev) AS kev,
	         count(*) FILTER (WHERE f.sla_due_at < now()) AS breached, count(*) FILTER (WHERE f.risk_score >= 50) AS high_risk,
	         max(f.risk_score)::float8 AS max_risk, avg(f.risk_score)::float8 AS avg_risk
	  FROM findings f JOIN rs ON rs.id = f.repository_id
	  WHERE f.status IN `+openStatuses+` GROUP BY rs.k),
	fx AS (
	  SELECT rs.k, count(*) AS fixed,
	         avg(EXTRACT(EPOCH FROM (f.resolved_at - f.first_seen_at)) / 86400)::float8 AS mttr,
	         avg(CASE WHEN f.sla_due_at IS NULL OR f.resolved_at <= f.sla_due_at THEN 1.0 ELSE 0.0 END)::float8 AS in_sla
	  FROM findings f JOIN rs ON rs.id = f.repository_id
	  WHERE f.status = 'fixed' AND f.resolved_at >= now() - make_interval(days => $2) GROUP BY rs.k),
	sc AS (
	  SELECT rs.k, max(j.finished_at) AS last_scan FROM scan_jobs j JOIN rs ON rs.id = j.repository_id
	  WHERE j.status IN ('succeeded', 'partial') GROUP BY rs.k),
	cov AS (
	  SELECT x.k, avg(x.cats / 3.0)::float8 AS coverage FROM (
	    SELECT rs.k, rs.id, (SELECT count(DISTINCT c.category) FROM scan_jobs j
	        JOIN scan_results sr ON sr.scan_job_id = j.id JOIN scanner_catalog c ON c.key = sr.scanner_key
	        WHERE j.repository_id = rs.id AND j.target_id IS NULL AND sr.status = 'succeeded'
	          AND j.finished_at >= now() - interval '30 days' AND c.category IN ('sast', 'sca', 'secrets')) AS cats
	    FROM rs) x GROUP BY x.k)
	SELECT g.k, g.repos, COALESCE(fo.c, 0), COALESCE(fo.h, 0), COALESCE(fo.m, 0), COALESCE(fo.l, 0), COALESCE(fo.i, 0),
	       COALESCE(fo.kev, 0), COALESCE(fo.breached, 0), COALESCE(fo.high_risk, 0), fo.max_risk, fo.avg_risk,
	       COALESCE(fx.fixed, 0), fx.mttr, fx.in_sla, sc.last_scan, cov.coverage
	FROM g LEFT JOIN fo ON fo.k IS NOT DISTINCT FROM g.k LEFT JOIN fx ON fx.k IS NOT DISTINCT FROM g.k
	LEFT JOIN sc ON sc.k IS NOT DISTINCT FROM g.k LEFT JOIN cov ON cov.k IS NOT DISTINCT FROM g.k`, d.col, cond)
	rows, err := s.DB.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Group
	var ids []uuid.UUID
	for rows.Next() {
		g := Group{Open: map[string]int{}}
		var c, h, m, l, i int
		if err := rows.Scan(&g.ID, &g.Repositories, &c, &h, &m, &l, &i, &g.KEV, &g.SLABreached, &g.HighRisk, &g.MaxRisk, &g.AvgRisk,
			&g.Fixed, &g.MTTRDays, &g.SLACompliance, &g.LastScanAt, &g.Coverage); err != nil {
			return nil, err
		}
		g.Open = map[string]int{"critical": c, "high": h, "medium": m, "low": l, "info": i}
		g.OpenTotal = c + h + m + l + i
		g.RiskScore, g.RiskBasis = rollup(g.MaxRisk, g.HighRisk)
		g.RiskBand = "none"
		if g.MaxRisk != nil {
			g.RiskBand = risk.Band(g.RiskScore)
		}
		for _, v := range []*float64{g.AvgRisk, g.MTTRDays, g.SLACompliance, g.Coverage} {
			if v != nil {
				*v = float64(int(*v*10+0.5)) / 10
				if v == g.SLACompliance || v == g.Coverage {
					*v = float64(int(*v*1000+0.5)) / 10 // percent, one decimal
				}
			}
		}
		if g.ID != nil {
			ids = append(ids, *g.ID)
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	labels := map[uuid.UUID]string{}
	if len(ids) > 0 {
		lrows, err := s.DB.Query(ctx, d.labelSQL, ids)
		if err != nil {
			return nil, err
		}
		for lrows.Next() {
			var id uuid.UUID
			var name string
			if err := lrows.Scan(&id, &name); err != nil {
				lrows.Close()
				return nil, err
			}
			labels[id] = name
		}
		lrows.Close()
	}
	for i := range out {
		if out[i].ID == nil {
			out[i].Label = map[string]string{"application": "No application", "business_unit": "No business unit", "team": "No team",
				"owner": "No owner", "region": "No region"}[dim]
		} else {
			out[i].Label = labels[*out[i].ID]
		}
	}
	sort.SliceStable(out, func(a, b int) bool {
		if out[a].RiskScore != out[b].RiskScore {
			return out[a].RiskScore > out[b].RiskScore
		}
		return out[a].Label < out[b].Label
	})
	return out, nil
}

func (s *Service) aggregate(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	days, err := intParam(r, "days", 90, 7, 365)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	by := r.URL.Query().Get("by")
	if by == "" {
		by = "application"
	}
	out, err := s.groups(r.Context(), p, by, days, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Group{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"by": by, "days": days, "items": out})
}

// AppPosture is an application's posture with its metadata.
type AppPosture struct {
	Group
	Key          string  `json:"application_key"`
	Criticality  string  `json:"criticality"`
	Lifecycle    string  `json:"lifecycle"`
	Environment  string  `json:"environment"`
	BusinessUnit *string `json:"business_unit"`
	Owner        *string `json:"owner"`
	// Targets counts scan targets (images, web applications, APIs, SBOMs).
	Targets int `json:"scan_targets"`
}

func (s *Service) applications(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	days, err := intParam(r, "days", 90, 7, 365)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	gs, err := s.groups(ctx, p, "application", days, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ids := make([]uuid.UUID, 0, len(gs))
	for _, g := range gs {
		if g.ID != nil {
			ids = append(ids, *g.ID)
		}
	}
	type meta struct {
		key, crit, life, env string
		bu, owner            *string
		targets              int
	}
	metas := map[uuid.UUID]meta{}
	rows, err := s.DB.Query(ctx, `SELECT a.id, a.application_key, a.criticality, a.lifecycle, a.environment, bu.name,
		COALESCE(NULLIF(u.display_name, ''), u.email),
		(SELECT count(*) FROM scan_targets t JOIN repositories r ON r.id = t.repository_id WHERE r.application_id = a.id AND t.enabled)
		FROM applications a LEFT JOIN business_units bu ON bu.id = a.business_unit_id
		LEFT JOIN users u ON u.id = COALESCE(a.owner_user_id, a.technical_owner_user_id, a.security_owner_user_id)
		WHERE a.id = ANY($1)`, ids)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for rows.Next() {
		var id uuid.UUID
		var m meta
		if err := rows.Scan(&id, &m.key, &m.crit, &m.life, &m.env, &m.bu, &m.owner, &m.targets); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		metas[id] = m
	}
	rows.Close()
	out := make([]AppPosture, 0, len(gs))
	for _, g := range gs {
		a := AppPosture{Group: g}
		if g.ID != nil {
			m := metas[*g.ID]
			a.Key, a.Criticality, a.Lifecycle, a.Environment, a.BusinessUnit, a.Owner, a.Targets = m.key, m.crit, m.life, m.env, m.bu, m.owner, m.targets
		}
		out = append(out, a)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"days": days, "items": out})
}

// Benchmark compares groups on normalised metrics.
type Benchmark struct {
	Group
	// Per repository, so large and small groups compare fairly.
	OpenPerRepo     float64 `json:"open_per_repository"`
	CriticalHighPer float64 `json:"critical_high_per_repository"`
	// Rank of the group on its risk (1 = riskiest).
	Rank int `json:"rank"`
}

// benchmarkMetric names a metric and whether lower values are better.
type benchmarkMetric struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	LowerBetter bool   `json:"lower_is_better"`
}

var benchmarkMetrics = []benchmarkMetric{
	{"risk_score", "Risk", true},
	{"open_per_repository", "Open findings per repository", true},
	{"critical_high_per_repository", "Critical and high per repository", true},
	{"kev_open", "Exploited (KEV) open", true},
	{"mttr_days", "Mean time to remediate (days)", true},
	{"sla_compliance", "Fixed within SLA (%)", false},
	{"coverage", "Scan coverage (%)", false},
}

func (s *Service) benchmark(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	days, err := intParam(r, "days", 90, 7, 365)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	by := r.URL.Query().Get("by")
	if by == "" {
		by = "application"
	}
	if !slices.Contains([]string{"application", "business_unit", "team", "owner", "region"}, by) {
		s.fail(w, r, httpx.BadRequest("by must be application, business_unit, team, owner or region"))
		return
	}
	gs, err := s.groups(r.Context(), p, by, days, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := make([]Benchmark, 0, len(gs))
	for i, g := range gs {
		b := Benchmark{Group: g, Rank: i + 1}
		if g.Repositories > 0 {
			b.OpenPerRepo = float64(int(float64(g.OpenTotal)/float64(g.Repositories)*10+0.5)) / 10
			b.CriticalHighPer = float64(int(float64(g.Open["critical"]+g.Open["high"])/float64(g.Repositories)*10+0.5)) / 10
		}
		out = append(out, b)
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"by": by, "days": days, "metrics": benchmarkMetrics, "items": out})
}
