package review

import (
	"context"
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

const fromJoins = ` FROM human_reviews h JOIN findings f ON f.id = h.finding_id JOIN repositories r ON r.id = h.repository_id
	LEFT JOIN applications a ON a.id = r.application_id LEFT JOIN users ru ON ru.id = h.reviewer_id `

// Count is one bucket of a distribution.
type Count struct {
	Key   string `json:"key"`
	Label string `json:"label,omitempty"`
	Count int    `json:"count"`
}

func (s *Service) counts(ctx context.Context, f *filter, expr, labelExpr string, limit int) ([]Count, error) {
	if labelExpr == "" {
		labelExpr = "''"
	}
	sql := `SELECT COALESCE(` + expr + `::text, 'none'), COALESCE(max(` + labelExpr + `), ''), count(*)` + fromJoins + ` WHERE ` + f.sql() +
		` GROUP BY 1 ORDER BY 3 DESC, 1`
	if limit > 0 {
		sql += " LIMIT " + strconv.Itoa(limit)
	}
	rows, err := s.DB.Query(ctx, sql, f.args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Count])
	if out == nil {
		out = []Count{}
	}
	return out, err
}

// Workload is one analyst's review load.
type Workload struct {
	ReviewerID   *uuid.UUID `json:"reviewer_id"`
	ReviewerName string     `json:"reviewer_name"`
	Assigned     int        `json:"assigned"`
	Pending      int        `json:"pending"`
	InProgress   int        `json:"in_progress"`
	Completed    int        `json:"completed"`
	Overdue      int        `json:"overdue"`
	AvgHours     *float64   `json:"avg_completion_hours"`
}

func (s *Service) workloadRows(ctx context.Context, f *filter) ([]Workload, error) {
	rows, err := s.DB.Query(ctx, `SELECT h.reviewer_id, COALESCE(max(COALESCE(NULLIF(ru.display_name, ''), ru.email)), 'Unassigned'),
		count(*) FILTER (WHERE h.status <> 'completed'),
		count(*) FILTER (WHERE h.status IN ('pending', 'assigned', 'reopened')),
		count(*) FILTER (WHERE h.status IN ('in_progress', 'awaiting_information', 'awaiting_independent_review')),
		count(*) FILTER (WHERE h.status = 'completed'),
		count(*) FILTER (WHERE h.status <> 'completed' AND h.due_at < now()),
		(avg(extract(epoch FROM h.completed_at - h.created_at)) FILTER (WHERE h.status = 'completed') / 3600)::float8`+
		fromJoins+` WHERE `+f.sql()+` GROUP BY h.reviewer_id ORDER BY 3 DESC, 2`, f.args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Workload])
	if out == nil {
		out = []Workload{}
	}
	return out, err
}

// TrendPoint is one day of the completion trend.
type TrendPoint struct {
	Day       string `json:"day"`
	Created   int    `json:"created"`
	Completed int    `json:"completed"`
}

func dateRange(q url.Values) (time.Time, time.Time) {
	to := time.Now().UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	from := to.AddDate(0, 0, -30)
	if v := q.Get("from"); v != "" {
		if t, err := parseTime(v); err == nil {
			from = t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := parseTime(v); err == nil {
			to = t
			if len(v) == 10 {
				to = to.Add(24 * time.Hour)
			}
		}
	}
	if to.Sub(from) > 366*24*time.Hour {
		from = to.AddDate(-1, 0, 0)
	}
	return from, to
}

func withoutDates(q url.Values) url.Values {
	c := url.Values{}
	for k, v := range q {
		if k != "from" && k != "to" {
			c[k] = v
		}
	}
	return c
}

func (s *Service) trend(ctx context.Context, p *authz.Principal, q url.Values) ([]TrendPoint, error) {
	f, err := s.buildFilter(p, withoutDates(q), "h.created_at")
	if err != nil {
		return nil, err
	}
	from, to := dateRange(q)
	n := len(f.args)
	args := append(append([]any{}, f.args...), from, to)
	rows, err := s.DB.Query(ctx, fmt.Sprintf(`WITH base AS (SELECT h.created_at, h.completed_at`+fromJoins+` WHERE `+f.sql()+`)
		SELECT to_char(d, 'YYYY-MM-DD'),
		  (SELECT count(*) FROM base WHERE created_at >= d AND created_at < d + interval '1 day'),
		  (SELECT count(*) FROM base WHERE completed_at >= d AND completed_at < d + interval '1 day')
		FROM generate_series(date_trunc('day', $%d::timestamptz), $%d::timestamptz - interval '1 second', interval '1 day') d ORDER BY d`, n+1, n+2), args...)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[TrendPoint])
	if out == nil {
		out = []TrendPoint{}
	}
	return out, err
}

func (s *Service) awaitingRemediation(ctx context.Context, f *filter, limit int) ([]Item, int, error) {
	cond := f.sql() + ` AND h.disposition = 'confirmed' AND h.remediation_status IN ('open', 'in_progress', 'reopened', 'pending_verification')`
	var n int
	if err := s.DB.QueryRow(ctx, `SELECT count(*)`+fromJoins+` WHERE `+cond, f.args...).Scan(&n); err != nil {
		return nil, 0, err
	}
	rows, err := s.DB.Query(ctx, itemSelect+` WHERE `+cond+` ORDER BY array_position(ARRAY['critical','high','medium','low','info'],
		COALESCE(h.assessed_severity, h.original_severity)), h.completed_at LIMIT `+strconv.Itoa(limit), f.args...)
	if err != nil {
		return nil, 0, err
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Item, error) { return scanItem(row) })
	if items == nil {
		items = []Item{}
	}
	return items, n, err
}

// Overview is the Human Eye dashboard.
type Overview struct {
	Metrics struct {
		Total          int      `json:"total"`
		Pending        int      `json:"pending"`
		InProgress     int      `json:"in_progress"`
		Completed      int      `json:"completed"`
		Confirmed      int      `json:"confirmed"`
		FalsePositives int      `json:"false_positives"`
		Duplicates     int      `json:"duplicates"`
		NotExploitable int      `json:"not_exploitable"`
		AcceptedRisks  int      `json:"accepted_risks"`
		Overdue        int      `json:"overdue"`
		AvgHours       *float64 `json:"avg_completion_hours"`
		AwaitingRemedy int      `json:"confirmed_awaiting_remediation"`
		AwaitingSecond int      `json:"awaiting_independent_review"`
	} `json:"metrics"`
	BySeverity          []Count      `json:"by_severity"`
	ByStatus            []Count      `json:"by_status"`
	ByDisposition       []Count      `json:"by_disposition"`
	ByScanner           []Count      `json:"by_scanner"`
	Workload            []Workload   `json:"workload"`
	Trend               []TrendPoint `json:"trend"`
	AwaitingRemediation []Item       `json:"awaiting_remediation"`
}

func (s *Service) overview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	q := r.URL.Query()
	f, err := s.buildFilter(p, q, "h.created_at")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var o Overview
	m := &o.Metrics
	err = s.DB.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER (WHERE h.status IN ('pending', 'assigned', 'reopened')),
		count(*) FILTER (WHERE h.status IN ('in_progress', 'awaiting_information', 'awaiting_independent_review')),
		count(*) FILTER (WHERE h.status = 'completed'),
		count(*) FILTER (WHERE h.status = 'completed' AND h.disposition = 'confirmed'),
		count(*) FILTER (WHERE h.status = 'completed' AND h.disposition = 'false_positive'),
		count(*) FILTER (WHERE h.status = 'completed' AND h.disposition = 'duplicate'),
		count(*) FILTER (WHERE h.status = 'completed' AND h.disposition = 'not_exploitable'),
		count(*) FILTER (WHERE h.status = 'completed' AND h.disposition = 'accepted_risk'),
		count(*) FILTER (WHERE h.status <> 'completed' AND h.due_at < now()),
		(avg(extract(epoch FROM h.completed_at - h.created_at)) FILTER (WHERE h.status = 'completed') / 3600)::float8,
		count(*) FILTER (WHERE h.status = 'awaiting_independent_review')`+fromJoins+` WHERE `+f.sql(), f.args...).
		Scan(&m.Total, &m.Pending, &m.InProgress, &m.Completed, &m.Confirmed, &m.FalsePositives, &m.Duplicates, &m.NotExploitable,
			&m.AcceptedRisks, &m.Overdue, &m.AvgHours, &m.AwaitingSecond)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, x := range []struct {
		dst       *[]Count
		expr, lbl string
		limit     int
	}{
		{&o.BySeverity, "COALESCE(h.assessed_severity, h.original_severity)", "", 0},
		{&o.ByStatus, "h.status", "", 0},
		{&o.ByDisposition, "h.disposition", "", 0},
		{&o.ByScanner, "h.scanner_key", "", 20},
	} {
		if *x.dst, err = s.counts(ctx, f, x.expr, x.lbl, x.limit); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if o.Workload, err = s.workloadRows(ctx, f); err != nil {
		s.fail(w, r, err)
		return
	}
	if o.Trend, err = s.trend(ctx, p, q); err != nil {
		s.fail(w, r, err)
		return
	}
	if o.AwaitingRemediation, m.AwaitingRemedy, err = s.awaitingRemediation(ctx, f, 10); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, o)
}

// workload lists analyst workload (Assignments page).
func (s *Service) workload(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !isWorker(p) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	f, err := s.buildFilter(p, r.URL.Query(), "h.created_at")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := s.workloadRows(ctx, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// SeverityAdjustment is one human severity change.
type SeverityAdjustment struct {
	ReviewID   uuid.UUID `json:"review_id"`
	ReviewKey  string    `json:"review_key"`
	Title      string    `json:"title"`
	Repository string    `json:"repository"`
	Original   string    `json:"original"`
	Assessed   string    `json:"assessed"`
	Reason     string    `json:"justification"`
}

// Report is the Review Reports payload.
type Report struct {
	From               time.Time            `json:"from"`
	To                 time.Time            `json:"to"`
	TotalReviewed      int                  `json:"total_reviewed"`
	Confirmed          int                  `json:"confirmed"`
	FalsePositives     int                  `json:"false_positives"`
	FalsePositivePct   float64              `json:"false_positive_pct"`
	AvgHours           *float64             `json:"avg_review_hours"`
	Overdue            int                  `json:"overdue"`
	BySeverity         []Count              `json:"by_severity"`
	ByScanner          []Count              `json:"by_scanner"`
	ByRepository       []Count              `json:"by_repository"`
	ByDisposition      []Count              `json:"by_disposition"`
	ByAnalyst          []Workload           `json:"by_analyst"`
	SeverityUp         int                  `json:"severity_raised"`
	SeverityDown       int                  `json:"severity_lowered"`
	Adjustments        []SeverityAdjustment `json:"severity_adjustments"`
	Independent        []Count              `json:"independent_review_results"`
	AwaitingRemedy     int                  `json:"confirmed_awaiting_remediation"`
	AwaitingRemedyList []Item               `json:"awaiting_remediation"`
}

// reports covers reviews completed in the period (default: 30 days).
func (s *Service) reports(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	q := r.URL.Query()
	from, to := dateRange(q)
	cq := withoutDates(q)
	f, err := s.buildFilter(p, cq, "h.completed_at")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	open, err := s.buildFilter(p, cq, "h.created_at")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f.where = append(f.where, "h.status = 'completed'")
	f.add("h.completed_at >= ?", from)
	f.add("h.completed_at < ?", to)
	rep := Report{From: from, To: to}
	err = s.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE h.disposition = 'confirmed'), count(*) FILTER (WHERE h.disposition = 'false_positive'),
		(avg(extract(epoch FROM h.completed_at - h.created_at)) / 3600)::float8,
		count(*) FILTER (WHERE h.assessed_severity IS NOT NULL AND array_position(ARRAY['info','low','medium','high','critical'], h.assessed_severity)
		                 > array_position(ARRAY['info','low','medium','high','critical'], h.original_severity)),
		count(*) FILTER (WHERE h.assessed_severity IS NOT NULL AND array_position(ARRAY['info','low','medium','high','critical'], h.assessed_severity)
		                 < array_position(ARRAY['info','low','medium','high','critical'], h.original_severity))`+fromJoins+` WHERE `+f.sql(), f.args...).
		Scan(&rep.TotalReviewed, &rep.Confirmed, &rep.FalsePositives, &rep.AvgHours, &rep.SeverityUp, &rep.SeverityDown)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rep.TotalReviewed > 0 {
		rep.FalsePositivePct = float64(int(float64(rep.FalsePositives)/float64(rep.TotalReviewed)*1000+0.5)) / 10
	}
	open.where = append(open.where, "h.status <> 'completed' AND h.due_at < now()")
	if err := s.DB.QueryRow(ctx, `SELECT count(*)`+fromJoins+` WHERE `+open.sql(), open.args...).Scan(&rep.Overdue); err != nil {
		s.fail(w, r, err)
		return
	}
	for _, x := range []struct {
		dst       *[]Count
		expr, lbl string
		limit     int
	}{
		{&rep.BySeverity, "COALESCE(h.assessed_severity, h.original_severity)", "", 0},
		{&rep.ByScanner, "h.scanner_key", "", 50},
		{&rep.ByRepository, "h.repository_id", "r.full_name", 50},
		{&rep.ByDisposition, "h.disposition", "", 0},
	} {
		if *x.dst, err = s.counts(ctx, f, x.expr, x.lbl, x.limit); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if rep.ByAnalyst, err = s.workloadRows(ctx, f); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT h.id, h.review_key, f.title, r.full_name, h.original_severity, h.assessed_severity, h.severity_justification`+
		fromJoins+` WHERE `+f.sql()+` AND h.assessed_severity IS NOT NULL AND h.assessed_severity <> h.original_severity ORDER BY h.completed_at DESC LIMIT 100`, f.args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rep.Adjustments, err = pgx.CollectRows(rows, pgx.RowToStructByPos[SeverityAdjustment]); err != nil {
		s.fail(w, r, err)
		return
	}
	if rep.Adjustments == nil {
		rep.Adjustments = []SeverityAdjustment{}
	}
	rows, err = s.DB.Query(ctx, `SELECT ap.outcome, '', count(*) FROM human_review_approvals ap JOIN human_reviews h ON h.id = ap.review_id
		JOIN findings f ON f.id = h.finding_id JOIN repositories r ON r.id = h.repository_id LEFT JOIN applications a ON a.id = r.application_id
		LEFT JOIN users ru ON ru.id = h.reviewer_id WHERE `+strings.Join(withoutStatus(f.where), " AND ")+
		` GROUP BY 1 ORDER BY 1`, f.args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rep.Independent, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Count]); err != nil {
		s.fail(w, r, err)
		return
	}
	if rep.Independent == nil {
		rep.Independent = []Count{}
	}
	nf, err := s.buildFilter(p, cq, "h.created_at")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if rep.AwaitingRemedyList, rep.AwaitingRemedy, err = s.awaitingRemediation(ctx, nf, 50); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rep)
}

// withoutStatus drops the completed-only condition (independent review
// outcomes include rejected decisions on reviews that are still open) and
// rewrites the completed_at range to the approval time.
func withoutStatus(where []string) []string {
	out := make([]string, 0, len(where))
	for _, c := range where {
		switch {
		case c == "h.status = 'completed'":
			continue
		case strings.HasPrefix(c, "h.completed_at "):
			out = append(out, "ap.created_at "+strings.TrimPrefix(c, "h.completed_at "))
		default:
			out = append(out, c)
		}
	}
	return out
}

// csvCell neutralizes spreadsheet formulas.
func csvCell(s string) string {
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		return "'" + s
	}
	return s
}

// exportCSV exports reviews matching the filters (CSV).
func (s *Service) exportCSV(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermFindingsExport) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	f, err := s.buildFilter(p, r.URL.Query(), "h.created_at")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Only repositories where the caller may export, not every repository
	// they can read because they may export somewhere.
	ef := authz.FilterFor(p, authz.PermFindingsExport)
	escope, eargs := org.ScopeSQL(ef, "r.id", "r.business_unit_id", "r.country_id", len(f.args)+1)
	f.args = append(f.args, eargs...)
	f.where = append(f.where, escope)
	rows, err := s.DB.Query(ctx, `SELECT h.review_key, h.finding_id::text, f.title, f.category, h.original_severity, COALESCE(h.assessed_severity, ''),
		COALESCE(h.assessed_cvss::text, ''), h.assessed_cvss_vector, h.scanner_key, r.full_name, COALESCE(a.name, ''), h.branch, h.commit_sha,
		h.file_path, COALESCE(h.start_line::text, ''), h.status, COALESCE(h.disposition, ''), COALESCE(h.remediation_status, ''), h.priority,
		COALESCE(COALESCE(NULLIF(ru.display_name, ''), ru.email), ''), COALESCE(to_char(h.due_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), ''),
		to_char(h.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
		COALESCE(to_char(h.completed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), ''),
		COALESCE((SELECT d.reason FROM human_review_decisions d WHERE d.review_id = h.id ORDER BY d.created_at DESC LIMIT 1), ''),
		COALESCE((SELECT ap.outcome FROM human_review_approvals ap WHERE ap.review_id = h.id ORDER BY ap.created_at DESC LIMIT 1), '')`+
		fromJoins+` WHERE `+f.sql()+` ORDER BY h.created_at DESC LIMIT 50000`, f.args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	// The stamp is in the headers: the CSV must start with its header row.
	httpx.Download(w, "text/csv; charset=utf-8", fmt.Sprintf("human-reviews-%s.csv", time.Now().UTC().Format("20060102")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"review_id", "finding_id", "title", "category", "scanner_severity", "assessed_severity", "assessed_cvss", "assessed_cvss_vector",
		"scanner", "repository", "application", "branch", "commit", "file", "line", "review_status", "disposition", "remediation_status", "priority",
		"reviewer", "due_at", "created_at", "completed_at", "decision_reason", "independent_review"})
	n := 0
	for rows.Next() {
		vals := make([]string, 25)
		ptrs := make([]any, 25)
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			s.Log.Error("review export", "err", err)
			return
		}
		for i := range vals {
			vals[i] = csvCell(vals[i])
		}
		_ = cw.Write(vals)
		n++
	}
	cw.Flush()
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "human_review.export", TargetType: "organization", TargetID: p.OrganizationID.String(), Metadata: map[string]any{"rows": n, "query": r.URL.RawQuery}})
}
