package scans

import (
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
)

// Read-only findings API. Triage, assignment and SLAs arrive in Phase 6.
func (s *Service) registerFindings(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/findings", s.listFindings)
	mux.HandleFunc("GET /api/v1/findings/summary", s.findingsSummary)
	mux.HandleFunc("GET /api/v1/findings/{id}", s.getFinding)
}

// FindingView is the API representation.
type FindingView struct {
	ID             uuid.UUID  `json:"id"`
	RepositoryID   uuid.UUID  `json:"repository_id"`
	RepositoryName string     `json:"repository_name"`
	RepositoryKey  string     `json:"repository_key"`
	Category       string     `json:"category"`
	ScannerKeys    []string   `json:"scanner_keys"`
	RuleID         string     `json:"rule_id"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Severity       string     `json:"severity"`
	CWE            []string   `json:"cwe"`
	CVE            string     `json:"cve"`
	CVSS           *float64   `json:"cvss"`
	PackageName    string     `json:"package_name"`
	PackageVersion string     `json:"package_version"`
	FixedVersion   string     `json:"fixed_version"`
	FilePath       string     `json:"file_path"`
	StartLine      *int       `json:"start_line"`
	Status         string     `json:"status"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
	AssigneeID     *uuid.UUID `json:"assignee_id"`
	AssigneeName   *string    `json:"assignee_name"`
	SLADueAt       *time.Time `json:"sla_due_at"`
	Recurrence     int        `json:"recurrence_count"`
	AcceptedUntil  *time.Time `json:"accepted_until"`
	AIStatus       string     `json:"ai_status"`
	// Human Eye outcome (the scanner data above is unchanged by it).
	HumanReviewID    *uuid.UUID `json:"human_review_id"`
	HumanReviewKey   *string    `json:"human_review_key"`
	HumanReviewState *string    `json:"human_review_status"`
	HumanDisposition *string    `json:"human_disposition"`
	HumanSeverity    *string    `json:"human_severity"`
	// Unified lifecycle status (derived, see LifecycleExpr): new, open,
	// in_progress, under_review, confirmed, false_positive, accepted_risk,
	// resolved, reopened.
	Lifecycle string `json:"lifecycle_status"`
	// Vulnerability intelligence and contextual risk.
	CVSSVersion      string     `json:"cvss_version"`
	CVSSVector       string     `json:"cvss_vector"`
	Confidence       string     `json:"confidence"`
	EPSS             *float64   `json:"epss"`
	EPSSPercentile   *float64   `json:"epss_percentile"`
	KEV              bool       `json:"kev"`
	KEVDueDate       *time.Time `json:"kev_due_date"`
	ExploitAvailable bool       `json:"exploit_available"`
	Reachability     string     `json:"reachability"`
	// ReachabilityBasis explains the reachability (empty when unknown).
	ReachabilityBasis string `json:"reachability_basis"`
	// SuppressionRuleID is the approved rule that decided the status.
	SuppressionRuleID *uuid.UUID `json:"suppression_rule_id"`
	// Malicious: the package itself is malware (OSV MAL-*).
	Malicious bool `json:"malicious"`
	// IntroducedCommit is the commit of the scan that first detected it.
	IntroducedCommit string     `json:"introduced_commit"`
	RiskScore        *float64   `json:"risk_score"`
	ApplicationID    *uuid.UUID `json:"application_id"`
	ApplicationName  *string    `json:"application_name"`
	// Scan target the finding belongs to (nil: the repository's code).
	TargetID     *uuid.UUID   `json:"scan_target_id"`
	TargetKind   *string      `json:"scan_target_kind"`
	TargetName   *string      `json:"scan_target_name"`
	Snippet      string       `json:"snippet,omitempty"`
	SnippetStart *int         `json:"snippet_start_line,omitempty"`
	Occurrences  []Occurrence `json:"occurrences,omitempty"`
}

// Occurrence is one sighting of a finding.
type Occurrence struct {
	ScanJobID  uuid.UUID `json:"scan_job_id"`
	ScannerKey string    `json:"scanner_key"`
	CommitSHA  string    `json:"commit_sha"`
	FilePath   string    `json:"file_path"`
	StartLine  *int      `json:"start_line"`
	SeenAt     time.Time `json:"seen_at"`
}

const findingSelect = `
	SELECT f.id, f.repository_id, r.full_name, r.repository_key, f.category, f.scanner_keys, f.rule_id, f.title, f.description, f.severity,
	       f.cwe, f.cve, f.cvss::float8, f.package_name, f.package_version, f.fixed_version, f.file_path, f.start_line,
	       f.status, f.first_seen_at, f.last_seen_at, f.resolved_at, f.assignee_id,
	       COALESCE(NULLIF(au.display_name, ''), au.email), f.sla_due_at, f.recurrence_count, f.accepted_until, f.ai_status,
	       hr.id, hr.review_key, hr.status, f.human_disposition, f.human_severity, ` + LifecycleExpr + `,
	       f.cvss_version, f.cvss_vector, f.confidence, f.epss_score::float8, f.epss_percentile::float8, f.kev, f.kev_due_date,
	       f.exploit_available, f.reachability, f.risk_score::float8, app.id, app.name, f.scan_target_id, stg.kind, stg.name, f.reachability_basis, f.suppression_rule_id, f.malicious,
	       COALESCE((SELECT fj.commit_sha FROM scan_jobs fj WHERE fj.id = f.first_scan_job_id), '')
	FROM findings f JOIN repositories r ON r.id = f.repository_id LEFT JOIN users au ON au.id = f.assignee_id
	LEFT JOIN human_reviews hr ON hr.finding_id = f.id LEFT JOIN applications app ON app.id = r.application_id
	LEFT JOIN scan_targets stg ON stg.id = f.scan_target_id`

// LifecycleExpr derives the unified lifecycle status from the stored
// status, Human Eye state, recurrence and triage activity. Stored statuses
// are unchanged (history, SLA and AI policy depend on them):
//
//	resolved       status fixed
//	false_positive status false_positive
//	accepted_risk  status accepted_risk
//	under_review   status needs_review, or a Human Eye review is open
//	confirmed      a human reviewer confirmed it (still open)
//	in_progress    status in_progress
//	reopened       detected again after being fixed
//	new            first seen by the latest scan, nobody has touched it
//	open           everything else that is open
const LifecycleExpr = `CASE
	WHEN f.status = 'fixed' THEN 'resolved'
	WHEN f.status = 'false_positive' THEN 'false_positive'
	WHEN f.status = 'accepted_risk' THEN 'accepted_risk'
	WHEN f.status = 'needs_review' OR (hr.id IS NOT NULL AND hr.status <> 'completed') THEN 'under_review'
	WHEN f.human_disposition = 'confirmed' THEN 'confirmed'
	WHEN f.status = 'in_progress' THEN 'in_progress'
	WHEN f.recurrence_count > 0 THEN 'reopened'
	WHEN f.assignee_id IS NULL AND f.first_scan_job_id IS NOT DISTINCT FROM f.last_scan_job_id
	     AND f.ai_status IN ('none', 'queued', 'failed', 'skipped') THEN 'new'
	ELSE 'open' END`

// LifecycleStatuses lists the unified statuses in workflow order.
var LifecycleStatuses = []string{"new", "open", "in_progress", "under_review", "confirmed", "false_positive", "accepted_risk", "resolved", "reopened"}

func scanFinding(row pgx.Row) (FindingView, error) {
	var f FindingView
	err := row.Scan(&f.ID, &f.RepositoryID, &f.RepositoryName, &f.RepositoryKey, &f.Category, &f.ScannerKeys, &f.RuleID, &f.Title, &f.Description,
		&f.Severity, &f.CWE, &f.CVE, &f.CVSS, &f.PackageName, &f.PackageVersion, &f.FixedVersion, &f.FilePath, &f.StartLine,
		&f.Status, &f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.AssigneeID, &f.AssigneeName, &f.SLADueAt, &f.Recurrence,
		&f.AcceptedUntil, &f.AIStatus, &f.HumanReviewID, &f.HumanReviewKey, &f.HumanReviewState, &f.HumanDisposition, &f.HumanSeverity,
		&f.Lifecycle, &f.CVSSVersion, &f.CVSSVector, &f.Confidence, &f.EPSS, &f.EPSSPercentile, &f.KEV, &f.KEVDueDate, &f.ExploitAvailable,
		&f.Reachability, &f.RiskScore, &f.ApplicationID, &f.ApplicationName, &f.TargetID, &f.TargetKind, &f.TargetName, &f.ReachabilityBasis, &f.SuppressionRuleID, &f.Malicious, &f.IntroducedCommit)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, errNotFound
	}
	return f, err
}

var (
	findingStatuses   = []string{"open", "fixed", "false_positive", "accepted_risk", "in_progress", "needs_review"}
	findingCategories = []string{"secrets", "sast", "sca", "iac", "container", "license", "dast", "other"}
)

// findingsWhere builds the scoped WHERE clause shared by list and summary.
func (s *Service) findingsWhere(r *http.Request) ([]string, []any, error) {
	p := s.Principal(r.Context())
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.None() {
		return nil, nil, authz.ErrForbidden
	}
	args := []any{p.OrganizationID}
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	args = append(args, sargs...)
	where := []string{"f.organization_id = $1", "r.archived_at IS NULL", scope}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	q := r.URL.Query()
	status := q.Get("status")
	switch {
	case status == "" || status == "open":
		where = append(where, "f.status IN ('open', 'in_progress', 'needs_review')")
	case status == "all":
	case slices.Contains(findingStatuses, status):
		add("f.status = ?", status)
	default:
		return nil, nil, httpx.BadRequest("invalid status")
	}
	if v := q.Get("severity"); v != "" {
		var sev []string
		for _, x := range strings.Split(v, ",") {
			if !slices.Contains(scanners.Severities, x) {
				return nil, nil, httpx.BadRequest("invalid severity")
			}
			sev = append(sev, x)
		}
		add("f.severity = ANY(?)", sev)
	}
	if v := q.Get("category"); v != "" {
		if !slices.Contains(findingCategories, v) {
			return nil, nil, httpx.BadRequest("invalid category")
		}
		add("f.category = ?", v)
	}
	if v := q.Get("scanner"); v != "" {
		add("? = ANY(f.scanner_keys)", v)
	}
	if v := q.Get("repository_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, nil, httpx.BadRequest("invalid repository_id")
		}
		add("f.repository_id = ?", id)
	}
	switch v := q.Get("assignee"); v {
	case "":
	case "me":
		add("f.assignee_id = ?", s.Principal(r.Context()).UserID)
	case "none":
		where = append(where, "f.assignee_id IS NULL")
	default:
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, nil, httpx.BadRequest("assignee must be me, none or a user id")
		}
		add("f.assignee_id = ?", id)
	}
	switch q.Get("sla") {
	case "":
	case "breached":
		where = append(where, "f.sla_due_at < now() AND f.status IN ('open', 'in_progress', 'needs_review')")
	case "due_soon":
		where = append(where, "f.sla_due_at BETWEEN now() AND now() + interval '7 days' AND f.status IN ('open', 'in_progress', 'needs_review')")
	default:
		return nil, nil, httpx.BadRequest("sla must be breached or due_soon")
	}
	if v := q.Get("lifecycle"); v != "" {
		var ls []string
		for _, x := range strings.Split(v, ",") {
			if !slices.Contains(LifecycleStatuses, x) {
				return nil, nil, httpx.BadRequest("invalid lifecycle status")
			}
			ls = append(ls, x)
		}
		// Lifecycle spans every stored status; the default "open only"
		// filter does not apply.
		if status == "" {
			where = slices.DeleteFunc(where, func(c string) bool { return c == "f.status IN ('open', 'in_progress', 'needs_review')" })
		}
		add("("+LifecycleExpr+") = ANY(?)", ls)
	}
	switch q.Get("kev") {
	case "":
	case "true":
		where = append(where, "f.kev")
	case "false":
		where = append(where, "NOT f.kev")
	default:
		return nil, nil, httpx.BadRequest("kev must be true or false")
	}
	for _, x := range []struct {
		param, col string
		max        float64
	}{{"epss_min", "f.epss_percentile", 1}, {"risk_min", "f.risk_score", 100}} {
		if v := q.Get(x.param); v != "" {
			n, err := strconv.ParseFloat(v, 64)
			if err != nil || n < 0 || n > x.max {
				return nil, nil, httpx.BadRequest(fmt.Sprintf("%s must be between 0 and %g", x.param, x.max))
			}
			add(x.col+" >= ?", n)
		}
	}
	for _, x := range []struct {
		param, col string
		allowed    []string
	}{{"confidence", "f.confidence", []string{"high", "medium", "low", "unknown"}}, {"reachability", "f.reachability", []string{"reachable", "not_reachable", "unknown"}}} {
		if v := q.Get(x.param); v != "" {
			if !slices.Contains(x.allowed, v) {
				return nil, nil, httpx.BadRequest("invalid " + x.param)
			}
			add(x.col+" = ?", v)
		}
	}
	if v := q.Get("application_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, nil, httpx.BadRequest("invalid application_id")
		}
		add("r.application_id = ?", id)
	}
	if v := q.Get("scan_target_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, nil, httpx.BadRequest("invalid scan_target_id")
		}
		add("f.scan_target_id = ?", id)
	}
	if q.Get("malicious") == "true" {
		where = append(where, "f.malicious")
	}
	switch v := q.Get("target_kind"); v {
	case "":
	case "repository":
		where = append(where, "f.scan_target_id IS NULL")
	case "image", "url", "api", "sbom":
		add("f.scan_target_id IN (SELECT id FROM scan_targets WHERE kind = ?)", v)
	default:
		return nil, nil, httpx.BadRequest("invalid target_kind")
	}
	switch v := q.Get("human_review"); v {
	case "":
	case "none":
		where = append(where, "NOT EXISTS (SELECT 1 FROM human_reviews hx WHERE hx.finding_id = f.id)")
	case "open":
		where = append(where, "EXISTS (SELECT 1 FROM human_reviews hx WHERE hx.finding_id = f.id AND hx.status <> 'completed')")
	case "confirmed", "false_positive", "duplicate", "not_exploitable", "accepted_risk", "mitigated", "out_of_scope":
		add("f.human_disposition = ?", v)
	default:
		return nil, nil, httpx.BadRequest("human_review must be none, open or a disposition")
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(v)) + "%"
		add("(lower(f.title) LIKE ? OR lower(f.rule_id) LIKE ? OR lower(f.file_path) LIKE ? OR lower(f.package_name) LIKE ? OR lower(f.cve) LIKE ?)", like)
	}
	return where, args, nil
}

func (s *Service) listFindings(w http.ResponseWriter, r *http.Request) {
	where, args, err := s.findingsWhere(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// Order: severity (default) or contextual risk ("sort=risk"). Both use
	// keyset pagination on (rank, last_seen_at, id); risk ranks are the
	// score in hundredths (-1 = not scored yet).
	rankExpr, prefix := sevRank, ""
	switch r.URL.Query().Get("sort") {
	case "", "severity":
	case "risk":
		rankExpr, prefix = riskRank, "r"
	default:
		s.fail(w, r, httpx.BadRequest("sort must be severity or risk"))
		return
	}
	if c := r.URL.Query().Get("cursor"); c != "" {
		if prefix != "" {
			if !strings.HasPrefix(c, prefix+"|") {
				s.fail(w, r, httpx.BadRequest("invalid cursor"))
				return
			}
			c = strings.TrimPrefix(c, prefix+"|")
		}
		parts := strings.SplitN(c, "|", 3)
		if len(parts) != 3 {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		rank, err1 := strconv.Atoi(parts[0])
		t, err2 := time.Parse(time.RFC3339Nano, parts[1])
		id, err3 := uuid.Parse(parts[2])
		if err1 != nil || err2 != nil || err3 != nil {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		args = append(args, rank, t, id)
		n := len(args)
		where = append(where, fmt.Sprintf("(%s, f.last_seen_at, f.id) < ($%d, $%d, $%d)", rankExpr, n-2, n-1, n))
	}
	sql := findingSelect + " WHERE " + strings.Join(where, " AND ") + " ORDER BY " + rankExpr + " DESC, f.last_seen_at DESC, f.id DESC LIMIT 100"
	rows, err := s.DB.Query(r.Context(), sql, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (FindingView, error) { return scanFinding(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []FindingView{}
	}
	var next *string
	if len(out) == 100 {
		last := out[len(out)-1]
		rank := scanners.SeverityRank(last.Severity)
		if prefix == "r" {
			rank = -1
			if last.RiskScore != nil {
				rank = int(*last.RiskScore*100 + 0.5)
			}
		}
		c := fmt.Sprintf("%d|%s|%s", rank, last.LastSeenAt.Format(time.RFC3339Nano), last.ID)
		if prefix != "" {
			c = prefix + "|" + c
		}
		next = &c
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "next_cursor": next})
}

const riskRank = "COALESCE(round(f.risk_score * 100)::int, -1)"

const sevRank = "array_position(ARRAY['info','low','medium','high','critical'], f.severity) - 1"

func (s *Service) findingsSummary(w http.ResponseWriter, r *http.Request) {
	where, args, err := s.findingsWhere(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var c [5]int
	err = s.DB.QueryRow(r.Context(), `SELECT count(*) FILTER (WHERE f.severity = 'critical'), count(*) FILTER (WHERE f.severity = 'high'),
		count(*) FILTER (WHERE f.severity = 'medium'), count(*) FILTER (WHERE f.severity = 'low'), count(*) FILTER (WHERE f.severity = 'info')
		FROM findings f JOIN repositories r ON r.id = f.repository_id LEFT JOIN human_reviews hr ON hr.finding_id = f.id
		WHERE `+strings.Join(where, " AND "), args...).Scan(&c[0], &c[1], &c[2], &c[3], &c[4])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"critical": c[0], "high": c[1], "medium": c[2], "low": c[3], "info": c[4]})
}

func (s *Service) getFinding(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f, err := scanFinding(s.DB.QueryRow(ctx, findingSelect+` WHERE f.organization_id = $1 AND f.id = $2`, p.OrganizationID, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsRead, f.RepositoryID); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = s.DB.QueryRow(ctx, `SELECT snippet, snippet_start_line FROM findings WHERE id = $1`, f.ID).Scan(&f.Snippet, &f.SnippetStart)
	rows, err := s.DB.Query(ctx, `SELECT sr.scan_job_id, sr.scanner_key, o.commit_sha, o.file_path, o.start_line, o.created_at
		FROM finding_occurrences o JOIN scan_results sr ON sr.id = o.scan_result_id
		WHERE o.finding_id = $1 ORDER BY o.created_at DESC LIMIT 50`, f.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	f.Occurrences, err = pgx.CollectRows(rows, pgx.RowToStructByPos[Occurrence])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, f)
}
