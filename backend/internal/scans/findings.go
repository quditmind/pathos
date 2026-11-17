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
	HumanReviewID    *uuid.UUID   `json:"human_review_id"`
	HumanReviewKey   *string      `json:"human_review_key"`
	HumanReviewState *string      `json:"human_review_status"`
	HumanDisposition *string      `json:"human_disposition"`
	HumanSeverity    *string      `json:"human_severity"`
	Snippet          string       `json:"snippet,omitempty"`
	SnippetStart     *int         `json:"snippet_start_line,omitempty"`
	Occurrences      []Occurrence `json:"occurrences,omitempty"`
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
	       hr.id, hr.review_key, hr.status, f.human_disposition, f.human_severity
	FROM findings f JOIN repositories r ON r.id = f.repository_id LEFT JOIN users au ON au.id = f.assignee_id
	LEFT JOIN human_reviews hr ON hr.finding_id = f.id`

func scanFinding(row pgx.Row) (FindingView, error) {
	var f FindingView
	err := row.Scan(&f.ID, &f.RepositoryID, &f.RepositoryName, &f.RepositoryKey, &f.Category, &f.ScannerKeys, &f.RuleID, &f.Title, &f.Description,
		&f.Severity, &f.CWE, &f.CVE, &f.CVSS, &f.PackageName, &f.PackageVersion, &f.FixedVersion, &f.FilePath, &f.StartLine,
		&f.Status, &f.FirstSeenAt, &f.LastSeenAt, &f.ResolvedAt, &f.AssigneeID, &f.AssigneeName, &f.SLADueAt, &f.Recurrence,
		&f.AcceptedUntil, &f.AIStatus, &f.HumanReviewID, &f.HumanReviewKey, &f.HumanReviewState, &f.HumanDisposition, &f.HumanSeverity)
	if errors.Is(err, pgx.ErrNoRows) {
		return f, errNotFound
	}
	return f, err
}

var (
	findingStatuses   = []string{"open", "fixed", "false_positive", "accepted_risk", "in_progress", "needs_review"}
	findingCategories = []string{"secrets", "sast", "sca", "iac", "container", "license", "other"}
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
	if c := r.URL.Query().Get("cursor"); c != "" {
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
		where = append(where, fmt.Sprintf("(%s, f.last_seen_at, f.id) < ($%d, $%d, $%d)", sevRank, n-2, n-1, n))
	}
	sql := findingSelect + " WHERE " + strings.Join(where, " AND ") + " ORDER BY " + sevRank + " DESC, f.last_seen_at DESC, f.id DESC LIMIT 100"
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
		c := fmt.Sprintf("%d|%s|%s", scanners.SeverityRank(last.Severity), last.LastSeenAt.Format(time.RFC3339Nano), last.ID)
		next = &c
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "next_cursor": next})
}

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
		FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE `+strings.Join(where, " AND "), args...).Scan(&c[0], &c[1], &c[2], &c[3], &c[4])
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
