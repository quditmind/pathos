package review

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Item is one row of the review queue.
type Item struct {
	ID                uuid.UUID  `json:"id"`
	ReviewKey         string     `json:"review_key"`
	FindingID         uuid.UUID  `json:"finding_id"`
	Title             string     `json:"title"`
	Category          string     `json:"category"`
	RuleID            string     `json:"rule_id"`
	Severity          string     `json:"severity"`
	AssessedSeverity  *string    `json:"assessed_severity"`
	Scanner           string     `json:"scanner"`
	RepositoryID      uuid.UUID  `json:"repository_id"`
	RepositoryName    string     `json:"repository_name"`
	RepositoryKey     string     `json:"repository_key"`
	ApplicationID     *uuid.UUID `json:"application_id"`
	ApplicationName   *string    `json:"application_name"`
	Branch            string     `json:"branch"`
	CommitSHA         string     `json:"commit_sha"`
	FilePath          string     `json:"file_path"`
	StartLine         *int       `json:"start_line"`
	DetectedAt        time.Time  `json:"detected_at"`
	ReviewerID        *uuid.UUID `json:"reviewer_id"`
	ReviewerName      *string    `json:"reviewer_name"`
	IndependentID     *uuid.UUID `json:"independent_reviewer_id"`
	IndependentName   *string    `json:"independent_reviewer_name"`
	Priority          string     `json:"priority"`
	Status            string     `json:"status"`
	Disposition       *string    `json:"disposition"`
	RemediationStatus *string    `json:"remediation_status"`
	DueAt             *time.Time `json:"due_at"`
	Overdue           bool       `json:"overdue"`
	Source            string     `json:"source"`
	Round             int        `json:"round"`
	FindingStatus     string     `json:"finding_status"`
	CreatedAt         time.Time  `json:"created_at"`
	CompletedAt       *time.Time `json:"completed_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

const itemSelect = `
	SELECT h.id, h.review_key, h.finding_id, f.title, f.category, f.rule_id, h.original_severity, h.assessed_severity, h.scanner_key,
	       h.repository_id, r.full_name, r.repository_key, a.id, a.name, h.branch, h.commit_sha, h.file_path, h.start_line, f.first_seen_at,
	       h.reviewer_id, COALESCE(NULLIF(ru.display_name, ''), ru.email), h.independent_reviewer_id, COALESCE(NULLIF(iu.display_name, ''), iu.email),
	       h.priority, h.status, h.disposition, h.remediation_status, h.due_at, (h.status <> 'completed' AND h.due_at < now()),
	       h.source, h.round, f.status, h.created_at, h.completed_at, h.updated_at
	FROM human_reviews h
	JOIN findings f ON f.id = h.finding_id
	JOIN repositories r ON r.id = h.repository_id
	LEFT JOIN applications a ON a.id = r.application_id
	LEFT JOIN users ru ON ru.id = h.reviewer_id
	LEFT JOIN users iu ON iu.id = h.independent_reviewer_id`

func scanItem(row pgx.Row) (Item, error) {
	var it Item
	err := row.Scan(&it.ID, &it.ReviewKey, &it.FindingID, &it.Title, &it.Category, &it.RuleID, &it.Severity, &it.AssessedSeverity, &it.Scanner,
		&it.RepositoryID, &it.RepositoryName, &it.RepositoryKey, &it.ApplicationID, &it.ApplicationName, &it.Branch, &it.CommitSHA, &it.FilePath,
		&it.StartLine, &it.DetectedAt, &it.ReviewerID, &it.ReviewerName, &it.IndependentID, &it.IndependentName, &it.Priority, &it.Status,
		&it.Disposition, &it.RemediationStatus, &it.DueAt, &it.Overdue, &it.Source, &it.Round, &it.FindingStatus, &it.CreatedAt, &it.CompletedAt,
		&it.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return it, errNotFound
	}
	return it, err
}

// filter is the scoped WHERE clause shared by the queue, overview and
// reports.
type filter struct {
	where []string
	args  []any
}

func (f *filter) add(cond string, v any) {
	f.args = append(f.args, v)
	f.where = append(f.where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(f.args))))
}

func (f *filter) sql() string { return strings.Join(f.where, " AND ") }

func listParam(q url.Values, key string) []string {
	var out []string
	for _, v := range q[key] {
		for _, x := range strings.Split(v, ",") {
			if x = strings.TrimSpace(x); x != "" {
				out = append(out, x)
			}
		}
	}
	return out
}

func checkAll(name string, vals, allowed []string) error {
	for _, v := range vals {
		if !slices.Contains(allowed, v) {
			return httpx.BadRequest("invalid " + name)
		}
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02", s)
}

// buildFilter scopes to the principal and applies query filters. dateCol
// is the column the from/to range applies to.
func (s *Service) buildFilter(p *authz.Principal, q url.Values, dateCol string) (*filter, error) {
	if p == nil {
		return nil, authz.ErrForbidden
	}
	af := authz.FilterFor(p, authz.PermReviewsRead)
	if af.None() {
		return nil, authz.ErrForbidden
	}
	f := &filter{args: []any{p.OrganizationID}, where: []string{"h.organization_id = $1", "r.archived_at IS NULL"}}
	scope, sargs := org.ScopeSQL(af, "r.id", "r.business_unit_id", "r.country_id", 2)
	f.args = append(f.args, sargs...)
	f.where = append(f.where, scope)
	if !isWorker(p) {
		f.where = append(f.where, "h.status = 'completed'")
	}
	if v := listParam(q, "status"); len(v) > 0 {
		if slices.Contains(v, "open") {
			f.where = append(f.where, "h.status <> 'completed'")
			v = slices.DeleteFunc(v, func(x string) bool { return x == "open" })
		}
		if len(v) > 0 {
			if err := checkAll("status", v, Statuses); err != nil {
				return nil, err
			}
			f.add("h.status = ANY(?)", v)
		}
	}
	if v := listParam(q, "disposition"); len(v) > 0 {
		if err := checkAll("disposition", v, Dispositions); err != nil {
			return nil, err
		}
		f.add("h.disposition = ANY(?)", v)
	}
	if v := listParam(q, "remediation_status"); len(v) > 0 {
		if err := checkAll("remediation_status", v, RemediationStatuses); err != nil {
			return nil, err
		}
		f.add("h.remediation_status = ANY(?)", v)
	}
	if v := listParam(q, "severity"); len(v) > 0 {
		if err := checkAll("severity", v, Severities); err != nil {
			return nil, err
		}
		f.add("COALESCE(h.assessed_severity, h.original_severity) = ANY(?)", v)
	}
	if v := listParam(q, "priority"); len(v) > 0 {
		if err := checkAll("priority", v, Priorities); err != nil {
			return nil, err
		}
		f.add("h.priority = ANY(?)", v)
	}
	if v := listParam(q, "scanner"); len(v) > 0 {
		f.add("(h.scanner_key = ANY(?::text[]) OR f.scanner_keys && ?::text[])", v)
	}
	if v := listParam(q, "category"); len(v) > 0 {
		f.add("f.category = ANY(?)", v)
	}
	for _, k := range []struct{ param, col string }{{"repository_id", "h.repository_id"}, {"application_id", "r.application_id"}} {
		if v := listParam(q, k.param); len(v) > 0 {
			ids := make([]uuid.UUID, 0, len(v))
			for _, x := range v {
				id, err := uuid.Parse(x)
				if err != nil {
					return nil, httpx.BadRequest("invalid " + k.param)
				}
				ids = append(ids, id)
			}
			f.add(k.col+" = ANY(?)", ids)
		}
	}
	for _, k := range []struct{ param, col string }{{"reviewer", "h.reviewer_id"}, {"independent_reviewer", "h.independent_reviewer_id"}} {
		switch v := q.Get(k.param); v {
		case "":
		case "me":
			f.add(k.col+" = ?", p.UserID)
		case "none":
			f.where = append(f.where, k.col+" IS NULL")
		default:
			id, err := uuid.Parse(v)
			if err != nil {
				return nil, httpx.BadRequest(k.param + " must be me, none or a user id")
			}
			f.add(k.col+" = ?", id)
		}
	}
	switch q.Get("overdue") {
	case "":
	case "true":
		f.where = append(f.where, "h.status <> 'completed' AND h.due_at < now()")
	case "false":
		f.where = append(f.where, "NOT (h.status <> 'completed' AND h.due_at < now())")
	default:
		return nil, httpx.BadRequest("overdue must be true or false")
	}
	if v := q.Get("source"); v != "" {
		if v != "automatic" && v != "manual" {
			return nil, httpx.BadRequest("source must be automatic or manual")
		}
		f.add("h.source = ?", v)
	}
	if v := strings.TrimSpace(q.Get("branch")); v != "" {
		f.add("h.branch = ?", v)
	}
	if v := q.Get("from"); v != "" {
		t, err := parseTime(v)
		if err != nil {
			return nil, httpx.BadRequest("from must be a date (YYYY-MM-DD) or RFC 3339 time")
		}
		f.add(dateCol+" >= ?", t)
	}
	if v := q.Get("to"); v != "" {
		t, err := parseTime(v)
		if err != nil {
			return nil, httpx.BadRequest("to must be a date (YYYY-MM-DD) or RFC 3339 time")
		}
		if len(v) == 10 {
			t = t.Add(24 * time.Hour)
		}
		f.add(dateCol+" < ?", t)
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		if len(v) > 200 {
			return nil, httpx.BadRequest("search text is too long")
		}
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(v)) + "%"
		f.add(`(lower(h.review_key) LIKE ? OR h.finding_id::text LIKE ? OR lower(f.title) LIKE ? OR lower(f.rule_id) LIKE ?
			OR lower(r.full_name) LIKE ? OR lower(r.repository_key) LIKE ? OR lower(h.file_path) LIKE ? OR lower(f.cve) LIKE ?)`, like)
	}
	return f, nil
}

var sortColumns = map[string]string{
	"review_key":   "h.review_key",
	"title":        "lower(f.title)",
	"severity":     "array_position(ARRAY['info','low','medium','high','critical'], COALESCE(h.assessed_severity, h.original_severity))",
	"scanner":      "h.scanner_key",
	"repository":   "lower(r.full_name)",
	"application":  "lower(a.name)",
	"branch":       "h.branch",
	"file_path":    "h.file_path",
	"detected_at":  "f.first_seen_at",
	"reviewer":     "lower(COALESCE(NULLIF(ru.display_name, ''), ru.email))",
	"priority":     "h.priority",
	"status":       "array_position(ARRAY['pending','assigned','in_progress','awaiting_information','awaiting_independent_review','reopened','completed'], h.status)",
	"due_at":       "h.due_at",
	"created_at":   "h.created_at",
	"updated_at":   "h.updated_at",
	"completed_at": "h.completed_at",
}

// Page is a page of queue items.
type Page struct {
	Items    []Item `json:"items"`
	Total    int    `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	q := r.URL.Query()
	f, err := s.buildFilter(s.Principal(ctx), q, "h.created_at")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	page, size := 1, 25
	if v := q.Get("page"); v != "" {
		if page, err = strconv.Atoi(v); err != nil || page < 1 || page > 100000 {
			s.fail(w, r, httpx.BadRequest("invalid page"))
			return
		}
	}
	if v := q.Get("page_size"); v != "" {
		if size, err = strconv.Atoi(v); err != nil || size < 1 || size > 200 {
			s.fail(w, r, httpx.BadRequest("page_size must be 1-200"))
			return
		}
	}
	var order string
	if sortKey := q.Get("sort"); sortKey != "" {
		col, ok := sortColumns[sortKey]
		if !ok {
			s.fail(w, r, httpx.BadRequest("invalid sort"))
			return
		}
		dir := "ASC"
		if q.Get("order") == "desc" {
			dir = "DESC"
		}
		order = col + " " + dir + " NULLS LAST, h.id"
	} else {
		order = "h.priority ASC, h.due_at ASC NULLS LAST, h.created_at ASC, h.id"
	}
	var total int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM human_reviews h JOIN findings f ON f.id = h.finding_id JOIN repositories r ON r.id = h.repository_id
		LEFT JOIN applications a ON a.id = r.application_id WHERE `+f.sql(), f.args...).Scan(&total); err != nil {
		s.fail(w, r, err)
		return
	}
	args := append(f.args, size, (page-1)*size)
	rows, err := s.DB.Query(ctx, itemSelect+" WHERE "+f.sql()+" ORDER BY "+order+
		fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args)), args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Item, error) { return scanItem(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []Item{}
	}
	httpx.WriteJSON(w, http.StatusOK, Page{Items: items, Total: total, Page: page, PageSize: size})
}

// --- manual creation ------------------------------------------------------

type createRequest struct {
	FindingIDs []uuid.UUID `json:"finding_ids"`
	Reason     string      `json:"reason"`
	Priority   *string     `json:"priority"`
	DueAt      *time.Time  `json:"due_at"`
	ReviewerID *uuid.UUID  `json:"reviewer_id"`
}

// create adds findings to the queue manually (reviews.assign). Findings that
// already have a review are reported, not duplicated.
func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req createRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.FindingIDs) == 0 || len(req.FindingIDs) > 500 {
		s.fail(w, r, httpx.BadRequest("select 1-500 findings"))
		return
	}
	reason, err := trimmed(req.Reason, 2000)
	if err != nil || len(reason) < 5 {
		s.fail(w, r, httpx.BadRequest("a reason (5-2000 characters) is required to add findings to the review queue"))
		return
	}
	if req.Priority != nil && !slices.Contains(Priorities, *req.Priority) {
		s.fail(w, r, httpx.BadRequest("priority must be p1-p4"))
		return
	}
	var created, existing []uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		reasons := make([]string, len(req.FindingIDs))
		for i, fid := range req.FindingIDs {
			var repo uuid.UUID
			if err := tx.QueryRow(ctx, `SELECT repository_id FROM findings WHERE organization_id = $1 AND id = $2`, p.OrganizationID, fid).Scan(&repo); err != nil {
				return httpx.BadRequest("finding " + fid.String() + " does not exist")
			}
			if err := s.require(ctx, p, authz.PermReviewsAssign, repo); err != nil {
				return err
			}
			reasons[i] = reason
		}
		var err error
		if created, err = insertReviews(ctx, tx, p.OrganizationID, req.FindingIDs, reasons, "manual", &p.UserID, req.Priority, req.DueAt); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT id FROM human_reviews WHERE finding_id = ANY($1) AND NOT (id = ANY($2))`, req.FindingIDs, created)
		if err != nil {
			return err
		}
		if existing, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID]); err != nil {
			return err
		}
		st, err := loadSettings(ctx, tx, p.OrganizationID)
		if err != nil {
			return err
		}
		for _, id := range created {
			v, err := scanRec(tx.QueryRow(ctx, recSelect+` WHERE h.id = $1 FOR UPDATE OF h`, id))
			if err != nil {
				return err
			}
			if err := s.audit(ctx, tx, p, "create", v, map[string]any{"reason": reason}); err != nil {
				return err
			}
			if req.ReviewerID != nil {
				if err := s.checkAssignee(ctx, tx, p.OrganizationID, v.RepoID, *req.ReviewerID); err != nil {
					return err
				}
				if err := assignTx(ctx, tx, v, &p.UserID, *req.ReviewerID, nil, "", st.NotifyAssignment); err != nil {
					return err
				}
			}
		}
		if req.ReviewerID == nil {
			return s.autoAssign(ctx, tx, p.OrganizationID, st, created)
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if created == nil {
		created = []uuid.UUID{}
	}
	if existing == nil {
		existing = []uuid.UUID{}
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"created": created, "existing": existing})
}

// --- assignment -------------------------------------------------------------

func (s *Service) checkAssignee(ctx context.Context, q db.Querier, orgID, repo, user uuid.UUID) error {
	if err := activeUser(ctx, q, orgID, user); err != nil {
		return err
	}
	ok, err := userHas(ctx, q, orgID, repo, user, authz.PermReviewsAssess)
	if err != nil {
		return err
	}
	if !ok {
		return httpx.BadRequest("the reviewer must hold reviews.assess on the repository")
	}
	return nil
}

type assignRequest struct {
	ReviewerID            *uuid.UUID `json:"reviewer_id"`
	IndependentReviewerID *uuid.UUID `json:"independent_reviewer_id"`
	DueAt                 *time.Time `json:"due_at"`
	Priority              *string    `json:"priority"`
	Note                  string     `json:"note"`
}

func (s *Service) assignOne(ctx context.Context, tx pgx.Tx, p *authz.Principal, id uuid.UUID, req assignRequest, st Settings) error {
	v, err := s.load(ctx, tx, p, id, true)
	if err != nil {
		return err
	}
	if err := s.require(ctx, p, authz.PermReviewsAssign, v.RepoID); err != nil {
		return err
	}
	if v.Status == StatusCompleted {
		return httpx.Conflict(v.Key + " is completed; reopen it to reassign")
	}
	note, err := trimmed(req.Note, 2000)
	if err != nil {
		return err
	}
	if req.ReviewerID != nil {
		if err := s.checkAssignee(ctx, tx, p.OrganizationID, v.RepoID, *req.ReviewerID); err != nil {
			return err
		}
		if v.IndependentID != nil && *v.IndependentID == *req.ReviewerID {
			return httpx.BadRequest("the reviewer and the independent reviewer must be different people")
		}
		if v.ReviewerID == nil || *v.ReviewerID != *req.ReviewerID {
			if err := assignTx(ctx, tx, v, &p.UserID, *req.ReviewerID, nil, note, st.NotifyAssignment); err != nil {
				return err
			}
			if note != "" {
				if err := insertComment(ctx, tx, v, p.UserID, "assignment", note); err != nil {
					return err
				}
			}
			if v, err = scanRec(tx.QueryRow(ctx, recSelect+` WHERE h.id = $1`, v.ID)); err != nil {
				return err
			}
		}
	}
	if req.IndependentReviewerID != nil {
		u := *req.IndependentReviewerID
		if err := activeUser(ctx, tx, p.OrganizationID, u); err != nil {
			return err
		}
		ok, err := userHas(ctx, tx, p.OrganizationID, v.RepoID, u, authz.PermReviewsApprove)
		if err != nil {
			return err
		}
		if !ok {
			return httpx.BadRequest("the independent reviewer must hold reviews.approve on the repository")
		}
		if v.ReviewerID != nil && *v.ReviewerID == u {
			return httpx.BadRequest("the reviewer and the independent reviewer must be different people")
		}
		if _, err := tx.Exec(ctx, `UPDATE human_reviews SET independent_reviewer_id = $2, updated_at = now() WHERE id = $1`, v.ID, u); err != nil {
			return err
		}
		if err := hist(ctx, tx, v, &p.UserID, "review.independent_assigned", "independent_reviewer_id", v.IndependentID, u, note); err != nil {
			return err
		}
	}
	if err := s.applyPlanning(ctx, tx, p, v, req.Priority, req.DueAt); err != nil {
		return err
	}
	return s.audit(ctx, tx, p, "assign", v, map[string]any{"reviewer_id": req.ReviewerID, "independent_reviewer_id": req.IndependentReviewerID,
		"due_at": req.DueAt, "priority": req.Priority})
}

// applyPlanning changes priority and due date.
func (s *Service) applyPlanning(ctx context.Context, tx pgx.Tx, p *authz.Principal, v rec, priority *string, due *time.Time) error {
	if priority != nil && *priority != v.Priority {
		if !slices.Contains(Priorities, *priority) {
			return httpx.BadRequest("priority must be p1-p4")
		}
		if _, err := tx.Exec(ctx, `UPDATE human_reviews SET priority = $2, updated_at = now() WHERE id = $1`, v.ID, *priority); err != nil {
			return err
		}
		if err := hist(ctx, tx, v, &p.UserID, "review.priority", "priority", v.Priority, *priority, ""); err != nil {
			return err
		}
	}
	if due != nil && (v.DueAt == nil || !v.DueAt.Equal(*due)) {
		if _, err := tx.Exec(ctx, `UPDATE human_reviews SET due_at = $2, updated_at = now() WHERE id = $1`, v.ID, *due); err != nil {
			return err
		}
		if err := hist(ctx, tx, v, &p.UserID, "review.due_date", "due_at", v.DueAt, *due, ""); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) assign(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req assignRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.ReviewerID == nil && req.IndependentReviewerID == nil {
		s.fail(w, r, httpx.BadRequest("reviewer_id or independent_reviewer_id is required"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		st, err := loadSettings(ctx, tx, p.OrganizationID)
		if err != nil {
			return err
		}
		return s.assignOne(ctx, tx, p, id, req, st)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeItem(w, r, id)
}

type patchRequest struct {
	Priority *string    `json:"priority"`
	DueAt    *time.Time `json:"due_at"`
}

func (s *Service) patch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req patchRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if err := s.require(ctx, p, authz.PermReviewsAssign, v.RepoID); err != nil {
			return err
		}
		if err := s.applyPlanning(ctx, tx, p, v, req.Priority, req.DueAt); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "update", v, map[string]any{"priority": req.Priority, "due_at": req.DueAt})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeItem(w, r, id)
}

type bulkRequest struct {
	ReviewIDs  []uuid.UUID `json:"review_ids"`
	Action     string      `json:"action"` // assign | priority | due_date
	ReviewerID *uuid.UUID  `json:"reviewer_id"`
	Priority   *string     `json:"priority"`
	DueAt      *time.Time  `json:"due_at"`
	Note       string      `json:"note"`
}

// bulk applies one change to up to 500 reviews atomically.
func (s *Service) bulk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	var req bulkRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(req.ReviewIDs) == 0 || len(req.ReviewIDs) > 500 {
		s.fail(w, r, httpx.BadRequest("select 1-500 reviews"))
		return
	}
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		st, err := loadSettings(ctx, tx, p.OrganizationID)
		if err != nil {
			return err
		}
		for _, id := range req.ReviewIDs {
			var err error
			switch req.Action {
			case "assign":
				if req.ReviewerID == nil {
					return httpx.BadRequest("reviewer_id is required")
				}
				err = s.assignOne(ctx, tx, p, id, assignRequest{ReviewerID: req.ReviewerID, DueAt: req.DueAt, Priority: req.Priority, Note: req.Note}, st)
			case "priority", "due_date":
				if req.Action == "priority" && req.Priority == nil || req.Action == "due_date" && req.DueAt == nil {
					return httpx.BadRequest("a value is required")
				}
				var v rec
				if v, err = s.load(ctx, tx, p, id, true); err == nil {
					if err = s.require(ctx, p, authz.PermReviewsAssign, v.RepoID); err == nil {
						if err = s.applyPlanning(ctx, tx, p, v, req.Priority, req.DueAt); err == nil {
							err = s.audit(ctx, tx, p, "update", v, map[string]any{"priority": req.Priority, "due_at": req.DueAt, "bulk": true})
						}
					}
				}
			default:
				return httpx.BadRequest("action must be assign, priority or due_date")
			}
			if err != nil {
				var he *httpx.Error
				if errors.As(err, &he) {
					he.Message = "review " + id.String() + ": " + he.Message
				}
				return err
			}
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]int{"updated": len(req.ReviewIDs)})
}

// start assigns an unassigned review to the caller (if allowed) and moves
// it to In Progress.
func (s *Service) start(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if err := requireEditable(v); err != nil {
			return err
		}
		if err := s.require(ctx, p, authz.PermReviewsAssess, v.RepoID); err != nil {
			return err
		}
		st, err := loadSettings(ctx, tx, p.OrganizationID)
		if err != nil {
			return err
		}
		if v.ReviewerID == nil {
			if !st.AllowSelfAssign && !s.can(ctx, p, authz.PermReviewsAssign, v.RepoID) {
				return httpx.E(http.StatusForbidden, "forbidden", "self-assignment is disabled; ask a review manager to assign the review")
			}
			if v.IndependentID != nil && *v.IndependentID == p.UserID {
				return httpx.BadRequest("you are the independent reviewer of this review")
			}
			if err := assignTx(ctx, tx, v, &p.UserID, p.UserID, nil, "self-assigned", false); err != nil {
				return err
			}
			if v, err = scanRec(tx.QueryRow(ctx, recSelect+` WHERE h.id = $1`, v.ID)); err != nil {
				return err
			}
		} else if err := s.requireAssessor(ctx, tx, p, v); err != nil {
			return err
		}
		if v.Status != StatusInProgress {
			if _, err := tx.Exec(ctx, `UPDATE human_reviews SET status = 'in_progress', started_at = COALESCE(started_at, now()), updated_at = now() WHERE id = $1`, v.ID); err != nil {
				return err
			}
			if err := hist(ctx, tx, v, &p.UserID, "review.status", "status", v.Status, StatusInProgress, ""); err != nil {
				return err
			}
		}
		if err := ensureAssessment(ctx, tx, v); err != nil {
			return err
		}
		// Automated triage's "needs review" state now has a human owner.
		return s.audit(ctx, tx, p, "start", v, nil)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeItem(w, r, id)
}

type statusRequest struct {
	Status string `json:"status"`
	Note   string `json:"note"`
}

// setStatus moves a review between In Progress and Awaiting Information.
// Completion and independent review go through decisions.
func (s *Service) setStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req statusRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Status != StatusInProgress && req.Status != StatusAwaitingInformation {
		s.fail(w, r, httpx.BadRequest("status must be in_progress or awaiting_information (use a decision to complete a review)"))
		return
	}
	note, err := trimmed(req.Note, 4000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Status == StatusAwaitingInformation && len(note) < 5 {
		s.fail(w, r, httpx.BadRequest("describe the information you are waiting for"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if err := requireEditable(v); err != nil {
			return err
		}
		if err := s.requireAssessor(ctx, tx, p, v); err != nil {
			return err
		}
		if v.Status == req.Status {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE human_reviews SET status = $2, started_at = COALESCE(started_at, now()), updated_at = now() WHERE id = $1`, v.ID, req.Status); err != nil {
			return err
		}
		if err := hist(ctx, tx, v, &p.UserID, "review.status", "status", v.Status, req.Status, note); err != nil {
			return err
		}
		if note != "" {
			kind := "comment"
			if req.Status == StatusAwaitingInformation {
				kind = "information_request"
			}
			if err := insertComment(ctx, tx, v, p.UserID, kind, note); err != nil {
				return err
			}
		}
		return s.audit(ctx, tx, p, "status", v, map[string]any{"from": v.Status, "to": req.Status})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeItem(w, r, id)
}

func (s *Service) writeItem(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	it, err := scanItem(s.DB.QueryRow(r.Context(), itemSelect+` WHERE h.id = $1 OR h.finding_id = $1`, id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, it)
}

// --- reviewers ------------------------------------------------------------

// Reviewer is a user who can take part in reviews.
type Reviewer struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	CanAssess   bool      `json:"can_assess"`
	CanApprove  bool      `json:"can_approve"`
	OpenReviews int       `json:"open_reviews"`
}

// reviewers lists users holding reviews.assess or reviews.approve (for
// assignment pickers). With repository_id, only users covering it.
func (s *Service) reviewers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !isWorker(p) && !p.HasOrgWide(authz.PermReviewsConfigure) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var repo *uuid.UUID
	if v := r.URL.Query().Get("repository_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, httpx.BadRequest("invalid repository_id"))
			return
		}
		if !s.can(ctx, p, authz.PermReviewsRead, id) {
			s.fail(w, r, errNotFound)
			return
		}
		repo = &id
	}
	assess, approve := map[uuid.UUID]bool{}, map[uuid.UUID]bool{}
	collect := func(perm authz.Permission, into map[uuid.UUID]bool) error {
		var ids []uuid.UUID
		var err error
		if repo != nil {
			ids, err = usersWith(ctx, s.DB, p.OrganizationID, *repo, perm)
		} else {
			var rows pgx.Rows
			rows, err = s.DB.Query(ctx, `SELECT DISTINCT u.id FROM role_assignments ra
				JOIN role_permissions rp ON rp.role_id = ra.role_id AND rp.permission_key = $2
				JOIN users u ON u.id = ra.user_id AND u.status = 'active' WHERE ra.organization_id = $1`, p.OrganizationID, string(perm))
			if err == nil {
				ids, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
			}
		}
		for _, id := range ids {
			into[id] = true
		}
		return err
	}
	if err := collect(authz.PermReviewsAssess, assess); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := collect(authz.PermReviewsApprove, approve); err != nil {
		s.fail(w, r, err)
		return
	}
	var ids []uuid.UUID
	for id := range assess {
		ids = append(ids, id)
	}
	for id := range approve {
		if !assess[id] {
			ids = append(ids, id)
		}
	}
	rows, err := s.DB.Query(ctx, `SELECT u.id, COALESCE(NULLIF(u.display_name, ''), u.email), u.email,
		(SELECT count(*) FROM human_reviews h WHERE h.reviewer_id = u.id AND h.status <> 'completed')
		FROM users u WHERE u.organization_id = $1 AND u.id = ANY($2) ORDER BY lower(COALESCE(NULLIF(u.display_name, ''), u.email))`, p.OrganizationID, ids)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Reviewer, error) {
		var v Reviewer
		err := row.Scan(&v.ID, &v.Name, &v.Email, &v.OpenReviews)
		v.CanAssess, v.CanApprove = assess[v.ID], approve[v.ID]
		return v, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Reviewer{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}
