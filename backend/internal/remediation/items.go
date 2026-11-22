// Package remediation is the remediation workspace (PATHOS 3.0 M8): one
// item per finding or group of findings of a repository, with an owner, a
// due date from the SLA engine, a status, a root cause, secure fix
// guidance (from the finding, its AI and Human Eye reviews, dependency
// fixes and verified AI fixes), the fix pull request and before-and-after
// evidence of the fix.
//
// An item closes only when a verification proves the fix (verify.go): a
// targeted rescan of the affected files with the findings' scanners, run
// by a worker with the verified-AI-fix machinery, or a finished scan of
// the repository that no longer reports the findings. The database refuses
// a closed item without the proving verification.
package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/gates"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scm"
)

// Service serves the remediation API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	// ScannerConfig returns a scanner's configuration in the profile of a
	// scan execution (scans.Service.ScannerConfigFor).
	ScannerConfig func(ctx context.Context, jobID *uuid.UUID, key string) json.RawMessage
	// CloneCredential resolves the clone credential of an SCM connection
	// for the worker (repos.Service.CloneCredential).
	CloneCredential func(ctx context.Context, orgID, connectionID uuid.UUID, repoFullName string) (scm.Credential, error)
}

// Register mounts the user-facing API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/remediation/items", s.list)
	mux.HandleFunc("POST /api/v1/remediation/items", s.create)
	mux.HandleFunc("POST /api/v1/remediation/items/bulk", s.bulk)
	mux.HandleFunc("GET /api/v1/remediation/items/{id}", s.get)
	mux.HandleFunc("PATCH /api/v1/remediation/items/{id}", s.patch)
	mux.HandleFunc("POST /api/v1/remediation/items/{id}/verify", s.verify)
	mux.HandleFunc("GET /api/v1/remediation/items/{id}/verifications", s.verifications)
	mux.HandleFunc("GET /api/v1/remediation/views", s.listViews)
	mux.HandleFunc("POST /api/v1/remediation/views", s.createView)
	mux.HandleFunc("DELETE /api/v1/remediation/views/{id}", s.deleteView)
}

// Statuses, kinds and priorities.
var (
	Statuses   = []string{"open", "planned", "in_progress", "fix_submitted", "verifying", "closed", "wont_fix"}
	Kinds      = []string{"code_fix", "dependency_upgrade", "configuration", "threat_mitigation", "design_change"}
	Priorities = []string{"critical", "high", "medium", "low"}
	// terminal statuses: the item's findings may join a new item.
	terminal = []string{"closed", "wont_fix"}
)

// manualTransitions are the status changes a person may make. "closed" is
// never set by hand: only a verification that proves the fix closes an
// item; "verifying" is set when a verification is queued.
var manualTransitions = map[string][]string{
	"open":          {"planned", "in_progress", "fix_submitted", "wont_fix"},
	"planned":       {"open", "in_progress", "fix_submitted", "wont_fix"},
	"in_progress":   {"open", "planned", "fix_submitted", "wont_fix"},
	"fix_submitted": {"in_progress", "wont_fix"},
	"verifying":     {},
	"closed":        {"open"},
	"wont_fix":      {"open"},
}

// CanTransition reports whether a person may change an item's status.
func CanTransition(from, to string) bool {
	return from == to || slices.Contains(manualTransitions[from], to)
}

// Errors.
var (
	ErrTransition = httpx.E(http.StatusConflict, "invalid_transition",
		"this status change is not allowed; an item closes only when a verification proves the fix").WithDiag("PTH-REM-1101")
	ErrNotVerifiable = func(reason string) *httpx.Error {
		return httpx.E(http.StatusConflict, "fix_not_verifiable", "the fix cannot be verified: "+reason).WithDiag("PTH-REM-1102")
	}
	ErrAlreadyTracked = httpx.E(http.StatusConflict, "finding_already_tracked",
		"a finding already belongs to an open remediation item").WithDiag("PTH-REM-1103")
	ErrVerificationRunning = httpx.E(http.StatusConflict, "verification_running",
		"a verification of this item is already queued or running").WithDiag("PTH-REM-1104")
)

const openFindingStatuses = `('open', 'in_progress', 'needs_review')`

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("an item with this name already exists")
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("a referenced item does not exist")
	}
	httpx.WriteError(w, r, s.Log, err)
}

func (s *Service) begin(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, authz.ErrForbidden
	}
	if err := featureflags.Require(r.Context(), s.DB, p.OrganizationID, gates.Flag); err != nil {
		return nil, err
	}
	return p, nil
}

func (s *Service) requireRepo(ctx context.Context, p *authz.Principal, perm authz.Permission, repoID uuid.UUID) error {
	err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: repoID})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, org.ErrScopeNotFound):
		return httpx.ErrNotFound
	case errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(perm):
		return httpx.ErrNotFound
	}
	return err
}

// --- model -------------------------------------------------------------------

// FixPRRef is a fix pull request linked to an item.
type FixPRRef struct {
	ID        uuid.UUID `json:"id"`
	Status    string    `json:"status"`
	PRURL     string    `json:"pr_url"`
	Kind      string    `json:"kind"`
	CreatedAt time.Time `json:"created_at"`
}

// VerificationRef is the latest verification of an item.
type VerificationRef struct {
	ID        uuid.UUID `json:"id"`
	Status    string    `json:"status"`
	Result    *string   `json:"result"`
	CreatedAt time.Time `json:"created_at"`
}

// Item is a remediation item.
type Item struct {
	ID               uuid.UUID        `json:"id"`
	Title            string           `json:"title"`
	Kind             string           `json:"kind"`
	Status           string           `json:"status"`
	Priority         string           `json:"priority"`
	RepositoryID     *uuid.UUID       `json:"repository_id"`
	RepositoryName   string           `json:"repository_name"`
	ApplicationID    *uuid.UUID       `json:"application_id"`
	ApplicationName  string           `json:"application_name"`
	OwnerID          *uuid.UUID       `json:"owner_id"`
	OwnerEmail       string           `json:"owner_email"`
	DueAt            *time.Time       `json:"due_at"`
	DueSource        string           `json:"due_source"`
	Overdue          bool             `json:"overdue"`
	RootCause        string           `json:"root_cause"`
	FindingCount     int              `json:"finding_count"`
	OpenFindingCount int              `json:"open_finding_count"`
	TopSeverity      string           `json:"top_severity"`
	AffectedFiles    []string         `json:"affected_files"`
	FixPullRequest   *FixPRRef        `json:"fix_pull_request"`
	LastVerification *VerificationRef `json:"last_verification"`
	// Threat is the M5 threat a threat_mitigation item mitigates (M9).
	Threat    *ThreatRef `json:"threat"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	ClosedAt  *time.Time `json:"closed_at"`
}

// fixPRExpr is the item's fix pull request: the one linked by hand, else
// the latest non-failed fix pull request of one of its findings
// (dependency upgrade or verified AI fix).
const fixPRExpr = `COALESCE(i.fix_pull_request_id, (SELECT ff.fix_pull_request_id FROM fix_pull_request_findings ff
	JOIN fix_pull_requests x ON x.id = ff.fix_pull_request_id JOIN remediation_item_findings rf ON rf.finding_id = ff.finding_id
	WHERE rf.item_id = i.id AND x.status <> 'failed' ORDER BY x.created_at DESC LIMIT 1))`

const itemSelect = `SELECT i.id, i.title, i.kind, i.status, i.priority, i.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name, ''),
	i.application_id, COALESCE(a.name, ''), i.owner_id, COALESCE(u.email, ''), i.due_at, i.due_source, i.root_cause,
	(SELECT count(*) FROM remediation_item_findings x WHERE x.item_id = i.id),
	(SELECT count(*) FROM remediation_item_findings x JOIN findings f ON f.id = x.finding_id WHERE x.item_id = i.id AND f.status IN ` + openFindingStatuses + `),
	COALESCE((SELECT f.severity FROM remediation_item_findings x JOIN findings f ON f.id = x.finding_id WHERE x.item_id = i.id
	          ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity) LIMIT 1), ''),
	COALESCE((SELECT array_agg(DISTINCT f.file_path ORDER BY f.file_path) FROM remediation_item_findings x JOIN findings f ON f.id = x.finding_id
	          WHERE x.item_id = i.id AND f.file_path <> ''), '{}'),
	fp.id, fp.status, fp.pr_url, fp.kind, fp.created_at,
	lv.id, lv.status, lv.result, lv.created_at,
	i.created_at, i.updated_at, i.closed_at,
	th.id, th.title, th.severity, th.status, tm.id, tm.title, tm.version
	FROM remediation_items i
	LEFT JOIN repositories r ON r.id = i.repository_id
	LEFT JOIN applications a ON a.id = i.application_id
	LEFT JOIN users u ON u.id = i.owner_id
	LEFT JOIN threats th ON th.id = i.threat_id
	LEFT JOIN threat_models tm ON tm.id = th.threat_model_id
	LEFT JOIN fix_pull_requests fp ON fp.id = ` + fixPRExpr + `
	LEFT JOIN LATERAL (SELECT v.id, v.status, v.result, v.created_at FROM remediation_verifications v WHERE v.item_id = i.id
	                   ORDER BY v.created_at DESC LIMIT 1) lv ON true`

func scanItem(row pgx.Row) (Item, error) {
	var it Item
	var fpID, lvID *uuid.UUID
	var fpStatus, fpURL, fpKind, lvStatus *string
	var fpAt, lvAt *time.Time
	var lvResult *string
	var thID, tmID *uuid.UUID
	var thTitle, thSev, thStatus, tmTitle *string
	var tmVersion *int
	err := row.Scan(&it.ID, &it.Title, &it.Kind, &it.Status, &it.Priority, &it.RepositoryID, &it.RepositoryName, &it.ApplicationID,
		&it.ApplicationName, &it.OwnerID, &it.OwnerEmail, &it.DueAt, &it.DueSource, &it.RootCause, &it.FindingCount, &it.OpenFindingCount,
		&it.TopSeverity, &it.AffectedFiles, &fpID, &fpStatus, &fpURL, &fpKind, &fpAt, &lvID, &lvStatus, &lvResult, &lvAt,
		&it.CreatedAt, &it.UpdatedAt, &it.ClosedAt, &thID, &thTitle, &thSev, &thStatus, &tmID, &tmTitle, &tmVersion)
	if err != nil {
		return it, err
	}
	if thID != nil && tmID != nil {
		v := 0
		if tmVersion != nil {
			v = *tmVersion
		}
		it.Threat = &ThreatRef{ID: *thID, Title: deref(thTitle), Severity: deref(thSev), Status: deref(thStatus), ThreatModelID: *tmID,
			ThreatModelTitle: deref(tmTitle), ThreatModelVersion: v}
	}
	if fpID != nil {
		it.FixPullRequest = &FixPRRef{ID: *fpID, Status: deref(fpStatus), PRURL: deref(fpURL), Kind: deref(fpKind), CreatedAt: derefTime(fpAt)}
	}
	if lvID != nil {
		it.LastVerification = &VerificationRef{ID: *lvID, Status: deref(lvStatus), Result: lvResult, CreatedAt: derefTime(lvAt)}
	}
	it.Overdue = it.DueAt != nil && it.DueAt.Before(time.Now()) && !slices.Contains(terminal, it.Status)
	if it.AffectedFiles == nil {
		it.AffectedFiles = []string{}
	}
	return it, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// --- list ----------------------------------------------------------------------

var sorts = map[string]string{
	"due_at":      "i.due_at ASC NULLS LAST, i.id",
	"-due_at":     "i.due_at DESC NULLS LAST, i.id",
	"priority":    "array_position(ARRAY['critical','high','medium','low'], i.priority), i.due_at ASC NULLS LAST, i.id",
	"-created_at": "i.created_at DESC, i.id",
	"created_at":  "i.created_at ASC, i.id",
	"status":      "array_position(ARRAY['open','planned','in_progress','fix_submitted','verifying','closed','wont_fix'], i.status), i.id",
}

// listFilter builds the WHERE clause of a list request.
func listFilter(p *authz.Principal, q map[string][]string) ([]string, []any, error) {
	get := func(k string) string {
		if v := q[k]; len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	args := []any{p.OrganizationID}
	where := []string{"i.organization_id = $1"}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if v := get("status"); v != "" {
		var st []string
		for _, x := range strings.Split(v, ",") {
			if !slices.Contains(Statuses, x) && x != "active" {
				return nil, nil, httpx.BadRequest("unknown status " + x)
			}
			if x == "active" {
				st = append(st, "open", "planned", "in_progress", "fix_submitted", "verifying")
			} else {
				st = append(st, x)
			}
		}
		add("i.status = ANY($%d::text[])", st)
	}
	if v := get("priority"); v != "" {
		pr := strings.Split(v, ",")
		for _, x := range pr {
			if !slices.Contains(Priorities, x) {
				return nil, nil, httpx.BadRequest("unknown priority " + x)
			}
		}
		add("i.priority = ANY($%d::text[])", pr)
	}
	for _, k := range []string{"owner_id", "repository_id", "application_id"} {
		if v := get(k); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				return nil, nil, httpx.BadRequest("invalid " + k)
			}
			add("i."+k+" = $%d", id)
		}
	}
	if v := get("threat_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, nil, httpx.BadRequest("invalid threat_id")
		}
		add("i.threat_id = $%d", id)
	}
	if get("unassigned") == "true" {
		where = append(where, "i.owner_id IS NULL")
	}
	if get("overdue") == "true" {
		where = append(where, "i.due_at < now() AND i.status NOT IN ('closed', 'wont_fix')")
	}
	if v := get("q"); v != "" {
		if len(v) > 200 {
			return nil, nil, httpx.BadRequest("q: at most 200 characters")
		}
		pat := "%" + strings.NewReplacer(`\`, `\\`, "%", `\%`, "_", `\_`).Replace(strings.ToLower(v)) + "%"
		add(`(lower(i.title) LIKE $%[1]d OR lower(i.root_cause) LIKE $%[1]d OR EXISTS (SELECT 1 FROM remediation_item_findings x JOIN findings f ON f.id = x.finding_id
			WHERE x.item_id = i.id AND (lower(f.file_path) LIKE $%[1]d OR lower(f.title) LIKE $%[1]d)))`, pat)
	}
	vis, vargs := gates.VisibilitySQL(p, authz.PermRemediationRead, "i.application_id", len(args)+1)
	args = append(args, vargs...)
	where = append(where, vis)
	return where, args, nil
}

func (s *Service) list(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermRemediationRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	where, args, err := listFilter(p, q)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	order := sorts["due_at"]
	if v := q.Get("sort"); v != "" {
		o, ok := sorts[v]
		if !ok {
			s.fail(w, r, httpx.BadRequest("sort must be one of due_at, -due_at, priority, status, created_at, -created_at"))
			return
		}
		order = o
	}
	limit := 50
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			s.fail(w, r, httpx.BadRequest("limit must be 1-200"))
			return
		}
		limit = n
	}
	// The cursor is an opaque offset (the list sorts by several keys).
	offset := 0
	if v := q.Get("cursor"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 1_000_000 {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		offset = n
	}
	var total int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM remediation_items i LEFT JOIN repositories r ON r.id = i.repository_id WHERE `+
		strings.Join(where, " AND "), args...).Scan(&total); err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, itemSelect+" WHERE "+strings.Join(where, " AND ")+" ORDER BY "+order+
		fmt.Sprintf(" LIMIT %d OFFSET %d", limit+1, offset), args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Item, error) { return scanItem(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next *string
	if len(items) > limit {
		items = items[:limit]
		c := strconv.Itoa(offset + limit)
		next = &c
	}
	if items == nil {
		items = []Item{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next, "total": total})
}

// --- create ----------------------------------------------------------------------

type createInput struct {
	FindingIDs []uuid.UUID `json:"finding_ids"`
	// Mode: per_finding (default, one item per finding) or group (one item
	// for all findings, which must share a repository).
	Mode      string     `json:"mode"`
	Title     string     `json:"title"`
	Kind      string     `json:"kind"`
	OwnerID   *uuid.UUID `json:"owner_id"`
	DueAt     *time.Time `json:"due_at"`
	Priority  string     `json:"priority"`
	RootCause string     `json:"root_cause"`
	// ThreatID links the items to an M5 threat (kind threat_mitigation);
	// without finding_ids it creates one application-level item.
	ThreatID *uuid.UUID `json:"threat_id"`
}

type findingRow struct {
	id, repoID uuid.UUID
	appID      *uuid.UUID
	title      string
	severity   string
	category   string
	status     string
	slaDue     *time.Time
}

// KindFor suggests an item kind from a finding category.
func KindFor(category string) string {
	switch category {
	case "sca":
		return "dependency_upgrade"
	case "iac", "container":
		return "configuration"
	}
	return "code_fix"
}

// PriorityFor maps a severity to a priority.
func PriorityFor(severity string) string {
	if slices.Contains(Priorities, severity) {
		return severity
	}
	return "low"
}

func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in createInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.Title, in.RootCause = strings.TrimSpace(in.Title), strings.TrimSpace(in.RootCause)
	if in.ThreatID != nil && len(in.FindingIDs) == 0 && len(in.Title) <= 300 && len(in.RootCause) <= 4000 &&
		(in.Priority == "" || slices.Contains(Priorities, in.Priority)) {
		id, err := s.createForThreat(ctx, p, in)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		it, err := scanItem(s.DB.QueryRow(ctx, itemSelect+" WHERE i.id = $1", id))
		if err != nil {
			s.fail(w, r, err)
			return
		}
		httpx.WriteJSON(w, http.StatusCreated, map[string]any{"items": []Item{it}})
		return
	}
	var threat *threatInfo
	if in.ThreatID != nil {
		t, err := s.loadThreat(ctx, s.DB, p, *in.ThreatID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if in.Kind == "" {
			in.Kind = "threat_mitigation"
		}
		threat = &t
	}
	switch {
	case len(in.FindingIDs) == 0 || len(in.FindingIDs) > 500:
		err = httpx.BadRequest("finding_ids: 1 to 500 findings")
	case in.Mode != "" && in.Mode != "per_finding" && in.Mode != "group":
		err = httpx.BadRequest("mode must be per_finding or group")
	case len(in.Title) > 300:
		err = httpx.BadRequest("title: at most 300 characters")
	case in.Kind != "" && !slices.Contains(Kinds, in.Kind):
		err = httpx.BadRequest("unknown kind")
	case in.Priority != "" && !slices.Contains(Priorities, in.Priority):
		err = httpx.BadRequest("priority must be critical, high, medium or low")
	case len(in.RootCause) > 4000:
		err = httpx.BadRequest("root_cause: at most 4000 characters")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	slices.SortFunc(in.FindingIDs, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	in.FindingIDs = slices.Compact(in.FindingIDs)
	rows, err := s.DB.Query(ctx, `SELECT f.id, f.repository_id, r.application_id, f.title, f.severity, f.category, f.status, f.sla_due_at
		FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE f.organization_id = $1 AND f.id = ANY($2) ORDER BY f.first_seen_at`,
		p.OrganizationID, in.FindingIDs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	fs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (findingRow, error) {
		var f findingRow
		return f, r.Scan(&f.id, &f.repoID, &f.appID, &f.title, &f.severity, &f.category, &f.status, &f.slaDue)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(fs) != len(in.FindingIDs) {
		s.fail(w, r, httpx.ErrNotFound)
		return
	}
	repos := map[uuid.UUID]bool{}
	for _, f := range fs {
		if !repos[f.repoID] {
			if err := s.requireRepo(ctx, p, authz.PermRemediationManage, f.repoID); err != nil {
				s.fail(w, r, err)
				return
			}
			repos[f.repoID] = true
		}
		if !strings.Contains(openFindingStatuses, "'"+f.status+"'") {
			s.fail(w, r, httpx.BadRequest("finding "+f.id.String()+" is not open ("+f.status+")"))
			return
		}
	}
	if threat != nil {
		for _, f := range fs {
			if err := checkThreatLink(*threat, f.appID, in.Kind); err != nil {
				s.fail(w, r, err)
				return
			}
		}
	}
	if in.Mode == "group" && len(repos) > 1 {
		s.fail(w, r, httpx.BadRequest("a group item covers findings of one repository"))
		return
	}
	if in.OwnerID != nil {
		if err := s.checkOwner(ctx, p.OrganizationID, *in.OwnerID); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	var groups [][]findingRow
	if in.Mode == "group" {
		groups = [][]findingRow{fs}
	} else {
		for _, f := range fs {
			groups = append(groups, []findingRow{f})
		}
	}
	var ids []uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		// One open item per finding.
		var taken int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM remediation_item_findings x JOIN remediation_items i ON i.id = x.item_id
			WHERE x.finding_id = ANY($1) AND i.status NOT IN ('closed', 'wont_fix')`, in.FindingIDs).Scan(&taken); err != nil {
			return err
		}
		if taken > 0 {
			return ErrAlreadyTracked
		}
		for _, g := range groups {
			id := uuid.Must(uuid.NewV7())
			first := g[0]
			title := in.Title
			if title == "" {
				title = first.title
				if len(g) > 1 {
					title = fmt.Sprintf("%s (+%d more)", first.title, len(g)-1)
				}
			}
			title = truncate(strings.TrimSpace(title), 300)
			if title == "" {
				title = "Remediation"
			}
			kind := in.Kind
			if kind == "" {
				kind = KindFor(first.category)
			}
			prio := in.Priority
			if prio == "" {
				prio = "low"
				for _, f := range g {
					if slices.Index(Priorities, PriorityFor(f.severity)) < slices.Index(Priorities, prio) {
						prio = PriorityFor(f.severity)
					}
				}
			}
			// Due date: the earliest SLA deadline of the findings.
			var due *time.Time
			for _, f := range g {
				if f.slaDue != nil && (due == nil || f.slaDue.Before(*due)) {
					t := *f.slaDue
					due = &t
				}
			}
			source := "none"
			if due != nil {
				source = "sla"
			}
			if in.DueAt != nil {
				due, source = in.DueAt, "manual"
			}
			var threatID *uuid.UUID
			if threat != nil {
				threatID = &threat.ID
			}
			if _, err := tx.Exec(ctx, `INSERT INTO remediation_items (id, organization_id, application_id, repository_id, title, kind, priority,
				root_cause, owner_id, due_at, due_source, created_by, threat_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
				id, p.OrganizationID, first.appID, first.repoID, title, kind, prio, in.RootCause, in.OwnerID, due, source, p.UserID, threatID); err != nil {
				return err
			}
			for _, f := range g {
				if _, err := tx.Exec(ctx, `INSERT INTO remediation_item_findings (organization_id, item_id, finding_id) VALUES ($1, $2, $3)`,
					p.OrganizationID, id, f.id); err != nil {
					return err
				}
			}
			fids := make([]string, len(g))
			for i, f := range g {
				fids[i] = f.id.String()
			}
			if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action: "remediation_item.create", TargetType: "remediation_item", TargetID: id.String(),
				Metadata: map[string]any{"finding_ids": fids, "kind": kind, "priority": prio, "owner_id": in.OwnerID, "due_at": due, "due_source": source}}); err != nil {
				return err
			}
			ids = append(ids, id)
		}
		return nil
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err = s.DB.Query(ctx, itemSelect+" WHERE i.organization_id = $1 AND i.id = ANY($2) ORDER BY i.created_at", p.OrganizationID, ids)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Item, error) { return scanItem(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"items": items})
}

func (s *Service) checkOwner(ctx context.Context, orgID, userID uuid.UUID) error {
	var ok bool
	if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE organization_id = $1 AND id = $2 AND status = 'active')`, orgID, userID).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return httpx.BadRequest("owner_id: no active user with this id")
	}
	return nil
}

// loadItem loads an item the principal may act on with perm.
func (s *Service) loadItem(ctx context.Context, p *authz.Principal, id uuid.UUID, perm authz.Permission) (Item, error) {
	it, err := scanItem(s.DB.QueryRow(ctx, itemSelect+" WHERE i.organization_id = $1 AND i.id = $2", p.OrganizationID, id))
	if err != nil {
		return it, err
	}
	if it.RepositoryID != nil {
		return it, s.requireRepo(ctx, p, perm, *it.RepositoryID)
	}
	if err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}); err != nil {
		return it, httpx.ErrNotFound
	}
	return it, nil
}

func itemID(r *http.Request) (uuid.UUID, error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return uuid.Nil, httpx.ErrNotFound
	}
	return id, nil
}

// --- update ------------------------------------------------------------------------

type patchInput struct {
	Title            *string    `json:"title"`
	Status           *string    `json:"status"`
	OwnerID          *uuid.UUID `json:"owner_id"`
	ClearOwner       bool       `json:"clear_owner"`
	DueAt            *time.Time `json:"due_at"`
	ClearDue         bool       `json:"clear_due"`
	Priority         *string    `json:"priority"`
	RootCause        *string    `json:"root_cause"`
	FixPullRequestID *uuid.UUID `json:"fix_pull_request_id"`
	// ThreatID links (uuid) or unlinks (null) an M5 threat (M9).
	ThreatID optionalUUID `json:"threat_id"`
}

func (s *Service) patch(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := itemID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	before, err := s.loadItem(ctx, p, id, authz.PermRemediationManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in patchInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.applyPatch(ctx, p, before, in); err != nil {
		s.fail(w, r, err)
		return
	}
	it, err := scanItem(s.DB.QueryRow(ctx, itemSelect+" WHERE i.id = $1", id))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, it)
}

// applyPatch validates and applies a change to one item (audited).
func (s *Service) applyPatch(ctx context.Context, p *authz.Principal, before Item, in patchInput) error {
	set := []string{"updated_at = now()"}
	args := []any{before.ID}
	meta := map[string]any{}
	add := func(col string, v any) {
		args = append(args, v)
		set = append(set, fmt.Sprintf("%s = $%d", col, len(args)))
		meta[col] = v
	}
	if in.Title != nil {
		t := strings.TrimSpace(*in.Title)
		if t == "" || len(t) > 300 {
			return httpx.BadRequest("title: 1 to 300 characters")
		}
		add("title", t)
	}
	if in.Status != nil {
		if !slices.Contains(Statuses, *in.Status) {
			return httpx.BadRequest("unknown status")
		}
		if !CanTransition(before.Status, *in.Status) {
			return ErrTransition
		}
		if *in.Status != before.Status {
			add("status", *in.Status)
			meta["status_before"] = before.Status
			if before.Status == "closed" {
				set = append(set, "closed_at = NULL", "closed_by_verification_id = NULL")
			}
		}
	}
	if in.ClearOwner {
		add("owner_id", nil)
	} else if in.OwnerID != nil {
		if err := s.checkOwner(ctx, p.OrganizationID, *in.OwnerID); err != nil {
			return err
		}
		add("owner_id", *in.OwnerID)
	}
	if in.ClearDue {
		// Back to the SLA engine: the earliest deadline of the findings.
		var due *time.Time
		if err := s.DB.QueryRow(ctx, `SELECT min(f.sla_due_at) FROM remediation_item_findings x JOIN findings f ON f.id = x.finding_id
			WHERE x.item_id = $1`, before.ID).Scan(&due); err != nil {
			return err
		}
		source := "none"
		if due != nil {
			source = "sla"
		}
		add("due_at", due)
		add("due_source", source)
	} else if in.DueAt != nil {
		add("due_at", *in.DueAt)
		add("due_source", "manual")
	}
	if in.Priority != nil {
		if !slices.Contains(Priorities, *in.Priority) {
			return httpx.BadRequest("priority must be critical, high, medium or low")
		}
		add("priority", *in.Priority)
	}
	if in.RootCause != nil {
		rc := strings.TrimSpace(*in.RootCause)
		if len(rc) > 4000 {
			return httpx.BadRequest("root_cause: at most 4000 characters")
		}
		add("root_cause", rc)
	}
	if in.FixPullRequestID != nil {
		var ok bool
		if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM fix_pull_requests WHERE organization_id = $1 AND id = $2 AND repository_id = $3)`,
			p.OrganizationID, *in.FixPullRequestID, before.RepositoryID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return httpx.BadRequest("fix_pull_request_id: no fix pull request of this repository")
		}
		add("fix_pull_request_id", *in.FixPullRequestID)
	}
	if in.ThreatID.Set {
		if in.ThreatID.Value == nil {
			add("threat_id", nil)
		} else {
			t, err := s.loadThreat(ctx, s.DB, p, *in.ThreatID.Value)
			if err != nil {
				return err
			}
			if err := checkThreatLink(t, before.ApplicationID, before.Kind); err != nil {
				return err
			}
			add("threat_id", t.ID)
		}
	}
	if len(meta) == 0 {
		return nil
	}
	submitted := in.Status != nil && *in.Status == "fix_submitted" && before.Status != "fix_submitted"
	return db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		args := append(args, p.OrganizationID)
		tag, err := tx.Exec(ctx, `UPDATE remediation_items SET `+strings.Join(set, ", ")+fmt.Sprintf(" WHERE id = $1 AND organization_id = $%d", len(args)), args...)
		if err != nil {
			if db.IsCheckViolation(err) {
				return ErrTransition
			}
			return err
		}
		if tag.RowsAffected() == 0 {
			return httpx.ErrNotFound
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "remediation_item.update", TargetType: "remediation_item", TargetID: before.ID.String(), Metadata: meta}); err != nil {
			return err
		}
		if submitted {
			return s.verifySubmitted(ctx, tx, p, before.ID)
		}
		return nil
	})
}

type bulkInput struct {
	IDs        []uuid.UUID `json:"ids"`
	OwnerID    *uuid.UUID  `json:"owner_id"`
	ClearOwner bool        `json:"clear_owner"`
	DueAt      *time.Time  `json:"due_at"`
	Status     *string     `json:"status"`
	Priority   *string     `json:"priority"`
}

// bulk applies one change to several items; every item is checked and the
// whole request fails when one cannot be changed.
func (s *Service) bulk(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in bulkInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(in.IDs) == 0 || len(in.IDs) > 200 {
		s.fail(w, r, httpx.BadRequest("ids: 1 to 200 items"))
		return
	}
	if in.OwnerID == nil && !in.ClearOwner && in.DueAt == nil && in.Status == nil && in.Priority == nil {
		s.fail(w, r, httpx.BadRequest("nothing to change"))
		return
	}
	items := make([]Item, 0, len(in.IDs))
	for _, id := range in.IDs {
		it, err := s.loadItem(ctx, p, id, authz.PermRemediationManage)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if in.Status != nil && !CanTransition(it.Status, *in.Status) {
			s.fail(w, r, ErrTransition)
			return
		}
		items = append(items, it)
	}
	for _, it := range items {
		if err := s.applyPatch(ctx, p, it, patchInput{OwnerID: in.OwnerID, ClearOwner: in.ClearOwner, DueAt: in.DueAt, Status: in.Status, Priority: in.Priority}); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"updated": len(items)})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }
