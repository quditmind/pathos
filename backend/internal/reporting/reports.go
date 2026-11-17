package reporting

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scans"
)

// Definition describes a custom report over findings.
type Definition struct {
	// Filters are the Findings page's filters (query parameter names).
	Filters map[string]string `json:"filters"`
	// GroupBy summarizes findings per value; "" lists findings.
	GroupBy string `json:"group_by"`
	// Columns of the finding list (ignored when grouping).
	Columns []string `json:"columns"`
}

// Report is a saved report.
type Report struct {
	ID          uuid.UUID   `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Definition  Definition  `json:"definition"`
	Shared      bool        `json:"shared"`
	Schedule    *string     `json:"schedule"`
	Recipients  []uuid.UUID `json:"recipients"`
	Owner       string      `json:"owner"`
	OwnerID     uuid.UUID   `json:"owner_id"`
	NextRunAt   *time.Time  `json:"next_run_at"`
	LastRunAt   *time.Time  `json:"last_run_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	CanEdit     bool        `json:"can_edit"`
}

var (
	filterKeys = []string{"status", "severity", "category", "scanner", "repository_id", "application_id", "assignee", "sla", "human_review",
		"lifecycle", "kev", "risk_min", "malicious", "control", "target_kind", "q"}
	groupBys = map[string]struct{ expr, label string }{
		"severity":      {"f.severity", "Severity"},
		"status":        {"f.status", "Status"},
		"category":      {"f.category", "Type"},
		"repository":    {"COALESCE(NULLIF(r.display_name, ''), r.full_name)", "Repository"},
		"application":   {"COALESCE((SELECT a.name FROM applications a WHERE a.id = r.application_id), 'No application')", "Application"},
		"business_unit": {"COALESCE((SELECT b.name FROM business_units b WHERE b.id = r.business_unit_id), 'No business unit')", "Business unit"},
		"scanner":       {"f.scanner_keys[1]", "Scanner"},
		"assignee":      {"COALESCE((SELECT u.email FROM users u WHERE u.id = f.assignee_id), 'Unassigned')", "Assignee"},
		"cve":           {"COALESCE(f.cve, '—')", "Vulnerability"},
	}
	columnDefs = map[string]struct{ expr, label string }{
		"title":      {"f.title", "Title"},
		"severity":   {"f.severity", "Severity"},
		"status":     {"f.status", "Status"},
		"category":   {"f.category", "Type"},
		"repository": {"COALESCE(NULLIF(r.display_name, ''), r.full_name)", "Repository"},
		"rule_id":    {"f.rule_id", "Rule"},
		"cve":        {"COALESCE(f.cve, '')", "Vulnerability"},
		"location":   {"f.file_path || COALESCE(':' || f.start_line, '')", "Location"},
		"package":    {"CASE WHEN f.package_name = '' THEN '' ELSE f.package_name || '@' || f.package_version END", "Package"},
		"fixed_in":   {"f.fixed_version", "Fixed in"},
		"risk":       {"COALESCE(f.risk_score::text, '')", "Risk"},
		"kev":        {"CASE WHEN f.kev THEN 'yes' ELSE '' END", "KEV"},
		"first_seen": {"to_char(f.first_seen_at, 'YYYY-MM-DD')", "First seen"},
		"sla_due":    {"COALESCE(to_char(f.sla_due_at, 'YYYY-MM-DD'), '')", "SLA due"},
		"assignee":   {"COALESCE((SELECT u.email FROM users u WHERE u.id = f.assignee_id), '')", "Assignee"},
		"scanners":   {"array_to_string(f.scanner_keys, ', ')", "Scanners"},
	}
	defaultColumns = []string{"severity", "title", "repository", "location", "status", "first_seen"}
	schedules      = map[string]string{"daily": "1 day", "weekly": "7 days", "monthly": "1 month"}
)

const maxRows = 5000

func (d *Definition) validate() error {
	if d.Filters == nil {
		d.Filters = map[string]string{}
	}
	for k, v := range d.Filters {
		if !slices.Contains(filterKeys, k) {
			return httpx.BadRequest("unknown filter " + k)
		}
		if len(v) > 500 {
			return httpx.BadRequest("filter " + k + " is too long")
		}
	}
	if d.GroupBy != "" {
		if _, ok := groupBys[d.GroupBy]; !ok {
			return httpx.BadRequest("unknown group_by")
		}
	}
	if len(d.Columns) == 0 {
		d.Columns = defaultColumns
	}
	if len(d.Columns) > 16 {
		return httpx.BadRequest("at most 16 columns")
	}
	for _, c := range d.Columns {
		if _, ok := columnDefs[c]; !ok {
			return httpx.BadRequest("unknown column " + c)
		}
	}
	return nil
}

func (s *Service) registerReports(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/reports", s.listReports)
	mux.HandleFunc("POST /api/v1/reports", s.createReport)
	mux.HandleFunc("POST /api/v1/reports/preview", s.previewReport)
	mux.HandleFunc("GET /api/v1/reports/{id}", s.getReport)
	mux.HandleFunc("PUT /api/v1/reports/{id}", s.updateReport)
	mux.HandleFunc("DELETE /api/v1/reports/{id}", s.deleteReport)
	mux.HandleFunc("GET /api/v1/reports/{id}/run", s.runReport)
}

const reportSelect = `SELECT r.id, r.name, r.description, r.definition, r.shared, r.schedule, r.recipients, COALESCE(u.email, ''), r.owner_id,
	r.next_run_at, r.last_run_at, r.updated_at FROM saved_reports r LEFT JOIN users u ON u.id = r.owner_id`

func scanReport(row pgx.Row, p *authz.Principal) (Report, error) {
	var rp Report
	var def []byte
	if err := row.Scan(&rp.ID, &rp.Name, &rp.Description, &def, &rp.Shared, &rp.Schedule, &rp.Recipients, &rp.Owner, &rp.OwnerID,
		&rp.NextRunAt, &rp.LastRunAt, &rp.UpdatedAt); err != nil {
		return rp, err
	}
	rp.CanEdit = rp.OwnerID == p.UserID || p.HasOrgWide(authz.PermSettingsManage)
	return rp, json.Unmarshal(def, &rp.Definition)
}

func (s *Service) reader(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil || !p.HasAnywhere(authz.PermFindingsRead) {
		return nil, authz.ErrForbidden
	}
	return p, nil
}

func (s *Service) listReports(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), reportSelect+` WHERE r.organization_id = $1 AND (r.owner_id = $2 OR r.shared OR $2 = ANY(r.recipients))
		ORDER BY lower(r.name)`, p.OrganizationID, p.UserID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Report, error) { return scanReport(row, p) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []Report{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "group_by": groupLabels(), "columns": columnLabels(), "filters": filterKeys})
}

func groupLabels() map[string]string {
	out := map[string]string{}
	for k, v := range groupBys {
		out[k] = v.label
	}
	return out
}

func columnLabels() map[string]string {
	out := map[string]string{}
	for k, v := range columnDefs {
		out[k] = v.label
	}
	return out
}

func (s *Service) load(ctx context.Context, p *authz.Principal, id uuid.UUID) (Report, error) {
	return scanReport(s.DB.QueryRow(ctx, reportSelect+` WHERE r.organization_id = $1 AND r.id = $2 AND (r.owner_id = $3 OR r.shared OR $3 = ANY(r.recipients))`,
		p.OrganizationID, id, p.UserID), p)
}

func (s *Service) getReport(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	rp, err := s.load(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rp)
}

type reportInput struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Definition  Definition  `json:"definition"`
	Shared      bool        `json:"shared"`
	Schedule    *string     `json:"schedule"`
	Recipients  []uuid.UUID `json:"recipients"`
}

func (s *Service) validateInput(ctx context.Context, p *authz.Principal, in *reportInput) error {
	in.Name, in.Description = strings.TrimSpace(in.Name), strings.TrimSpace(in.Description)
	if in.Name == "" || len(in.Name) > 200 || len(in.Description) > 2000 {
		return httpx.BadRequest("name is required (at most 200 characters)")
	}
	if err := in.Definition.validate(); err != nil {
		return err
	}
	if in.Schedule != nil {
		if _, ok := schedules[*in.Schedule]; !ok {
			return httpx.BadRequest("schedule must be daily, weekly or monthly")
		}
		if !p.HasAnywhere(authz.PermFindingsExport) {
			return httpx.E(http.StatusForbidden, "forbidden", "scheduling reports needs the findings.export permission")
		}
		if len(in.Recipients) == 0 {
			in.Recipients = []uuid.UUID{p.UserID}
		}
	}
	if len(in.Recipients) > 50 {
		return httpx.BadRequest("at most 50 recipients")
	}
	if len(in.Recipients) > 0 {
		var n int
		if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM users WHERE organization_id = $1 AND id = ANY($2) AND status = 'active'`,
			p.OrganizationID, in.Recipients).Scan(&n); err != nil {
			return err
		}
		if n != len(in.Recipients) {
			return httpx.BadRequest("recipients must be active users")
		}
	}
	if in.Recipients == nil {
		in.Recipients = []uuid.UUID{}
	}
	// A preview proves the filters are valid for the caller.
	_, _, err := s.where(p, in.Definition)
	return err
}

func nextRun(schedule *string) *time.Time {
	if schedule == nil {
		return nil
	}
	d := map[string]time.Duration{"daily": 24 * time.Hour, "weekly": 7 * 24 * time.Hour, "monthly": 30 * 24 * time.Hour}[*schedule]
	t := time.Now().Add(d).UTC()
	return &t
}

func (s *Service) createReport(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in reportInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.validateInput(r.Context(), p, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	id := uuid.Must(uuid.NewV7())
	def, _ := json.Marshal(in.Definition)
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `INSERT INTO saved_reports (id, organization_id, owner_id, name, description, definition, shared, schedule, recipients, next_run_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`, id, p.OrganizationID, p.UserID, in.Name, in.Description, def, in.Shared, in.Schedule,
			in.Recipients, nextRun(in.Schedule)); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("you already have a report with this name")
			}
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "report.create", TargetType: "report", TargetID: id.String(), Metadata: map[string]any{"name": in.Name, "schedule": in.Schedule, "shared": in.Shared}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rp, err := s.load(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, rp)
}

func (s *Service) updateReport(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	cur, err := s.load(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !cur.CanEdit {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var in reportInput
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.validateInput(r.Context(), p, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	def, _ := json.Marshal(in.Definition)
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `UPDATE saved_reports SET name = $2, description = $3, definition = $4, shared = $5, schedule = $6, recipients = $7,
			next_run_at = CASE WHEN $6::text IS NULL THEN NULL WHEN schedule IS DISTINCT FROM $6 OR next_run_at IS NULL THEN $8 ELSE next_run_at END,
			updated_at = now() WHERE id = $1`, id, in.Name, in.Description, def, in.Shared, in.Schedule, in.Recipients, nextRun(in.Schedule)); err != nil {
			if db.IsUniqueViolation(err) {
				return httpx.Conflict("a report with this name already exists")
			}
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "report.update", TargetType: "report", TargetID: id.String(), Metadata: map[string]any{"name": in.Name, "schedule": in.Schedule, "shared": in.Shared}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rp, err := s.load(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rp)
}

func (s *Service) deleteReport(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	cur, err := s.load(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !cur.CanEdit {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	err = db.InTx(r.Context(), s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(r.Context(), `DELETE FROM saved_reports WHERE id = $1`, id); err != nil {
			return err
		}
		return audit.Write(r.Context(), tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "report.delete", TargetType: "report", TargetID: id.String(), Metadata: map[string]any{"name": cur.Name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// where builds the scoped findings condition for a definition and caller.
func (s *Service) where(p *authz.Principal, d Definition) (string, []any, error) {
	q := url.Values{}
	for k, v := range d.Filters {
		q.Set(k, v)
	}
	where, args, err := scans.FindingsWhere(p, q)
	if err != nil {
		return "", nil, err
	}
	return strings.Join(where, " AND "), args, nil
}

// Result is a run of a report.
type Result struct {
	Columns   []string   `json:"columns"`
	Rows      [][]string `json:"rows"`
	Total     int        `json:"total"`
	Truncated bool       `json:"truncated"`
	RunAt     time.Time  `json:"run_at"`
}

func (s *Service) run(ctx context.Context, p *authz.Principal, d Definition) (Result, error) {
	res := Result{RunAt: time.Now().UTC(), Rows: [][]string{}}
	where, args, err := s.where(p, d)
	if err != nil {
		return res, err
	}
	from := ` FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE ` + where
	if d.GroupBy != "" {
		g := groupBys[d.GroupBy]
		res.Columns = []string{g.label, "Critical", "High", "Medium", "Low", "Info", "Total"}
		// #nosec G202 -- expressions come from fixed tables; values are placeholders
		rows, err := s.DB.Query(ctx, `SELECT `+g.expr+` AS k,
			count(*) FILTER (WHERE f.severity = 'critical'), count(*) FILTER (WHERE f.severity = 'high'), count(*) FILTER (WHERE f.severity = 'medium'),
			count(*) FILTER (WHERE f.severity = 'low'), count(*) FILTER (WHERE f.severity = 'info'), count(*)`+from+`
			GROUP BY 1 ORDER BY 2 DESC, 3 DESC, 7 DESC LIMIT `+fmt.Sprint(maxRows), args...)
		if err != nil {
			return res, err
		}
		defer rows.Close()
		for rows.Next() {
			var k *string
			var c [6]int
			if err := rows.Scan(&k, &c[0], &c[1], &c[2], &c[3], &c[4], &c[5]); err != nil {
				return res, err
			}
			key := "—"
			if k != nil {
				key = *k
			}
			row := []string{key}
			for _, n := range c {
				row = append(row, fmt.Sprint(n))
			}
			res.Rows = append(res.Rows, row)
			res.Total += c[5]
		}
		return res, rows.Err()
	}
	var exprs []string
	for _, c := range d.Columns {
		exprs = append(exprs, columnDefs[c].expr+"::text")
		res.Columns = append(res.Columns, columnDefs[c].label)
	}
	// #nosec G202 -- expressions come from fixed tables; values are placeholders
	if err := s.DB.QueryRow(ctx, `SELECT count(*)`+from, args...).Scan(&res.Total); err != nil {
		return res, err
	}
	// #nosec G202 -- expressions come from fixed tables; values are placeholders
	rows, err := s.DB.Query(ctx, `SELECT `+strings.Join(exprs, ", ")+from+`
		ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity), f.risk_score DESC NULLS LAST, f.first_seen_at LIMIT `+fmt.Sprint(maxRows), args...)
	if err != nil {
		return res, err
	}
	defer rows.Close()
	for rows.Next() {
		vals := make([]*string, len(exprs))
		ptrs := make([]any, len(exprs))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return res, err
		}
		row := make([]string, len(vals))
		for i, v := range vals {
			if v != nil {
				row[i] = *v
			}
		}
		res.Rows = append(res.Rows, row)
	}
	res.Truncated = res.Total > len(res.Rows)
	return res, rows.Err()
}

func (s *Service) previewReport(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var d Definition
	if err := httpx.DecodeJSON(w, r, &d); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := d.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.run(r.Context(), p, d)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(res.Rows) > 200 {
		res.Rows, res.Truncated = res.Rows[:200], true
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// csvSafe stops spreadsheet formula injection.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

// runReport runs a saved report as the caller: everyone sees only findings
// they may read, whoever saved or scheduled the report.
func (s *Service) runReport(w http.ResponseWriter, r *http.Request) {
	p, err := s.reader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, pgx.ErrNoRows)
		return
	}
	rp, err := s.load(r.Context(), p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.run(r.Context(), p, rp.Definition)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if r.URL.Query().Get("format") != "csv" {
		httpx.WriteJSON(w, http.StatusOK, res)
		return
	}
	if !p.HasAnywhere(authz.PermFindingsExport) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	_ = audit.Write(r.Context(), s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "report.export", TargetType: "report", TargetID: id.String(), Metadata: map[string]any{"rows": len(res.Rows)}})
	name := strings.Map(func(c rune) rune {
		if c < 0x20 || c == '"' || c == '\\' || c == '/' {
			return '_'
		}
		return c
	}, rp.Name)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`.csv"`)
	cw := csv.NewWriter(w)
	_ = cw.Write(res.Columns)
	for _, row := range res.Rows {
		safe := make([]string, len(row))
		for i, v := range row {
			safe[i] = csvSafe(v)
		}
		_ = cw.Write(safe)
	}
	cw.Flush()
}

// RunDue sends "report.scheduled" notifications for reports that are due
// and moves them to their next run. Returns the number sent.
func RunDue(ctx context.Context, q db.Querier) (int, error) {
	tag, err := q.Exec(ctx, `
		WITH due AS (
		  UPDATE saved_reports SET last_run_at = now(),
		    next_run_at = now() + CASE schedule WHEN 'daily' THEN interval '1 day' WHEN 'weekly' THEN interval '7 days' ELSE interval '1 month' END
		  WHERE schedule IS NOT NULL AND next_run_at <= now()
		  RETURNING id, organization_id, name, recipients)
		INSERT INTO notification_events (organization_id, event_key, payload)
		SELECT organization_id, 'report.scheduled', jsonb_build_object('report_id', id, 'report_name', name, 'recipient_ids', to_jsonb(recipients))
		FROM due`)
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
