package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"text/template"
	"time"
	"unicode"

	"github.com/google/uuid"

	"pathos/internal/platform/db"
)

// Item is a finding as shown in a message.
type Item struct {
	ID       string
	Title    string
	Severity string
	Location string
	SLADue   string
	Assignee string
}

// Data is what templates see. Values from scanned code (titles, paths,
// errors) are untrusted text: messages are plain text, the subject is
// sanitized, and the UI escapes everything it shows.
type Data struct {
	Org        string
	BaseURL    string
	Link       string
	Event      string
	EventLabel string
	Repository string
	Severity   string
	Actor      string
	Policy     string // policy.violated
	Count      int
	More       int
	Findings   []Item
	Finding    Item
	Scan       struct {
		ID, Trigger, Error string
		New, Fixed         int
		Attempts           int
		GateFailed         bool
	}
	Risk struct {
		Status, Justification, ExpiresAt, RequestedBy, DecidedBy, Note string
	}
	Schedule struct {
		Name, DueAt       string
		Missed            int
		Succeeded, Failed int
	}
	Worker struct {
		Name, Family, LastSeen string
		Queued                 int
	}
	Sync struct {
		Status, Error string
	}
	Import struct {
		Status, RequestedBy string
		Total, Failed       int
	}
	Review struct {
		Key, Status, Disposition, Priority, DueAt, Outcome string
	}

	// Recipient hints for dynamic recipients (not exposed to templates).
	assignees []uuid.UUID
	requester *uuid.UUID
	// independent is the designated independent reviewer, if any.
	independent *uuid.UUID
}

const maxListed = 10

func fmtTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func location(path string, line *int, pkg, ver string) string {
	if pkg != "" {
		return pkg + "@" + ver
	}
	if path != "" && line != nil {
		return fmt.Sprintf("%s:%d", path, *line)
	}
	return path
}

// eventRow is one notification_events row.
type eventRow struct {
	ID         uuid.UUID
	OrgID      uuid.UUID
	Key        string
	Repository *uuid.UUID
	Severity   *string
	SubjectID  *uuid.UUID
	Payload    map[string]any
	CreatedAt  time.Time
}

func payloadString(p map[string]any, k string) string {
	s, _ := p[k].(string)
	return s
}

func payloadInt(p map[string]any, k string) int {
	switch v := p[k].(type) {
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func payloadUUID(p map[string]any, k string) *uuid.UUID {
	if id, err := uuid.Parse(payloadString(p, k)); err == nil {
		return &id
	}
	return nil
}

func userName(ctx context.Context, q db.Querier, id *uuid.UUID) string {
	if id == nil {
		return ""
	}
	var n string
	_ = q.QueryRow(ctx, `SELECT COALESCE(NULLIF(display_name, ''), email) FROM users WHERE id = $1`, *id).Scan(&n)
	return n
}

const findingCols = `f.id, f.title, f.severity, f.file_path, f.start_line, COALESCE(f.package_name, ''), COALESCE(f.package_version, ''),
	f.sla_due_at, COALESCE(NULLIF(u.display_name, ''), u.email, '')`

func scanItems(ctx context.Context, q db.Querier, sql string, args ...any) ([]Item, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Item
	for rows.Next() {
		var (
			it       Item
			id       uuid.UUID
			path     string
			line     *int
			pkg, ver string
			due      *time.Time
		)
		if err := rows.Scan(&id, &it.Title, &it.Severity, &path, &line, &pkg, &ver, &due, &it.Assignee); err != nil {
			return nil, err
		}
		it.ID, it.Location, it.SLADue = id.String(), location(path, line, pkg, ver), fmtTime(due)
		out = append(out, it)
	}
	return out, rows.Err()
}

const severityOrder = `CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`

// load builds template data for an event from the database.
func load(ctx context.Context, q db.Querier, ev eventRow, baseURL string) (*Data, error) {
	d := &Data{BaseURL: baseURL, Event: ev.Key}
	if def, ok := LookupEvent(ev.Key); ok {
		d.EventLabel = def.Label
	}
	_ = q.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, ev.OrgID).Scan(&d.Org)
	if ev.Repository != nil {
		_ = q.QueryRow(ctx, `SELECT full_name FROM repositories WHERE id = $1`, *ev.Repository).Scan(&d.Repository)
	}
	if ev.Severity != nil {
		d.Severity = *ev.Severity
	}
	p := ev.Payload
	switch ev.Key {
	case "scan.failed", "findings.new":
		if ev.SubjectID == nil {
			return nil, errors.New("event has no scan job")
		}
		var started *time.Time
		var queued time.Time
		err := q.QueryRow(ctx, `SELECT trigger, error, attempts, findings_new, findings_fixed, gate_failed, started_at, queued_at
			FROM scan_jobs WHERE id = $1`, *ev.SubjectID).
			Scan(&d.Scan.Trigger, &d.Scan.Error, &d.Scan.Attempts, &d.Scan.New, &d.Scan.Fixed, &d.Scan.GateFailed, &started, &queued)
		if err != nil {
			return nil, fmt.Errorf("load scan job: %w", err)
		}
		d.Scan.ID = ev.SubjectID.String()
		d.Link = baseURL + "/scans?job=" + d.Scan.ID
		if ev.Key == "findings.new" {
			since := queued
			if started != nil {
				since = *started
			}
			items, err := scanItems(ctx, q, `SELECT `+findingCols+` FROM findings f LEFT JOIN users u ON u.id = f.assignee_id
				WHERE f.repository_id = $1 AND f.first_seen_at >= $2 ORDER BY `+severityOrder+`, f.title LIMIT $3`, *ev.Repository, since, maxListed)
			if err != nil {
				return nil, err
			}
			d.Findings, d.Count = items, d.Scan.New
			d.More = max(d.Scan.New-len(items), 0)
			d.Link = baseURL + "/findings?repository_id=" + ev.Repository.String()
		}
	case "finding.sla_breached", "policy.violated":
		if ev.Key == "policy.violated" {
			d.Policy, _ = p["policy_name"].(string)
		}
		var ids []uuid.UUID
		if raw, ok := p["finding_ids"].([]any); ok {
			for _, v := range raw {
				if s, ok := v.(string); ok {
					if id, err := uuid.Parse(s); err == nil {
						ids = append(ids, id)
					}
				}
			}
		}
		d.Count = len(ids)
		items, err := scanItems(ctx, q, `SELECT `+findingCols+` FROM findings f LEFT JOIN users u ON u.id = f.assignee_id
			WHERE f.id = ANY($1) ORDER BY `+severityOrder+`, f.sla_due_at LIMIT $2`, ids, maxListed)
		if err != nil {
			return nil, err
		}
		d.Findings, d.More = items, max(d.Count-len(items), 0)
		rows, err := q.Query(ctx, `SELECT DISTINCT assignee_id FROM findings WHERE id = ANY($1) AND assignee_id IS NOT NULL`, ids)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var a uuid.UUID
			if err := rows.Scan(&a); err == nil {
				d.assignees = append(d.assignees, a)
			}
		}
		rows.Close()
		d.Link = baseURL + "/findings?sla=breached"
		if ev.Key == "policy.violated" {
			d.Link = baseURL + "/findings?status=all"
			if pid, _ := p["policy_id"].(string); pid != "" {
				d.Link = baseURL + "/admin/policies?policy=" + pid
			}
		} else if ev.Repository != nil {
			d.Link += "&repository_id=" + ev.Repository.String()
		}
	case "finding.assigned":
		if err := loadFinding(ctx, q, d, ev.SubjectID, baseURL); err != nil {
			return nil, err
		}
		if a := payloadUUID(p, "assignee_id"); a != nil {
			d.assignees = []uuid.UUID{*a}
		}
		d.Actor = userName(ctx, q, payloadUUID(p, "actor"))
	case "risk.requested", "risk.decided":
		if ev.SubjectID == nil {
			return nil, errors.New("event has no risk acceptance")
		}
		var findingID uuid.UUID
		var req uuid.UUID
		var decided *uuid.UUID
		var expires time.Time
		err := q.QueryRow(ctx, `SELECT finding_id, requested_by, decided_by, status, justification, decision_note, expires_at
			FROM risk_acceptances WHERE id = $1`, *ev.SubjectID).
			Scan(&findingID, &req, &decided, &d.Risk.Status, &d.Risk.Justification, &d.Risk.Note, &expires)
		if err != nil {
			return nil, fmt.Errorf("load risk acceptance: %w", err)
		}
		if s := payloadString(p, "status"); s != "" {
			d.Risk.Status = s // the state at event time
		}
		d.Risk.ExpiresAt = fmtTime(&expires)
		d.Risk.RequestedBy, d.Risk.DecidedBy = userName(ctx, q, &req), userName(ctx, q, decided)
		d.requester = &req
		if err := loadFinding(ctx, q, d, &findingID, baseURL); err != nil {
			return nil, err
		}
		if ev.Key == "risk.requested" {
			d.Link = baseURL + "/risk"
		}
	case "schedule.missed":
		if ev.SubjectID != nil {
			_ = q.QueryRow(ctx, `SELECT name FROM scan_schedules WHERE id = $1`, *ev.SubjectID).Scan(&d.Schedule.Name)
		}
		d.Schedule.Missed = payloadInt(p, "missed")
		if t, err := time.Parse(time.RFC3339Nano, payloadString(p, "due_at")); err == nil {
			d.Schedule.DueAt = fmtTime(&t)
		}
		d.Link = baseURL + "/scans/schedules"
	case "repository.sync_failed":
		d.Sync.Status, d.Sync.Error = payloadString(p, "status"), payloadString(p, "error")
		if ev.Repository != nil {
			_ = q.QueryRow(ctx, `SELECT COALESCE(NULLIF(display_name, ''), full_name) FROM repositories WHERE id = $1`, *ev.Repository).Scan(&d.Repository)
			d.Link = baseURL + "/repositories?repo=" + ev.Repository.String()
		}
	case "import.failed":
		if ev.SubjectID != nil {
			var by uuid.UUID
			err := q.QueryRow(ctx, `SELECT j.status, j.total_items, j.requested_by,
				(SELECT count(*) FROM repository_import_items i WHERE i.job_id = j.id AND i.status IN ('failed', 'needs_attention'))
				FROM repository_import_jobs j WHERE j.id = $1`, *ev.SubjectID).Scan(&d.Import.Status, &d.Import.Total, &by, &d.Import.Failed)
			if err != nil {
				return nil, fmt.Errorf("load import job: %w", err)
			}
			d.Import.Status = strings.ReplaceAll(d.Import.Status, "_", " ")
			d.Import.RequestedBy = userName(ctx, q, &by)
			d.requester = &by
			d.Link = baseURL + "/repositories/imports/" + ev.SubjectID.String()
		}
	case "schedule.completed", "schedule.failed":
		if ev.SubjectID != nil {
			var by *uuid.UUID
			_ = q.QueryRow(ctx, `SELECT name, created_by FROM scan_schedules WHERE id = $1`, *ev.SubjectID).Scan(&d.Schedule.Name, &by)
			d.requester = by
		}
		d.Schedule.Succeeded, d.Schedule.Failed = payloadInt(p, "succeeded"), payloadInt(p, "failed")
		d.Link = baseURL + "/scans?schedule_id=" + ev.SubjectID.String()
	case "review.assigned", "review.independent_requested", "review.independent_decided", "review.overdue":
		if ev.SubjectID == nil {
			return nil, errors.New("event has no review")
		}
		var findingID uuid.UUID
		var reviewer *uuid.UUID
		var due *time.Time
		var disp *string
		err := q.QueryRow(ctx, `SELECT finding_id, review_key, status, disposition, priority, due_at, reviewer_id FROM human_reviews WHERE id = $1`,
			*ev.SubjectID).Scan(&findingID, &d.Review.Key, &d.Review.Status, &disp, &d.Review.Priority, &due, &reviewer)
		if err != nil {
			return nil, fmt.Errorf("load review: %w", err)
		}
		if err := loadFinding(ctx, q, d, &findingID, baseURL); err != nil {
			return nil, err
		}
		d.Review.Status = strings.ReplaceAll(d.Review.Status, "_", " ")
		d.Review.DueAt = fmtTime(due)
		d.Review.Disposition = strings.ReplaceAll(payloadString(p, "disposition"), "_", " ")
		if d.Review.Disposition == "" && disp != nil {
			d.Review.Disposition = strings.ReplaceAll(*disp, "_", " ")
		}
		d.Review.Outcome = strings.ReplaceAll(payloadString(p, "outcome"), "_", " ")
		if a := payloadUUID(p, "assignee_id"); a != nil {
			d.assignees = []uuid.UUID{*a}
		} else if reviewer != nil && ev.Key != "review.independent_requested" {
			d.assignees = []uuid.UUID{*reviewer}
		}
		d.requester = payloadUUID(p, "decided_by")
		d.Actor = userName(ctx, q, payloadUUID(p, "actor"))
		if ev.Key == "review.independent_requested" {
			d.Actor = userName(ctx, q, d.requester)
			d.independent = payloadUUID(p, "independent_reviewer_id")
		}
		d.Link = baseURL + "/human-review/reviews/" + ev.SubjectID.String()
	case "worker.offline":
		d.Worker.Name, d.Worker.Family = payloadString(p, "name"), payloadString(p, "family")
		if t, err := time.Parse(time.RFC3339Nano, payloadString(p, "last_seen_at")); err == nil {
			d.Worker.LastSeen = fmtTime(&t)
		}
		d.Worker.Queued = payloadInt(p, "queued")
		d.Link = baseURL + "/admin/scanners"
	}
	if d.Link == "" {
		d.Link = baseURL + "/"
	}
	return d, nil
}

func loadFinding(ctx context.Context, q db.Querier, d *Data, id *uuid.UUID, baseURL string) error {
	if id == nil {
		return errors.New("event has no finding")
	}
	items, err := scanItems(ctx, q, `SELECT `+findingCols+` FROM findings f LEFT JOIN users u ON u.id = f.assignee_id WHERE f.id = $1`, *id)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return errors.New("finding no longer exists")
	}
	d.Finding = items[0]
	d.Link = baseURL + "/findings?status=all&finding=" + id.String()
	return nil
}

// Sample returns representative data for template previews.
func Sample(key, baseURL string) *Data {
	d := &Data{Org: "Example Corp", BaseURL: baseURL, Event: key, Repository: "acme/payments-api", Severity: "critical",
		Actor: "Dana Analyst", Count: 3, More: 1, Link: baseURL + "/findings"}
	if def, ok := LookupEvent(key); ok {
		d.EventLabel = def.Label
	}
	d.Findings = []Item{
		{Title: "SQL injection in OrderController.search", Severity: "critical", Location: "src/orders/controller.ts:88", SLADue: "2026-11-20 09:00 UTC", Assignee: "Sam Developer"},
		{Title: "CVE-2025-1234: lodash prototype pollution", Severity: "high", Location: "lodash@4.17.20", SLADue: "2026-12-10 09:00 UTC"},
	}
	d.Finding = d.Findings[0]
	d.Scan.ID, d.Scan.Trigger, d.Scan.Error = "0190c0de-0000-7000-8000-000000000000", "schedule", "clone failed: repository not found"
	d.Scan.New, d.Scan.Fixed, d.Scan.Attempts, d.Scan.GateFailed = 3, 1, 3, true
	d.Risk.Status, d.Risk.Justification, d.Risk.ExpiresAt = "approved", "Endpoint is internal only and protected by the WAF rule PAY-12.", "2027-02-15 00:00 UTC"
	d.Risk.RequestedBy, d.Risk.DecidedBy, d.Risk.Note = "Sam Developer", "Riley Manager", "Re-assess after the Q1 migration."
	d.Schedule.Name, d.Schedule.DueAt, d.Schedule.Missed = "Nightly EMEA", "2026-11-15 02:00 UTC", 2
	d.Schedule.Succeeded, d.Schedule.Failed = 41, 1
	d.Worker.Name, d.Worker.Family, d.Worker.LastSeen, d.Worker.Queued = "worker-core-1", "core", "2026-11-15 09:41 UTC", 12
	d.Sync.Status, d.Sync.Error = "permission_denied", "scm: the credential does not have permission for this operation"
	d.Import.Status, d.Import.RequestedBy, d.Import.Total, d.Import.Failed = "failed", "Sam Developer", 4, 1
	d.Review.Key, d.Review.Status, d.Review.Disposition, d.Review.Priority = "QD-HR-000042", "in progress", "false positive", "p1"
	d.Review.DueAt, d.Review.Outcome = "2026-11-19 09:00 UTC", "approved"
	return d
}

// limitWriter stops template output beyond a size.
type limitWriter struct {
	buf   bytes.Buffer
	limit int
}

var errTooLong = errors.New("rendered message is too long")

func (w *limitWriter) Write(p []byte) (int, error) {
	if w.buf.Len()+len(p) > w.limit {
		return 0, errTooLong
	}
	return w.buf.Write(p)
}

// Parse validates a subject/body pair.
func Parse(subject, body string) (*template.Template, *template.Template, error) {
	st, err := template.New("subject").Option("missingkey=error").Parse(subject)
	if err != nil {
		return nil, nil, fmt.Errorf("subject: %w", err)
	}
	bt, err := template.New("body").Option("missingkey=error").Parse(body)
	if err != nil {
		return nil, nil, fmt.Errorf("body: %w", err)
	}
	return st, bt, nil
}

// Render produces subject and body. The subject is a single sanitized line.
func Render(subject, body string, d *Data) (string, string, error) {
	st, bt, err := Parse(subject, body)
	if err != nil {
		return "", "", err
	}
	sw := &limitWriter{limit: 2000}
	if err := st.Execute(sw, d); err != nil {
		return "", "", fmt.Errorf("subject: %w", err)
	}
	bw := &limitWriter{limit: 64 << 10}
	if err := bt.Execute(bw, d); err != nil {
		return "", "", fmt.Errorf("body: %w", err)
	}
	out := strings.TrimSpace(bw.buf.String())
	out += "\n\n—\nPATHOS · " + d.Org + "\nManage notifications: " + d.BaseURL + "/admin/notifications"
	return SanitizeHeader(sw.buf.String(), 200), out, nil
}

// SanitizeHeader collapses a value to one printable line (no header injection).
func SanitizeHeader(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return ' '
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > max {
		s = string(r[:max-1]) + "…"
	}
	return s
}
