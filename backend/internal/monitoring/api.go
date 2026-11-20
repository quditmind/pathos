package monitoring

import (
	"context"
	"encoding/csv"
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
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Error codes (catalogue: internal/platform/diag/catalogue_m9.go).
const (
	CodeBadFilter     = "PTH-MON-1101"
	CodeBadSettings   = "PTH-MON-1102"
	CodeDriftFailed   = "PTH-MON-1103"
	CodeLoopFailed    = "PTH-MON-1104"
	CodeRecordFailed  = "PTH-MON-1105"
	maxPage           = 200
	defaultPage       = 50
	maxCSVRows        = 10000
	maxDriftItemsJSON = 500
)

// Service serves the monitoring API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the endpoints.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/monitoring/types", s.types)
	mux.HandleFunc("GET /api/v1/monitoring/events", s.events)
	mux.HandleFunc("GET /api/v1/monitoring/summary", s.summary)
	mux.HandleFunc("GET /api/v1/monitoring/drift", s.listDrift)
	mux.HandleFunc("GET /api/v1/monitoring/drift/{id}", s.getDrift)
	mux.HandleFunc("GET /api/v1/monitoring/settings", s.getSettings)
	mux.HandleFunc("PUT /api/v1/monitoring/settings", s.putSettings)
}

func badFilter(msg string) error {
	return httpx.E(http.StatusBadRequest, "invalid_filter", msg).WithDiag(CodeBadFilter)
}

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, pgx.ErrNoRows):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

// begin checks the flag and that the caller may read findings somewhere.
func (s *Service) begin(r *http.Request, perm authz.Permission) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil {
		return nil, httpx.ErrUnauthenticated
	}
	if err := featureflags.Require(r.Context(), s.DB, p.OrganizationID, Flag); err != nil {
		return nil, err
	}
	org := p.OrganizationID
	if err := FillCommits(r.Context(), s.DB, &org); err != nil {
		s.Log.Warn("drift commit evidence not completed", "err", err, "error_code", CodeRecordFailed)
	}
	if !p.HasAnywhere(perm) {
		return nil, authz.ErrForbidden
	}
	return p, nil
}

// visibilitySQL limits rows (alias e, with repository_id and
// application_id columns) to what the principal may read: a repository
// row when the repository is in the caller's findings.read scope; an
// application row when every active repository of the application is.
func visibilitySQL(p *authz.Principal, alias string, first int) (string, []any) {
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.All {
		return "true", nil
	}
	if f.None() {
		return "false", nil
	}
	scope, args := org.ScopeSQL(f, "vr.id", "vr.business_unit_id", "vr.country_id", first)
	appScope, appArgs := org.ScopeSQL(f, "ar.id", "ar.business_unit_id", "ar.country_id", first+len(args))
	return "((" + alias + ".repository_id IS NOT NULL AND EXISTS (SELECT 1 FROM repositories vr WHERE vr.id = " + alias + ".repository_id AND " + scope + ")) OR (" +
		alias + ".repository_id IS NULL AND " + alias + ".application_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM repositories ar WHERE ar.application_id = " +
		alias + ".application_id AND ar.archived_at IS NULL AND NOT " + appScope + ")))", append(args, appArgs...)
}

func (s *Service) types(w http.ResponseWriter, r *http.Request) {
	if _, err := s.begin(r, authz.PermFindingsRead); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": Types})
}

// FeedEvent is an event as the API returns it.
type FeedEvent struct {
	ID              uuid.UUID      `json:"id"`
	Type            string         `json:"type"`
	TypeLabel       string         `json:"type_label"`
	Loop            *int           `json:"loop"`
	Severity        string         `json:"severity"`
	Title           string         `json:"title"`
	Summary         string         `json:"summary"`
	EvidenceLabel   string         `json:"evidence_label"`
	Evidence        map[string]any `json:"evidence"`
	ApplicationID   *uuid.UUID     `json:"application_id"`
	ApplicationName string         `json:"application_name"`
	RepositoryID    *uuid.UUID     `json:"repository_id"`
	RepositoryName  string         `json:"repository_name"`
	SubjectType     *string        `json:"subject_type"`
	SubjectID       *uuid.UUID     `json:"subject_id"`
	Link            string         `json:"link"`
	Details         map[string]any `json:"details"`
	CreatedAt       time.Time      `json:"created_at"`
}

const eventSelect = `SELECT e.id, e.event_type, e.feedback_loop, e.severity, e.title, e.summary, e.evidence_label, e.evidence,
	e.application_id, COALESCE(a.name, ''), e.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name, ''),
	e.subject_type, e.subject_id, e.details, e.created_at
	FROM monitoring_events e LEFT JOIN applications a ON a.id = e.application_id LEFT JOIN repositories r ON r.id = e.repository_id`

func scanEvent(row pgx.Row) (FeedEvent, error) {
	var e FeedEvent
	var ev, det []byte
	var loop *int16
	var st string
	if err := row.Scan(&e.ID, &e.Type, &loop, &e.Severity, &e.Title, &e.Summary, &e.EvidenceLabel, &ev, &e.ApplicationID, &e.ApplicationName,
		&e.RepositoryID, &e.RepositoryName, &st, &e.SubjectID, &det, &e.CreatedAt); err != nil {
		return e, err
	}
	if loop != nil {
		n := int(*loop)
		e.Loop = &n
	}
	if st != "" {
		e.SubjectType = &st
	}
	_ = json.Unmarshal(ev, &e.Evidence)
	_ = json.Unmarshal(det, &e.Details)
	if e.Evidence == nil {
		e.Evidence = map[string]any{}
	}
	if e.Details == nil {
		e.Details = map[string]any{}
	}
	if def, ok := LookupType(e.Type); ok {
		e.TypeLabel = def.Label
	} else {
		e.TypeLabel = e.Type
	}
	e.Link = linkFor(e)
	return e, nil
}

// linkFor is the in-app page where the event's subject is shown.
func linkFor(e FeedEvent) string {
	id := func(p *uuid.UUID) string {
		if p == nil {
			return ""
		}
		return p.String()
	}
	switch e.Type {
	case TypeArchitectureDrift:
		if e.SubjectID != nil && e.ApplicationID != nil {
			return "/monitoring?tab=drift&application_id=" + id(e.ApplicationID) + "&drift=" + id(e.SubjectID)
		}
	case TypeRediscoveryQueued, TypeDependencyChanged:
		if e.ApplicationID != nil {
			return "/codegraph/" + id(e.ApplicationID)
		}
	case TypeThreatModelUpdated, TypeThreatModelReview:
		if e.SubjectID != nil {
			return "/threat-models/" + id(e.SubjectID)
		}
	case TypeFixVerificationQueued, TypeFixVerified:
		if e.SubjectID != nil {
			return "/remediation/items/" + id(e.SubjectID)
		}
	case TypeGateFailed:
		return "/remediation/gates"
	case TypeRiskRescored, TypeFindingsNew, TypeAITriageQueued:
		if e.RepositoryID != nil {
			return "/findings?repository_id=" + id(e.RepositoryID)
		}
	}
	return ""
}

// filter is the parsed query of the feed.
type filter struct {
	where []string
	args  []any
	limit int
}

func (f *filter) add(cond string, v any) {
	f.args = append(f.args, v)
	f.where = append(f.where, fmt.Sprintf(cond, len(f.args)))
}

func parseUUIDParam(q map[string][]string, k string) (*uuid.UUID, error) {
	v := ""
	if vs := q[k]; len(vs) > 0 {
		v = vs[0]
	}
	if v == "" {
		return nil, nil
	}
	id, err := uuid.Parse(v)
	if err != nil {
		return nil, badFilter(k + " must be a UUID")
	}
	return &id, nil
}

func parseLimit(v string) (int, error) {
	if v == "" {
		return defaultPage, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > maxPage {
		return 0, badFilter("limit must be 1-200")
	}
	return n, nil
}

func parseList(v string) []string {
	out := []string{}
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func (s *Service) eventFilter(p *authz.Principal, r *http.Request) (*filter, error) {
	q := r.URL.Query()
	f := &filter{where: []string{"e.organization_id = $1"}, args: []any{p.OrganizationID}}
	for _, k := range []string{"application_id", "repository_id"} {
		id, err := parseUUIDParam(q, k)
		if err != nil {
			return nil, err
		}
		if id != nil {
			f.add("e."+k+" = $%d", *id)
		}
	}
	if v := q.Get("type"); v != "" {
		ts := parseList(v)
		for _, t := range ts {
			if _, ok := LookupType(t); !ok {
				return nil, badFilter("unknown event type " + strconv.Quote(t))
			}
		}
		f.add("e.event_type = ANY($%d)", ts)
	}
	if v := q.Get("severity"); v != "" {
		ss := parseList(v)
		for _, sv := range ss {
			if !slices.Contains(Severities, sv) {
				return nil, badFilter("severity must be critical, high, medium, low or info")
			}
		}
		f.add("e.severity = ANY($%d)", ss)
	}
	if v := q.Get("loop"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 7 {
			return nil, badFilter("loop must be 1-7")
		}
		f.add("e.feedback_loop = $%d", n)
	}
	var since, until *time.Time
	for k, dst := range map[string]**time.Time{"since": &since, "until": &until} {
		if v := q.Get(k); v != "" {
			t, err := time.Parse(time.RFC3339, v)
			if err != nil {
				return nil, badFilter(k + " must be an RFC 3339 time")
			}
			*dst = &t
		}
	}
	if since != nil && until != nil && until.Before(*since) {
		return nil, badFilter("until is before since")
	}
	if since != nil {
		f.add("e.created_at >= $%d", *since)
	}
	if until != nil {
		f.add("e.created_at <= $%d", *until)
	}
	if v := q.Get("cursor"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return nil, badFilter("invalid cursor")
		}
		f.add("e.id < $%d", id)
	}
	limit, err := parseLimit(q.Get("limit"))
	if err != nil {
		return nil, err
	}
	f.limit = limit
	vis, vargs := visibilitySQL(p, "e", len(f.args)+1)
	f.args = append(f.args, vargs...)
	f.where = append(f.where, vis)
	return f, nil
}

func (s *Service) events(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r, authz.PermFindingsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	csvOut := r.URL.Query().Get("format") == "csv"
	if f := r.URL.Query().Get("format"); f != "" && f != "csv" && f != "json" {
		s.fail(w, r, badFilter("format must be json or csv"))
		return
	}
	if csvOut && !p.HasAnywhere(authz.PermFindingsExport) {
		s.fail(w, r, httpx.ErrForbidden.WithDiag("PTH-REP-1001"))
		return
	}
	f, err := s.eventFilter(p, r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit := f.limit
	if csvOut {
		limit = maxCSVRows
	}
	// UUIDv7 ids are time-ordered: keyset pagination on id.
	// #nosec G202 -- the conditions are built from placeholders
	rows, err := s.DB.Query(ctx, eventSelect+" WHERE "+strings.Join(f.where, " AND ")+fmt.Sprintf(" ORDER BY e.id DESC LIMIT %d", limit+1), f.args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (FeedEvent, error) { return scanEvent(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next *string
	if len(items) > limit {
		items = items[:limit]
		c := items[limit-1].ID.String()
		next = &c
	}
	if items == nil {
		items = []FeedEvent{}
	}
	if csvOut {
		_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "monitoring.export", TargetType: "monitoring_feed", TargetID: p.OrganizationID.String(), Metadata: map[string]any{"rows": len(items)}})
		writeEventsCSV(w, items)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

// csvSafe neutralises spreadsheet formula injection.
func csvSafe(v string) string {
	if v != "" && strings.ContainsRune("=+-@\t\r", rune(v[0])) {
		return "'" + v
	}
	return v
}

func writeEventsCSV(w http.ResponseWriter, items []FeedEvent) {
	httpx.Download(w, "text/csv; charset=utf-8", "pathos-monitoring-"+time.Now().UTC().Format("20060102")+".csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"created_at", "type", "loop", "severity", "title", "summary", "evidence_label", "application", "repository", "evidence"})
	for _, e := range items {
		loop := ""
		if e.Loop != nil {
			loop = strconv.Itoa(*e.Loop)
		}
		ev, _ := json.Marshal(e.Evidence)
		_ = cw.Write([]string{e.CreatedAt.UTC().Format(time.RFC3339), e.Type, loop, e.Severity, csvSafe(e.Title), csvSafe(e.Summary), e.EvidenceLabel,
			csvSafe(e.ApplicationName), csvSafe(e.RepositoryName), string(ev)})
	}
	cw.Flush()
}

func (s *Service) summary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r, authz.PermFindingsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	days := 30
	if v := q.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 365 {
			s.fail(w, r, badFilter("days must be 1-365"))
			return
		}
		days = n
	}
	app, err := parseUUIDParam(q, "application_id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	args := []any{p.OrganizationID, days, app}
	vis, vargs := visibilitySQL(p, "e", len(args)+1)
	args = append(args, vargs...)
	out := map[string]any{"days": days}
	byType, bySev := map[string]int{}, map[string]int{}
	total := 0
	var latest *time.Time
	// #nosec G202 -- vis is built from placeholders
	rows, err := s.DB.Query(ctx, `SELECT e.event_type, e.severity, count(*), max(e.created_at) FROM monitoring_events e
		WHERE e.organization_id = $1 AND e.created_at >= now() - make_interval(days => $2) AND ($3::uuid IS NULL OR e.application_id = $3)
		  AND `+vis+` GROUP BY 1, 2`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for rows.Next() {
		var t, sv string
		var n int
		var at time.Time
		if err := rows.Scan(&t, &sv, &n, &at); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		byType[t] += n
		bySev[sv] += n
		total += n
		if latest == nil || at.After(*latest) {
			x := at
			latest = &x
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	var dTotal, dChanged int
	var dLatest *time.Time
	// #nosec G202 -- vis is built from placeholders
	if err := s.DB.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE e.has_changes), max(e.created_at) FILTER (WHERE e.has_changes)
		FROM architecture_drifts e WHERE e.organization_id = $1 AND e.created_at >= now() - make_interval(days => $2)
		  AND ($3::uuid IS NULL OR e.application_id = $3) AND `+vis, args...).Scan(&dTotal, &dChanged, &dLatest); err != nil {
		s.fail(w, r, err)
		return
	}
	out["total"], out["by_type"], out["by_severity"], out["latest_at"] = total, byType, bySev, latest
	out["drift"] = map[string]any{"total": dTotal, "with_changes": dChanged, "latest_at": dLatest}
	httpx.WriteJSON(w, http.StatusOK, out)
}

// DriftItem is one architectural change.
type DriftItem struct {
	Change        string        `json:"change"`
	Category      string        `json:"category"`
	Key           string        `json:"key"`
	Label         string        `json:"label"`
	Detail        string        `json:"detail"`
	File          string        `json:"file"`
	EvidenceLabel string        `json:"evidence_label"`
	Evidence      []EvidenceRef `json:"evidence"`
}

// EvidenceRef is one piece of evidence of a drift item (a CodeGraph
// evidence row of the edge, or the node's source location).
type EvidenceRef struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Detail string `json:"detail,omitempty"`
	File   string `json:"file,omitempty"`
	Line   *int   `json:"line,omitempty"`
}

// Drift is a drift record.
type Drift struct {
	ID              uuid.UUID      `json:"id"`
	ApplicationID   uuid.UUID      `json:"application_id"`
	ApplicationName string         `json:"application_name"`
	RepositoryID    uuid.UUID      `json:"repository_id"`
	RepositoryName  string         `json:"repository_name"`
	FromSnapshotID  *uuid.UUID     `json:"from_snapshot_id"`
	ToSnapshotID    uuid.UUID      `json:"to_snapshot_id"`
	FromCommit      string         `json:"from_commit"`
	ToCommit        string         `json:"to_commit"`
	Severity        string         `json:"severity"`
	HasChanges      bool           `json:"has_changes"`
	Counts          map[string]int `json:"counts"`
	CreatedAt       time.Time      `json:"created_at"`
	Items           *[]DriftItem   `json:"items,omitempty"`
	Truncated       *bool          `json:"truncated,omitempty"`
}

const driftSelect = `SELECT e.id, e.application_id, COALESCE(a.name, ''), e.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name, ''),
	e.from_snapshot_id, e.to_snapshot_id, e.from_commit, e.to_commit, e.severity, e.has_changes, e.counts, e.created_at
	FROM architecture_drifts e LEFT JOIN applications a ON a.id = e.application_id LEFT JOIN repositories r ON r.id = e.repository_id`

func scanDrift(row pgx.Row) (Drift, error) {
	var d Drift
	var counts []byte
	if err := row.Scan(&d.ID, &d.ApplicationID, &d.ApplicationName, &d.RepositoryID, &d.RepositoryName, &d.FromSnapshotID, &d.ToSnapshotID,
		&d.FromCommit, &d.ToCommit, &d.Severity, &d.HasChanges, &counts, &d.CreatedAt); err != nil {
		return d, err
	}
	_ = json.Unmarshal(counts, &d.Counts)
	if d.Counts == nil {
		d.Counts = map[string]int{}
	}
	return d, nil
}

func (s *Service) listDrift(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r, authz.PermFindingsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	f := &filter{where: []string{"e.organization_id = $1"}, args: []any{p.OrganizationID}}
	for _, k := range []string{"application_id", "repository_id"} {
		id, err := parseUUIDParam(q, k)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if id != nil {
			f.add("e."+k+" = $%d", *id)
		}
	}
	switch q.Get("changed_only") {
	case "", "true", "1":
		f.where = append(f.where, "e.has_changes")
	case "false", "0":
	default:
		s.fail(w, r, badFilter("changed_only must be true or false"))
		return
	}
	if v := q.Get("cursor"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			s.fail(w, r, badFilter("invalid cursor"))
			return
		}
		f.add("e.id < $%d", id)
	}
	limit, err := parseLimit(q.Get("limit"))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	vis, vargs := visibilitySQL(p, "e", len(f.args)+1)
	f.args = append(f.args, vargs...)
	f.where = append(f.where, vis)
	// #nosec G202 -- the conditions are built from placeholders
	rows, err := s.DB.Query(ctx, driftSelect+" WHERE "+strings.Join(f.where, " AND ")+fmt.Sprintf(" ORDER BY e.id DESC LIMIT %d", limit+1), f.args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Drift, error) { return scanDrift(r) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var next *string
	if len(items) > limit {
		items = items[:limit]
		c := items[limit-1].ID.String()
		next = &c
	}
	if items == nil {
		items = []Drift{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func (s *Service) getDrift(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r, authz.PermFindingsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, httpx.ErrNotFound)
		return
	}
	args := []any{p.OrganizationID, id}
	vis, vargs := visibilitySQL(p, "e", len(args)+1)
	args = append(args, vargs...)
	var raw []byte
	var trunc bool
	// #nosec G202 -- vis is built from placeholders
	row := s.DB.QueryRow(ctx, `SELECT x.*, e.items, e.truncated FROM (`+driftSelect+` WHERE e.organization_id = $1 AND e.id = $2 AND `+vis+`) x
		JOIN architecture_drifts e ON e.id = x.id`, args...)
	var d Drift
	var counts []byte
	if err := row.Scan(&d.ID, &d.ApplicationID, &d.ApplicationName, &d.RepositoryID, &d.RepositoryName, &d.FromSnapshotID, &d.ToSnapshotID,
		&d.FromCommit, &d.ToCommit, &d.Severity, &d.HasChanges, &counts, &d.CreatedAt, &raw, &trunc); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = json.Unmarshal(counts, &d.Counts)
	items := []DriftItem{}
	_ = json.Unmarshal(raw, &items)
	d.Items, d.Truncated = &items, &trunc
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (s *Service) getSettings(w http.ResponseWriter, r *http.Request) {
	p, err := s.begin(r, authz.PermFindingsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := LoadSettings(r.Context(), s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (s *Service) putSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.begin(r, authz.PermSettingsManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.Authz.Require(ctx, p, authz.PermSettingsManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}); err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		DriftAlerts           *bool   `json:"drift_alerts"`
		DriftAlertMinSeverity *string `json:"drift_alert_min_severity"`
	}
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	cur, err := LoadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	next := cur
	if in.DriftAlerts != nil {
		next.DriftAlerts = *in.DriftAlerts
	}
	if in.DriftAlertMinSeverity != nil {
		next.DriftAlertMinSeverity = *in.DriftAlertMinSeverity
	}
	if !slices.Contains([]string{"critical", "high", "medium", "low"}, next.DriftAlertMinSeverity) {
		s.fail(w, r, (&httpx.Error{Status: http.StatusUnprocessableEntity, Code: "validation_failed", Message: "invalid monitoring settings",
			Fields: map[string]string{"drift_alert_min_severity": "must be critical, high, medium or low"}}).WithDiag(CodeBadSettings))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO monitoring_settings (organization_id, drift_alerts, drift_alert_min_severity, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, now()) ON CONFLICT (organization_id) DO UPDATE SET drift_alerts = EXCLUDED.drift_alerts,
			drift_alert_min_severity = EXCLUDED.drift_alert_min_severity, updated_by = EXCLUDED.updated_by, updated_at = now()`,
			p.OrganizationID, next.DriftAlerts, next.DriftAlertMinSeverity, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "monitoring.settings_update", TargetType: "monitoring_settings", TargetID: p.OrganizationID.String(),
			Metadata: map[string]any{"drift_alerts": next.DriftAlerts, "drift_alert_min_severity": next.DriftAlertMinSeverity,
				"was_drift_alerts": cur.DriftAlerts}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := LoadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}
