package insights

import (
	"context"
	"errors"
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
	"pathos/internal/material"
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Service serves the material change and developer attribution API.
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/material-changes/rules", s.rules)
	mux.HandleFunc("GET /api/v1/scans/{id}/material-changes", s.scanChanges)
	mux.HandleFunc("GET /api/v1/repositories/{id}/material-changes", s.repoChanges)
	mux.HandleFunc("GET /api/v1/insights/settings", s.getSettings)
	mux.HandleFunc("PUT /api/v1/insights/settings", s.putSettings)
	mux.HandleFunc("GET /api/v1/insights/developers", s.developers)
	mux.HandleFunc("GET /api/v1/insights/teams", s.teams)
	mux.HandleFunc("GET /api/v1/insights/trend", s.trend)
	mux.HandleFunc("GET /api/v1/insights/identities", s.identities)
	mux.HandleFunc("POST /api/v1/insights/identities", s.linkIdentity)
	mux.HandleFunc("DELETE /api/v1/insights/identities/{id}", s.unlinkIdentity)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	case db.IsUniqueViolation(err):
		err = httpx.Conflict("this git author name is already linked")
	case db.IsForeignKeyViolation(err):
		err = httpx.BadRequest("the user does not exist")
	}
	httpx.WriteError(w, r, s.Log, err)
}

func orgScope(p *authz.Principal) authz.Scope {
	return authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID}
}

// requireRepo checks perm on a repository, hiding its existence from
// callers without access.
func (s *Service) requireRepo(ctx context.Context, p *authz.Principal, perm authz.Permission, repoID uuid.UUID) error {
	err := s.Authz.Require(ctx, p, perm, authz.Scope{Type: authz.ScopeRepository, ID: repoID})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, org.ErrScopeNotFound):
		return errNotFound
	case errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(perm):
		return errNotFound
	}
	return err
}

// --- material changes -------------------------------------------------------

// RuleInfo is a rule as shown to users.
type RuleInfo struct {
	material.Rule
	CategoryLabel string `json:"category_label"`
}

func (s *Service) rules(w http.ResponseWriter, r *http.Request) {
	p := s.Principal(r.Context())
	if !p.HasAnywhere(authz.PermScansRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	out := make([]RuleInfo, 0, len(material.Rules))
	for _, ru := range material.Rules {
		out = append(out, RuleInfo{Rule: ru, CategoryLabel: material.CategoryLabels[ru.Category]})
	}
	cats := make([]map[string]string, 0, len(material.Categories))
	for _, c := range material.Categories {
		cats = append(cats, map[string]string{"key": c, "label": material.CategoryLabels[c]})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "categories": cats})
}

// Run is a scan's comparison outcome.
type Run struct {
	ScanJobID        uuid.UUID `json:"scan_job_id"`
	RepositoryID     uuid.UUID `json:"repository_id"`
	Status           string    `json:"status"`
	Reason           string    `json:"reason"`
	BaseSHA          string    `json:"base_sha"`
	HeadSHA          string    `json:"head_sha"`
	FilesChanged     int       `json:"files_changed"`
	Truncated        bool      `json:"truncated"`
	ChangeCount      int       `json:"change_count"`
	DependencyStatus string    `json:"dependency_status"`
	CommitsComplete  bool      `json:"commits_complete"`
	CreatedAt        time.Time `json:"created_at"`
}

// Change is a stored material change.
type Change struct {
	ID            uuid.UUID `json:"id"`
	ScanJobID     uuid.UUID `json:"scan_job_id"`
	Category      string    `json:"category"`
	CategoryLabel string    `json:"category_label"`
	RuleID        string    `json:"rule_id"`
	RuleTitle     string    `json:"rule_title"`
	Level         string    `json:"level"`
	FilePath      string    `json:"file_path"`
	ChangeType    string    `json:"change_type"`
	Side          string    `json:"side"`
	StartLine     *int      `json:"start_line"`
	EndLine       *int      `json:"end_line"`
	MatchCount    int       `json:"match_count"`
	Snippet       string    `json:"snippet"`
	Explanation   string    `json:"explanation"`
	Detail        string    `json:"detail"`
	// AuthorName is set only while developer attribution is enabled and
	// the caller holds insights.people.
	AuthorName string    `json:"author_name,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	// Scan context (repository listing).
	CommitSHA string `json:"commit_sha,omitempty"`
	BaseSHA   string `json:"base_sha,omitempty"`
}

const changeCols = `c.id, c.scan_job_id, c.category, c.rule_id, c.level, c.file_path, c.change_type, c.side, c.start_line, c.end_line,
	c.match_count, c.snippet, c.explanation, c.detail, c.author_name, c.created_at, mr.head_sha, mr.base_sha`

func scanChange(row pgx.CollectableRow) (Change, error) {
	var c Change
	err := row.Scan(&c.ID, &c.ScanJobID, &c.Category, &c.RuleID, &c.Level, &c.FilePath, &c.ChangeType, &c.Side, &c.StartLine, &c.EndLine,
		&c.MatchCount, &c.Snippet, &c.Explanation, &c.Detail, &c.AuthorName, &c.CreatedAt, &c.CommitSHA, &c.BaseSHA)
	c.CategoryLabel = material.CategoryLabels[c.Category]
	if ru, ok := material.RuleByID(c.RuleID); ok {
		c.RuleTitle = ru.Title
	}
	return c, err
}

// showAuthors reports whether author names may be returned to p.
func (s *Service) showAuthors(ctx context.Context, p *authz.Principal) bool {
	return p.HasOrgWide(authz.PermInsightsPeople) && AttributionEnabled(ctx, s.DB, p.OrganizationID)
}

func (s *Service) scanChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	var repoID uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT repository_id FROM scan_jobs WHERE id = $1 AND organization_id = $2`, id, p.OrganizationID).Scan(&repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermScansRead, repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	var run *Run
	var rr Run
	err = s.DB.QueryRow(ctx, `SELECT scan_job_id, repository_id, status, reason, base_sha, head_sha, files_changed, truncated, change_count,
		dependency_status, commits_complete, created_at FROM material_change_runs WHERE scan_job_id = $1`, id).
		Scan(&rr.ScanJobID, &rr.RepositoryID, &rr.Status, &rr.Reason, &rr.BaseSHA, &rr.HeadSHA, &rr.FilesChanged, &rr.Truncated,
			&rr.ChangeCount, &rr.DependencyStatus, &rr.CommitsComplete, &rr.CreatedAt)
	switch {
	case err == nil:
		run = &rr
	case !errors.Is(err, pgx.ErrNoRows):
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT `+changeCols+` FROM material_changes c JOIN material_change_runs mr ON mr.scan_job_id = c.scan_job_id
		WHERE c.scan_job_id = $1 ORDER BY CASE c.level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, c.category, c.file_path, c.start_line`, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, scanChange)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.finishChanges(ctx, p, items)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"run": run, "items": nonNilChanges(items)})
}

func (s *Service) finishChanges(ctx context.Context, p *authz.Principal, items []Change) {
	show := s.showAuthors(ctx, p)
	for i := range items {
		if !show {
			items[i].AuthorName = ""
		}
	}
}

func nonNilChanges(v []Change) []Change {
	if v == nil {
		return []Change{}
	}
	return v
}

func (s *Service) repoChanges(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	repoID, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermScansRead, repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	limit := 200
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			s.fail(w, r, httpx.BadRequest("limit must be between 1 and 1000"))
			return
		}
		limit = n
	}
	cat := q.Get("category")
	if cat != "" && !slices.Contains(material.Categories, cat) {
		s.fail(w, r, httpx.BadRequest("unknown category"))
		return
	}
	days := 90
	if v := q.Get("days"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 3650 {
			s.fail(w, r, httpx.BadRequest("days must be between 1 and 3650"))
			return
		}
		days = n
	}
	rows, err := s.DB.Query(ctx, `SELECT `+changeCols+` FROM material_changes c JOIN material_change_runs mr ON mr.scan_job_id = c.scan_job_id
		WHERE c.repository_id = $1 AND ($2 = '' OR c.category = $2) AND c.created_at >= now() - make_interval(days => $3)
		ORDER BY c.created_at DESC, CASE c.level WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, c.file_path LIMIT $4`, repoID, cat, days, limit+1)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := pgx.CollectRows(rows, scanChange)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	more := len(items) > limit
	if more {
		items = items[:limit]
	}
	s.finishChanges(ctx, p, items)
	runs, err := s.DB.Query(ctx, `SELECT scan_job_id, repository_id, status, reason, base_sha, head_sha, files_changed, truncated, change_count,
		dependency_status, commits_complete, created_at FROM material_change_runs WHERE repository_id = $1 ORDER BY created_at DESC LIMIT 20`, repoID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	recent, err := pgx.CollectRows(runs, func(row pgx.CollectableRow) (Run, error) {
		var rr Run
		err := row.Scan(&rr.ScanJobID, &rr.RepositoryID, &rr.Status, &rr.Reason, &rr.BaseSHA, &rr.HeadSHA, &rr.FilesChanged, &rr.Truncated,
			&rr.ChangeCount, &rr.DependencyStatus, &rr.CommitsComplete, &rr.CreatedAt)
		return rr, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if recent == nil {
		recent = []Run{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": nonNilChanges(items), "truncated": more, "runs": recent})
}

// --- settings ----------------------------------------------------------------

// Settings are the organization's developer insight settings.
type Settings struct {
	AttributionEnabled bool       `json:"attribution_enabled"`
	UpdatedAt          *time.Time `json:"updated_at"`
	CanManage          bool       `json:"can_manage"`
	CanViewPeople      bool       `json:"can_view_people"`
	CanLinkIdentities  bool       `json:"can_link_identities"`
}

func (s *Service) loadSettings(ctx context.Context, p *authz.Principal) (Settings, error) {
	st := Settings{CanManage: p.HasOrgWide(authz.PermSettingsManage), CanViewPeople: p.HasOrgWide(authz.PermInsightsPeople),
		CanLinkIdentities: p.HasOrgWide(authz.PermUsersManage)}
	err := s.DB.QueryRow(ctx, `SELECT attribution_enabled, updated_at FROM developer_insight_settings WHERE organization_id = $1`, p.OrganizationID).
		Scan(&st.AttributionEnabled, &st.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	return st, err
}

func (s *Service) getSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasOrgWide(authz.PermSettingsManage) && !p.HasOrgWide(authz.PermInsightsPeople) && !p.HasOrgWide(authz.PermUsersManage) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	st, err := s.loadSettings(ctx, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// putSettings switches attribution. Turning it off erases every stored
// author name (attributions, commits, identity links and the authors shown
// on material changes).
func (s *Service) putSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermSettingsManage, orgScope(p)); err != nil {
		s.fail(w, r, err)
		return
	}
	var in struct {
		AttributionEnabled *bool `json:"attribution_enabled"`
	}
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	if in.AttributionEnabled == nil {
		s.fail(w, r, httpx.BadRequest("attribution_enabled is required"))
		return
	}
	erased := map[string]int64{}
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var was bool
		_ = tx.QueryRow(ctx, `SELECT attribution_enabled FROM developer_insight_settings WHERE organization_id = $1 FOR UPDATE`, p.OrganizationID).Scan(&was)
		if _, err := tx.Exec(ctx, `INSERT INTO developer_insight_settings (organization_id, attribution_enabled, updated_by, updated_at)
			VALUES ($1, $2, $3, now()) ON CONFLICT (organization_id) DO UPDATE SET attribution_enabled = EXCLUDED.attribution_enabled,
			updated_by = EXCLUDED.updated_by, updated_at = now()`, p.OrganizationID, *in.AttributionEnabled, p.UserID); err != nil {
			return err
		}
		if !*in.AttributionEnabled {
			for _, q := range []struct{ name, sql string }{
				{"attributions", `DELETE FROM finding_attribution WHERE organization_id = $1`},
				{"commits", `DELETE FROM scan_commits WHERE organization_id = $1`},
				{"identity_links", `DELETE FROM developer_identities WHERE organization_id = $1`},
				{"material_change_authors", `UPDATE material_changes SET author_name = '' WHERE organization_id = $1 AND author_name <> ''`},
				{"finding_introducing_authors", `UPDATE findings SET introduced_author = '' WHERE organization_id = $1 AND introduced_author <> ''`},
			} {
				tag, err := tx.Exec(ctx, q.sql, p.OrganizationID)
				if err != nil {
					return err
				}
				erased[q.name] = tag.RowsAffected()
			}
		}
		md := map[string]any{"attribution_enabled": *in.AttributionEnabled, "was_enabled": was}
		if len(erased) > 0 {
			md["erased"] = erased
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "insights.settings.update", TargetType: "organization", TargetID: p.OrganizationID.String(), Metadata: md})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	st, err := s.loadSettings(ctx, p)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// --- people views ------------------------------------------------------------

// requirePeople checks insights.people (organization-wide) and that
// attribution is enabled; ok is false when the response was written.
func (s *Service) requirePeople(w http.ResponseWriter, r *http.Request) (*authz.Principal, bool) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermInsightsPeople, orgScope(p)); err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	if !AttributionEnabled(ctx, s.DB, p.OrganizationID) {
		s.fail(w, r, httpx.E(http.StatusConflict, "attribution_disabled", "developer attribution is turned off for this organization"))
		return nil, false
	}
	return p, true
}

func daysParam(r *http.Request, def int) (int, error) {
	v := r.URL.Query().Get("days")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 7 || n > 730 {
		return 0, httpx.BadRequest("days must be between 7 and 730")
	}
	return n, nil
}

// LinkedUser is the PATHOS user an author name is linked to.
type LinkedUser struct {
	ID   uuid.UUID `json:"id"`
	Name string    `json:"name"`
}

// Developer is one git author's statistics in the period.
type Developer struct {
	AuthorName      string      `json:"author_name"`
	User            *LinkedUser `json:"user"`
	Introduced      int         `json:"introduced"`
	IntroducedHigh  int         `json:"introduced_critical_high"`
	Fixed           int         `json:"fixed"`
	StillOpen       int         `json:"still_open"`
	MeanTimeToFixHr *float64    `json:"mean_time_to_fix_hours"`
	Repositories    int         `json:"repositories"`
}

// statsSQL aggregates attribution per lower-cased author name in the
// period ($1 org, $2 since).
const statsSQL = `
WITH intro AS (
  SELECT lower(a.introduced_by) AS k, min(a.introduced_by) AS name, count(*) AS n,
         count(*) FILTER (WHERE f.severity IN ('critical', 'high')) AS hi,
         count(*) FILTER (WHERE f.status IN ('open', 'in_progress', 'needs_review')) AS open,
         array_agg(DISTINCT a.repository_id) AS repos
  FROM finding_attribution a JOIN findings f ON f.id = a.finding_id
  WHERE a.organization_id = $1 AND a.introduced_by <> '' AND a.introduced_at >= $2 GROUP BY 1),
fix AS (
  SELECT lower(a.fixed_by) AS k, min(a.fixed_by) AS name, count(*) AS n,
         avg(EXTRACT(EPOCH FROM (a.fixed_at - f.first_seen_at)) / 3600.0) AS mttf,
         array_agg(DISTINCT a.repository_id) AS repos
  FROM finding_attribution a JOIN findings f ON f.id = a.finding_id
  WHERE a.organization_id = $1 AND a.fixed_by <> '' AND a.fixed_at >= $2 GROUP BY 1)
SELECT COALESCE(i.name, x.name), COALESCE(i.n, 0), COALESCE(i.hi, 0), COALESCE(x.n, 0), COALESCE(i.open, 0), x.mttf,
       (SELECT count(DISTINCT r) FROM unnest(COALESCE(i.repos, '{}') || COALESCE(x.repos, '{}')) r),
       di.user_id, COALESCE(NULLIF(u.display_name, ''), u.email, '')
FROM intro i FULL JOIN fix x ON x.k = i.k
LEFT JOIN developer_identities di ON di.organization_id = $1 AND lower(di.author_name) = COALESCE(i.k, x.k)
LEFT JOIN users u ON u.id = di.user_id`

func (s *Service) loadDevelopers(ctx context.Context, orgID uuid.UUID, since time.Time) ([]Developer, error) {
	rows, err := s.DB.Query(ctx, statsSQL+` ORDER BY 2 DESC, 4 DESC, 1`, orgID, since)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Developer, error) {
		var d Developer
		var uid *uuid.UUID
		var uname string
		err := row.Scan(&d.AuthorName, &d.Introduced, &d.IntroducedHigh, &d.Fixed, &d.StillOpen, &d.MeanTimeToFixHr, &d.Repositories, &uid, &uname)
		if uid != nil {
			d.User = &LinkedUser{ID: *uid, Name: uname}
		}
		if d.MeanTimeToFixHr != nil {
			v := float64(int(*d.MeanTimeToFixHr*10+0.5)) / 10
			d.MeanTimeToFixHr = &v
		}
		return d, err
	})
}

func (s *Service) developers(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePeople(w, r)
	if !ok {
		return
	}
	days, err := daysParam(r, 90)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.loadDevelopers(r.Context(), p.OrganizationID, time.Now().AddDate(0, 0, -days))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if items == nil {
		items = []Developer{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"days": days, "items": items})
}

// Team aggregates the linked developers of a team.
type Team struct {
	ID              *uuid.UUID `json:"id"`
	Name            string     `json:"name"`
	Developers      int        `json:"developers"`
	Introduced      int        `json:"introduced"`
	IntroducedHigh  int        `json:"introduced_critical_high"`
	Fixed           int        `json:"fixed"`
	StillOpen       int        `json:"still_open"`
	MeanTimeToFixHr *float64   `json:"mean_time_to_fix_hours"`
}

func (s *Service) teams(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePeople(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	days, err := daysParam(r, 90)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	devs, err := s.loadDevelopers(ctx, p.OrganizationID, time.Now().AddDate(0, 0, -days))
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT t.id, t.name, tm.user_id FROM teams t JOIN team_members tm ON tm.team_id = t.id
		WHERE t.organization_id = $1 ORDER BY t.name`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	members, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (teamMember, error) {
		var m teamMember
		err := row.Scan(&m.team, &m.name, &m.user)
		return m, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"days": days, "items": aggregateTeams(devs, members)})
}

type teamMember struct {
	team uuid.UUID
	name string
	user uuid.UUID
}

// aggregateTeams sums developer statistics per team of their linked user;
// unlinked authors form the "Not linked to a user" row. A developer in
// several teams counts in each. The mean time to fix is weighted by the
// number of fixes.
func aggregateTeams(devs []Developer, members []teamMember) []Team {
	teamsOf := map[uuid.UUID][]uuid.UUID{}
	var order []*Team
	byTeam := map[uuid.UUID]*Team{}
	for _, m := range members {
		teamsOf[m.user] = append(teamsOf[m.user], m.team)
		if byTeam[m.team] == nil {
			id := m.team
			byTeam[id] = &Team{ID: &id, Name: m.name}
			order = append(order, byTeam[id])
		}
	}
	noTeam := &Team{Name: "Linked users without a team"}
	unlinked := &Team{Name: "Not linked to a user"}
	order = append(order, noTeam, unlinked)
	type acc struct{ sum, n float64 }
	mttf := map[*Team]*acc{}
	add := func(t *Team, d Developer) {
		t.Developers++
		t.Introduced += d.Introduced
		t.IntroducedHigh += d.IntroducedHigh
		t.Fixed += d.Fixed
		t.StillOpen += d.StillOpen
		if d.MeanTimeToFixHr != nil && d.Fixed > 0 {
			if mttf[t] == nil {
				mttf[t] = &acc{}
			}
			mttf[t].sum += *d.MeanTimeToFixHr * float64(d.Fixed)
			mttf[t].n += float64(d.Fixed)
		}
	}
	for _, d := range devs {
		switch {
		case d.User == nil:
			add(unlinked, d)
		case len(teamsOf[d.User.ID]) == 0:
			add(noTeam, d)
		default:
			for _, id := range teamsOf[d.User.ID] {
				add(byTeam[id], d)
			}
		}
	}
	out := []Team{}
	for _, t := range order {
		if t.ID == nil && t.Developers == 0 {
			continue
		}
		if a := mttf[t]; a != nil && a.n > 0 {
			v := float64(int(a.sum/a.n*10+0.5)) / 10
			t.MeanTimeToFixHr = &v
		}
		out = append(out, *t)
	}
	return out
}

// TrendPoint is one week of introduced and fixed findings.
type TrendPoint struct {
	Week       string `json:"week"` // Monday, YYYY-MM-DD
	Introduced int    `json:"introduced"`
	Fixed      int    `json:"fixed"`
}

func (s *Service) trend(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requirePeople(w, r)
	if !ok {
		return
	}
	days, err := daysParam(r, 180)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	author := strings.TrimSpace(r.URL.Query().Get("author"))
	if len(author) > 200 {
		s.fail(w, r, httpx.BadRequest("author is too long"))
		return
	}
	rows, err := s.DB.Query(r.Context(), `
		WITH weeks AS (SELECT generate_series(date_trunc('week', $2::timestamptz), date_trunc('week', now()), interval '1 week') AS wk)
		SELECT to_char(w.wk, 'YYYY-MM-DD'),
		  (SELECT count(*) FROM finding_attribution a WHERE a.organization_id = $1 AND a.introduced_by <> ''
		     AND ($3 = '' OR lower(a.introduced_by) = lower($3)) AND date_trunc('week', a.introduced_at) = w.wk),
		  (SELECT count(*) FROM finding_attribution a WHERE a.organization_id = $1 AND a.fixed_by <> ''
		     AND ($3 = '' OR lower(a.fixed_by) = lower($3)) AND date_trunc('week', a.fixed_at) = w.wk)
		FROM weeks w ORDER BY w.wk`, p.OrganizationID, time.Now().AddDate(0, 0, -days), author)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	pts, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (TrendPoint, error) {
		var t TrendPoint
		err := row.Scan(&t.Week, &t.Introduced, &t.Fixed)
		return t, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"days": days, "author": author, "items": pts})
}

// --- identities --------------------------------------------------------------

// Identity links a git author name to a PATHOS user.
type Identity struct {
	ID         uuid.UUID `json:"id"`
	AuthorName string    `json:"author_name"`
	UserID     uuid.UUID `json:"user_id"`
	UserName   string    `json:"user_name"`
	CreatedAt  time.Time `json:"created_at"`
}

func (s *Service) requireLinking(w http.ResponseWriter, r *http.Request) (*authz.Principal, bool) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if err := s.Authz.Require(ctx, p, authz.PermUsersManage, orgScope(p)); err != nil {
		s.fail(w, r, err)
		return nil, false
	}
	if !AttributionEnabled(ctx, s.DB, p.OrganizationID) {
		s.fail(w, r, httpx.E(http.StatusConflict, "attribution_disabled", "developer attribution is turned off for this organization"))
		return nil, false
	}
	return p, true
}

// identities lists the links and the author names seen that are not
// linked yet.
func (s *Service) identities(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireLinking(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	rows, err := s.DB.Query(ctx, `SELECT di.id, di.author_name, di.user_id, COALESCE(NULLIF(u.display_name, ''), u.email), di.created_at
		FROM developer_identities di JOIN users u ON u.id = di.user_id WHERE di.organization_id = $1 ORDER BY lower(di.author_name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	links, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Identity, error) {
		var i Identity
		err := row.Scan(&i.ID, &i.AuthorName, &i.UserID, &i.UserName, &i.CreatedAt)
		return i, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err = s.DB.Query(ctx, `SELECT min(n) FROM (
		  SELECT author_name AS n FROM scan_commits WHERE organization_id = $1
		  UNION ALL SELECT introduced_by FROM finding_attribution WHERE organization_id = $1 AND introduced_by <> ''
		  UNION ALL SELECT fixed_by FROM finding_attribution WHERE organization_id = $1 AND fixed_by <> '') x
		WHERE n <> '' AND NOT EXISTS (SELECT 1 FROM developer_identities di WHERE di.organization_id = $1 AND lower(di.author_name) = lower(x.n))
		GROUP BY lower(n) ORDER BY 1 LIMIT 1000`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	unlinked, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if links == nil {
		links = []Identity{}
	}
	if unlinked == nil {
		unlinked = []string{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": links, "unlinked_authors": unlinked})
}

func (s *Service) linkIdentity(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireLinking(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	var in struct {
		AuthorName string    `json:"author_name"`
		UserID     uuid.UUID `json:"user_id"`
	}
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.AuthorName = cleanName(in.AuthorName)
	if in.AuthorName == "" || len(in.AuthorName) > 200 || in.UserID == uuid.Nil {
		s.fail(w, r, httpx.BadRequest("author_name (1-200 characters) and user_id are required"))
		return
	}
	id := uuid.Must(uuid.NewV7())
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO developer_identities (id, organization_id, author_name, user_id, created_by) VALUES ($1, $2, $3, $4, $5)`,
			id, p.OrganizationID, in.AuthorName, in.UserID, p.UserID); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "insights.identity.link", TargetType: "user", TargetID: in.UserID.String(), Metadata: map[string]any{"author_name": in.AuthorName}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (s *Service) unlinkIdentity(w http.ResponseWriter, r *http.Request) {
	p, ok := s.requireLinking(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var name string
		var user uuid.UUID
		if err := tx.QueryRow(ctx, `DELETE FROM developer_identities WHERE id = $1 AND organization_id = $2 RETURNING author_name, user_id`,
			id, p.OrganizationID).Scan(&name, &user); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "insights.identity.unlink", TargetType: "user", TargetID: user.String(), Metadata: map[string]any{"author_name": name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
