package inventory

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

// Phase is one of the nine lifecycle phases of an application. HasData is
// true only when PATHOS holds real records for the phase; Available is
// false for phases whose module is not built yet.
type Phase struct {
	Number    int            `json:"number"`
	Key       string         `json:"key"`
	Title     string         `json:"title"`
	Available bool           `json:"available"`
	HasData   bool           `json:"has_data"`
	Summary   string         `json:"summary"`
	Metrics   map[string]int `json:"metrics"`
	// Restricted: the caller lacks the permission to see this phase's data.
	Restricted bool `json:"restricted"`
}

// AppLifecycle is the lifecycle of one application.
type AppLifecycle struct {
	ID               uuid.UUID  `json:"id"`
	Key              string     `json:"application_key"`
	Name             string     `json:"name"`
	OnboardingStatus string     `json:"onboarding_status"`
	Criticality      string     `json:"criticality"`
	LastScanAt       *time.Time `json:"last_scan_at"`
	Phases           []Phase    `json:"phases"`
	PhasesWithData   int        `json:"phases_with_data"`
}

type lifecycleCounts struct {
	ID              uuid.UUID
	Key             string
	Name            string
	Status          string
	Criticality     string
	Repos           int
	Sources         int
	Components      int
	Scans           int
	LastScan        *time.Time
	OpenFindings    int
	Findings        int
	AIReviews       int
	AIEvidence      int
	HumanReviews    int
	FixPRs          int
	RiskAcceptances int
	PRChecks        int
	Versions        int
	Runtime         int
}

// lifecycleQuery counts, per application, the records of each phase in the
// repositories the caller can read (repos.read scope).
func lifecycleQuery(p *authz.Principal, where string, args []any) (string, []any) {
	f := authz.FilterFor(p, authz.PermReposRead)
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", len(args)+1)
	vis, vargs := visibleAppSQL(p, authz.PermReposRead, len(args)+len(sargs)+1)
	repoJoin := `JOIN repositories r ON r.id = %s WHERE r.application_id = a.id AND r.archived_at IS NULL AND ` + scope
	sub := func(sel, from, on string) string {
		return "(SELECT " + sel + " FROM " + from + " " + fmt.Sprintf(repoJoin, on) + ")"
	}
	q := `SELECT a.id, a.application_key, a.name, a.onboarding_status, a.criticality,
		(SELECT count(*) FROM repositories r WHERE r.application_id = a.id AND r.archived_at IS NULL AND ` + scope + `),
		(SELECT count(*) FROM asset_onboardings o WHERE o.application_id = a.id),
		` + sub("count(*)", "sbom_components c", "c.repository_id") + `,
		` + sub("count(*)", "scan_jobs j", "j.repository_id") + `,
		` + sub("max(j.finished_at)", "scan_jobs j", "j.repository_id") + `,
		` + sub("count(*) FILTER (WHERE f.status IN ('open', 'in_progress', 'needs_review'))", "findings f", "f.repository_id") + `,
		` + sub("count(*)", "findings f", "f.repository_id") + `,
		` + sub("count(*)", "ai_reviews ar JOIN findings f ON f.id = ar.finding_id", "f.repository_id") + `,
		` + sub("count(*)", "ai_evidence_records e JOIN findings f ON f.id = e.finding_id", "f.repository_id") + `,
		` + sub("count(*)", "human_reviews h", "h.repository_id") + `,
		` + sub("count(*)", "fix_pull_requests x", "x.repository_id") + `,
		` + sub("count(*)", "risk_acceptances ra JOIN findings f ON f.id = ra.finding_id", "f.repository_id") + `,
		` + sub("count(*)", "pr_checks pc", "pc.repository_id") + `,
		(SELECT count(*) FROM application_versions v WHERE v.application_id = a.id),
		(SELECT count(*) FROM runtime_app_mappings m WHERE m.application_id = a.id)
		FROM applications a WHERE ` + where + ` AND ` + vis
	all := append(append(append([]any{}, args...), sargs...), vargs...)
	return q, all
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// buildPhases turns the counts into the nine phases.
func buildPhases(c lifecycleCounts, p *authz.Principal) []Phase {
	findings := p.HasAnywhere(authz.PermFindingsRead)
	sbom := p.HasAnywhere(authz.PermSBOMRead)
	ph := func(n int, key, title string) Phase {
		return Phase{Number: n, Key: key, Title: title, Available: true, Metrics: map[string]int{}}
	}
	out := make([]Phase, 0, 9)

	connect := ph(1, "connect", "Connect")
	connect.Metrics["repositories"], connect.Metrics["onboarding_repositories"] = c.Repos, c.Sources
	connect.HasData = c.Repos > 0 || c.Sources > 0
	connect.Summary = map[bool]string{true: plural(c.Repos, "repository connected", "repositories connected"), false: "No repository connected yet"}[connect.HasData]
	if c.Repos == 0 && c.Sources > 0 {
		connect.Summary = plural(c.Sources, "repository in onboarding", "repositories in onboarding")
	}
	out = append(out, connect)

	inv := ph(2, "inventory", "Inventory")
	inv.HasData = true
	inv.Summary = map[bool]string{true: "Registered in the inventory", false: "Onboarding in progress (draft)"}[c.Status == "complete"]
	out = append(out, inv)

	disc := ph(3, "discover", "Discover")
	disc.Metrics["components"] = c.Components
	disc.HasData = c.Components > 0
	disc.Summary = map[bool]string{true: plural(c.Components, "SBOM component", "SBOM components") + " (CodeGraph arrives in M4)",
		false: "No SBOM yet; CodeGraph arrives in M4"}[disc.HasData]
	if !sbom {
		disc.Restricted, disc.HasData, disc.Summary, disc.Metrics = true, false, "You cannot view SBOM data", map[string]int{}
	}
	out = append(out, disc)

	out = append(out, Phase{Number: 4, Key: "threat_model", Title: "Threat model", Available: false, Metrics: map[string]int{},
		Summary: "No threat model data: threat models arrive in M5"})
	out = append(out, Phase{Number: 5, Key: "reverse_engineering", Title: "Reverse engineering", Available: false, Metrics: map[string]int{},
		Summary: "No reverse engineering data: binary analysis arrives in M10"})

	assess := ph(6, "assess", "Assess")
	assess.Metrics["scans"], assess.Metrics["findings"], assess.Metrics["open_findings"] = c.Scans, c.Findings, c.OpenFindings
	assess.HasData = c.Scans > 0 || c.Findings > 0
	assess.Summary = map[bool]string{true: plural(c.Scans, "scan", "scans") + ", " + plural(c.OpenFindings, "open finding", "open findings"),
		false: "Not scanned yet"}[assess.HasData]
	if !findings {
		assess.Metrics = map[string]int{"scans": c.Scans}
		assess.HasData = c.Scans > 0
		assess.Summary = map[bool]string{true: plural(c.Scans, "scan", "scans"), false: "Not scanned yet"}[assess.HasData]
	}
	out = append(out, assess)

	val := ph(7, "validate", "Validate & intelligence")
	val.Metrics["ai_reviews"], val.Metrics["human_reviews"] = c.AIReviews, c.HumanReviews
	// AI evidence records (PATHOS 3.0 M7) of the application's findings:
	// one per AI decision or conclusion, written whatever the flag.
	val.Metrics["ai_evidence_records"] = c.AIEvidence
	val.HasData = c.AIReviews > 0 || c.HumanReviews > 0 || c.AIEvidence > 0
	val.Summary = map[bool]string{true: plural(c.AIReviews, "AI review", "AI reviews") + ", " + plural(c.HumanReviews, "human review", "human reviews"),
		false: "No AI or human reviews yet"}[val.HasData]
	if c.AIEvidence > 0 {
		val.Summary += ", " + plural(c.AIEvidence, "AI evidence record", "AI evidence records")
	}
	if !findings {
		val.Restricted, val.HasData, val.Summary, val.Metrics = true, false, "You cannot view findings", map[string]int{}
	}
	out = append(out, val)

	rem := ph(8, "remediate", "Remediate & gate")
	rem.Metrics["fix_pull_requests"], rem.Metrics["risk_acceptances"], rem.Metrics["pull_request_checks"] = c.FixPRs, c.RiskAcceptances, c.PRChecks
	rem.HasData = c.FixPRs > 0 || c.RiskAcceptances > 0 || c.PRChecks > 0
	rem.Summary = map[bool]string{true: plural(c.FixPRs, "fix pull request", "fix pull requests") + ", " + plural(c.RiskAcceptances, "risk acceptance", "risk acceptances") +
		", " + plural(c.PRChecks, "pull request check", "pull request checks"), false: "No fixes, gates or risk decisions yet"}[rem.HasData]
	if !findings {
		rem.Restricted, rem.HasData, rem.Summary, rem.Metrics = true, false, "You cannot view findings", map[string]int{}
	}
	out = append(out, rem)

	rep := ph(9, "report", "Report & monitor")
	rep.Metrics["versions"], rep.Metrics["runtime_mappings"] = c.Versions, c.Runtime
	rep.HasData = c.Versions > 0 || c.Runtime > 0
	rep.Summary = map[bool]string{true: plural(c.Versions, "release version", "release versions") + ", " + plural(c.Runtime, "runtime mapping", "runtime mappings"),
		false: "No release versions or runtime mappings yet"}[rep.HasData]
	out = append(out, rep)
	return out
}

func toLifecycle(c lifecycleCounts, p *authz.Principal) AppLifecycle {
	l := AppLifecycle{ID: c.ID, Key: c.Key, Name: c.Name, OnboardingStatus: c.Status, Criticality: c.Criticality, LastScanAt: c.LastScan,
		Phases: buildPhases(c, p)}
	for _, ph := range l.Phases {
		if ph.HasData {
			l.PhasesWithData++
		}
	}
	return l
}

func (s *Service) lifecycleRows(ctx context.Context, p *authz.Principal, where string, args []any, tail string) ([]AppLifecycle, error) {
	q, all := lifecycleQuery(p, where, args)
	rows, err := s.DB.Query(ctx, q+tail, all...)
	if err != nil {
		return nil, err
	}
	counts, err := pgx.CollectRows(rows, pgx.RowToStructByPos[lifecycleCounts])
	if err != nil {
		return nil, err
	}
	out := make([]AppLifecycle, 0, len(counts))
	for _, c := range counts {
		out = append(out, toLifecycle(c, p))
	}
	return out, nil
}

// applicationLifecycle: GET /api/v1/applications/{id}/lifecycle (the
// profile's lifecycle progress strip).
func (s *Service) applicationLifecycle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	list, err := s.lifecycleRows(ctx, p, "a.organization_id = $1 AND a.id = $2", []any{p.OrganizationID, id}, "")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(list) == 0 {
		s.fail(w, r, errNotFound)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, list[0])
}

// lifecycleOverview: GET /api/v1/lifecycle/overview lists every visible
// application with the phases that hold real data (at most 500, by name).
func (s *Service) lifecycleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReposRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	list, err := s.lifecycleRows(ctx, p, "a.organization_id = $1 AND a.archived_at IS NULL", []any{p.OrganizationID},
		" ORDER BY lower(a.name) LIMIT 500")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	totals := make([]int, 9)
	for _, l := range list {
		for i, ph := range l.Phases {
			if ph.HasData {
				totals[i]++
			}
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": list, "phase_totals": totals, "truncated": len(list) == 500})
}

// ActivityItem is one entry of the application's activity.
type ActivityItem struct {
	At       time.Time      `json:"at"`
	Kind     string         `json:"kind"` // audit | tags
	Action   string         `json:"action"`
	Actor    string         `json:"actor"`
	Target   string         `json:"target"`
	Summary  string         `json:"summary"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// applicationActivity: GET /api/v1/applications/{id}/activity merges the
// audit entries of the application and its repositories (callers with
// audit.read organization-wide) and its tag history.
func (s *Service) applicationActivity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	app, err := s.loadVisibleApp(ctx, s.DB, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items := []ActivityItem{}
	rows, err := s.DB.Query(ctx, `SELECT h.created_at, h.actor_email, h.target_type, h.target_name, h.category_name, h.old_tags, h.new_tags, h.source
		FROM tag_assignment_history h WHERE h.organization_id = $1 AND ((h.target_type = 'application' AND h.target_id = $2)
		  OR (h.target_type = 'repository' AND h.target_id IN (SELECT id FROM repositories WHERE application_id = $2)))
		ORDER BY h.created_at DESC LIMIT 100`, p.OrganizationID, app.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for rows.Next() {
		var at time.Time
		var actor, ttype, tname, cat, source string
		var oldT, newT []string
		if err := rows.Scan(&at, &actor, &ttype, &tname, &cat, &oldT, &newT, &source); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		items = append(items, ActivityItem{At: at, Kind: "tags", Action: "tags.change", Actor: actor, Target: tname,
			Summary:  fmt.Sprintf("%s tags (%s): %v → %v", cat, source, oldT, newT),
			Metadata: map[string]any{"category": cat, "old": oldT, "new": newT, "source": source, "target_type": ttype}})
	}
	rows.Close()
	auditVisible := p.HasOrgWide(authz.PermAuditRead)
	if auditVisible {
		recs, err := s.DB.Query(ctx, `SELECT l.created_at, l.actor_email, l.action, l.target_type, l.metadata
			FROM audit_logs l WHERE l.organization_id = $1 AND l.outcome = 'success' AND (
			  (l.target_type = 'application' AND l.target_id = $2)
			  OR (l.target_type = 'repository' AND l.target_id IN (SELECT id::text FROM repositories WHERE application_id = $3)))
			ORDER BY l.created_at DESC LIMIT 100`, p.OrganizationID, app.ID.String(), app.ID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for recs.Next() {
			var at time.Time
			var actor, action, ttype string
			var meta map[string]any
			if err := recs.Scan(&at, &actor, &action, &ttype, &meta); err != nil {
				recs.Close()
				s.fail(w, r, err)
				return
			}
			name, _ := meta["name"].(string)
			items = append(items, ActivityItem{At: at, Kind: "audit", Action: action, Actor: actor, Target: name, Summary: action,
				Metadata: map[string]any{"target_type": ttype}})
		}
		recs.Close()
	}
	sortActivity(items)
	if len(items) > 150 {
		items = items[:150]
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "audit_visible": auditVisible})
}

func sortActivity(items []ActivityItem) {
	sort.SliceStable(items, func(i, j int) bool { return items[i].At.After(items[j].At) })
}
