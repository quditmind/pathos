package releases

import (
	"context"
	"encoding/json"
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
	"pathos/internal/org"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Component policy condition kinds.
const (
	CondComponentAge = "component_age"
	CondOutdated     = "outdated"
	CondLicense      = "license"
	CondVulnSeverity = "vulnerability_severity"
)

// PolicyParams are the parameters of a condition (only the ones for its
// kind are used).
type PolicyParams struct {
	MaxDays        int      `json:"max_days,omitempty"`        // component_age
	VersionsBehind string   `json:"versions_behind,omitempty"` // outdated: any | major
	Licenses       []string `json:"licenses,omitempty"`        // license
	IncludeUnknown bool     `json:"include_unknown,omitempty"` // license: no licence declared
	MinSeverity    string   `json:"min_severity,omitempty"`    // vulnerability_severity
}

// ComponentPolicy is an operational policy over the inventory.
type ComponentPolicy struct {
	ID             uuid.UUID    `json:"id"`
	Name           string       `json:"name"`
	Description    string       `json:"description"`
	Enabled        bool         `json:"enabled"`
	ConditionKind  string       `json:"condition_kind"`
	Params         PolicyParams `json:"params"`
	ViolationState string       `json:"violation_state"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
	EvaluatedAt    *time.Time   `json:"evaluated_at"`
	OpenViolations int          `json:"open_violations"`
}

var severities = []string{"critical", "high", "medium", "low", "info"}

func sevRank(s string) int {
	if i := slices.Index(severities, s); i >= 0 {
		return i
	}
	return len(severities)
}

// Validate normalizes and checks a policy definition.
func (p *ComponentPolicy) Validate() error {
	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" || len(p.Name) > 200 {
		return httpx.BadRequest("name must be 1-200 characters")
	}
	if len(p.Description) > 2000 {
		return httpx.BadRequest("description must be at most 2000 characters")
	}
	switch p.ViolationState {
	case "":
		p.ViolationState = "warn"
	case "fail", "warn", "info":
	default:
		return httpx.BadRequest("violation_state must be fail, warn or info")
	}
	x := p.Params
	clean := PolicyParams{}
	switch p.ConditionKind {
	case CondComponentAge:
		if x.MaxDays < 1 || x.MaxDays > 36500 {
			return httpx.BadRequest("max_days must be between 1 and 36500")
		}
		clean.MaxDays = x.MaxDays
	case CondOutdated:
		switch x.VersionsBehind {
		case "":
			clean.VersionsBehind = "any"
		case "any", "major":
			clean.VersionsBehind = x.VersionsBehind
		default:
			return httpx.BadRequest("versions_behind must be any or major")
		}
	case CondLicense:
		for _, l := range x.Licenses {
			l = strings.TrimSpace(l)
			if l == "" || len(l) > 100 {
				return httpx.BadRequest("licences must be SPDX identifiers")
			}
			clean.Licenses = append(clean.Licenses, l)
		}
		if len(clean.Licenses) == 0 && !x.IncludeUnknown {
			return httpx.BadRequest("list at least one licence or include components without a licence")
		}
		if len(clean.Licenses) > 200 {
			return httpx.BadRequest("at most 200 licences")
		}
		clean.IncludeUnknown = x.IncludeUnknown
	case CondVulnSeverity:
		if sevRank(x.MinSeverity) >= len(severities) {
			return httpx.BadRequest("min_severity must be critical, high, medium, low or info")
		}
		clean.MinSeverity = x.MinSeverity
	default:
		return httpx.BadRequest("condition_kind must be component_age, outdated, license or vulnerability_severity")
	}
	p.Params = clean
	return nil
}

// CompFacts is what the evaluation knows about a component.
type CompFacts struct {
	Name, Version string
	Licenses      []string
	// Health from deps.dev (opt-in feed); HasHealth false = unknown.
	HasHealth       bool
	LatestVersion   string
	LatestPublished *time.Time
	// WorstOpenSeverity of open findings on this component ("" = none).
	WorstOpenSeverity string
	OpenVulns         int
}

// Evaluate reports whether a component violates a policy, with a detail.
// evaluated is false when the data needed is unknown (no package health
// for age/outdated): such components are not reported as violations.
func Evaluate(p ComponentPolicy, c CompFacts, now time.Time) (violates, evaluated bool, detail string) {
	switch p.ConditionKind {
	case CondLicense:
		known := false
		for _, l := range c.Licenses {
			if l == "" || strings.EqualFold(l, "NOASSERTION") || strings.EqualFold(l, "NONE") {
				continue
			}
			known = true
			for _, deny := range p.Params.Licenses {
				if strings.EqualFold(l, deny) {
					return true, true, "licence " + l
				}
			}
		}
		if !known && p.Params.IncludeUnknown {
			return true, true, "no licence declared"
		}
		return false, true, ""
	case CondVulnSeverity:
		if c.WorstOpenSeverity != "" && sevRank(c.WorstOpenSeverity) <= sevRank(p.Params.MinSeverity) {
			return true, true, fmt.Sprintf("%d open vulnerabilit%s, highest %s", c.OpenVulns, map[bool]string{true: "y", false: "ies"}[c.OpenVulns == 1], c.WorstOpenSeverity)
		}
		return false, true, ""
	case CondOutdated:
		if !c.HasHealth || c.LatestVersion == "" || c.Version == "" {
			return false, false, ""
		}
		if strings.TrimPrefix(c.LatestVersion, "v") == strings.TrimPrefix(c.Version, "v") {
			return false, true, ""
		}
		if p.Params.VersionsBehind == "major" {
			cm, ok1 := major(c.Version)
			lm, ok2 := major(c.LatestVersion)
			if !ok1 || !ok2 {
				return false, false, ""
			}
			if lm > cm {
				return true, true, fmt.Sprintf("major version %d behind the latest %s", lm-cm, c.LatestVersion)
			}
			return false, true, ""
		}
		if newer, ok := newerVersion(c.LatestVersion, c.Version); ok && newer {
			return true, true, "latest version is " + c.LatestVersion
		} else if !ok {
			return false, false, ""
		}
		return false, true, ""
	case CondComponentAge:
		if !c.HasHealth || c.LatestPublished == nil {
			return false, false, ""
		}
		days := int(now.Sub(*c.LatestPublished).Hours() / 24)
		if days > p.Params.MaxDays {
			return true, true, fmt.Sprintf("no release for %d days (last %s)", days, c.LatestPublished.UTC().Format("2006-01-02"))
		}
		return false, true, ""
	}
	return false, false, ""
}

// versionParts parses the leading numeric dot-separated parts of a
// version ("v1.2.3-rc1" → [1 2 3]).
func versionParts(v string) ([]int, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+ "); i >= 0 {
		v = v[:i]
	}
	if v == "" {
		return nil, false
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		out = append(out, n)
	}
	return out, true
}

func major(v string) (int, bool) {
	p, ok := versionParts(v)
	if !ok {
		return 0, false
	}
	return p[0], true
}

// newerVersion reports whether a > b numerically.
func newerVersion(a, b string) (bool, bool) {
	pa, ok1 := versionParts(a)
	pb, ok2 := versionParts(b)
	if !ok1 || !ok2 {
		return false, false
	}
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y, true
		}
	}
	return false, true
}

const policySelect = `SELECT p.id, p.name, p.description, p.enabled, p.condition_kind, p.params, p.violation_state,
	p.created_at, p.updated_at, p.evaluated_at,
	(SELECT count(*) FROM component_policy_violations v WHERE v.policy_id = p.id AND v.resolved_at IS NULL)
	FROM component_policies p`

func scanPolicy(row pgx.Row) (ComponentPolicy, error) {
	var p ComponentPolicy
	var params []byte
	err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.ConditionKind, &params, &p.ViolationState,
		&p.CreatedAt, &p.UpdatedAt, &p.EvaluatedAt, &p.OpenViolations)
	if err == nil {
		_ = json.Unmarshal(params, &p.Params)
	}
	return p, err
}

// reader: viewing policies needs sbom.read anywhere; changing them needs
// settings.manage (like security policies).
func (s *Service) policyReader(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	if p == nil || !p.HasAnywhere(authz.PermSBOMRead) {
		return p, authz.ErrForbidden
	}
	return p, nil
}

func (s *Service) policyAdmin(r *http.Request) (*authz.Principal, error) {
	p := s.Principal(r.Context())
	return p, s.Authz.Require(r.Context(), p, authz.PermSettingsManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID})
}

func (s *Service) listPolicies(w http.ResponseWriter, r *http.Request) {
	p, err := s.policyReader(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(r.Context(), policySelect+` WHERE p.organization_id = $1 ORDER BY lower(p.name)`, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ComponentPolicy, error) { return scanPolicy(row) })
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []ComponentPolicy{}
	}
	ok, _ := s.Authz.Can(r.Context(), p, authz.PermSettingsManage, authz.Scope{Type: authz.ScopeOrganization, ID: p.OrganizationID})
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "can_manage": ok})
}

func (s *Service) createPolicy(w http.ResponseWriter, r *http.Request) {
	s.savePolicy(w, r, uuid.Nil)
}

func (s *Service) updatePolicy(w http.ResponseWriter, r *http.Request) {
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.savePolicy(w, r, id)
}

func (s *Service) savePolicy(w http.ResponseWriter, r *http.Request, id uuid.UUID) {
	ctx := r.Context()
	p, err := s.policyAdmin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var body struct {
		ComponentPolicy
		Enabled *bool `json:"enabled"` // default true
	}
	if err := httpx.DecodeJSON(w, r, &body); err != nil {
		s.fail(w, r, err)
		return
	}
	req := body.ComponentPolicy
	req.Enabled = body.Enabled == nil || *body.Enabled
	if err := req.Validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	params, _ := json.Marshal(req.Params)
	create := id == uuid.Nil
	if create {
		id = uuid.Must(uuid.NewV7())
	}
	var out ComponentPolicy
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if create {
			_, err = tx.Exec(ctx, `INSERT INTO component_policies (id, organization_id, name, description, enabled, condition_kind, params, violation_state, created_by)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`, id, p.OrganizationID, req.Name, req.Description, req.Enabled, req.ConditionKind, params, req.ViolationState, p.UserID)
		} else {
			var tag interface{ RowsAffected() int64 }
			tag, err = tx.Exec(ctx, `UPDATE component_policies SET name = $3, description = $4, enabled = $5, condition_kind = $6, params = $7,
				violation_state = $8, updated_at = now() WHERE organization_id = $1 AND id = $2`,
				p.OrganizationID, id, req.Name, req.Description, req.Enabled, req.ConditionKind, params, req.ViolationState)
			if err == nil && tag.RowsAffected() == 0 {
				return errNotFound
			}
			if err == nil {
				// Violations are recomputed from the new definition.
				_, err = tx.Exec(ctx, `DELETE FROM component_policy_violations WHERE policy_id = $1`, id)
			}
		}
		if db.IsUniqueViolation(err) {
			return httpx.Conflict("a component policy with this name already exists")
		}
		if err != nil {
			return err
		}
		action := "component_policy.update"
		if create {
			action = "component_policy.create"
		}
		if err := audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: action, TargetType: "component_policy", TargetID: id.String(),
			Metadata: map[string]any{"name": req.Name, "condition_kind": req.ConditionKind, "params": req.Params, "enabled": req.Enabled}}); err != nil {
			return err
		}
		if req.Enabled {
			if _, err := evaluateOrg(ctx, tx, p.OrganizationID, &id, time.Now()); err != nil {
				return err
			}
		}
		out, err = scanPolicy(tx.QueryRow(ctx, policySelect+` WHERE p.id = $1`, id))
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	code := http.StatusOK
	if create {
		code = http.StatusCreated
	}
	httpx.WriteJSON(w, code, out)
}

func (s *Service) deletePolicy(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.policyAdmin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var name string
		if err := tx.QueryRow(ctx, `DELETE FROM component_policies WHERE organization_id = $1 AND id = $2 RETURNING name`, p.OrganizationID, id).Scan(&name); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "component_policy.delete", TargetType: "component_policy", TargetID: id.String(), Metadata: map[string]any{"name": name}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) evaluateNow(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.policyAdmin(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var st EvalStats
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if st, err = evaluateOrg(ctx, tx, p.OrganizationID, nil, time.Now()); err != nil {
			return err
		}
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "component_policy.evaluate", TargetType: "component_policy", TargetID: "all",
			Metadata: map[string]any{"policies": st.Policies, "violations": st.Violations, "not_evaluated": st.NotEvaluated}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

// EvalStats summarizes an evaluation.
type EvalStats struct {
	Policies   int `json:"policies"`
	Components int `json:"components"`
	Violations int `json:"violations"`
	// NotEvaluated counts (policy, component) pairs skipped for lack of
	// data (no package health: enable the deps.dev feed).
	NotEvaluated int `json:"not_evaluated"`
}

type invRow struct {
	repo uuid.UUID
	purl string
	CompFacts
}

// evaluateOrg evaluates enabled policies (or one) over the inventory of
// non-archived repositories, upserting violations and resolving those that
// no longer match.
func evaluateOrg(ctx context.Context, tx pgx.Tx, orgID uuid.UUID, only *uuid.UUID, now time.Time) (EvalStats, error) {
	var st EvalStats
	rows, err := tx.Query(ctx, policySelect+` WHERE p.organization_id = $1 AND p.enabled AND ($2::uuid IS NULL OR p.id = $2)`, orgID, only)
	if err != nil {
		return st, err
	}
	pols, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (ComponentPolicy, error) { return scanPolicy(row) })
	if err != nil || len(pols) == 0 {
		return st, err
	}
	st.Policies = len(pols)
	rows, err = tx.Query(ctx, `
		SELECT c.repository_id, c.name, c.version, c.purl, c.licenses, h.purl_base IS NOT NULL, COALESCE(h.latest_version, ''), h.latest_published_at,
		       COALESCE(v.worst, ''), COALESCE(v.n, 0)
		FROM (SELECT DISTINCT ON (repository_id, name, version) repository_id, name, version, purl, licenses
		      FROM sbom_components WHERE organization_id = $1 ORDER BY repository_id, name, version, purl) c
		JOIN repositories r ON r.id = c.repository_id AND r.archived_at IS NULL
		LEFT JOIN package_health h ON h.found AND c.purl <> '' AND h.purl_base = regexp_replace(split_part(c.purl, '?', 1), '@[^@/]*$', '')
		LEFT JOIN LATERAL (SELECT count(*) AS n, (array_agg(f.severity ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity)))[1] AS worst
		      FROM findings f WHERE f.repository_id = c.repository_id AND f.package_name = c.name AND f.package_version = c.version
		        AND f.category IN ('sca', 'container') AND f.status IN ('open', 'in_progress', 'needs_review')) v ON true`, orgID)
	if err != nil {
		return st, err
	}
	inv, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (invRow, error) {
		var x invRow
		err := row.Scan(&x.repo, &x.Name, &x.Version, &x.purl, &x.Licenses, &x.HasHealth, &x.LatestVersion, &x.LatestPublished, &x.WorstOpenSeverity, &x.OpenVulns)
		return x, err
	})
	if err != nil {
		return st, err
	}
	st.Components = len(inv)
	for _, pol := range pols {
		b := &pgx.Batch{}
		for _, c := range inv {
			bad, ok, detail := Evaluate(pol, c.CompFacts, now)
			if !ok {
				st.NotEvaluated++
				continue
			}
			if !bad {
				continue
			}
			st.Violations++
			b.Queue(`INSERT INTO component_policy_violations (organization_id, policy_id, repository_id, component_name, component_version, purl, detail, first_seen_at, last_seen_at)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $8)
				ON CONFLICT (policy_id, repository_id, component_name, component_version) DO UPDATE
				SET last_seen_at = EXCLUDED.last_seen_at, detail = EXCLUDED.detail, purl = EXCLUDED.purl, resolved_at = NULL,
				    first_seen_at = CASE WHEN component_policy_violations.resolved_at IS NULL THEN component_policy_violations.first_seen_at ELSE EXCLUDED.first_seen_at END`,
				orgID, pol.ID, c.repo, c.Name, c.Version, c.purl, clip(detail, 1000), now)
		}
		if b.Len() > 0 {
			if err := tx.SendBatch(ctx, b).Close(); err != nil {
				return st, err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE component_policy_violations SET resolved_at = $2 WHERE policy_id = $1 AND resolved_at IS NULL AND last_seen_at < $2`,
			pol.ID, now); err != nil {
			return st, err
		}
		if _, err := tx.Exec(ctx, `UPDATE component_policies SET evaluated_at = $2 WHERE id = $1`, pol.ID, now); err != nil {
			return st, err
		}
	}
	return st, nil
}

// EvaluateAll evaluates every organization's component policies.
func EvaluateAll(ctx context.Context, pool *pgxpool.Pool) error {
	rows, err := pool.Query(ctx, `SELECT DISTINCT organization_id FROM component_policies WHERE enabled`)
	if err != nil {
		return err
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		return err
	}
	for _, o := range orgs {
		if err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
			_, err := evaluateOrg(ctx, tx, o, nil, time.Now())
			return err
		}); err != nil {
			return err
		}
	}
	return nil
}

// RunBackground re-evaluates component policies hourly (jobs role), so
// violations follow new scans and package health updates.
func RunBackground(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		if err := EvaluateAll(ctx, pool); err != nil && ctx.Err() == nil {
			log.Warn("component policy evaluation failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Violation is an open (or resolved) policy violation.
type Violation struct {
	ID             uuid.UUID  `json:"id"`
	PolicyID       uuid.UUID  `json:"policy_id"`
	PolicyName     string     `json:"policy_name"`
	ViolationState string     `json:"violation_state"`
	RepositoryID   uuid.UUID  `json:"repository_id"`
	Repository     string     `json:"repository"`
	Component      string     `json:"component"`
	Version        string     `json:"component_version"`
	PURL           string     `json:"purl"`
	Detail         string     `json:"detail"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	ResolvedAt     *time.Time `json:"resolved_at"`
}

func (s *Service) listViolations(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	f := authz.FilterFor(p, authz.PermSBOMRead)
	if f.None() {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	var policy, repo *uuid.UUID
	for k, dst := range map[string]**uuid.UUID{"policy_id": &policy, "repository_id": &repo} {
		if v := q.Get(k); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				s.fail(w, r, httpx.BadRequest("invalid "+k))
				return
			}
			*dst = &id
		}
	}
	resolved := q.Get("state") == "resolved"
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 5)
	rows, err := s.DB.Query(ctx, `SELECT v.id, v.policy_id, p.name, p.violation_state, v.repository_id, r.full_name, v.component_name,
		  v.component_version, v.purl, v.detail, v.first_seen_at, v.last_seen_at, v.resolved_at
		FROM component_policy_violations v JOIN component_policies p ON p.id = v.policy_id JOIN repositories r ON r.id = v.repository_id
		WHERE v.organization_id = $1 AND ($2::uuid IS NULL OR v.policy_id = $2) AND ($3::uuid IS NULL OR v.repository_id = $3)
		  AND (v.resolved_at IS NOT NULL) = $4 AND `+scope+`
		ORDER BY array_position(ARRAY['fail','warn','info'], p.violation_state), v.last_seen_at DESC LIMIT 1000`,
		append([]any{p.OrganizationID, policy, repo, resolved}, sargs...)...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Violation])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Violation{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// EvaluateOrganization re-evaluates every enabled component policy of one
// organization now (the dependency-change feedback loop, PATHOS 3.0 M9).
func EvaluateOrganization(ctx context.Context, pool *pgxpool.Pool, orgID uuid.UUID) (EvalStats, error) {
	var st EvalStats
	err := db.InTx(ctx, pool, func(tx pgx.Tx) error {
		var err error
		st, err = evaluateOrg(ctx, tx, orgID, nil, time.Now())
		return err
	})
	return st, err
}
