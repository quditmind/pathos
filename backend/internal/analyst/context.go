package analyst

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/intel"
	"pathos/internal/org"
)

// The analyst answers from a context built for each question, limited to
// what the user may read: overall figures, the riskiest applications, and
// the findings that match the question (or the riskiest ones). Only
// finding metadata is sent, never source code or secret values.

// FindingRef is a finding as the analyst sees it.
type FindingRef struct {
	ID           uuid.UUID `json:"id"`
	Title        string    `json:"title"`
	Severity     string    `json:"severity"`
	Risk         *float64  `json:"risk_score"`
	KEV          bool      `json:"kev"`
	Exploit      bool      `json:"exploit_available"`
	CVE          string    `json:"cve,omitempty"`
	Package      string    `json:"package,omitempty"`
	Reachability string    `json:"reachability,omitempty"`
	Category     string    `json:"category"`
	Repository   string    `json:"repository"`
	Application  string    `json:"application,omitempty"`
	Status       string    `json:"status"`
	Location     string    `json:"location,omitempty"`
	FirstSeen    time.Time `json:"first_seen"`
}

// Context is what one question is answered from.
type Context struct {
	Totals       map[string]any `json:"totals"`
	Applications []any          `json:"riskiest_applications"`
	Findings     []FindingRef   `json:"findings"`
	Matched      bool           `json:"findings_match_the_question"`
	// Filter describes how the findings were selected, when restricted.
	Filter          string `json:"findings_selection,omitempty"`
	Vulnerabilities []any  `json:"vulnerabilities,omitempty"`
}

var (
	idRe       = regexp.MustCompile(`(?i)\b(CVE-\d{4}-\d{4,}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3})\b`)
	wordRe     = regexp.MustCompile(`[A-Za-z0-9@._/-]{3,60}`)
	stopwords  = map[string]bool{}
	stopSource = `the and for are with what which who how why when where this that these those our you your have has had was were will would
	should could can does did not any all most more less many much show list give tell about from into over under than then them they their
	there here its it's is are be been being on in of to a an by as at or if so do my me we us findings finding vulnerabilities vulnerability
	issues issue risk risks security top please explain summary summarize app apps application applications repository repositories repo repos
	package packages affected affect affects fix fixed first should need needs using used use version versions latest open`
)

func init() {
	for _, w := range strings.Fields(stopSource) {
		stopwords[w] = true
	}
}

// keywords extracts search terms from a question.
func keywords(q string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range idRe.FindAllString(q, -1) {
		k := strings.ToUpper(m)
		if strings.HasPrefix(k, "GHSA-") {
			k = "GHSA-" + strings.ToLower(k[5:])
		}
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	for _, w := range wordRe.FindAllString(q, -1) {
		lw := strings.ToLower(strings.Trim(w, "._/-"))
		if len(lw) < 3 || stopwords[lw] || seen[lw] || idRe.MatchString(w) {
			continue
		}
		seen[lw] = true
		out = append(out, lw)
		if len(out) >= 10 {
			break
		}
	}
	return out
}

func (s *Service) buildContext(ctx context.Context, p *authz.Principal, question string) (Context, error) {
	c := Context{Totals: map[string]any{}, Applications: []any{}, Findings: []FindingRef{}}
	f := authz.FilterFor(p, authz.PermFindingsRead)
	if f.None() {
		return c, authz.ErrForbidden
	}
	scope, sargs := org.ScopeSQL(f, "r.id", "r.business_unit_id", "r.country_id", 2)
	args := append([]any{p.OrganizationID}, sargs...)
	base := `FROM findings x JOIN repositories r ON r.id = x.repository_id WHERE x.organization_id = $1 AND r.archived_at IS NULL AND ` + scope
	var crit, high, med, low, kev, highRisk, repos int
	// #nosec G202 -- scope is built from placeholders
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FILTER (WHERE x.severity = 'critical'), count(*) FILTER (WHERE x.severity = 'high'),
		count(*) FILTER (WHERE x.severity = 'medium'), count(*) FILTER (WHERE x.severity = 'low'), count(*) FILTER (WHERE x.kev),
		count(*) FILTER (WHERE x.risk_score >= 75), count(DISTINCT x.repository_id) `+base+`
		AND x.status IN ('open', 'in_progress', 'needs_review')`, args...).Scan(&crit, &high, &med, &low, &kev, &highRisk, &repos); err != nil {
		return c, err
	}
	c.Totals = map[string]any{"open_by_severity": map[string]int{"critical": crit, "high": high, "medium": med, "low": low},
		"open_actively_exploited_kev": kev, "open_with_critical_risk": highRisk, "repositories_with_open_findings": repos,
		"as_of": time.Now().UTC().Format(time.RFC3339)}
	if s.Posture != nil {
		if gs, err := s.Posture.Groups(ctx, p, "application", 90); err == nil {
			for i, g := range gs {
				if i >= 8 {
					break
				}
				c.Applications = append(c.Applications, map[string]any{"application": g.Label, "risk_score": g.RiskScore, "risk_band": g.RiskBand,
					"open": g.Open, "kev_open": g.KEV, "sla_breached": g.SLABreached, "coverage_percent": g.Coverage, "mean_days_to_fix": g.MTTRDays})
			}
		}
	}
	kws := keywords(question)
	sel := `SELECT x.id, x.title, x.severity, x.risk_score::float8, x.kev, x.exploit_available, x.cve,
		CASE WHEN x.package_name <> '' THEN x.package_name || '@' || x.package_version ELSE '' END, x.reachability, x.category,
		COALESCE(NULLIF(r.display_name, ''), r.full_name), COALESCE(a.name, ''), x.status,
		CASE WHEN x.file_path <> '' THEN x.file_path || COALESCE(':' || x.start_line, '') ELSE '' END, x.first_seen_at
		FROM findings x JOIN repositories r ON r.id = x.repository_id LEFT JOIN applications a ON a.id = r.application_id
		WHERE x.organization_id = $1 AND r.archived_at IS NULL AND ` + scope + ` AND x.status IN ('open', 'in_progress', 'needs_review')`
	load := func(extra string, xargs []any) error {
		// #nosec G202 -- sel and extra are fixed SQL with placeholders
		rows, err := s.DB.Query(ctx, sel+extra+` ORDER BY x.risk_score DESC NULLS LAST, x.last_seen_at DESC LIMIT 25`, append(append([]any{}, args...), xargs...)...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var fr FindingRef
			if err := rows.Scan(&fr.ID, &fr.Title, &fr.Severity, &fr.Risk, &fr.KEV, &fr.Exploit, &fr.CVE, &fr.Package, &fr.Reachability, &fr.Category,
				&fr.Repository, &fr.Application, &fr.Status, &fr.Location, &fr.FirstSeen); err != nil {
				return err
			}
			c.Findings = append(c.Findings, fr)
		}
		return rows.Err()
	}
	// Questions about exploited vulnerabilities get exactly those findings,
	// so the answer cannot mix in others.
	lq := strings.ToLower(question)
	switch {
	case strings.Contains(lq, "kev") || strings.Contains(lq, "actively exploited") || strings.Contains(lq, "known exploited"):
		if err := load(` AND x.kev`, nil); err != nil {
			return c, err
		}
		c.Matched, c.Filter = true, "open findings in the CISA KEV catalog (actively exploited) only"
		return s.withVulns(ctx, c, keywords(question))
	case strings.Contains(lq, "exploit"):
		if err := load(` AND (x.kev OR x.exploit_available)`, nil); err != nil {
			return c, err
		}
		c.Matched, c.Filter = true, "open findings that are actively exploited or have a public exploit only"
		return s.withVulns(ctx, c, keywords(question))
	}
	if len(kws) > 0 {
		var pats []string
		for _, k := range kws {
			pats = append(pats, "%"+strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(strings.ToLower(k))+"%")
		}
		n := len(args) + 1
		cond := fmt.Sprintf(` AND (lower(x.title) LIKE ANY($%[1]d) OR lower(x.rule_id) LIKE ANY($%[1]d) OR lower(x.cve) LIKE ANY($%[1]d)
			OR lower(x.package_name) LIKE ANY($%[1]d) OR lower(x.file_path) LIKE ANY($%[1]d) OR lower(r.full_name) LIKE ANY($%[1]d)
			OR lower(COALESCE(a.name, '')) LIKE ANY($%[1]d) OR x.category = ANY($%[2]d))`, n, n+1)
		if err := load(cond, []any{pats, kws}); err != nil {
			return c, err
		}
		c.Matched = len(c.Findings) > 0
	}
	if len(c.Findings) == 0 {
		if err := load("", nil); err != nil {
			return c, err
		}
	}
	return s.withVulns(ctx, c, kws)
}

// withVulns adds the vulnerability records of identifiers in the question.
func (s *Service) withVulns(ctx context.Context, c Context, kws []string) (Context, error) {
	for _, k := range kws {
		if !idRe.MatchString(k) {
			continue
		}
		if v, err := intel.LookupVuln(ctx, s.DB, k); err == nil && v != nil {
			c.Vulnerabilities = append(c.Vulnerabilities, map[string]any{"id": v.ID, "aliases": v.Aliases, "summary": v.Summary,
				"details": clip(v.Details, 1500), "exploit_references": v.ExploitRefs, "cwes": v.CWEs, "affected": v.Affected})
		}
	}
	return c, nil
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
