// Package policy implements security policies: conditions on findings and
// their context (repository, application) mapped to actions (block the
// scan and pull request gates, require a Human Eye review, tighten the SLA,
// notify). Policies are evaluated in SQL with bound parameters only.
package policy

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Conditions all must hold (AND). Empty lists and nil pointers do not
// constrain. Values inside one list are alternatives (OR).
type Conditions struct {
	MinSeverity      string   `json:"min_severity,omitempty"`
	Categories       []string `json:"categories,omitempty"`
	Scanners         []string `json:"scanners,omitempty"`
	CWE              []string `json:"cwe,omitempty"`
	MinRisk          *int     `json:"min_risk,omitempty"`
	KEV              *bool    `json:"kev,omitempty"`
	Malicious        *bool    `json:"malicious,omitempty"`
	ExploitAvailable *bool    `json:"exploit_available,omitempty"`
	Reachability     []string `json:"reachability,omitempty"`
	MinAgeDays       *int     `json:"min_age_days,omitempty"`
	// Context of the finding's repository.
	Criticality        []string `json:"criticality,omitempty"`
	InternetExposure   []string `json:"internet_exposure,omitempty"`
	Environments       []string `json:"environments,omitempty"`
	DataClassification []string `json:"data_classification,omitempty"`
	ComplianceScopes   []string `json:"compliance_scopes,omitempty"`
	RepositoryIDs      []string `json:"repository_ids,omitempty"`
	ApplicationIDs     []string `json:"application_ids,omitempty"`
}

// Actions taken for matching findings.
type Actions struct {
	// Block fails the scan's security gate when a new finding matches, and
	// a pull request check when a finding it introduces matches.
	Block bool `json:"block,omitempty"`
	// RequireReview queues matching findings for a Human Eye review.
	RequireReview bool `json:"require_review,omitempty"`
	// SLADays tightens the remediation deadline to at most this many days
	// after the finding was first seen.
	SLADays *int `json:"sla_days,omitempty"`
	// Notify sends a "policy.violated" notification for new violations.
	Notify bool `json:"notify,omitempty"`
}

var (
	severities   = []string{"critical", "high", "medium", "low", "info"}
	categories   = []string{"secrets", "sast", "sca", "iac", "container", "dast", "license", "other"}
	reachability = []string{"reachable", "not_reachable", "unknown"}
	criticality  = []string{"critical", "high", "medium", "low"}
	keyRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,62}$`)
	cweRe        = regexp.MustCompile(`^CWE-[0-9]{1,5}$`)
	uuidRe       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

// SeverityRank orders severities (critical highest).
func SeverityRank(s string) int {
	if i := slices.Index(severities, s); i >= 0 {
		return len(severities) - i
	}
	return 0
}

func checkList(name string, v []string, ok func(string) bool) error {
	if len(v) > 100 {
		return fmt.Errorf("%s: at most 100 values", name)
	}
	for _, x := range v {
		if !ok(x) {
			return fmt.Errorf("%s: invalid value %q", name, x)
		}
	}
	return nil
}

func in(set []string) func(string) bool {
	return func(s string) bool { return slices.Contains(set, s) }
}

// Normalize cleans and validates a policy definition.
func Normalize(c *Conditions, a *Actions) error {
	c.MinSeverity = strings.ToLower(strings.TrimSpace(c.MinSeverity))
	for i, x := range c.CWE {
		x = strings.ToUpper(strings.TrimSpace(x))
		if !strings.HasPrefix(x, "CWE-") {
			x = "CWE-" + x
		}
		c.CWE[i] = x
	}
	for i := range c.RepositoryIDs {
		c.RepositoryIDs[i] = strings.ToLower(strings.TrimSpace(c.RepositoryIDs[i]))
	}
	for i := range c.ApplicationIDs {
		c.ApplicationIDs[i] = strings.ToLower(strings.TrimSpace(c.ApplicationIDs[i]))
	}
	errs := []error{}
	if c.MinSeverity != "" && !slices.Contains(severities, c.MinSeverity) {
		errs = append(errs, errors.New("min_severity must be critical, high, medium, low or info"))
	}
	errs = append(errs,
		checkList("categories", c.Categories, in(categories)),
		checkList("scanners", c.Scanners, keyRe.MatchString),
		checkList("cwe", c.CWE, cweRe.MatchString),
		checkList("reachability", c.Reachability, in(reachability)),
		checkList("criticality", c.Criticality, in(criticality)),
		checkList("internet_exposure", c.InternetExposure, keyRe.MatchString),
		checkList("environments", c.Environments, keyRe.MatchString),
		checkList("data_classification", c.DataClassification, keyRe.MatchString),
		checkList("compliance_scopes", c.ComplianceScopes, keyRe.MatchString),
		checkList("repository_ids", c.RepositoryIDs, uuidRe.MatchString),
		checkList("application_ids", c.ApplicationIDs, uuidRe.MatchString),
	)
	if c.MinRisk != nil && (*c.MinRisk < 0 || *c.MinRisk > 100) {
		errs = append(errs, errors.New("min_risk must be 0-100"))
	}
	if c.MinAgeDays != nil && (*c.MinAgeDays < 0 || *c.MinAgeDays > 3650) {
		errs = append(errs, errors.New("min_age_days must be 0-3650"))
	}
	if c.Empty() {
		errs = append(errs, errors.New("a policy needs at least one condition"))
	}
	if a.SLADays != nil && (*a.SLADays < 1 || *a.SLADays > 365) {
		errs = append(errs, errors.New("sla_days must be 1-365"))
	}
	if !a.Block && !a.RequireReview && a.SLADays == nil && !a.Notify {
		errs = append(errs, errors.New("a policy needs at least one action"))
	}
	return errors.Join(errs...)
}

// Empty reports whether no condition is set.
func (c Conditions) Empty() bool {
	return c.MinSeverity == "" && len(c.Categories) == 0 && len(c.Scanners) == 0 && len(c.CWE) == 0 && c.MinRisk == nil &&
		c.KEV == nil && c.Malicious == nil && c.ExploitAvailable == nil && len(c.Reachability) == 0 && c.MinAgeDays == nil &&
		len(c.Criticality) == 0 && len(c.InternetExposure) == 0 && len(c.Environments) == 0 && len(c.DataClassification) == 0 &&
		len(c.ComplianceScopes) == 0 && len(c.RepositoryIDs) == 0 && len(c.ApplicationIDs) == 0
}

// BranchOnly reports whether the policy uses conditions that only findings
// tracked on the scan branch have (contextual risk, reachability, age,
// exploit availability). Such policies do not apply to pull request checks.
func (c Conditions) BranchOnly() bool {
	return c.MinRisk != nil || len(c.Reachability) > 0 || c.MinAgeDays != nil || c.ExploitAvailable != nil
}

// Columns maps condition fields to SQL expressions of one row source.
// Repository columns are always r.*.
type Columns struct {
	Severity, Category, Scanners, CWE, Risk, KEV, Malicious, Exploit, Reachability, FirstSeen string
}

// FindingColumns: findings f JOIN repositories r.
var FindingColumns = Columns{
	Severity: "f.severity", Category: "f.category", Scanners: "f.scanner_keys", CWE: "f.cwe", Risk: "f.risk_score",
	KEV: "f.kev", Malicious: "f.malicious", Exploit: "f.exploit_available", Reachability: "f.reachability", FirstSeen: "f.first_seen_at",
}

// PRColumns: pr_findings pf JOIN pr_checks c JOIN repositories r. KEV and
// malicious come from the intelligence data for the finding's CVE.
var PRColumns = Columns{
	Severity: "pf.severity", Category: "pf.category", Scanners: "ARRAY[pf.scanner_key]", CWE: "pf.cwe",
	KEV:       "EXISTS (SELECT 1 FROM intel_kev k WHERE k.cve_id = pf.cve)",
	Malicious: "(pf.cve LIKE 'MAL-%' OR pf.rule_id LIKE 'MAL-%' OR pf.title ~* '^(malicious code in|malware in|embedded malicious code)')",
}

// Where renders the conditions as a SQL boolean expression, appending
// bound values to args (placeholders continue from len(*args)+1).
func Where(c Conditions, col Columns, args *[]any) (string, error) {
	var parts []string
	arg := func(v any) string {
		*args = append(*args, v)
		return fmt.Sprintf("$%d", len(*args))
	}
	need := func(expr, field string) error {
		if expr == "" {
			return fmt.Errorf("condition %s is not available here", field)
		}
		return nil
	}
	if c.MinSeverity != "" {
		var sev []string
		for _, s := range severities {
			if SeverityRank(s) >= SeverityRank(c.MinSeverity) {
				sev = append(sev, s)
			}
		}
		parts = append(parts, col.Severity+" = ANY("+arg(sev)+"::text[])")
	}
	if len(c.Categories) > 0 {
		parts = append(parts, col.Category+" = ANY("+arg(c.Categories)+"::text[])")
	}
	if len(c.Scanners) > 0 {
		parts = append(parts, col.Scanners+" && "+arg(c.Scanners)+"::text[]")
	}
	if len(c.CWE) > 0 {
		parts = append(parts, col.CWE+" && "+arg(c.CWE)+"::text[]")
	}
	if c.MinRisk != nil {
		if err := need(col.Risk, "min_risk"); err != nil {
			return "", err
		}
		parts = append(parts, "COALESCE("+col.Risk+", 0) >= "+arg(*c.MinRisk))
	}
	for _, b := range []struct {
		v     *bool
		expr  string
		field string
	}{{c.KEV, col.KEV, "kev"}, {c.Malicious, col.Malicious, "malicious"}, {c.ExploitAvailable, col.Exploit, "exploit_available"}} {
		if b.v == nil {
			continue
		}
		if err := need(b.expr, b.field); err != nil {
			return "", err
		}
		parts = append(parts, "("+b.expr+") = "+arg(*b.v))
	}
	if len(c.Reachability) > 0 {
		if err := need(col.Reachability, "reachability"); err != nil {
			return "", err
		}
		parts = append(parts, col.Reachability+" = ANY("+arg(c.Reachability)+"::text[])")
	}
	if c.MinAgeDays != nil {
		if err := need(col.FirstSeen, "min_age_days"); err != nil {
			return "", err
		}
		parts = append(parts, col.FirstSeen+" <= now() - make_interval(days => "+arg(*c.MinAgeDays)+")")
	}
	if len(c.Criticality) > 0 {
		parts = append(parts, "r.criticality = ANY("+arg(c.Criticality)+"::text[])")
	}
	if len(c.InternetExposure) > 0 {
		parts = append(parts, "r.internet_exposure = ANY("+arg(c.InternetExposure)+"::text[])")
	}
	if len(c.Environments) > 0 {
		parts = append(parts, "r.environment = ANY("+arg(c.Environments)+"::text[])")
	}
	if len(c.DataClassification) > 0 {
		parts = append(parts, "r.data_classification = ANY("+arg(c.DataClassification)+"::text[])")
	}
	if len(c.ComplianceScopes) > 0 {
		parts = append(parts, "EXISTS (SELECT 1 FROM repository_compliance_scopes cs WHERE cs.repository_id = r.id AND cs.scope_key = ANY("+
			arg(c.ComplianceScopes)+"::text[]))")
	}
	if len(c.RepositoryIDs) > 0 {
		parts = append(parts, "r.id = ANY("+arg(c.RepositoryIDs)+"::uuid[])")
	}
	if len(c.ApplicationIDs) > 0 {
		parts = append(parts, "r.application_id = ANY("+arg(c.ApplicationIDs)+"::uuid[])")
	}
	if len(parts) == 0 {
		return "", errors.New("a policy needs at least one condition")
	}
	return "(" + strings.Join(parts, " AND ") + ")", nil
}
