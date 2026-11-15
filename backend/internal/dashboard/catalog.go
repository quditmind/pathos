// Package dashboard serves posture KPIs and chart aggregates.
//
// The KPI catalog below is the single source of truth for the dashboard: the
// frontend renders whatever the API returns. KPIs whose data source arrives
// in a later phase are returned with Available=false and the phase number,
// and the UI shows "Not yet available" instead of a made-up number.
package dashboard

import "pathos/internal/authz"

// Unit controls value formatting in the UI.
type Unit string

const (
	UnitCount   Unit = "count"
	UnitPercent Unit = "percent"
	UnitDays    Unit = "days"
	UnitScore   Unit = "score"
)

// Polarity tells the UI whether an increase is good or bad.
type Polarity string

const (
	HigherIsBetter Polarity = "higher_is_better"
	LowerIsBetter  Polarity = "lower_is_better"
	Neutral        Polarity = "neutral"
)

// KPIDef defines one dashboard KPI.
type KPIDef struct {
	Key         string
	Label       string
	Group       string
	Description string
	Unit        Unit
	Polarity    Polarity
	Phase       int    // roadmap phase that provides the data
	Drill       string // UI route for drill-down
	// Requires is the permission needed to see the value (org-wide for
	// org-only permissions). Users without it see the card as restricted.
	Requires authz.Permission
	// GeoScoped means region/country/business unit filters apply.
	GeoScoped bool
}

// Groups in display order.
var Groups = []string{"Risk posture", "Remediation", "Assets & coverage", "Scanning", "AI review", "Supply chain", "Platform"}

// KPIs is the 24-card catalog (6×4 grid on desktop).
var KPIs = []KPIDef{
	{"open_findings", "Open findings", "Risk posture", "Findings not resolved, accepted or marked false positive", UnitCount, LowerIsBetter, 4, "/findings?status=open", authz.PermFindingsRead, true},
	{"critical_findings", "Critical open", "Risk posture", "Open findings with Critical severity", UnitCount, LowerIsBetter, 4, "/findings?status=open&severity=critical", authz.PermFindingsRead, true},
	{"high_findings", "High open", "Risk posture", "Open findings with High severity", UnitCount, LowerIsBetter, 4, "/findings?status=open&severity=high", authz.PermFindingsRead, true},
	{"risk_score", "Risk score", "Risk posture", "Severity-weighted open findings per repository (critical 10, high 5, medium 2, low 0.5)", UnitScore, LowerIsBetter, 4, "/findings?status=open", authz.PermFindingsRead, true},
	{"secrets_exposed", "Exposed secrets", "Risk posture", "Open secret findings (Gitleaks, TruffleHog, …)", UnitCount, LowerIsBetter, 4, "/findings?status=open&category=secrets", authz.PermFindingsRead, true},
	{"vulnerable_dependencies", "Vulnerable dependencies", "Risk posture", "Distinct packages with open SCA findings", UnitCount, LowerIsBetter, 4, "/findings?status=open&category=sca", authz.PermFindingsRead, true},

	{"sla_breaches", "SLA breaches", "Remediation", "Open findings past their remediation deadline", UnitCount, LowerIsBetter, 6, "/findings?sla=breached", authz.PermFindingsRead, true},
	{"mttr_days", "Mean time to remediate", "Remediation", "Average days from first seen to resolved, in the period", UnitDays, LowerIsBetter, 6, "/findings?status=resolved", authz.PermFindingsRead, true},
	{"findings_resolved", "Resolved", "Remediation", "Findings resolved in the period", UnitCount, HigherIsBetter, 6, "/findings?status=resolved", authz.PermFindingsRead, true},
	{"accepted_risks", "Accepted risks", "Remediation", "Active accepted-risk decisions", UnitCount, Neutral, 6, "/findings?status=accepted_risk", authz.PermFindingsRead, true},

	{"repositories", "Repositories", "Assets & coverage", "Active repositories under management", UnitCount, Neutral, 3, "/repositories", authz.PermReposRead, true},
	{"applications", "Applications", "Assets & coverage", "Applications (assets) grouping repositories", UnitCount, Neutral, 3, "/applications", authz.PermReposRead, true},
	{"scan_coverage", "Scan coverage", "Assets & coverage", "Active repositories scanned in the period", UnitPercent, HigherIsBetter, 4, "/repositories?scanned=false", authz.PermReposRead, true},
	{"unowned_repositories", "Without owner", "Assets & coverage", "Repositories with no application or owner", UnitCount, LowerIsBetter, 3, "/repositories?owner=none", authz.PermReposRead, true},

	{"scans_completed", "Scans completed", "Scanning", "Scan jobs finished in the period", UnitCount, HigherIsBetter, 4, "/scans?status=succeeded", authz.PermScansRead, true},
	{"scan_success_rate", "Scan success rate", "Scanning", "Succeeded / finished scan jobs in the period", UnitPercent, HigherIsBetter, 4, "/scans?status=failed", authz.PermScansRead, true},

	{"ai_reviews", "AI reviews", "AI review", "Findings reviewed by AI in the period", UnitCount, Neutral, 5, "/ai", authz.PermFindingsRead, true},
	{"ai_false_positive_rate", "AI false-positive rate", "AI review", "Share of AI reviews with a False Positive verdict", UnitPercent, Neutral, 5, "/ai?status=applied", authz.PermFindingsRead, true},
	{"pending_human_review", "Awaiting human review", "AI review", "AI verdicts that need human approval", UnitCount, LowerIsBetter, 5, "/ai", authz.PermFindingsRead, true},

	{"sbom_components", "SBOM components", "Supply chain", "Distinct components across the latest SBOMs", UnitCount, Neutral, 6, "/sbom", authz.PermSBOMRead, true},
	{"license_violations", "License violations", "Supply chain", "Components with a disallowed license", UnitCount, LowerIsBetter, 6, "/sbom?license=violations", authz.PermSBOMRead, true},

	{"active_users", "Active users", "Platform", "Users with access to PATHOS", UnitCount, Neutral, 1, "/admin/users?status=active", authz.PermUsersRead, false},
	{"pending_invitations", "Pending invitations", "Platform", "Invited users who have not signed in yet", UnitCount, LowerIsBetter, 1, "/admin/users?status=invited", authz.PermUsersRead, false},
	{"security_events", "Security events", "Platform", "Denied actions and failed sign-ins in the period", UnitCount, LowerIsBetter, 1, "/admin/audit?outcome=denied", authz.PermAuditRead, false},
}

// CurrentPhase is the last completed roadmap phase; KPIs with Phase <= it
// have a data source.
const CurrentPhase = 5

// ChartDef defines one chart panel.
type ChartDef struct {
	Key      string
	Title    string
	Kind     string // line | bar | stacked_bar | donut
	Phase    int
	Requires authz.Permission
	Drill    string
}

var Charts = []ChartDef{
	{"findings_trend", "Open findings by severity", "stacked_bar", 4, authz.PermFindingsRead, "/findings"},
	{"severity_distribution", "Severity distribution", "donut", 4, authz.PermFindingsRead, "/findings"},
	{"top_repositories", "Riskiest repositories", "bar", 4, authz.PermFindingsRead, "/repositories"},
	{"repos_by_criticality", "Repositories by criticality", "bar", 3, authz.PermReposRead, "/repositories"},
	{"scanner_activity", "Scans by scanner", "bar", 4, authz.PermScansRead, "/scans"},
	{"sign_ins", "Sign-ins per day", "line", 1, authz.PermAuditRead, "/admin/audit?action=auth.login"},
	{"admin_activity", "Administrative changes", "bar", 1, authz.PermAuditRead, "/admin/audit"},
}
