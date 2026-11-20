// Package authz implements PATHOS authorization: a fixed permission catalog,
// system roles, scoped role assignments and policy checks.
//
// The Go catalog in this file is the source of truth. `pathosctl migrate`
// synchronizes it into the permissions, roles and role_permissions tables.
package authz

// Permission is a stable permission key such as "users.manage".
type Permission string

const (
	PermDashboardRead Permission = "dashboard.read"
	// PermInsightsPeople shows developer attribution (who introduced and
	// who fixed findings). It is organization-wide on purpose: data about
	// people is not split by repository scope.
	PermInsightsPeople Permission = "insights.people"

	PermUsersRead   Permission = "users.read"
	PermUsersManage Permission = "users.manage"
	PermTeamsManage Permission = "teams.manage"
	PermRolesRead   Permission = "roles.read"
	PermRolesAssign Permission = "roles.assign"
	PermRolesManage Permission = "roles.manage"

	PermOrgRead   Permission = "org.read"
	PermOrgManage Permission = "org.manage"

	PermAuditRead Permission = "audit.read"

	PermReposRead       Permission = "repos.read"
	PermReposManage     Permission = "repos.manage"
	PermSCMManage       Permission = "scm.manage"
	PermTagsManage      Permission = "tags.manage"
	PermAssetsConfigure Permission = "assets.configure"

	PermScannersRead    Permission = "scanners.read"
	PermScannersManage  Permission = "scanners.manage"
	PermProfilesManage  Permission = "profiles.manage"
	PermScansRead       Permission = "scans.read"
	PermScansRun        Permission = "scans.run"
	PermScansCompare    Permission = "scans.compare"
	PermSchedulesManage Permission = "schedules.manage"

	PermFindingsRead       Permission = "findings.read"
	PermFindingsTriage     Permission = "findings.triage"
	PermFindingsAcceptRisk Permission = "findings.accept_risk"
	PermFindingsExport     Permission = "findings.export"

	PermSBOMRead Permission = "sbom.read"

	// Threat modelling (PATHOS 3.0 M5). Approving is separate from
	// editing: an approver is never the author of the version.
	PermThreatsRead    Permission = "threats.read"
	PermThreatsManage  Permission = "threats.manage"
	PermThreatsApprove Permission = "threats.approve"

	PermReviewsRead      Permission = "reviews.read"
	PermReviewsAssess    Permission = "reviews.assess"
	PermReviewsAssign    Permission = "reviews.assign"
	PermReviewsApprove   Permission = "reviews.approve"
	PermReviewsConfigure Permission = "reviews.configure"

	PermAIReview    Permission = "ai.review"
	PermAIConfigure Permission = "ai.configure"
	// PermAIFix requests AI-proposed code fixes, which PATHOS verifies
	// before a pull request can be opened from them.
	PermAIFix     Permission = "ai.fix"
	PermMCPManage Permission = "mcp.manage"
	// PermAIEvidenceRead views AI evidence records (PATHOS 3.0 M7); each
	// record also needs read access to its subject.
	PermAIEvidenceRead Permission = "ai.evidence_read"

	PermNotificationsManage Permission = "notifications.manage"
	PermSettingsManage      Permission = "settings.manage"

	// Remediate & gate (PATHOS 3.0 M8).
	PermRemediationRead    Permission = "remediation.read"
	PermRemediationManage  Permission = "remediation.manage"
	PermGatesManage        Permission = "gates.manage"
	PermGatesApproveExcept Permission = "gates.approve_exception"
)

// PermissionInfo describes a catalog entry.
type PermissionInfo struct {
	Key         Permission
	Category    string
	Description string
	// OrgOnly permissions are only meaningful at organization scope (for
	// example user management). Assignments at narrower scopes never grant
	// them.
	OrgOnly bool
}

// Permissions is the full catalog, in display order.
var Permissions = []PermissionInfo{
	{PermDashboardRead, "Overview", "View dashboards and posture analytics", false},
	{PermInsightsPeople, "Overview", "View developer attribution: who introduced and fixed findings, per developer and team (when enabled)", true},

	{PermUsersRead, "Administration", "View users", true},
	{PermUsersManage, "Administration", "Invite, provision, deactivate and reactivate users", true},
	{PermTeamsManage, "Administration", "Create and manage teams", true},
	{PermRolesRead, "Administration", "View roles, permissions and role assignments", true},
	{PermRolesAssign, "Administration", "Grant and revoke role assignments", false},
	{PermRolesManage, "Administration", "Create and edit custom roles", true},
	{PermOrgRead, "Administration", "View regions, countries and business units", false},
	{PermOrgManage, "Administration", "Manage regions, countries and business units", true},
	{PermAuditRead, "Administration", "View the audit log", true},
	{PermSettingsManage, "Administration", "Manage platform settings", true},
	{PermNotificationsManage, "Administration", "Manage SMTP settings, templates and notification rules", true},

	{PermReposRead, "Assets", "View repositories and applications", false},
	{PermReposManage, "Assets", "Import, edit, tag and archive repositories and applications", false},
	{PermSCMManage, "Assets", "Manage SCM connections, OAuth applications and credentials", true},
	{PermTagsManage, "Assets", "Create, edit and delete tags and tag categories", true},
	{PermAssetsConfigure, "Assets", "Configure asset classifications, required fields and colours", true},

	{PermScannersRead, "Scanning", "View the scanner catalog", false},
	{PermScannersManage, "Scanning", "Enable, disable and configure scanners", true},
	{PermProfilesManage, "Scanning", "Create and edit scan profiles", true},
	{PermScansRead, "Scanning", "View scan jobs and results", false},
	{PermScansRun, "Scanning", "Start, retry and cancel scans", false},
	{PermScansCompare, "Scanning", "Compare scan executions and view scan history", false},
	{PermSchedulesManage, "Scanning", "Manage scan schedules", false},

	{PermFindingsRead, "Findings", "View findings and evidence", false},
	{PermFindingsTriage, "Findings", "Change finding status, assign and comment", false},
	{PermFindingsAcceptRisk, "Findings", "Approve accepted-risk and false-positive decisions", false},
	{PermFindingsExport, "Findings", "Export findings", false},
	{PermSBOMRead, "Findings", "View SBOMs and component inventory", false},
	{PermThreatsRead, "Threat model", "View threat models, threats, their evidence and versions", false},
	{PermThreatsManage, "Threat model", "Create, generate, edit, import and submit threat models; change threats with a reason", false},
	{PermThreatsApprove, "Threat model", "Approve, reject or request changes on threat models in review (never one's own)", false},

	{PermReviewsRead, "Human Eye", "View the review queue, completed assessments and review reports", false},
	{PermReviewsAssess, "Human Eye", "Perform assessments: investigate, upload evidence, comment and submit review decisions", false},
	{PermReviewsAssign, "Human Eye", "Add findings to the review queue, assign reviewers, set priorities and due dates", false},
	{PermReviewsApprove, "Human Eye", "Act as independent reviewer: approve, reject or request information on review decisions", false},
	{PermReviewsConfigure, "Human Eye", "Manage Human Eye configuration and workflow rules", true},

	{PermAIReview, "AI & MCP", "Run and approve AI reviews", false},
	{PermAIConfigure, "AI & MCP", "Manage AI providers and configurations", true},
	{PermAIFix, "AI & MCP", "Request AI-proposed code fixes for findings (verified by a worker before a pull request can be opened)", false},
	{PermAIEvidenceRead, "AI & MCP", "View AI evidence records (model, prompt and response, reasoning, conclusion, reviewer) of subjects one can read", false},
	{PermMCPManage, "AI & MCP", "Manage MCP servers and tool permissions", true},

	{PermRemediationRead, "Remediate & gate", "View remediation items, fix verifications, security gates, gate decisions and exceptions", false},
	{PermRemediationManage, "Remediate & gate", "Create, assign and update remediation items, verify fixes and request gate exceptions", false},
	{PermGatesManage, "Remediate & gate", "Create, change and delete security gates (each references a security policy)", true},
	{PermGatesApproveExcept, "Remediate & gate", "Approve or reject gate exceptions and approvals requested by someone else", false},
}

// SystemRole is a seeded, immutable role.
type SystemRole struct {
	Key         string
	Name        string
	Description string
	Permissions []Permission
}

func all() []Permission {
	out := make([]Permission, len(Permissions))
	for i, p := range Permissions {
		out[i] = p.Key
	}
	return out
}

var readOnly = []Permission{
	PermDashboardRead, PermOrgRead, PermReposRead, PermScannersRead,
	PermScansRead, PermScansCompare, PermFindingsRead, PermSBOMRead, PermReviewsRead, PermThreatsRead, PermRemediationRead, PermAIEvidenceRead,
}

func with(base []Permission, extra ...Permission) []Permission {
	out := append([]Permission(nil), base...)
	return append(out, extra...)
}

// RoleSuperAdmin is granted to the bootstrap administrator.
const RoleSuperAdmin = "super_admin"

// SystemRoles are the eleven seeded roles. See docs/RBAC_MATRIX.md.
var SystemRoles = []SystemRole{
	{RoleSuperAdmin, "Super Administrator", "Full control of the PATHOS platform", all()},
	{"platform_admin", "Platform Administrator",
		"Operates the platform: users, SCM, scanners, settings. Does not triage findings or approve risk",
		with(readOnly,
			PermUsersRead, PermUsersManage, PermTeamsManage, PermRolesRead, PermRolesAssign,
			PermOrgManage, PermAuditRead, PermSettingsManage, PermNotificationsManage,
			PermReposManage, PermSCMManage, PermTagsManage, PermAssetsConfigure, PermScannersManage, PermProfilesManage,
			PermScansRun, PermSchedulesManage, PermAIConfigure, PermMCPManage, PermReviewsAssign, PermReviewsConfigure, PermGatesManage)},
	{"security_manager", "Security Manager",
		"Owns the security program for a scope: policy, risk acceptance, scheduling, reporting",
		with(readOnly,
			PermUsersRead, PermRolesRead, PermRolesAssign, PermAuditRead,
			PermReposManage, PermTagsManage, PermProfilesManage, PermScansRun, PermSchedulesManage,
			PermFindingsTriage, PermFindingsAcceptRisk, PermFindingsExport, PermAIReview, PermAIFix,
			PermReviewsAssess, PermReviewsAssign, PermReviewsApprove, PermReviewsConfigure, PermInsightsPeople,
			PermThreatsManage, PermThreatsApprove, PermRemediationManage, PermGatesManage, PermGatesApproveExcept)},
	{"security_analyst", "Security Analyst",
		"Triages findings, runs scans and AI reviews",
		with(readOnly, PermScansRun, PermFindingsTriage, PermFindingsExport, PermAIReview, PermAIFix, PermReviewsAssess, PermThreatsManage, PermRemediationManage)},
	{"appsec_engineer", "AppSec Engineer",
		"Tunes scanners and profiles, onboards repositories, triages findings",
		with(readOnly, PermReposManage, PermTagsManage, PermProfilesManage, PermScansRun, PermSchedulesManage,
			PermFindingsTriage, PermFindingsExport, PermAIReview, PermAIFix, PermReviewsAssess, PermThreatsManage, PermRemediationManage)},
	{"independent_reviewer", "Independent Reviewer",
		"Second-level reviewer: validates other analysts' Human Eye decisions before closure",
		with(readOnly, PermReviewsApprove, PermFindingsExport, PermThreatsApprove, PermGatesApproveExcept)},
	{"repository_contributor", "Repository Contributor",
		"Imports and maintains repositories in scope and runs scans; owners of a repository can also edit its descriptive metadata",
		with(readOnly, PermReposManage, PermScansRun)},
	{"application_owner", "Application Owner",
		"Accountable for applications in scope: views posture, assigns and triages findings",
		with(readOnly, PermScansRun, PermFindingsTriage, PermFindingsExport, PermThreatsManage, PermRemediationManage)},
	{"developer", "Developer",
		"Views and remediates findings on assigned repositories",
		with(readOnly, PermFindingsTriage, PermRemediationManage)},
	{"auditor", "Auditor",
		"Read-only access to everything including the audit log and user list",
		with(readOnly, PermUsersRead, PermRolesRead, PermAuditRead, PermFindingsExport)},
	{"viewer", "Viewer", "Read-only access to posture data in scope", readOnly},
}

// LookupPermission returns catalog info for key.
func LookupPermission(key Permission) (PermissionInfo, bool) {
	for _, p := range Permissions {
		if p.Key == key {
			return p, true
		}
	}
	return PermissionInfo{}, false
}

// LookupSystemRole returns the system role with key.
func LookupSystemRole(key string) (SystemRole, bool) {
	for _, r := range SystemRoles {
		if r.Key == key {
			return r, true
		}
	}
	return SystemRole{}, false
}
