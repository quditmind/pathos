// Package review implements Human Review: manual security assessment of
// findings by analysts (review queue, assessment workspace, evidence,
// decisions, independent review, assignments, reports and configuration).
//
// A review references an existing finding; scanner data is never copied
// into a second finding record. Review status, final disposition and
// remediation status are three separate fields. See docs/HUMAN_REVIEW.md.
package review

import "slices"

// Review statuses (workflow).
const (
	StatusPending             = "pending"
	StatusAssigned            = "assigned"
	StatusInProgress          = "in_progress"
	StatusAwaitingInformation = "awaiting_information"
	StatusAwaitingIndependent = "awaiting_independent_review"
	StatusCompleted           = "completed"
	StatusReopened            = "reopened"
)

// Statuses lists review statuses in workflow order.
var Statuses = []string{StatusPending, StatusAssigned, StatusInProgress, StatusAwaitingInformation, StatusAwaitingIndependent, StatusCompleted, StatusReopened}

// Final dispositions.
const (
	DispConfirmed      = "confirmed"
	DispFalsePositive  = "false_positive"
	DispDuplicate      = "duplicate"
	DispNotExploitable = "not_exploitable"
	DispAcceptedRisk   = "accepted_risk"
	DispMitigated      = "mitigated"
	DispNeedsInfo      = "needs_more_information"
	DispOutOfScope     = "out_of_scope"
)

// Dispositions lists final dispositions.
var Dispositions = []string{DispConfirmed, DispFalsePositive, DispDuplicate, DispNotExploitable, DispAcceptedRisk, DispMitigated, DispNeedsInfo, DispOutOfScope}

// Remediation statuses.
var RemediationStatuses = []string{"not_required", "open", "in_progress", "fixed", "pending_verification", "verified", "reopened"}

// Priorities, p1 most urgent.
var Priorities = []string{"p1", "p2", "p3", "p4"}

// Severities in descending order.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// SeverityRank returns 4 for critical down to 0 for info (-1 unknown).
func SeverityRank(s string) int {
	if i := slices.Index(Severities, s); i >= 0 {
		return len(Severities) - 1 - i
	}
	return -1
}

// Answer values of exploitability questions.
var Answers = []string{"yes", "no", "unknown", "not_applicable"}

// Question is one structured exploitability question.
type Question struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Questions are the exploitability assessment questions, in order.
var Questions = []Question{
	{"reproducible", "Is the finding reproducible?"},
	{"reachable", "Is the vulnerable code reachable?"},
	{"attacker_controlled", "Is the input attacker-controlled?"},
	{"authentication_required", "Is authentication required?"},
	{"authorization_required", "Is authorization required?"},
	{"user_interaction_required", "Is user interaction required?"},
	{"input_validation_present", "Are input validation controls present?"},
	{"sanitization_present", "Are sanitization controls present?"},
	{"compensating_controls_present", "Are compensating security controls present?"},
	{"exploitable", "Is exploitation practically possible?"},
	{"sensitive_data_exposed", "Is sensitive information exposed?"},
	{"accessible_in_production", "Is the vulnerable functionality accessible in production?"},
}

// Field is one free-text assessment field.
type Field struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	// Options, when set, restrict the value.
	Options []string `json:"options,omitempty"`
}

// AssessmentFields are the exploitability text fields.
var AssessmentFields = []Field{
	{Key: "attack_scenario", Label: "Attack scenario"},
	{Key: "attack_complexity", Label: "Attack complexity", Options: []string{"low", "high"}},
	{Key: "required_privileges", Label: "Required privileges", Options: []string{"none", "low", "high"}},
	{Key: "network_accessibility", Label: "Network accessibility", Options: []string{"internet", "internal_network", "adjacent", "local", "physical"}},
	{Key: "potential_impact", Label: "Potential impact"},
	{Key: "business_impact", Label: "Business impact"},
	{Key: "technical_impact", Label: "Technical impact"},
	{Key: "exploitability_justification", Label: "Exploitability justification"},
	{Key: "investigation_notes", Label: "Additional investigation notes"},
}

// ReproductionFields are the reproduction documentation template.
var ReproductionFields = []Field{
	{Key: "preconditions", Label: "Preconditions"},
	{Key: "environment", Label: "Environment"},
	{Key: "steps", Label: "Steps to reproduce"},
	{Key: "expected_result", Label: "Expected result"},
	{Key: "actual_result", Label: "Actual result"},
	{Key: "observed_impact", Label: "Observed impact"},
	{Key: "supporting_evidence", Label: "Supporting evidence"},
}

// RiskFields are contextual risk factors (CVSS metrics are separate).
var RiskFields = []Field{
	{Key: "business_criticality", Label: "Business criticality", Options: []string{"critical", "high", "medium", "low"}},
	{Key: "internet_exposure", Label: "Internet exposure", Options: []string{"internet_facing", "internal", "not_exposed", "unknown"}},
	{Key: "environmental_impact", Label: "Environmental impact"},
}

// RemediationFields are the reviewer's remediation guidance.
var RemediationFields = []Field{
	{Key: "explanation", Label: "Vulnerability explanation"},
	{Key: "root_cause", Label: "Root cause"},
	{Key: "affected_code", Label: "Affected code"},
	{Key: "recommendation", Label: "Recommended remediation"},
	{Key: "secure_example", Label: "Secure code example"},
	{Key: "references", Label: "Security references"},
	{Key: "action_items", Label: "Developer action items"},
	{Key: "verification_steps", Label: "Suggested verification steps"},
	{Key: "custom_instructions", Label: "Custom remediation instructions"},
}

// EvidenceTypes and classifications.
var (
	EvidenceTypes = []string{"screenshot", "code_snippet", "http_request", "http_response", "command_output", "application_log",
		"security_log", "reproduction_result", "document", "other"}
	EvidenceClassifications = []string{"internal", "confidential", "restricted"}
)

// RequiredFieldKeys are the assessment keys that settings may require.
func RequiredFieldKeys() []string {
	out := make([]string, 0, len(Questions)+len(AssessmentFields))
	for _, q := range Questions {
		out = append(out, q.Key)
	}
	for _, f := range AssessmentFields {
		out = append(out, f.Key)
	}
	return out
}

func fieldByKey(fs []Field, key string) (Field, bool) {
	for _, f := range fs {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

func isQuestion(key string) bool {
	return slices.ContainsFunc(Questions, func(q Question) bool { return q.Key == key })
}

// Catalog is the static vocabulary served to the UI.
type Catalog struct {
	Statuses            []string   `json:"statuses"`
	Dispositions        []string   `json:"dispositions"`
	RemediationStatuses []string   `json:"remediation_statuses"`
	Priorities          []string   `json:"priorities"`
	Answers             []string   `json:"answers"`
	Questions           []Question `json:"questions"`
	AssessmentFields    []Field    `json:"assessment_fields"`
	ReproductionFields  []Field    `json:"reproduction_fields"`
	RiskFields          []Field    `json:"risk_fields"`
	RemediationFields   []Field    `json:"remediation_fields"`
	EvidenceTypes       []string   `json:"evidence_types"`
	Classifications     []string   `json:"evidence_classifications"`
	AIKinds             []string   `json:"ai_kinds"`
}

// AIKinds lists assistance kinds in display order.
var AIKinds = []string{"explanation", "code_summary", "code_paths", "investigation_questions", "false_positive_indicators",
	"evidence_suggestions", "remediation", "secure_code", "references", "assessment_summary"}

// TheCatalog returns the catalog.
func TheCatalog() Catalog {
	return Catalog{Statuses: Statuses, Dispositions: Dispositions, RemediationStatuses: RemediationStatuses, Priorities: Priorities,
		Answers: Answers, Questions: Questions, AssessmentFields: AssessmentFields, ReproductionFields: ReproductionFields,
		RiskFields: RiskFields, RemediationFields: RemediationFields, EvidenceTypes: EvidenceTypes, Classifications: EvidenceClassifications,
		AIKinds: AIKinds}
}
