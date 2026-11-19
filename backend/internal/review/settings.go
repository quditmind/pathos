package review

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/scanners"
)

// Settings is the organization's Human Eye configuration.
type Settings struct {
	AutoQueue                     bool              `json:"auto_queue"`
	AutoTriggers                  []string          `json:"auto_triggers"`
	AutoScanners                  []string          `json:"auto_scanners"`
	AutoCategories                []string          `json:"auto_categories"`
	AutoMinSeverity               string            `json:"auto_min_severity"`
	PriorityBySeverity            map[string]string `json:"priority_by_severity"`
	SLADays                       map[string]int    `json:"sla_days"`
	AssignmentStrategy            string            `json:"assignment_strategy"`
	AssignmentPool                []uuid.UUID       `json:"assignment_pool"`
	AllowSelfAssign               bool              `json:"allow_self_assign"`
	IndependentReviewSeverities   []string          `json:"independent_review_severities"`
	IndependentReviewDispositions []string          `json:"independent_review_dispositions"`
	// Decisions needing independent review whose severity or disposition
	// is listed here also need a final approval by a third person.
	FinalApprovalSeverities      []string   `json:"final_approval_severities"`
	FinalApprovalDispositions    []string   `json:"final_approval_dispositions"`
	EvidenceRequiredDispositions []string   `json:"evidence_required_dispositions"`
	EvidenceRequiredSeverities   []string   `json:"evidence_required_severities"`
	RequiredFields               []string   `json:"required_fields"`
	NotifyAssignment             bool       `json:"notify_assignment"`
	NotifyIndependentReview      bool       `json:"notify_independent_review"`
	NotifyOverdue                bool       `json:"notify_overdue"`
	AIAssist                     bool       `json:"ai_assist"`
	AISendCode                   bool       `json:"ai_send_code"`
	EvidenceMaxMB                int        `json:"evidence_max_mb"`
	UnassignedCanAssess          bool       `json:"unassigned_can_assess"`
	UpdatedAt                    *time.Time `json:"updated_at,omitempty"`
	UpdatedBy                    *string    `json:"updated_by,omitempty"`
}

const settingsCols = `auto_queue, auto_triggers, auto_scanners, auto_categories, auto_min_severity, priority_by_severity, sla_days,
	assignment_strategy, assignment_pool, allow_self_assign, independent_review_severities, independent_review_dispositions,
	evidence_required_dispositions, evidence_required_severities, required_fields, notify_assignment, notify_independent_review,
	notify_overdue, ai_assist, ai_send_code, evidence_max_mb, unassigned_can_assess, final_approval_severities, final_approval_dispositions`

// EnsureSettings creates an organization's default Human Eye settings
// (idempotent; seeded for every new organization).
func EnsureSettings(ctx context.Context, q db.Querier, orgID uuid.UUID) error {
	_, err := q.Exec(ctx, `INSERT INTO human_review_settings (organization_id) VALUES ($1) ON CONFLICT DO NOTHING`, orgID)
	return err
}

// loadSettings returns the configuration, creating the defaults on first use.
func loadSettings(ctx context.Context, q db.Querier, orgID uuid.UUID) (Settings, error) {
	if _, err := q.Exec(ctx, `INSERT INTO human_review_settings (organization_id) VALUES ($1) ON CONFLICT DO NOTHING`, orgID); err != nil {
		return Settings{}, err
	}
	var st Settings
	var prio, sla []byte
	var at time.Time
	var by *string
	err := q.QueryRow(ctx, `SELECT `+settingsCols+`, s.updated_at, COALESCE(NULLIF(u.display_name, ''), u.email)
		FROM human_review_settings s LEFT JOIN users u ON u.id = s.updated_by WHERE s.organization_id = $1`, orgID).
		Scan(&st.AutoQueue, &st.AutoTriggers, &st.AutoScanners, &st.AutoCategories, &st.AutoMinSeverity, &prio, &sla, &st.AssignmentStrategy,
			&st.AssignmentPool, &st.AllowSelfAssign, &st.IndependentReviewSeverities, &st.IndependentReviewDispositions,
			&st.EvidenceRequiredDispositions, &st.EvidenceRequiredSeverities, &st.RequiredFields, &st.NotifyAssignment,
			&st.NotifyIndependentReview, &st.NotifyOverdue, &st.AIAssist, &st.AISendCode, &st.EvidenceMaxMB, &st.UnassignedCanAssess,
			&st.FinalApprovalSeverities, &st.FinalApprovalDispositions, &at, &by)
	if err != nil {
		return st, err
	}
	_ = json.Unmarshal(prio, &st.PriorityBySeverity)
	_ = json.Unmarshal(sla, &st.SLADays)
	st.UpdatedAt, st.UpdatedBy = &at, by
	return st, nil
}

// priorityFor returns the configured priority for a severity.
func (st Settings) priorityFor(sev string) string {
	if p, ok := st.PriorityBySeverity[sev]; ok && slices.Contains(Priorities, p) {
		return p
	}
	return "p3"
}

// dueFor returns the review due date for a severity (nil: no SLA).
func (st Settings) dueFor(sev string, from time.Time) *time.Time {
	if d, ok := st.SLADays[sev]; ok && d > 0 {
		t := from.Add(time.Duration(d) * 24 * time.Hour)
		return &t
	}
	return nil
}

func (st *Settings) validate() error {
	sub := func(name string, vals, allowed []string) error {
		for _, v := range vals {
			if !slices.Contains(allowed, v) {
				return httpx.BadRequest(fmt.Sprintf("%s: unknown value %q", name, v))
			}
		}
		return nil
	}
	nonNil := func(v []string) []string {
		if v == nil {
			return []string{}
		}
		return v
	}
	st.AutoTriggers, st.AutoScanners, st.AutoCategories = nonNil(st.AutoTriggers), nonNil(st.AutoScanners), nonNil(st.AutoCategories)
	st.IndependentReviewSeverities, st.IndependentReviewDispositions = nonNil(st.IndependentReviewSeverities), nonNil(st.IndependentReviewDispositions)
	st.FinalApprovalSeverities, st.FinalApprovalDispositions = nonNil(st.FinalApprovalSeverities), nonNil(st.FinalApprovalDispositions)
	st.EvidenceRequiredDispositions, st.EvidenceRequiredSeverities = nonNil(st.EvidenceRequiredDispositions), nonNil(st.EvidenceRequiredSeverities)
	st.RequiredFields = nonNil(st.RequiredFields)
	if st.AssignmentPool == nil {
		st.AssignmentPool = []uuid.UUID{}
	}
	finalDisp := slices.DeleteFunc(slices.Clone(Dispositions), func(d string) bool { return d == DispNeedsInfo })
	var scannerKeys []string
	for _, sc := range scanners.Catalog {
		scannerKeys = append(scannerKeys, sc.Key)
	}
	for _, err := range []error{
		sub("auto_triggers", st.AutoTriggers, []string{"needs_review", "ai_needs_review", "ai_false_positive", "new_findings"}),
		sub("auto_scanners", st.AutoScanners, scannerKeys),
		sub("auto_categories", st.AutoCategories, scanners.FindingCategories),
		sub("auto_min_severity", []string{st.AutoMinSeverity}, Severities),
		sub("assignment_strategy", []string{st.AssignmentStrategy}, []string{"manual", "round_robin", "least_loaded"}),
		sub("independent_review_severities", st.IndependentReviewSeverities, Severities),
		sub("independent_review_dispositions", st.IndependentReviewDispositions, finalDisp),
		sub("final_approval_severities", st.FinalApprovalSeverities, Severities),
		sub("final_approval_dispositions", st.FinalApprovalDispositions, finalDisp),
		sub("evidence_required_dispositions", st.EvidenceRequiredDispositions, finalDisp),
		sub("evidence_required_severities", st.EvidenceRequiredSeverities, Severities),
		sub("required_fields", st.RequiredFields, RequiredFieldKeys()),
	} {
		if err != nil {
			return err
		}
	}
	if st.PriorityBySeverity == nil {
		st.PriorityBySeverity = map[string]string{}
	}
	for k, v := range st.PriorityBySeverity {
		if !slices.Contains(Severities, k) || !slices.Contains(Priorities, v) {
			return httpx.BadRequest("priority_by_severity maps severities to p1-p4")
		}
	}
	if st.SLADays == nil {
		st.SLADays = map[string]int{}
	}
	for k, v := range st.SLADays {
		if !slices.Contains(Severities, k) || v < 0 || v > 365 {
			return httpx.BadRequest("sla_days maps severities to 0-365 days (0 = no due date)")
		}
	}
	if st.EvidenceMaxMB < 1 || st.EvidenceMaxMB > 100 {
		return httpx.BadRequest("evidence_max_mb must be 1-100")
	}
	if len(st.AssignmentPool) > 200 {
		return httpx.BadRequest("the assignment pool is limited to 200 analysts")
	}
	if st.AssignmentStrategy != "manual" && len(st.AssignmentPool) == 0 {
		return httpx.BadRequest("automatic assignment needs at least one analyst in the assignment pool")
	}
	return nil
}

func (s *Service) getSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasAnywhere(authz.PermReviewsRead) && !p.HasOrgWide(authz.PermReviewsConfigure) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, st)
}

func (s *Service) putSettings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if !p.HasOrgWide(authz.PermReviewsConfigure) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	var st Settings
	if err := httpx.DecodeJSON(w, r, &st); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := st.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	err := db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		before, err := loadSettings(ctx, tx, p.OrganizationID)
		if err != nil {
			return err
		}
		for _, u := range st.AssignmentPool {
			if err := activeUser(ctx, tx, p.OrganizationID, u); err != nil {
				return httpx.BadRequest("every analyst in the assignment pool must be an active user")
			}
		}
		prio, _ := json.Marshal(st.PriorityBySeverity)
		sla, _ := json.Marshal(st.SLADays)
		if _, err := tx.Exec(ctx, `UPDATE human_review_settings SET auto_queue = $2, auto_triggers = $3, auto_scanners = $4, auto_categories = $5,
			auto_min_severity = $6, priority_by_severity = $7, sla_days = $8, assignment_strategy = $9, assignment_pool = $10, allow_self_assign = $11,
			independent_review_severities = $12, independent_review_dispositions = $13, evidence_required_dispositions = $14,
			evidence_required_severities = $15, required_fields = $16, notify_assignment = $17, notify_independent_review = $18,
			notify_overdue = $19, ai_assist = $20, ai_send_code = $21, evidence_max_mb = $22, unassigned_can_assess = $23,
			updated_by = $24, final_approval_severities = $25, final_approval_dispositions = $26, updated_at = now() WHERE organization_id = $1`,
			p.OrganizationID, st.AutoQueue, st.AutoTriggers, st.AutoScanners, st.AutoCategories, st.AutoMinSeverity, prio, sla,
			st.AssignmentStrategy, st.AssignmentPool, st.AllowSelfAssign, st.IndependentReviewSeverities, st.IndependentReviewDispositions,
			st.EvidenceRequiredDispositions, st.EvidenceRequiredSeverities, st.RequiredFields, st.NotifyAssignment, st.NotifyIndependentReview,
			st.NotifyOverdue, st.AIAssist, st.AISendCode, st.EvidenceMaxMB, st.UnassignedCanAssess, p.UserID,
			st.FinalApprovalSeverities, st.FinalApprovalDispositions); err != nil {
			return err
		}
		before.UpdatedAt, before.UpdatedBy = nil, nil
		return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
			Action: "human_review.settings_update", TargetType: "human_review_settings", TargetID: p.OrganizationID.String(),
			Metadata: map[string]any{"before": before, "after": st}})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
