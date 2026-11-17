package review

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

type decisionRequest struct {
	Disposition string `json:"disposition"`
	Reason      string `json:"reason"`
	// Duplicate: the primary finding.
	DuplicateOf *uuid.UUID `json:"duplicate_of"`
	// DuplicateReferenceUnavailable allows a duplicate without a reference
	// (e.g. the primary finding is tracked outside PATHOS).
	DuplicateReferenceUnavailable bool `json:"duplicate_reference_unavailable"`
	// Accepted risk.
	RiskOwnerID   *uuid.UUID `json:"risk_owner_id"`
	RiskExpiresAt *time.Time `json:"risk_expires_at"`
	// Confirmed: remediation planning.
	RemediationOwnerID  *uuid.UUID `json:"remediation_owner_id"`
	RemediationDueAt    *time.Time `json:"remediation_due_at"`
	RemediationPriority *string    `json:"remediation_priority"`
}

// fieldErrors is a 422 with per-field messages.
func fieldErrors(fields map[string]string) error {
	msgs := make([]string, 0, len(fields))
	for _, m := range fields {
		msgs = append(msgs, m)
	}
	slices.Sort(msgs)
	return &httpx.Error{Status: http.StatusUnprocessableEntity, Code: "validation_failed", Message: strings.Join(msgs, " "), Fields: fields}
}

// validateDecision applies the disposition rules and the configured
// requirements. It returns whether an independent review is required.
func (s *Service) validateDecision(ctx context.Context, tx pgx.Tx, p *authz.Principal, v rec, st Settings, req *decisionRequest) (bool, error) {
	errs := map[string]string{}
	if !slices.Contains(Dispositions, req.Disposition) {
		return false, httpx.BadRequest("invalid disposition")
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if len(req.Reason) > 8000 {
		errs["reason"] = "The reason is too long (8000 characters at most)."
	}
	minReason := 10
	switch req.Disposition {
	case DispFalsePositive, DispNotExploitable, DispAcceptedRisk:
		minReason = 30
	}
	if len(req.Reason) < minReason {
		switch req.Disposition {
		case DispFalsePositive:
			errs["reason"] = fmt.Sprintf("Explain why the scanner detection is incorrect (at least %d characters).", minReason)
		case DispNotExploitable:
			errs["reason"] = fmt.Sprintf("Give the technical justification for why the finding is not exploitable (at least %d characters).", minReason)
		case DispAcceptedRisk:
			errs["reason"] = fmt.Sprintf("Justify accepting the risk (at least %d characters).", minReason)
		default:
			errs["reason"] = fmt.Sprintf("A documented reason is required (at least %d characters).", minReason)
		}
	}
	a, err := loadAssessment(ctx, tx, v.ID, v.Round)
	if err != nil {
		return false, err
	}
	var evidence int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM human_review_evidence WHERE review_id = $1 AND deleted_at IS NULL`, v.ID).Scan(&evidence); err != nil {
		return false, err
	}
	switch req.Disposition {
	case DispDuplicate:
		if req.DuplicateOf == nil && !req.DuplicateReferenceUnavailable {
			errs["duplicate_of"] = "Reference the primary finding this one duplicates."
		}
		if req.DuplicateOf != nil {
			var repo uuid.UUID
			if *req.DuplicateOf == v.FindingID {
				errs["duplicate_of"] = "A finding cannot duplicate itself."
			} else if err := tx.QueryRow(ctx, `SELECT repository_id FROM findings WHERE organization_id = $1 AND id = $2`, p.OrganizationID, *req.DuplicateOf).
				Scan(&repo); err != nil || !s.can(ctx, p, authz.PermFindingsRead, repo) {
				errs["duplicate_of"] = "The primary finding does not exist."
			}
		}
	case DispNotExploitable:
		just, _ := a.Fields["exploitability_justification"].(string)
		if evidence == 0 && len(strings.TrimSpace(just)) < 20 {
			errs["evidence"] = "Not exploitable needs supporting evidence or an exploitability justification in the Exploitability tab."
		}
	case DispAcceptedRisk:
		if req.RiskOwnerID == nil {
			errs["risk_owner_id"] = "Name the risk owner."
		} else if err := activeUser(ctx, tx, p.OrganizationID, *req.RiskOwnerID); err != nil {
			errs["risk_owner_id"] = "The risk owner must be an active user."
		}
		now := s.now()
		switch {
		case req.RiskExpiresAt == nil:
			errs["risk_expires_at"] = "Set when the risk acceptance expires."
		case !req.RiskExpiresAt.After(now):
			errs["risk_expires_at"] = "The expiry date must be in the future."
		case req.RiskExpiresAt.After(now.AddDate(3, 0, 0)):
			errs["risk_expires_at"] = "Risk can be accepted for at most three years."
		}
		if len(req.Reason) > 4000 {
			errs["reason"] = "A risk acceptance justification is limited to 4000 characters."
		}
	case DispConfirmed:
		if req.RemediationPriority != nil && !slices.Contains(Priorities, *req.RemediationPriority) {
			errs["remediation_priority"] = "Remediation priority must be p1-p4."
		}
		if req.RemediationOwnerID != nil {
			if err := activeUser(ctx, tx, p.OrganizationID, *req.RemediationOwnerID); err != nil {
				errs["remediation_owner_id"] = "The remediation owner must be an active user."
			}
		}
	}
	final := req.Disposition != DispNeedsInfo
	if final {
		// Configured assessment fields. "Unknown" is an answer; it is never
		// read as evidence that the finding is not exploitable.
		var missing []string
		for _, k := range st.RequiredFields {
			var val string
			if isQuestion(k) {
				val, _ = a.Answers[k].(string)
			} else {
				val, _ = a.Fields[k].(string)
			}
			if strings.TrimSpace(val) == "" {
				label := k
				for _, q := range Questions {
					if q.Key == k {
						label = q.Label
					}
				}
				if f, ok := fieldByKey(AssessmentFields, k); ok {
					label = f.Label
				}
				missing = append(missing, label)
			}
		}
		if len(missing) > 0 {
			errs["assessment"] = "Complete the required assessment fields: " + strings.Join(missing, "; ") + "."
		}
		needEvidence := slices.Contains(st.EvidenceRequiredDispositions, req.Disposition) || slices.Contains(st.EvidenceRequiredSeverities, v.EffectiveSeverity())
		if needEvidence && evidence == 0 {
			errs["evidence"] = "At least one evidence item is required for this decision."
		}
	}
	if len(errs) > 0 {
		return false, fieldErrors(errs)
	}
	if !final {
		return false, nil
	}
	independent := req.Disposition == DispAcceptedRisk || st.needsFinalApproval(v, req.Disposition) ||
		slices.Contains(st.IndependentReviewDispositions, req.Disposition) ||
		slices.Contains(st.IndependentReviewSeverities, v.EffectiveSeverity()) ||
		slices.Contains(st.IndependentReviewSeverities, v.OriginalSeverity)
	return independent, nil
}

// decide records a disposition. It completes the review, sends it to an
// independent reviewer, or (needs more information) keeps it open.
func (s *Service) decide(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req decisionRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if err := requireEditable(v); err != nil {
			return err
		}
		if err := s.requireAssessor(ctx, tx, p, v); err != nil {
			return err
		}
		st, err := loadSettings(ctx, tx, p.OrganizationID)
		if err != nil {
			return err
		}
		independent, err := s.validateDecision(ctx, tx, p, v, st, &req)
		if err != nil {
			return err
		}
		outcome := "final"
		switch {
		case req.Disposition == DispNeedsInfo:
			outcome = "open"
		case independent:
			outcome = "pending_approval"
		}
		did := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO human_review_decisions (id, organization_id, review_id, round, disposition, reason, duplicate_of,
			risk_owner_id, risk_expires_at, assessed_severity, requires_independent, outcome, decided_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
			did, v.OrgID, v.ID, v.Round, req.Disposition, req.Reason, req.DuplicateOf, req.RiskOwnerID, req.RiskExpiresAt, v.AssessedSeverity,
			independent, outcome, p.UserID); err != nil {
			return err
		}
		if err := hist(ctx, tx, v, &p.UserID, "decision.submitted", "disposition", v.Disposition,
			map[string]any{"disposition": req.Disposition, "outcome": outcome, "decision_id": did}, req.Reason); err != nil {
			return err
		}
		if err := s.audit(ctx, tx, p, "decision", v, map[string]any{"disposition": req.Disposition, "outcome": outcome, "reason": req.Reason,
			"decision_id": did}); err != nil {
			return err
		}
		switch outcome {
		case "open":
			return s.transition(ctx, tx, v, &p.UserID, StatusAwaitingInformation, strPtr(DispNeedsInfo), req.Reason)
		case "pending_approval":
			if req.Disposition == DispAcceptedRisk {
				if err := s.requestRiskAcceptance(ctx, tx, v, p.UserID, req); err != nil {
					return err
				}
			}
			if _, err := tx.Exec(ctx, `UPDATE human_reviews SET submitted_at = now() WHERE id = $1`, v.ID); err != nil {
				return err
			}
			if err := s.transition(ctx, tx, v, &p.UserID, StatusAwaitingIndependent, &req.Disposition, ""); err != nil {
				return err
			}
			if st.NotifyIndependentReview {
				return emit(ctx, tx, v, "review.independent_requested", map[string]any{"decided_by": p.UserID, "disposition": req.Disposition,
					"independent_reviewer_id": v.IndependentID})
			}
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE human_reviews SET submitted_at = now() WHERE id = $1`, v.ID); err != nil {
			return err
		}
		return s.complete(ctx, tx, v, p.UserID, nil, req)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeItem(w, r, id)
}

// transition changes status (and disposition) with history.
func (s *Service) transition(ctx context.Context, tx pgx.Tx, v rec, actor *uuid.UUID, status string, disposition *string, note string) error {
	if _, err := tx.Exec(ctx, `UPDATE human_reviews SET status = $2, disposition = $3, started_at = COALESCE(started_at, now()), updated_at = now()
		WHERE id = $1`, v.ID, status, disposition); err != nil {
		return err
	}
	if status != v.Status {
		if err := hist(ctx, tx, v, actor, "review.status", "status", v.Status, status, note); err != nil {
			return err
		}
	}
	return nil
}

// requestRiskAcceptance opens a pending risk acceptance in the existing
// workflow; the independent reviewer (with findings.accept_risk) decides it.
func (s *Service) requestRiskAcceptance(ctx context.Context, tx pgx.Tx, v rec, by uuid.UUID, req decisionRequest) error {
	// A pending request from an earlier submission of this review is replaced.
	if _, err := tx.Exec(ctx, `UPDATE risk_acceptances SET status = 'withdrawn', decided_at = now(), decision_note = 'superseded by a new Human Eye decision'
		WHERE id = (SELECT risk_acceptance_id FROM human_reviews WHERE id = $1) AND status = 'pending'`, v.ID); err != nil {
		return err
	}
	var active bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM risk_acceptances WHERE finding_id = $1 AND status IN ('pending', 'approved'))`, v.FindingID).Scan(&active); err != nil {
		return err
	}
	if active {
		return httpx.Conflict("the finding already has an active or pending risk acceptance (see Risk acceptances)")
	}
	raID := uuid.Must(uuid.NewV7())
	just := fmt.Sprintf("Human Eye review %s: %s (risk owner recorded in the review)", v.Key, req.Reason)
	if len(just) > 4000 {
		just = just[:4000]
	}
	if _, err := tx.Exec(ctx, `INSERT INTO risk_acceptances (id, organization_id, finding_id, requested_by, justification, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`, raID, v.OrgID, v.FindingID, by, just, *req.RiskExpiresAt); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE human_reviews SET risk_acceptance_id = $2 WHERE id = $1`, v.ID, raID); err != nil {
		return err
	}
	return hist(ctx, tx, v, &by, "risk_acceptance.requested", "risk_acceptance_id", nil, raID, "")
}

// complete closes the review with its final disposition and reflects the
// outcome on the finding.
func (s *Service) complete(ctx context.Context, tx pgx.Tx, v rec, decidedBy uuid.UUID, approver *uuid.UUID, req decisionRequest) error {
	remediation := "not_required"
	if req.Disposition == DispConfirmed {
		remediation = "open"
		if v.FindingStatus == "fixed" {
			remediation = "pending_verification"
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE human_reviews SET status = 'completed', disposition = $2, remediation_status = $3, completed_at = now(),
		remediation_owner_id = COALESCE($4, remediation_owner_id), remediation_due_at = COALESCE($5, remediation_due_at),
		remediation_priority = COALESCE($6, remediation_priority), updated_at = now() WHERE id = $1`,
		v.ID, req.Disposition, remediation, req.RemediationOwnerID, req.RemediationDueAt, req.RemediationPriority); err != nil {
		return err
	}
	actor := decidedBy
	if approver != nil {
		actor = *approver
	}
	if err := hist(ctx, tx, v, &actor, "review.completed", "status", v.Status, StatusCompleted, "final disposition: "+req.Disposition); err != nil {
		return err
	}
	if err := hist(ctx, tx, v, &actor, "remediation.status", "remediation_status", v.Remediation, remediation, ""); err != nil {
		return err
	}
	return s.applyToFinding(ctx, tx, v, actor, req)
}

// applyToFinding records the human outcome on the finding without
// rewriting its scanner data: false positives close the finding, accepted
// risk is approved in the risk acceptance workflow, and other decisions
// take the finding out of "needs review".
func (s *Service) applyToFinding(ctx context.Context, tx pgx.Tx, v rec, actor uuid.UUID, req decisionRequest) error {
	a := [16]byte(actor)
	if err := db.SetChangeContext(ctx, tx, &a, "user", fmt.Sprintf("Human Eye review %s: %s. %s", v.Key, strings.ReplaceAll(req.Disposition, "_", " "), req.Reason)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE findings SET human_review_id = $2, human_disposition = $3, human_severity = $4, human_reviewed_at = now(),
		updated_at = now() WHERE id = $1`, v.FindingID, v.ID, req.Disposition, v.AssessedSeverity); err != nil {
		return err
	}
	switch req.Disposition {
	case DispFalsePositive:
		if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'false_positive', resolved_at = now()
			WHERE id = $1 AND status IN ('open', 'in_progress', 'needs_review')`, v.FindingID); err != nil {
			return err
		}
	case DispAcceptedRisk:
		var raID *uuid.UUID
		if err := tx.QueryRow(ctx, `SELECT risk_acceptance_id FROM human_reviews WHERE id = $1`, v.ID).Scan(&raID); err != nil {
			return err
		}
		if raID == nil {
			return httpx.Conflict("the review has no risk acceptance request")
		}
		var expires time.Time
		var status string
		if err := tx.QueryRow(ctx, `SELECT status, expires_at FROM risk_acceptances WHERE id = $1 FOR UPDATE`, *raID).Scan(&status, &expires); err != nil {
			return err
		}
		if status == "pending" {
			if _, err := tx.Exec(ctx, `UPDATE risk_acceptances SET status = 'approved', decided_by = $2, decided_at = now(),
				decision_note = $3 WHERE id = $1`, *raID, actor, "approved in Human Eye "+v.Key); err != nil {
				return err
			}
		} else if status != "approved" {
			return httpx.Conflict("the linked risk acceptance is " + status)
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'accepted_risk', accepted_until = $2 WHERE id = $1`, v.FindingID, expires); err != nil {
			return err
		}
	default:
		// The finding leaves "needs review"; a human-confirmed finding that
		// an AI had closed as a false positive is reopened.
		if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'open'
			WHERE id = $1 AND (status = 'needs_review' OR (status = 'false_positive' AND $2 = 'confirmed'))`, v.FindingID, req.Disposition); err != nil {
			return err
		}
		if req.Disposition == DispConfirmed && req.RemediationOwnerID != nil {
			// Remediation owner becomes the finding's assignee (existing
			// remediation workflow and notification).
			if _, err := tx.Exec(ctx, `UPDATE findings SET assignee_id = $2 WHERE id = $1 AND assignee_id IS DISTINCT FROM $2`,
				v.FindingID, *req.RemediationOwnerID); err != nil {
				return err
			}
		}
	}
	return nil
}

type independentRequest struct {
	Outcome  string `json:"outcome"` // approved | rejected | information_requested
	Comments string `json:"comments"`
}

// independentReview records the second reviewer's outcome. It never edits
// the first reviewer's assessment or decision.
func (s *Service) independentReview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req independentRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !slices.Contains([]string{"approved", "rejected", "information_requested"}, req.Outcome) {
		s.fail(w, r, httpx.BadRequest("outcome must be approved, rejected or information_requested"))
		return
	}
	comments, err := trimmed(req.Comments, 8000)
	if err != nil || (req.Outcome != "approved" && len(comments) < 10) || comments == "" {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "validation_failed", "independent comments are required (at least 10 characters to reject or request information)"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if v.Status != StatusAwaitingIndependent {
			return httpx.Conflict("the review is not awaiting independent review")
		}
		if err := s.require(ctx, p, authz.PermReviewsApprove, v.RepoID); err != nil {
			return err
		}
		// Approvals so far on the pending decision (level 1: the
		// independent reviewer; level 2: the final approver).
		var prior []struct {
			reviewer uuid.UUID
			outcome  string
		}
		var d decisionRequest
		var did, author uuid.UUID
		var outcome string
		var round int
		if err := tx.QueryRow(ctx, `SELECT id, disposition, reason, duplicate_of, risk_owner_id, risk_expires_at, decided_by, outcome, round
			FROM human_review_decisions WHERE review_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1`, v.ID).
			Scan(&did, &d.Disposition, &d.Reason, &d.DuplicateOf, &d.RiskOwnerID, &d.RiskExpiresAt, &author, &outcome, &round); err != nil {
			return err
		}
		if outcome != "pending_approval" || round != v.Round {
			return httpx.Conflict("no decision awaits independent review")
		}
		if author == p.UserID {
			return httpx.E(http.StatusForbidden, "forbidden", "an independent reviewer must not review their own decision")
		}
		if d.Disposition == DispAcceptedRisk && req.Outcome == "approved" && !s.can(ctx, p, authz.PermFindingsAcceptRisk, v.RepoID) {
			return httpx.E(http.StatusForbidden, "forbidden", "approving accepted risk requires findings.accept_risk")
		}
		prows, err := tx.Query(ctx, `SELECT reviewer_id, outcome FROM human_review_approvals WHERE decision_id = $1 ORDER BY level`, did)
		if err != nil {
			return err
		}
		for prows.Next() {
			var a struct {
				reviewer uuid.UUID
				outcome  string
			}
			if err := prows.Scan(&a.reviewer, &a.outcome); err != nil {
				prows.Close()
				return err
			}
			prior = append(prior, a)
		}
		prows.Close()
		for _, a := range prior {
			if a.outcome != "approved" {
				return httpx.Conflict("this decision has already been reviewed")
			}
		}
		st, err := loadSettings(ctx, tx, v.OrgID)
		if err != nil {
			return err
		}
		levels := 1
		if st.needsFinalApproval(v, d.Disposition) {
			levels = 2
		}
		level := len(prior) + 1
		if level > levels {
			return httpx.Conflict("this decision has already been reviewed")
		}
		if level == 1 && v.IndependentID != nil && *v.IndependentID != p.UserID {
			return httpx.E(http.StatusForbidden, "forbidden", "another independent reviewer is assigned to this review")
		}
		if level == 2 && prior[0].reviewer == p.UserID {
			return httpx.E(http.StatusForbidden, "forbidden", "the final approval must come from a third person, not the independent reviewer")
		}
		aid := uuid.Must(uuid.NewV7())
		if _, err := tx.Exec(ctx, `INSERT INTO human_review_approvals (id, organization_id, review_id, decision_id, reviewer_id, outcome, comments, level)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`, aid, v.OrgID, v.ID, did, p.UserID, req.Outcome, comments, level); err != nil {
			return err
		}
		event := "independent_review." + req.Outcome
		if level == 2 {
			event = "final_approval." + req.Outcome
		}
		if err := hist(ctx, tx, v, &p.UserID, event, "independent_review", nil,
			map[string]any{"outcome": req.Outcome, "decision_id": did, "approval_id": aid, "level": level, "levels": levels}, comments); err != nil {
			return err
		}
		if req.Outcome == "approved" && level < levels {
			// Approved by the independent reviewer; a final approver decides.
			if err := s.audit(ctx, tx, p, "independent_review", v, map[string]any{"outcome": req.Outcome, "decision_id": did,
				"disposition": d.Disposition, "level": level, "awaiting": "final_approval"}); err != nil {
				return err
			}
			return emit(ctx, tx, v, "review.independent_requested", map[string]any{"decided_by": author, "disposition": d.Disposition,
				"stage": "final_approval", "approved_by": p.UserID})
		}
		if err := s.audit(ctx, tx, p, "independent_review", v, map[string]any{"outcome": req.Outcome, "decision_id": did, "disposition": d.Disposition}); err != nil {
			return err
		}
		if err := emit(ctx, tx, v, "review.independent_decided", map[string]any{"decided_by": author, "outcome": req.Outcome, "actor": p.UserID}); err != nil {
			return err
		}
		switch req.Outcome {
		case "approved":
			return s.complete(ctx, tx, v, author, &p.UserID, d)
		default:
			if d.Disposition == DispAcceptedRisk {
				status := "rejected"
				if req.Outcome == "information_requested" {
					status = "withdrawn"
				}
				if _, err := tx.Exec(ctx, `UPDATE risk_acceptances SET status = $2, decided_by = CASE WHEN $2 = 'rejected' THEN $3::uuid ELSE decided_by END,
					decided_at = now(), decision_note = $4 WHERE id = $1 AND status = 'pending'`,
					v.RiskAcceptanceID, status, p.UserID, "Human Eye "+v.Key+": "+comments); err != nil {
					return err
				}
			}
			next := StatusInProgress
			if req.Outcome == "information_requested" {
				next = StatusAwaitingInformation
			}
			return s.transition(ctx, tx, v, &p.UserID, next, nil, comments)
		}
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeItem(w, r, id)
}

// reopen starts a new review round on a completed review. The previous
// round's assessment is kept (and copied as the starting point); the
// finding's human outcome is reverted.
func (s *Service) reopen(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	reason, err := trimmed(req.Reason, 4000)
	if err != nil || len(reason) < 10 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "validation_failed", "a reason (at least 10 characters) is required to reopen a review"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if v.Status != StatusCompleted {
			return httpx.Conflict("only completed reviews can be reopened")
		}
		if !s.can(ctx, p, authz.PermReviewsAssign, v.RepoID) && !s.can(ctx, p, authz.PermReviewsApprove, v.RepoID) {
			return authz.ErrForbidden
		}
		a := [16]byte(p.UserID)
		if err := db.SetChangeContext(ctx, tx, &a, "user", "Human Eye review "+v.Key+" reopened: "+reason); err != nil {
			return err
		}
		if v.Disposition != nil {
			switch *v.Disposition {
			case DispFalsePositive:
				if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'open' WHERE id = $1 AND status = 'false_positive' AND human_review_id = $2`, v.FindingID, v.ID); err != nil {
					return err
				}
			case DispAcceptedRisk:
				if v.RiskAcceptanceID != nil {
					if _, err := tx.Exec(ctx, `UPDATE risk_acceptances SET status = 'revoked', decided_by = $2, decided_at = now(), decision_note = $3
						WHERE id = $1 AND status = 'approved'`, *v.RiskAcceptanceID, p.UserID, "Human Eye "+v.Key+" reopened: "+reason); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `UPDATE findings SET status = 'open' WHERE id = $1 AND status = 'accepted_risk'`, v.FindingID); err != nil {
						return err
					}
				}
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE findings SET human_disposition = NULL, human_severity = NULL, human_reviewed_at = NULL
			WHERE id = $1 AND human_review_id = $2`, v.FindingID, v.ID); err != nil {
			return err
		}
		status := StatusReopened
		if _, err := tx.Exec(ctx, `UPDATE human_reviews SET status = $2, round = round + 1, disposition = NULL, remediation_status = NULL,
			completed_at = NULL, submitted_at = NULL, risk_acceptance_id = NULL, updated_at = now() WHERE id = $1`, v.ID, status); err != nil {
			return err
		}
		if err := hist(ctx, tx, v, &p.UserID, "review.reopened", "status", v.Status, status, reason); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO human_review_assessments (review_id, round, organization_id, answers, fields, reproduction, risk,
			remediation, dataflow_notes, updated_by)
			SELECT review_id, round + 1, organization_id, answers, fields, reproduction, risk, remediation, dataflow_notes, $2
			FROM human_review_assessments WHERE review_id = $1 AND round = $3 ON CONFLICT DO NOTHING`, v.ID, p.UserID, v.Round); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "reopen", v, map[string]any{"reason": reason, "previous_disposition": v.Disposition})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeItem(w, r, id)
}

type remediationRequest struct {
	Status   *string    `json:"status"`
	OwnerID  *uuid.UUID `json:"owner_id"`
	DueAt    *time.Time `json:"due_at"`
	Priority *string    `json:"priority"`
	Link     *string    `json:"link"`
	Note     string     `json:"note"`
}

// setRemediation tracks remediation of a confirmed finding.
func (s *Service) setRemediation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req remediationRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if req.Status != nil && (!slices.Contains(RemediationStatuses, *req.Status) || *req.Status == "not_required") {
		s.fail(w, r, httpx.BadRequest("invalid remediation status"))
		return
	}
	if req.Priority != nil && !slices.Contains(Priorities, *req.Priority) {
		s.fail(w, r, httpx.BadRequest("priority must be p1-p4"))
		return
	}
	if req.Link != nil {
		l := strings.TrimSpace(*req.Link)
		if len(l) > 1000 || (l != "" && !strings.HasPrefix(l, "https://") && !strings.HasPrefix(l, "http://")) {
			s.fail(w, r, httpx.BadRequest("the tracking link must be an http(s) URL"))
			return
		}
		req.Link = &l
	}
	note, err := trimmed(req.Note, 4000)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, true)
		if err != nil {
			return err
		}
		if v.Disposition == nil || *v.Disposition != DispConfirmed || v.Status != StatusCompleted {
			return httpx.Conflict("remediation is tracked for completed reviews with a Confirmed disposition")
		}
		if !s.can(ctx, p, authz.PermReviewsAssess, v.RepoID) && !s.can(ctx, p, authz.PermFindingsTriage, v.RepoID) {
			return authz.ErrForbidden
		}
		if req.Status != nil && *req.Status == "verified" {
			if v.FindingStatus != "fixed" {
				return httpx.Conflict("the latest scan still reports the finding; it can be verified once a scan no longer detects it")
			}
			if len(note) < 5 {
				return httpx.E(http.StatusUnprocessableEntity, "validation_failed", "describe how the fix was verified")
			}
		}
		var owner *uuid.UUID
		var due *time.Time
		var prio *string
		var link string
		if err := tx.QueryRow(ctx, `SELECT remediation_owner_id, remediation_due_at, remediation_priority, remediation_link FROM human_reviews WHERE id = $1`,
			v.ID).Scan(&owner, &due, &prio, &link); err != nil {
			return err
		}
		set := func(field string, old, new any, sql string, arg any) error {
			if _, err := tx.Exec(ctx, `UPDATE human_reviews SET `+sql+` = $2, updated_at = now() WHERE id = $1`, v.ID, arg); err != nil {
				return err
			}
			return hist(ctx, tx, v, &p.UserID, "remediation.update", field, old, new, note)
		}
		if req.Status != nil && (v.Remediation == nil || *v.Remediation != *req.Status) {
			if err := set("remediation_status", v.Remediation, *req.Status, "remediation_status", *req.Status); err != nil {
				return err
			}
		}
		if req.OwnerID != nil && (owner == nil || *owner != *req.OwnerID) {
			if err := activeUser(ctx, tx, p.OrganizationID, *req.OwnerID); err != nil {
				return err
			}
			if err := set("remediation_owner_id", owner, *req.OwnerID, "remediation_owner_id", *req.OwnerID); err != nil {
				return err
			}
			a := [16]byte(p.UserID)
			if err := db.SetChangeContext(ctx, tx, &a, "user", ""); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE findings SET assignee_id = $2, updated_at = now() WHERE id = $1`, v.FindingID, *req.OwnerID); err != nil {
				return err
			}
		}
		if req.DueAt != nil && (due == nil || !due.Equal(*req.DueAt)) {
			if err := set("remediation_due_at", due, *req.DueAt, "remediation_due_at", *req.DueAt); err != nil {
				return err
			}
		}
		if req.Priority != nil && (prio == nil || *prio != *req.Priority) {
			if err := set("remediation_priority", prio, *req.Priority, "remediation_priority", *req.Priority); err != nil {
				return err
			}
		}
		if req.Link != nil && *req.Link != link {
			if err := set("remediation_link", link, *req.Link, "remediation_link", *req.Link); err != nil {
				return err
			}
		}
		meta, _ := json.Marshal(req)
		return s.audit(ctx, tx, p, "remediation", v, map[string]any{"change": json.RawMessage(meta)})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeItem(w, r, id)
}

// needsFinalApproval reports whether a decision needs a third person's
// final approval after the independent reviewer (multi-level approval).
func (st Settings) needsFinalApproval(v rec, disposition string) bool {
	return slices.Contains(st.FinalApprovalDispositions, disposition) ||
		slices.Contains(st.FinalApprovalSeverities, v.EffectiveSeverity()) ||
		slices.Contains(st.FinalApprovalSeverities, v.OriginalSeverity)
}
