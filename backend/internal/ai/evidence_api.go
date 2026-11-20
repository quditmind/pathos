package ai

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/platform/crypto"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// Error codes of the evidence API (catalogue: internal/platform/diag).
const (
	CodeCodeNotAllowed  = "PTH-AI-1101"
	CodeTaskInvalid     = "PTH-AI-1102"
	CodeAlreadyReviewed = "PTH-AI-1103"
	CodeReplayModel     = "PTH-AI-1201"
	CodeReplayPurged    = "PTH-AI-1202"
	CodeReplayLimit     = "PTH-AI-1203"
	CodeReplayExternal  = "PTH-AI-1204"
	// replaysPerHour bounds replays per organization (they cost tokens).
	replaysPerHour = 30
)

// SubjectAccess checks that p may read (or, with manage, act on) a
// subject; modules register one per subject kind (threat models).
type SubjectAccess func(ctx context.Context, p *authz.Principal, subjectID uuid.UUID, manage bool) error

// SubjectReviewer applies a person's decision on an AI conclusion to its
// subject inside the transaction that records the decision (threat
// suggestions: accepted stays, rejected is removed from the draft).
type SubjectReviewer func(ctx context.Context, tx pgx.Tx, p *authz.Principal, rec EvidenceRecord, accept bool, note string) error

// EvidenceRecord is the API view of a record.
type EvidenceRecord struct {
	ID               uuid.UUID       `json:"id"`
	Task             string          `json:"task"`
	TaskLabel        string          `json:"task_label"`
	Operation        string          `json:"operation"`
	SubjectKind      string          `json:"subject_kind"`
	SubjectID        *uuid.UUID      `json:"subject_id"`
	FindingID        *uuid.UUID      `json:"finding_id"`
	Related          json.RawMessage `json:"related"`
	ParentID         *uuid.UUID      `json:"parent_id"`
	ConfigVersionID  *uuid.UUID      `json:"config_version_id"`
	Provider         string          `json:"provider"`
	ProviderLocation string          `json:"provider_location"`
	Model            string          `json:"model"`
	ModelReported    string          `json:"model_reported"`
	ModelDigest      string          `json:"model_digest"`
	PromptTemplate   string          `json:"prompt_template"`
	Parameters       json.RawMessage `json:"parameters"`
	Deterministic    bool            `json:"deterministic"`
	DeterminismNote  string          `json:"determinism_note"`
	SentCode         bool            `json:"sent_code"`
	InputSHA256      string          `json:"input_sha256"`
	ResponseSHA256   string          `json:"response_sha256"`
	Steps            []string        `json:"steps"`
	Conclusion       string          `json:"conclusion"`
	Verdict          string          `json:"verdict"`
	Confidence       *float64        `json:"confidence"`
	Status           string          `json:"status"`
	ErrorCode        string          `json:"error_code"`
	Error            string          `json:"error"`
	InputTokens      int64           `json:"input_tokens"`
	OutputTokens     int64           `json:"output_tokens"`
	ReviewDecision   string          `json:"review_decision"`
	ReviewerID       *uuid.UUID      `json:"reviewer_id"`
	ReviewerName     *string         `json:"reviewer_name"`
	ReviewedAt       *time.Time      `json:"reviewed_at"`
	ReviewNote       string          `json:"review_note"`
	ReplayOf         *uuid.UUID      `json:"replay_of"`
	Comparison       json.RawMessage `json:"comparison"`
	PayloadExpiresAt *time.Time      `json:"payload_expires_at"`
	PayloadPurgedAt  *time.Time      `json:"payload_purged_at"`
	PayloadAvailable bool            `json:"payload_available"`
	RequestedBy      *uuid.UUID      `json:"requested_by"`
	RequestedByName  *string         `json:"requested_by_name"`
	CreatedAt        time.Time       `json:"created_at"`
	// Label is the rule 5 evidence label: every AI conclusion is
	// ai_inferred; Confirmed says a person accepted it.
	Label     string `json:"label"`
	Confirmed bool   `json:"confirmed"`
	// ProposesSuppression: the conclusion would close or suppress the
	// subject (false positive, not exploitable); it never does by itself.
	ProposesSuppression bool `json:"proposes_suppression"`
	// Replayable, else ReplayUnavailable says why.
	Replayable        bool   `json:"replayable"`
	ReplayUnavailable string `json:"replay_unavailable,omitempty"`
	CanReview         bool   `json:"can_review"`
}

const evidenceSelect = `SELECT e.id, e.task, e.operation, e.subject_kind, e.subject_id, e.finding_id, e.related, e.parent_id, e.config_version_id,
	e.provider, e.provider_location, e.model, e.model_reported, e.model_digest, e.prompt_template, e.parameters, e.deterministic, e.sent_code,
	e.input_sha256, e.response_sha256, e.steps, e.conclusion, e.verdict, e.confidence::float8, e.status, e.error_code, e.error,
	e.input_tokens, e.output_tokens, e.review_decision, e.reviewer_id, COALESCE(NULLIF(ru.display_name, ''), ru.email), e.reviewed_at,
	e.review_note, e.replay_of, e.comparison, e.payload_expires_at, e.payload_purged_at,
	EXISTS (SELECT 1 FROM ai_evidence_payloads pl WHERE pl.record_id = COALESCE(e.parent_id, e.id)),
	e.requested_by, COALESCE(NULLIF(qu.display_name, ''), qu.email), e.created_at
	FROM ai_evidence_records e LEFT JOIN users ru ON ru.id = e.reviewer_id LEFT JOIN users qu ON qu.id = e.requested_by`

func scanEvidence(row pgx.Row) (EvidenceRecord, error) {
	var e EvidenceRecord
	var steps []byte
	err := row.Scan(&e.ID, &e.Task, &e.Operation, &e.SubjectKind, &e.SubjectID, &e.FindingID, &e.Related, &e.ParentID, &e.ConfigVersionID,
		&e.Provider, &e.ProviderLocation, &e.Model, &e.ModelReported, &e.ModelDigest, &e.PromptTemplate, &e.Parameters, &e.Deterministic, &e.SentCode,
		&e.InputSHA256, &e.ResponseSHA256, &steps, &e.Conclusion, &e.Verdict, &e.Confidence, &e.Status, &e.ErrorCode, &e.Error,
		&e.InputTokens, &e.OutputTokens, &e.ReviewDecision, &e.ReviewerID, &e.ReviewerName, &e.ReviewedAt,
		&e.ReviewNote, &e.ReplayOf, &e.Comparison, &e.PayloadExpiresAt, &e.PayloadPurgedAt, &e.PayloadAvailable,
		&e.RequestedBy, &e.RequestedByName, &e.CreatedAt)
	if err != nil {
		return e, err
	}
	_ = json.Unmarshal(steps, &e.Steps)
	if e.Steps == nil {
		e.Steps = []string{}
	}
	if t, ok := TaskByKey(e.Task); ok {
		e.TaskLabel = t.Label
	}
	_, e.DeterminismNote = Determinism(e.Provider)
	e.Label = "ai_inferred"
	e.Confirmed = e.ReviewDecision == ReviewAccepted
	e.ProposesSuppression = e.Verdict == FalsePositive || e.Verdict == NotExploitable
	switch {
	case e.ProviderLocation == LocationUser:
		e.ReplayUnavailable = "produced outside PATHOS (the person's own assistant): no prompt to replay"
	case !e.PayloadAvailable && e.PayloadPurgedAt != nil:
		e.ReplayUnavailable = "the redacted prompt was deleted at the end of the retention period"
	case !e.PayloadAvailable:
		e.ReplayUnavailable = "the redacted prompt was not stored (prompt storage is off or the call was refused before sending)"
	case e.ConfigVersionID == nil:
		e.ReplayUnavailable = "no AI configuration version is recorded"
	default:
		e.Replayable = true
	}
	return e, nil
}

func (s *Service) loadEvidence(ctx context.Context, orgID, id uuid.UUID) (EvidenceRecord, error) {
	e, err := scanEvidence(s.DB.QueryRow(ctx, evidenceSelect+` WHERE e.organization_id = $1 AND e.id = $2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return e, errNotFound
	}
	return e, err
}

// access checks that p may see a record (manage: act on it: review or
// replay). Every record needs ai.evidence_read; the subject decides the
// rest: findings by their repository, threat models through the threat
// model module, other subjects (errors, conversations, reports) by their
// requester or an AI administrator.
func (s *Service) access(ctx context.Context, p *authz.Principal, e EvidenceRecord, manage bool) error {
	if !p.HasAnywhere(authz.PermAIEvidenceRead) {
		return authz.ErrForbidden
	}
	switch {
	case e.FindingID != nil:
		perms := []authz.Permission{authz.PermAIEvidenceRead, authz.PermFindingsRead}
		if manage {
			perms = append(perms, authz.PermAIReview)
		}
		for _, perm := range perms {
			if _, err := s.requireFinding(ctx, p, perm, *e.FindingID); err != nil {
				if errors.Is(err, authz.ErrForbidden) {
					return errNotFound
				}
				return err
			}
		}
		return nil
	case e.SubjectKind == "threat_model" || e.SubjectKind == "threat":
		check := s.SubjectAccess[e.SubjectKind]
		if check == nil || e.SubjectID == nil {
			return errNotFound
		}
		if err := check(ctx, p, *e.SubjectID, manage); err != nil {
			return errNotFound
		}
		return nil
	default:
		if (e.RequestedBy != nil && *e.RequestedBy == p.UserID) || p.HasOrgWide(authz.PermAIConfigure) {
			return nil
		}
		return errNotFound
	}
}

type evidenceCursor struct {
	At time.Time `json:"t"`
	ID uuid.UUID `json:"i"`
}

func (s *Service) listEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.flagged(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermAIEvidenceRead) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	q := r.URL.Query()
	where := []string{"e.organization_id = $1"}
	args := []any{p.OrganizationID}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	enum := func(name string, allowed []string, col string) bool {
		v := q.Get(name)
		if v == "" {
			return true
		}
		if !slices.Contains(allowed, v) {
			s.fail(w, r, httpx.BadRequest("unknown "+name+" "+v))
			return false
		}
		add(col+" = ?", v)
		return true
	}
	tasks := []string{}
	for _, t := range Tasks {
		tasks = append(tasks, t.Key)
	}
	if !enum("task", tasks, "e.task") || !enum("status", []string{"succeeded", "invalid_output", "failed", "disabled"}, "e.status") ||
		!enum("review_decision", []string{ReviewPending, ReviewAccepted, ReviewRejected, ReviewNotRequired}, "e.review_decision") ||
		!enum("subject_kind", []string{"finding", "threat", "threat_model", "codegraph_edge", "error", "conversation", "report", "human_review"}, "e.subject_kind") ||
		!enum("provider_location", []string{LocationLocal, LocationCloud, LocationUser}, "e.provider_location") {
		return
	}
	for _, f := range []struct{ name, cond string }{
		{"subject_id", "e.subject_id = ?"},
		{"finding_id", "e.finding_id = ?"},
		// A threat's records: the threat as subject, or its suggestion
		// record (and that record's call).
		{"threat_id", "(e.subject_kind = 'threat' AND e.subject_id = ?::uuid OR e.id IN (SELECT t.ai_evidence_id FROM threats t WHERE t.id = ?::uuid " +
			"UNION SELECT x.parent_id FROM ai_evidence_records x JOIN threats t ON t.ai_evidence_id = x.id WHERE t.id = ?::uuid AND x.parent_id IS NOT NULL))"},
	} {
		if v := q.Get(f.name); v != "" {
			id, err := uuid.Parse(v)
			if err != nil {
				s.fail(w, r, httpx.BadRequest("invalid "+f.name))
				return
			}
			args = append(args, id)
			where = append(where, strings.ReplaceAll(f.cond, "?", "$"+strconv.Itoa(len(args))))
		}
	}
	if q.Get("include_items") != "true" && q.Get("threat_id") == "" {
		// Threat-suggestion items are listed under their call unless asked.
		where = append(where, "e.operation <> 'threat_suggestion_item'")
	}
	limit := 50
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 200 {
		limit = v
	}
	if c := q.Get("cursor"); c != "" {
		raw, err := base64.RawURLEncoding.DecodeString(c)
		var cur evidenceCursor
		if err != nil || json.Unmarshal(raw, &cur) != nil {
			s.fail(w, r, httpx.BadRequest("invalid cursor"))
			return
		}
		args = append(args, cur.At, cur.ID)
		where = append(where, "(e.created_at, e.id) < ($"+strconv.Itoa(len(args)-1)+", $"+strconv.Itoa(len(args))+")")
	}
	out := []EvidenceRecord{}
	var next string
	// Records the caller cannot see are skipped: read in batches until the
	// page is full (at most five batches).
	for batch := 0; batch < 5 && len(out) < limit; batch++ {
		// #nosec G202 -- where holds placeholders only
		rows, err := s.DB.Query(ctx, evidenceSelect+" WHERE "+strings.Join(where, " AND ")+
			" ORDER BY e.created_at DESC, e.id DESC LIMIT "+strconv.Itoa(limit*2), args...)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (EvidenceRecord, error) { return scanEvidence(r) })
		if err != nil {
			s.fail(w, r, err)
			return
		}
		for _, e := range list {
			if len(out) == limit {
				break
			}
			if s.access(ctx, p, e, false) == nil {
				e.CanReview = s.canReview(ctx, p, e)
				out = append(out, e)
			}
			b, _ := json.Marshal(evidenceCursor{At: e.CreatedAt, ID: e.ID})
			next = base64.RawURLEncoding.EncodeToString(b)
		}
		if len(list) < limit*2 {
			if len(out) < limit {
				next = ""
			}
			break
		}
		// Continue after the last row read.
		last := list[len(list)-1]
		args = append(args, last.CreatedAt, last.ID)
		where = append(where, "(e.created_at, e.id) < ($"+strconv.Itoa(len(args)-1)+", $"+strconv.Itoa(len(args))+")")
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "next_cursor": next})
}

// canReview reports whether p could record a decision on e now.
func (s *Service) canReview(ctx context.Context, p *authz.Principal, e EvidenceRecord) bool {
	if !reviewable(e) {
		return false
	}
	return s.access(ctx, p, e, true) == nil
}

func reviewable(e EvidenceRecord) bool {
	if e.Status != "succeeded" || e.Operation == "threat_suggestion" || e.Operation == "replay" {
		return false
	}
	return e.ReviewDecision == ReviewPending || e.ReviewDecision == ReviewNotRequired
}

func (s *Service) getEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.flagged(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	e, err := s.loadEvidence(ctx, p.OrganizationID, id)
	if err == nil {
		err = s.access(ctx, p, e, false)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	e.CanReview = s.canReview(ctx, p, e)
	out := map[string]any{"record": e}
	children := []EvidenceRecord{}
	if rows, err := s.DB.Query(ctx, evidenceSelect+` WHERE e.organization_id = $1 AND (e.parent_id = $2 OR e.replay_of = $2) ORDER BY e.created_at`,
		p.OrganizationID, id); err == nil {
		list, _ := pgx.CollectRows(rows, func(r pgx.CollectableRow) (EvidenceRecord, error) { return scanEvidence(r) })
		for _, c := range list {
			c.CanReview = s.canReview(ctx, p, c)
			children = append(children, c)
		}
	}
	out["related_records"] = children
	inc := r.URL.Query().Get("include")
	if strings.Contains(inc, "prompt") || strings.Contains(inc, "response") {
		pl, err := s.openPayload(ctx, p.OrganizationID, e)
		switch {
		case errors.Is(err, errNoPayload):
			out["payload_unavailable"] = e.ReplayUnavailable
		case err != nil:
			s.fail(w, r, err)
			return
		default:
			if strings.Contains(inc, "prompt") {
				out["prompt"] = map[string]any{"system": pl.System, "user": pl.User, "schema": pl.Schema, "request": pl.Request}
			}
			if strings.Contains(inc, "response") {
				out["response"] = pl.Response
			}
			_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action: "ai_evidence.view_payload", TargetType: "ai_evidence_record", TargetID: e.ID.String(), RequestID: httpx.RequestID(r)})
		}
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

var errNoPayload = errors.New("no payload")

// openPayload decrypts the record's payload (the parent's for an item).
func (s *Service) openPayload(ctx context.Context, orgID uuid.UUID, e EvidenceRecord) (payload, error) {
	var pl payload
	rid := e.ID
	if e.ParentID != nil {
		rid = *e.ParentID
	}
	var sealed crypto.Sealed
	err := s.DB.QueryRow(ctx, `SELECT ciphertext, wrapped_dek, key_version FROM ai_evidence_payloads WHERE organization_id = $1 AND record_id = $2`,
		orgID, rid).Scan(&sealed.Ciphertext, &sealed.WrappedDEK, &sealed.KeyVersion)
	if errors.Is(err, pgx.ErrNoRows) || s.Secrets == nil || s.Secrets.Keys == nil {
		return pl, errNoPayload
	}
	if err != nil {
		return pl, err
	}
	body, err := s.Secrets.Keys.Open(sealed, payloadAAD(rid))
	if err != nil {
		return pl, err
	}
	err = json.Unmarshal(body, &pl)
	return pl, err
}

type reviewRequest struct {
	Decision string `json:"decision"`
	Note     string `json:"note"`
}

func (s *Service) reviewEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.flagged(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req reviewRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	req.Note = strings.TrimSpace(req.Note)
	if req.Decision != ReviewAccepted && req.Decision != ReviewRejected {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "ai_evidence_invalid", "decision must be accepted or rejected"))
		return
	}
	if len(req.Note) > 2000 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "ai_evidence_invalid", "note is at most 2000 characters"))
		return
	}
	e, err := s.loadEvidence(ctx, p.OrganizationID, id)
	if err == nil {
		err = s.access(ctx, p, e, true)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !reviewable(e) {
		s.fail(w, r, httpx.E(http.StatusConflict, "ai_evidence_reviewed",
			"this record cannot be reviewed: it is "+strings.ReplaceAll(e.ReviewDecision, "_", " ")+" ("+e.Status+", "+e.Operation+")").WithDiag(CodeAlreadyReviewed))
		return
	}
	accept := req.Decision == ReviewAccepted
	// A pending AI review of a finding is decided through the review flow
	// (four-eyes, findings.triage, critical guardrail), which also records
	// the decision on this record.
	var reviewID uuid.UUID
	var reviewStatus string
	if e.Task == TaskFindingValidation && s.DB.QueryRow(ctx, `SELECT id, status FROM ai_reviews WHERE organization_id = $1 AND evidence_record_id = $2`,
		p.OrganizationID, e.ID).Scan(&reviewID, &reviewStatus) == nil && reviewStatus == "pending_approval" {
		if err := s.decideReview(ctx, p, reviewID, accept, req.Note); err != nil {
			s.fail(w, r, err)
			return
		}
	} else {
		err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `UPDATE ai_evidence_records SET review_decision = $3, reviewer_id = $4, reviewed_at = now(), review_note = $5
				WHERE organization_id = $1 AND id = $2 AND review_decision IN ('pending', 'not_required')`, p.OrganizationID, e.ID, req.Decision, p.UserID, req.Note)
			if err != nil {
				return err
			}
			if tag.RowsAffected() == 0 {
				return httpx.E(http.StatusConflict, "ai_evidence_reviewed", "this record was reviewed meanwhile").WithDiag(CodeAlreadyReviewed)
			}
			if rv := s.SubjectReviewers[e.Operation]; rv != nil {
				if err := rv(ctx, tx, p, e, accept, req.Note); err != nil {
					return err
				}
			}
			return audit.Write(ctx, tx, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
				Action: "ai_evidence.review", TargetType: "ai_evidence_record", TargetID: e.ID.String(), RequestID: httpx.RequestID(r),
				Metadata: map[string]any{"decision": req.Decision, "note": req.Note, "operation": e.Operation, "subject_kind": e.SubjectKind,
					"subject_id": e.SubjectID, "verdict": e.Verdict}})
		})
		if err != nil {
			s.fail(w, r, err)
			return
		}
	}
	e, err = s.loadEvidence(ctx, p.OrganizationID, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, e)
}

// --- replay ------------------------------------------------------------------------

func normalize(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// compare describes how a replay differs from the original.
func compare(orig EvidenceRecord, resp Response, in interpretation) map[string]any {
	same := orig.Verdict != "" && orig.Verdict == in.Verdict
	if orig.Verdict == "" || orig.Verdict == "answered" || orig.Verdict == "suggested" || orig.Verdict == "proposed" {
		same = normalize(orig.Conclusion) == normalize(in.Conclusion)
	}
	added, removed := []string{}, []string{}
	for _, s := range in.Steps {
		if !slices.Contains(orig.Steps, s) {
			added = append(added, s)
		}
	}
	for _, s := range orig.Steps {
		if !slices.Contains(in.Steps, s) {
			removed = append(removed, s)
		}
	}
	out := map[string]any{
		"same_conclusion":       same,
		"same_verdict":          orig.Verdict == in.Verdict,
		"identical_response":    orig.ResponseSHA256 != "" && orig.ResponseSHA256 == shaHex(resp.JSON),
		"original_verdict":      orig.Verdict,
		"replay_verdict":        in.Verdict,
		"original_conclusion":   orig.Conclusion,
		"replay_conclusion":     in.Conclusion,
		"steps_added":           added,
		"steps_removed":         removed,
		"original_model":        orig.ModelReported,
		"replay_model":          resp.Model,
		"model_changed":         orig.ModelReported != "" && resp.Model != "" && orig.ModelReported != resp.Model,
		"deterministic":         orig.Deterministic,
		"determinism_note":      orig.DeterminismNote,
		"original_confidence":   orig.Confidence,
		"replay_confidence":     in.Confidence,
		"original_record_id":    orig.ID,
		"original_created_at":   orig.CreatedAt,
		"original_status":       orig.Status,
		"original_input_sha256": orig.InputSHA256,
	}
	return out
}

func (s *Service) replayEvidence(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.flagged(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathID(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	e, err := s.loadEvidence(ctx, p.OrganizationID, id)
	if err == nil {
		err = s.access(ctx, p, e, true)
	}
	if err == nil && e.ParentID != nil {
		// An item replays the call that produced it.
		if e, err = s.loadEvidence(ctx, p.OrganizationID, *e.ParentID); err == nil {
			err = s.access(ctx, p, e, true)
		}
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if e.ProviderLocation == LocationUser {
		s.fail(w, r, httpx.E(http.StatusConflict, "ai_replay_unavailable", e.ReplayUnavailable).WithDiag(CodeReplayExternal))
		return
	}
	pl, err := s.openPayload(ctx, p.OrganizationID, e)
	if errors.Is(err, errNoPayload) {
		s.fail(w, r, httpx.E(http.StatusConflict, "ai_replay_unavailable", e.ReplayUnavailable).WithDiag(CodeReplayPurged))
		return
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if e.ConfigVersionID == nil {
		s.fail(w, r, httpx.E(http.StatusConflict, "ai_replay_unavailable", e.ReplayUnavailable).WithDiag(CodeReplayModel))
		return
	}
	var used int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM ai_evidence_records WHERE organization_id = $1 AND operation = 'replay'
		AND created_at > now() - interval '1 hour'`, p.OrganizationID).Scan(&used); err != nil {
		s.fail(w, r, err)
		return
	}
	if used >= replaysPerHour {
		s.fail(w, r, httpx.E(http.StatusTooManyRequests, "rate_limited", "at most "+strconv.Itoa(replaysPerHour)+" replays per hour").WithDiag(CodeReplayLimit))
		return
	}
	cv, err := scanCV(s.DB.QueryRow(ctx, cvSelect+` WHERE v.organization_id = $1 AND v.id = $2`, p.OrganizationID, *e.ConfigVersionID))
	var rc resolved
	if err == nil {
		rc, err = s.resolveVersion(ctx, p.OrganizationID, cv, uuid.Nil, "replay")
	}
	if err != nil {
		s.fail(w, r, httpx.E(http.StatusConflict, "ai_replay_unavailable",
			"the AI configuration or provider of this record no longer exists, so the same model cannot be called").WithDiag(CodeReplayModel))
		return
	}
	orig := e
	var cmpOut map[string]any
	sub := Subject{Kind: e.SubjectKind, ID: e.SubjectID, FindingID: e.FindingID, RequestedBy: &p.UserID}
	_ = json.Unmarshal(e.Related, &sub.Related)
	spec := callSpec{Task: e.Task, Operation: "replay", Template: e.PromptTemplate, System: pl.System, User: pl.User, Schema: pl.Schema,
		Effort: pl.Request.Effort, MaxTokens: pl.Request.MaxTokens, SentCode: e.SentCode, Subject: sub, Review: ReviewNotRequired, ReplayOf: &orig.ID}
	spec.compare = func(resp Response, in interpretation) map[string]any {
		cmpOut = compare(orig, resp, in)
		return cmpOut
	}
	cctx, cancel := context.WithTimeout(ctx, 6*time.Minute)
	defer cancel()
	_, _, nid, err := s.invoke(cctx, p.OrganizationID, rc, spec)
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email,
		Action: "ai_evidence.replay", TargetType: "ai_evidence_record", TargetID: orig.ID.String(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"replay_record_id": nid, "ok": err == nil}})
	if nid == uuid.Nil {
		s.fail(w, r, err)
		return
	}
	rec, lerr := s.loadEvidence(ctx, p.OrganizationID, nid)
	if lerr != nil {
		s.fail(w, r, lerr)
		return
	}
	status := http.StatusCreated
	out := map[string]any{"record": rec, "original": orig, "comparison": cmpOut}
	if err != nil {
		// The failed replay is recorded too; the answer says why.
		status = http.StatusBadGateway
		out["error"] = map[string]any{"code": errorCode(err), "message": rec.Error}
		if errors.Is(err, ErrCodeNotAllowed) {
			s.fail(w, r, httpx.E(http.StatusConflict, "ai_code_not_allowed", "this record sent source code, and its configuration no longer allows it").
				WithDiag(CodeCodeNotAllowed))
			return
		}
	}
	httpx.WriteJSON(w, status, out)
}
