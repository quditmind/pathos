package review

import (
	"context"
	"encoding/json"
	"errors"
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

// FindingInfo is the finding's scanner data (read-only here).
type FindingInfo struct {
	ID             uuid.UUID  `json:"id"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Category       string     `json:"category"`
	RuleID         string     `json:"rule_id"`
	ScannerKeys    []string   `json:"scanner_keys"`
	Severity       string     `json:"severity"`
	CVSS           *float64   `json:"cvss"`
	CWE            []string   `json:"cwe"`
	CVE            string     `json:"cve"`
	OWASP          []string   `json:"owasp"`
	PackageName    string     `json:"package_name"`
	PackageVersion string     `json:"package_version"`
	FixedVersion   string     `json:"fixed_version"`
	FilePath       string     `json:"file_path"`
	StartLine      *int       `json:"start_line"`
	EndLine        *int       `json:"end_line"`
	Snippet        string     `json:"snippet"`
	SnippetStart   *int       `json:"snippet_start_line"`
	Status         string     `json:"status"`
	AIStatus       string     `json:"ai_status"`
	FirstSeenAt    time.Time  `json:"first_seen_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	SLADueAt       *time.Time `json:"sla_due_at"`
	AssigneeName   *string    `json:"assignee_name"`
}

// Original is the scanner's assessment preserved on the review.
type Original struct {
	Severity     string          `json:"severity"`
	CVSS         *float64        `json:"cvss"`
	CVSSVector   string          `json:"cvss_vector"`
	Output       json.RawMessage `json:"output"`
	Rule         json.RawMessage `json:"rule"`
	CapturedAt   *time.Time      `json:"captured_at"`
	CaptureError string          `json:"capture_error"`
}

// Assessment is the analyst's structured assessment of one round.
type Assessment struct {
	Round         int            `json:"round"`
	Answers       map[string]any `json:"answers"`
	Fields        map[string]any `json:"fields"`
	Reproduction  map[string]any `json:"reproduction"`
	Risk          map[string]any `json:"risk"`
	Remediation   map[string]any `json:"remediation"`
	DataflowNotes map[string]any `json:"dataflow_notes"`
	UpdatedBy     *string        `json:"updated_by"`
	UpdatedAt     *time.Time     `json:"updated_at"`
}

// AIReviewInfo is the latest automated AI review of the finding.
type AIReviewInfo struct {
	ID                uuid.UUID `json:"id"`
	Verdict           string    `json:"verdict"`
	Confidence        float64   `json:"confidence"`
	SuggestedSeverity string    `json:"suggested_severity"`
	Rationale         string    `json:"rationale"`
	Remediation       string    `json:"remediation"`
	Status            string    `json:"status"`
	Source            string    `json:"source"`
	Model             string    `json:"model"`
	CreatedAt         time.Time `json:"created_at"`
}

// TriageInfo is the automated triage state of the finding.
type TriageInfo struct {
	Status    string     `json:"status"`
	Source    *string    `json:"source"`
	Reason    *string    `json:"reason"`
	ChangedAt *time.Time `json:"changed_at"`
}

// Approval is an independent reviewer's outcome.
type Approval struct {
	ID           uuid.UUID `json:"id"`
	ReviewerID   uuid.UUID `json:"reviewer_id"`
	ReviewerName string    `json:"reviewer_name"`
	Outcome      string    `json:"outcome"`
	Comments     string    `json:"comments"`
	CreatedAt    time.Time `json:"created_at"`
}

// Decision is one submitted disposition with its independent review.
type Decision struct {
	ID                  uuid.UUID  `json:"id"`
	Round               int        `json:"round"`
	Disposition         string     `json:"disposition"`
	Reason              string     `json:"reason"`
	DuplicateOf         *uuid.UUID `json:"duplicate_of"`
	DuplicateOfTitle    *string    `json:"duplicate_of_title"`
	RiskOwnerID         *uuid.UUID `json:"risk_owner_id"`
	RiskOwnerName       *string    `json:"risk_owner_name"`
	RiskExpiresAt       *time.Time `json:"risk_expires_at"`
	AssessedSeverity    *string    `json:"assessed_severity"`
	RequiresIndependent bool       `json:"requires_independent"`
	Outcome             string     `json:"outcome"`
	DecidedBy           uuid.UUID  `json:"decided_by"`
	DecidedByName       string     `json:"decided_by_name"`
	CreatedAt           time.Time  `json:"created_at"`
	Approvals           []Approval `json:"approvals"`
}

// Capabilities tell the UI what the caller may do (the API enforces them).
type Capabilities struct {
	Assess       bool   `json:"assess"`
	Start        bool   `json:"start"`
	Assign       bool   `json:"assign"`
	Approve      bool   `json:"approve"`
	Comment      bool   `json:"comment"`
	Reopen       bool   `json:"reopen"`
	Remediate    bool   `json:"remediate"`
	UploadFiles  bool   `json:"upload_files"`
	AI           bool   `json:"ai"`
	AIReason     string `json:"ai_unavailable_reason,omitempty"`
	AcceptRisk   bool   `json:"accept_risk"`
	SourceViewer bool   `json:"source_viewer"`
}

// Detail is the assessment workspace payload.
type Detail struct {
	Item
	Finding              FindingInfo   `json:"finding"`
	RepositoryKey        string        `json:"repository_key"`
	DefaultBranch        string        `json:"default_branch"`
	SourceType           string        `json:"source_type"`
	ScanJobID            *uuid.UUID    `json:"scan_job_id"`
	ScanKey              *string       `json:"scan_key"`
	SourceReason         string        `json:"source_reason"`
	CreatedByName        *string       `json:"created_by_name"`
	Original             Original      `json:"original"`
	Assessment           Assessment    `json:"assessment"`
	AssessedCVSS         *float64      `json:"assessed_cvss"`
	AssessedCVSSVector   string        `json:"assessed_cvss_vector"`
	SeverityReason       string        `json:"severity_justification"`
	RemediationOwnerID   *uuid.UUID    `json:"remediation_owner_id"`
	RemediationOwner     *string       `json:"remediation_owner_name"`
	RemediationDueAt     *time.Time    `json:"remediation_due_at"`
	RemediationPriority  *string       `json:"remediation_priority"`
	RemediationLink      string        `json:"remediation_link"`
	RiskAcceptanceID     *uuid.UUID    `json:"risk_acceptance_id"`
	StartedAt            *time.Time    `json:"started_at"`
	SubmittedAt          *time.Time    `json:"submitted_at"`
	AIReview             *AIReviewInfo `json:"ai_review"`
	Triage               TriageInfo    `json:"triage"`
	Decisions            []Decision    `json:"decisions"`
	EvidenceCount        int           `json:"evidence_count"`
	RequiresIndependent  bool          `json:"requires_independent_review"`
	RequiredFields       []string      `json:"required_fields"`
	EvidenceRequired     bool          `json:"evidence_required_for"`
	EvidenceDispositions []string      `json:"evidence_required_dispositions"`
	Can                  Capabilities  `json:"can"`
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.load(ctx, s.DB, p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// The scanner record is captured on first view if the background job
	// has not reached this review yet.
	if err := s.captureOriginal(ctx, v); err != nil {
		s.Log.Warn("capture scanner output", "review", v.Key, "err", err)
	}
	d, err := s.detail(ctx, p, v)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (s *Service) detail(ctx context.Context, p *authz.Principal, v rec) (Detail, error) {
	var d Detail
	var err error
	if d.Item, err = scanItem(s.DB.QueryRow(ctx, itemSelect+` WHERE h.id = $1`, v.ID)); err != nil {
		return d, err
	}
	f := &d.Finding
	var out, rule []byte
	err = s.DB.QueryRow(ctx, `SELECT f.id, f.title, f.description, f.category, f.rule_id, f.scanner_keys, f.severity, f.cvss::float8, f.cwe, f.cve,
		f.package_name, f.package_version, f.fixed_version, f.file_path, f.start_line, f.end_line, f.snippet, f.snippet_start_line, f.status, f.ai_status,
		f.first_seen_at, f.last_seen_at, f.sla_due_at, COALESCE(NULLIF(au.display_name, ''), au.email),
		r.repository_key, r.default_branch, r.source_type, h.scan_job_id, j.scan_key, h.source_reason, COALESCE(NULLIF(cu.display_name, ''), cu.email),
		h.original_severity, h.original_cvss::float8, h.original_cvss_vector, h.original_output, h.original_rule, h.original_captured_at,
		h.original_capture_error, h.assessed_cvss::float8, h.assessed_cvss_vector, h.severity_justification, h.remediation_owner_id,
		COALESCE(NULLIF(ou.display_name, ''), ou.email), h.remediation_due_at, h.remediation_priority, h.remediation_link, h.risk_acceptance_id,
		h.started_at, h.submitted_at
		FROM human_reviews h JOIN findings f ON f.id = h.finding_id JOIN repositories r ON r.id = h.repository_id
		LEFT JOIN users au ON au.id = f.assignee_id LEFT JOIN users cu ON cu.id = h.created_by LEFT JOIN users ou ON ou.id = h.remediation_owner_id
		LEFT JOIN scan_jobs j ON j.id = h.scan_job_id
		WHERE h.id = $1`, v.ID).Scan(&f.ID, &f.Title, &f.Description, &f.Category, &f.RuleID, &f.ScannerKeys, &f.Severity, &f.CVSS, &f.CWE, &f.CVE,
		&f.PackageName, &f.PackageVersion, &f.FixedVersion, &f.FilePath, &f.StartLine, &f.EndLine, &f.Snippet, &f.SnippetStart, &f.Status, &f.AIStatus,
		&f.FirstSeenAt, &f.LastSeenAt, &f.SLADueAt, &f.AssigneeName,
		&d.RepositoryKey, &d.DefaultBranch, &d.SourceType, &d.ScanJobID, &d.ScanKey, &d.SourceReason, &d.CreatedByName,
		&d.Original.Severity, &d.Original.CVSS, &d.Original.CVSSVector, &out, &rule, &d.Original.CapturedAt,
		&d.Original.CaptureError, &d.AssessedCVSS, &d.AssessedCVSSVector, &d.SeverityReason, &d.RemediationOwnerID,
		&d.RemediationOwner, &d.RemediationDueAt, &d.RemediationPriority, &d.RemediationLink, &d.RiskAcceptanceID,
		&d.StartedAt, &d.SubmittedAt)
	if err != nil {
		return d, err
	}
	if f.Category == "secrets" {
		f.Snippet = "" // never show code around a secret
	}
	f.OWASP = OWASPFor(f.CWE, f.Category)
	d.Original.Output, d.Original.Rule = out, rule
	if d.Assessment, err = loadAssessment(ctx, s.DB, v.ID, v.Round); err != nil {
		return d, err
	}
	var ai AIReviewInfo
	err = s.DB.QueryRow(ctx, `SELECT id, verdict, confidence::float8, suggested_severity, rationale, remediation, status, source, model, created_at
		FROM ai_reviews WHERE finding_id = $1 AND status <> 'superseded' ORDER BY created_at DESC LIMIT 1`, v.FindingID).
		Scan(&ai.ID, &ai.Verdict, &ai.Confidence, &ai.SuggestedSeverity, &ai.Rationale, &ai.Remediation, &ai.Status, &ai.Source, &ai.Model, &ai.CreatedAt)
	if err == nil {
		d.AIReview = &ai
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return d, err
	}
	d.Triage.Status = f.Status
	err = s.DB.QueryRow(ctx, `SELECT source, reason, created_at FROM finding_status_history WHERE finding_id = $1 ORDER BY created_at DESC, id DESC LIMIT 1`,
		v.FindingID).Scan(&d.Triage.Source, &d.Triage.Reason, &d.Triage.ChangedAt)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return d, err
	}
	if d.Decisions, err = loadDecisions(ctx, s.DB, v.ID); err != nil {
		return d, err
	}
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM human_review_evidence WHERE review_id = $1 AND deleted_at IS NULL`, v.ID).Scan(&d.EvidenceCount); err != nil {
		return d, err
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		return d, err
	}
	d.RequiresIndependent = slices.Contains(st.IndependentReviewSeverities, v.EffectiveSeverity()) || slices.Contains(st.IndependentReviewSeverities, v.OriginalSeverity)
	d.RequiredFields = st.RequiredFields
	d.EvidenceRequired = slices.Contains(st.EvidenceRequiredSeverities, v.EffectiveSeverity())
	d.EvidenceDispositions = st.EvidenceRequiredDispositions
	d.Can = s.capabilities(ctx, p, v, st)
	return d, nil
}

func (s *Service) capabilities(ctx context.Context, p *authz.Principal, v rec, st Settings) Capabilities {
	c := Capabilities{SourceViewer: s.Source != nil}
	assess := s.can(ctx, p, authz.PermReviewsAssess, v.RepoID)
	assign := s.can(ctx, p, authz.PermReviewsAssign, v.RepoID)
	approve := s.can(ctx, p, authz.PermReviewsApprove, v.RepoID)
	open := v.Status != StatusCompleted && v.Status != StatusAwaitingIndependent
	mine := v.ReviewerID != nil && *v.ReviewerID == p.UserID
	c.Assess = open && assess && (mine || assign || st.UnassignedCanAssess)
	c.Start = open && assess && v.Status != StatusInProgress && (mine || (v.ReviewerID == nil && (st.AllowSelfAssign || assign)) || assign)
	c.Assign = v.Status != StatusCompleted && assign
	c.AcceptRisk = s.can(ctx, p, authz.PermFindingsAcceptRisk, v.RepoID)
	if v.Status == StatusAwaitingIndependent && approve {
		var author uuid.UUID
		if err := s.DB.QueryRow(ctx, `SELECT decided_by FROM human_review_decisions WHERE review_id = $1 ORDER BY created_at DESC LIMIT 1`, v.ID).Scan(&author); err == nil {
			c.Approve = author != p.UserID && (v.IndependentID == nil || *v.IndependentID == p.UserID)
		}
	}
	c.Comment = assess || assign || approve
	c.Reopen = v.Status == StatusCompleted && (assign || approve)
	c.Remediate = v.Disposition != nil && *v.Disposition == DispConfirmed && (assess || s.can(ctx, p, authz.PermFindingsTriage, v.RepoID))
	c.UploadFiles = c.Assess && s.Evidence != nil
	switch {
	case !st.AIAssist:
		c.AIReason = "AI assistance is disabled in Review Configurations"
	case s.AI == nil:
		c.AIReason = "AI assistance is not available in this deployment"
	default:
		var ok bool
		_ = s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ai_configurations WHERE organization_id = $1 AND is_default AND archived_at IS NULL)`,
			p.OrganizationID).Scan(&ok)
		if !ok {
			c.AIReason = "No AI provider is configured: an administrator must add one under AI settings"
		}
	}
	c.AI = c.AIReason == "" && (assess || approve)
	return c
}

func loadAssessment(ctx context.Context, q db.Querier, reviewID uuid.UUID, round int) (Assessment, error) {
	a := Assessment{Round: round, Answers: map[string]any{}, Fields: map[string]any{}, Reproduction: map[string]any{}, Risk: map[string]any{},
		Remediation: map[string]any{}, DataflowNotes: map[string]any{}}
	var ans, fields, repro, risk, rem, df []byte
	var at time.Time
	err := q.QueryRow(ctx, `SELECT a.answers, a.fields, a.reproduction, a.risk, a.remediation, a.dataflow_notes,
		COALESCE(NULLIF(u.display_name, ''), u.email), a.updated_at
		FROM human_review_assessments a LEFT JOIN users u ON u.id = a.updated_by WHERE a.review_id = $1 AND a.round = $2`, reviewID, round).
		Scan(&ans, &fields, &repro, &risk, &rem, &df, &a.UpdatedBy, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	a.UpdatedAt = &at
	for _, x := range []struct {
		b   []byte
		dst *map[string]any
	}{{ans, &a.Answers}, {fields, &a.Fields}, {repro, &a.Reproduction}, {risk, &a.Risk}, {rem, &a.Remediation}, {df, &a.DataflowNotes}} {
		_ = json.Unmarshal(x.b, x.dst)
	}
	return a, nil
}

func loadDecisions(ctx context.Context, q db.Querier, reviewID uuid.UUID) ([]Decision, error) {
	rows, err := q.Query(ctx, `SELECT d.id, d.round, d.disposition, d.reason, d.duplicate_of, df.title, d.risk_owner_id,
		COALESCE(NULLIF(ro.display_name, ''), ro.email), d.risk_expires_at, d.assessed_severity, d.requires_independent, d.outcome, d.decided_by,
		COALESCE(NULLIF(du.display_name, ''), du.email), d.created_at
		FROM human_review_decisions d JOIN users du ON du.id = d.decided_by LEFT JOIN users ro ON ro.id = d.risk_owner_id
		LEFT JOIN findings df ON df.id = d.duplicate_of
		WHERE d.review_id = $1 ORDER BY d.created_at, d.id`, reviewID)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Decision, error) {
		var d Decision
		err := row.Scan(&d.ID, &d.Round, &d.Disposition, &d.Reason, &d.DuplicateOf, &d.DuplicateOfTitle, &d.RiskOwnerID, &d.RiskOwnerName,
			&d.RiskExpiresAt, &d.AssessedSeverity, &d.RequiresIndependent, &d.Outcome, &d.DecidedBy, &d.DecidedByName, &d.CreatedAt)
		d.Approvals = []Approval{}
		return d, err
	})
	if err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT a.decision_id, a.id, a.reviewer_id, COALESCE(NULLIF(u.display_name, ''), u.email), a.outcome, a.comments, a.created_at
		FROM human_review_approvals a JOIN users u ON u.id = a.reviewer_id WHERE a.review_id = $1 ORDER BY a.created_at, a.id`, reviewID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var did uuid.UUID
		var a Approval
		if err := rows.Scan(&did, &a.ID, &a.ReviewerID, &a.ReviewerName, &a.Outcome, &a.Comments, &a.CreatedAt); err != nil {
			return nil, err
		}
		for i := range out {
			if out[i].ID == did {
				out[i].Approvals = append(out[i].Approvals, a)
			}
		}
	}
	if out == nil {
		out = []Decision{}
	}
	return out, rows.Err()
}

// --- assessment -------------------------------------------------------------

func ensureAssessment(ctx context.Context, q db.Querier, v rec) error {
	_, err := q.Exec(ctx, `INSERT INTO human_review_assessments (review_id, round, organization_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
		v.ID, v.Round, v.OrgID)
	return err
}

type assessmentRequest struct {
	Answers       map[string]string `json:"answers"`
	Fields        map[string]string `json:"fields"`
	Reproduction  map[string]string `json:"reproduction"`
	Risk          map[string]string `json:"risk"`
	Remediation   map[string]string `json:"remediation"`
	DataflowNotes map[string]string `json:"dataflow_notes"`
	// AIRecommendationID records that the analyst used an AI suggestion.
	AIRecommendationID *uuid.UUID `json:"ai_recommendation_id"`
}

func checkTextMap(name string, m map[string]string, fields []Field, maxLen int) error {
	for k, v := range m {
		fd, ok := fieldByKey(fields, k)
		if !ok {
			return httpx.BadRequest(name + ": unknown field " + k)
		}
		if len(v) > maxLen {
			return httpx.BadRequest(name + ": " + fd.Label + " is too long")
		}
		if v != "" && len(fd.Options) > 0 && !slices.Contains(fd.Options, v) {
			return httpx.BadRequest(name + ": invalid value for " + fd.Label)
		}
	}
	return nil
}

// cvssRiskKeys are the CVSS metric selections stored in the risk section.
var cvssRiskKeys = []string{"cvss_version", "AV", "AC", "AT", "PR", "UI", "S", "C", "I", "A", "VC", "VI", "VA", "SC", "SI", "SA", "E"}

func (req *assessmentRequest) validate() error {
	for k, v := range req.Answers {
		if !isQuestion(k) {
			return httpx.BadRequest("answers: unknown question " + k)
		}
		if v != "" && !slices.Contains(Answers, v) {
			return httpx.BadRequest("answers: use yes, no, unknown or not_applicable")
		}
	}
	riskFields := slices.Clone(RiskFields)
	for _, k := range cvssRiskKeys {
		riskFields = append(riskFields, Field{Key: k, Label: k})
	}
	for _, c := range []struct {
		name   string
		m      map[string]string
		fields []Field
		max    int
	}{
		{"fields", req.Fields, AssessmentFields, 20000},
		{"reproduction", req.Reproduction, ReproductionFields, 20000},
		{"risk", req.Risk, riskFields, 4000},
		{"remediation", req.Remediation, RemediationFields, 20000},
	} {
		if err := checkTextMap(c.name, c.m, c.fields, c.max); err != nil {
			return err
		}
	}
	if len(req.DataflowNotes) > 200 {
		return httpx.BadRequest("dataflow_notes: too many annotations")
	}
	for k, v := range req.DataflowNotes {
		if len(k) > 50 || len(v) > 4000 {
			return httpx.BadRequest("dataflow_notes: annotation too long")
		}
	}
	return nil
}

// saveAssessment merges the given sections into the current round's
// assessment. Only keys present in the request change; history records
// each changed value.
func (s *Service) saveAssessment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req assessmentRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := req.validate(); err != nil {
		s.fail(w, r, err)
		return
	}
	var out Assessment
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
		if err := ensureAssessment(ctx, tx, v); err != nil {
			return err
		}
		cur, err := loadAssessment(ctx, tx, v.ID, v.Round)
		if err != nil {
			return err
		}
		changed := 0
		merge := func(section string, dst map[string]any, src map[string]string) error {
			for k, nv := range src {
				nv = strings.TrimRight(nv, " \t\r\n")
				ov, _ := dst[k].(string)
				if ov == nv {
					continue
				}
				if nv == "" {
					delete(dst, k)
				} else {
					dst[k] = nv
				}
				changed++
				var old, new any
				if ov != "" {
					old = ov
				}
				if nv != "" {
					new = nv
				}
				if err := hist(ctx, tx, v, &p.UserID, "assessment.update", section+"."+k, old, new, ""); err != nil {
					return err
				}
			}
			return nil
		}
		for _, sec := range []struct {
			name string
			dst  map[string]any
			src  map[string]string
		}{
			{"answers", cur.Answers, req.Answers}, {"fields", cur.Fields, req.Fields}, {"reproduction", cur.Reproduction, req.Reproduction},
			{"risk", cur.Risk, req.Risk}, {"remediation", cur.Remediation, req.Remediation}, {"dataflow_notes", cur.DataflowNotes, req.DataflowNotes},
		} {
			if err := merge(sec.name, sec.dst, sec.src); err != nil {
				return err
			}
		}
		if changed > 0 {
			enc := func(m map[string]any) []byte { b, _ := json.Marshal(m); return b }
			if _, err := tx.Exec(ctx, `UPDATE human_review_assessments SET answers = $3, fields = $4, reproduction = $5, risk = $6, remediation = $7,
				dataflow_notes = $8, updated_by = $9, updated_at = now() WHERE review_id = $1 AND round = $2`,
				v.ID, v.Round, enc(cur.Answers), enc(cur.Fields), enc(cur.Reproduction), enc(cur.Risk), enc(cur.Remediation), enc(cur.DataflowNotes),
				p.UserID); err != nil {
				return err
			}
			if v.Status == StatusAssigned || v.Status == StatusPending || v.Status == StatusReopened {
				if _, err := tx.Exec(ctx, `UPDATE human_reviews SET status = 'in_progress', started_at = COALESCE(started_at, now()), updated_at = now() WHERE id = $1`, v.ID); err != nil {
					return err
				}
				if err := hist(ctx, tx, v, &p.UserID, "review.status", "status", v.Status, StatusInProgress, "assessment started"); err != nil {
					return err
				}
			} else if _, err := tx.Exec(ctx, `UPDATE human_reviews SET updated_at = now() WHERE id = $1`, v.ID); err != nil {
				return err
			}
			if req.AIRecommendationID != nil {
				var ok bool
				if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM human_review_recommendations WHERE id = $1 AND review_id = $2)`,
					*req.AIRecommendationID, v.ID).Scan(&ok); err != nil {
					return err
				}
				if !ok {
					return httpx.BadRequest("unknown AI recommendation")
				}
				if err := hist(ctx, tx, v, &p.UserID, "ai.suggestion_used", "ai_recommendation_id", nil, *req.AIRecommendationID,
					"the analyst copied an AI suggestion into the assessment"); err != nil {
					return err
				}
			}
			if err := s.audit(ctx, tx, p, "assessment_update", v, map[string]any{"changes": changed}); err != nil {
				return err
			}
		}
		out, err = loadAssessment(ctx, tx, v.ID, v.Round)
		return err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type severityRequest struct {
	Severity      string   `json:"severity"`
	CVSSVector    string   `json:"cvss_vector"`
	CVSSScore     *float64 `json:"cvss_score"`
	Justification string   `json:"justification"`
}

// setSeverity records the human-assessed severity. The scanner's severity
// and score are never modified; every override needs a justification.
func (s *Service) setSeverity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req severityRequest
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !slices.Contains(Severities, req.Severity) {
		s.fail(w, r, httpx.BadRequest("severity must be critical, high, medium, low or info"))
		return
	}
	just, err := trimmed(req.Justification, 4000)
	if err != nil || len(just) < 10 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "validation_failed", "a justification (at least 10 characters) is required for a severity assessment"))
		return
	}
	score := req.CVSSScore
	vector := strings.TrimSpace(req.CVSSVector)
	if vector != "" {
		c, err := ParseCVSS(vector)
		if err != nil {
			s.fail(w, r, httpx.BadRequest(err.Error()))
			return
		}
		if c.Score != nil {
			if score != nil && *score != *c.Score {
				s.fail(w, r, httpx.BadRequest("the CVSS score does not match the CVSS 3.x vector"))
				return
			}
			score = c.Score
		}
	}
	if score != nil && (*score < 0 || *score > 10) {
		s.fail(w, r, httpx.BadRequest("the CVSS score must be between 0.0 and 10.0"))
		return
	}
	if score != nil {
		x := float64(int(*score*10+0.5)) / 10
		score = &x
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
		var oldScore *float64
		var oldVector string
		if err := tx.QueryRow(ctx, `SELECT assessed_cvss::float8, assessed_cvss_vector FROM human_reviews WHERE id = $1`, v.ID).Scan(&oldScore, &oldVector); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE human_reviews SET assessed_severity = $2, assessed_cvss = $3, assessed_cvss_vector = $4,
			severity_justification = $5, updated_at = now() WHERE id = $1`, v.ID, req.Severity, score, vector, just); err != nil {
			return err
		}
		old := map[string]any{"severity": v.AssessedSeverity, "cvss": oldScore, "vector": oldVector}
		new := map[string]any{"severity": req.Severity, "cvss": score, "vector": vector}
		if err := hist(ctx, tx, v, &p.UserID, "severity.assessed", "assessed_severity", old, new, just); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "severity", v, map[string]any{"original": v.OriginalSeverity, "from": v.AssessedSeverity, "to": req.Severity,
			"cvss": score, "vector": vector, "justification": just})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.writeItem(w, r, id)
}

// --- comments ---------------------------------------------------------------

// Comment is one collaboration message.
type Comment struct {
	ID         uuid.UUID `json:"id"`
	AuthorID   uuid.UUID `json:"author_id"`
	AuthorName string    `json:"author_name"`
	Kind       string    `json:"kind"`
	Body       string    `json:"body"`
	CreatedAt  time.Time `json:"created_at"`
}

func insertComment(ctx context.Context, q db.Querier, v rec, author uuid.UUID, kind, body string) error {
	if _, err := q.Exec(ctx, `INSERT INTO human_review_comments (id, organization_id, review_id, author_id, kind, body) VALUES ($1, $2, $3, $4, $5, $6)`,
		uuid.Must(uuid.NewV7()), v.OrgID, v.ID, author, kind, body); err != nil {
		return err
	}
	return hist(ctx, q, v, &author, "comment.add", "", nil, nil, body)
}

func (s *Service) listComments(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.load(ctx, s.DB, p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT c.id, c.author_id, COALESCE(NULLIF(u.display_name, ''), u.email), c.kind, c.body, c.created_at
		FROM human_review_comments c JOIN users u ON u.id = c.author_id WHERE c.review_id = $1 ORDER BY c.created_at, c.id LIMIT 1000`, v.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, pgx.RowToStructByPos[Comment])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Comment{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

func (s *Service) addComment(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Body string `json:"body"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	body, err := trimmed(req.Body, 8000)
	if err != nil || body == "" {
		s.fail(w, r, httpx.BadRequest("a comment of 1-8000 characters is required"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		v, err := s.load(ctx, tx, p, id, false)
		if err != nil {
			return err
		}
		if !s.can(ctx, p, authz.PermReviewsAssess, v.RepoID) && !s.can(ctx, p, authz.PermReviewsAssign, v.RepoID) &&
			!s.can(ctx, p, authz.PermReviewsApprove, v.RepoID) {
			return authz.ErrForbidden
		}
		kind := "comment"
		if v.Status == StatusAwaitingIndependent && s.can(ctx, p, authz.PermReviewsApprove, v.RepoID) && (v.ReviewerID == nil || *v.ReviewerID != p.UserID) {
			kind = "independent"
		}
		if err := insertComment(ctx, tx, v, p.UserID, kind, body); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "comment", v, nil)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// --- history ----------------------------------------------------------------

// HistoryEntry is one immutable activity record.
type HistoryEntry struct {
	ID        uuid.UUID       `json:"id"`
	Round     int             `json:"round"`
	ActorID   *uuid.UUID      `json:"actor_id"`
	Actor     *string         `json:"actor"`
	Action    string          `json:"action"`
	Field     string          `json:"field"`
	OldValue  json.RawMessage `json:"old_value"`
	NewValue  json.RawMessage `json:"new_value"`
	Note      string          `json:"note"`
	ReviewID  uuid.UUID       `json:"review_id"`
	FindingID uuid.UUID       `json:"finding_id"`
	CreatedAt time.Time       `json:"created_at"`
}

func (s *Service) history(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	v, err := s.load(ctx, s.DB, p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	rows, err := s.DB.Query(ctx, `SELECT h.id, h.round, h.actor_id, COALESCE(NULLIF(u.display_name, ''), u.email), h.action, h.field,
		h.old_value, h.new_value, h.note, h.review_id, h.finding_id, h.created_at
		FROM human_review_history h LEFT JOIN users u ON u.id = h.actor_id WHERE h.review_id = $1 ORDER BY h.created_at, h.id LIMIT 5000`, v.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (HistoryEntry, error) {
		var e HistoryEntry
		var old, new []byte
		err := row.Scan(&e.ID, &e.Round, &e.ActorID, &e.Actor, &e.Action, &e.Field, &old, &new, &e.Note, &e.ReviewID, &e.FindingID, &e.CreatedAt)
		e.OldValue, e.NewValue = old, new
		if e.OldValue == nil {
			e.OldValue = json.RawMessage("null")
		}
		if e.NewValue == nil {
			e.NewValue = json.RawMessage("null")
		}
		return e, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []HistoryEntry{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}
