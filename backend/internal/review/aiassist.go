package review

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/ai"
	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
	"pathos/internal/repos"
)

// Recommendation is a stored AI suggestion. It is advisory only.
type Recommendation struct {
	ID              uuid.UUID       `json:"id"`
	Kind            string          `json:"kind"`
	Provider        string          `json:"provider"`
	Model           string          `json:"model"`
	Content         json.RawMessage `json:"content"`
	TransmittedSHA  string          `json:"transmitted_sha256"`
	RequestedBy     uuid.UUID       `json:"requested_by"`
	RequestedByName string          `json:"requested_by_name"`
	CreatedAt       time.Time       `json:"created_at"`
	Label           string          `json:"label"`
	// Patch proposals carry a human decision; they are never applied.
	PatchStatus    *string    `json:"patch_status,omitempty"`
	PatchDecidedBy *string    `json:"patch_decided_by,omitempty"`
	PatchDecidedAt *time.Time `json:"patch_decided_at,omitempty"`
	PatchNote      string     `json:"patch_note,omitempty"`
}

// aiDailyLimitPerUser bounds interactive suggestions.
const aiDailyLimitPerUser = 200

func (s *Service) listRecommendations(w http.ResponseWriter, r *http.Request) {
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
	rows, err := s.DB.Query(ctx, `SELECT x.id, x.kind, x.provider, x.model, x.content, x.transmitted_sha256, x.requested_by,
		COALESCE(NULLIF(u.display_name, ''), u.email), x.created_at, 'AI suggestion', x.patch_status,
		COALESCE(NULLIF(du.display_name, ''), du.email), x.patch_decided_at, x.patch_note
		FROM human_review_recommendations x JOIN users u ON u.id = x.requested_by LEFT JOIN users du ON du.id = x.patch_decided_by
		WHERE x.review_id = $1 ORDER BY x.created_at DESC LIMIT 200`, v.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Recommendation, error) {
		var x Recommendation
		var content []byte
		err := row.Scan(&x.ID, &x.Kind, &x.Provider, &x.Model, &content, &x.TransmittedSHA, &x.RequestedBy, &x.RequestedByName, &x.CreatedAt, &x.Label,
			&x.PatchStatus, &x.PatchDecidedBy, &x.PatchDecidedAt, &x.PatchNote)
		x.Content = content
		return x, err
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if out == nil {
		out = []Recommendation{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out})
}

// requestRecommendation asks the configured AI provider for a suggestion.
// The response is stored for traceability and returned; it never changes
// the review, the finding or any decision.
func (s *Service) requestRecommendation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var req struct {
		Kind string `json:"kind"`
	}
	if err := httpx.DecodeJSON(w, r, &req); err != nil {
		s.fail(w, r, err)
		return
	}
	if !slices.Contains(AIKinds, req.Kind) {
		s.fail(w, r, httpx.BadRequest("unknown assistance kind"))
		return
	}
	v, err := s.load(ctx, s.DB, p, id, false)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !s.can(ctx, p, authz.PermReviewsAssess, v.RepoID) && !s.can(ctx, p, authz.PermReviewsApprove, v.RepoID) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	st, err := loadSettings(ctx, s.DB, p.OrganizationID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !st.AIAssist {
		s.fail(w, r, httpx.E(http.StatusConflict, "ai_disabled", "AI assistance is disabled in Review Configurations"))
		return
	}
	if s.AI == nil {
		s.fail(w, r, httpx.E(http.StatusServiceUnavailable, "ai_unavailable", "AI assistance is not available in this deployment"))
		return
	}
	var used int
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM human_review_recommendations WHERE requested_by = $1 AND created_at > now() - interval '24 hours'`,
		p.UserID).Scan(&used); err != nil {
		s.fail(w, r, err)
		return
	}
	if used >= aiDailyLimitPerUser {
		s.fail(w, r, httpx.E(http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("the limit of %d AI suggestions per day was reached", aiDailyLimitPerUser)).WithDiag("PTH-AI-1008"))
		return
	}
	ev, _, err := ai.LoadEvidence(ctx, s.DB, p.OrganizationID, v.FindingID, st.AISendCode)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	in := ai.AssistInput{Evidence: ev}
	if st.AISendCode && s.Source != nil && v.FilePath != "" && v.Category != "secrets" {
		if b, _, err := s.Source.ReadSourceFile(ctx, p.OrganizationID, v.RepoID, repos.SourceRef{Commit: v.CommitSHA, SnapshotID: v.SnapshotID}, v.FilePath); err == nil {
			in.SourceExcerpt = excerpt(string(b), v.StartLine, 60)
		}
	}
	if df, err := s.buildDataFlow(ctx, v); err == nil && len(df.Paths) > 0 {
		var b strings.Builder
		for i, fp := range df.Paths {
			fmt.Fprintf(&b, "Path %d (%s):\n", i+1, fp.Status)
			for _, n := range fp.Nodes {
				fmt.Fprintf(&b, "  [%s] %s:%d %s\n", n.Role, n.FilePath, n.Line, n.Message)
			}
		}
		in.DataFlow = b.String()
	}
	switch req.Kind {
	case "patch":
		if in.SourceExcerpt == "" {
			s.fail(w, r, httpx.E(http.StatusConflict, "source_required",
				"patch proposals need the source code: allow sending code to AI in Review Configurations (and in the AI configuration)"))
			return
		}
	case "risk_explanation":
		var score *float64
		var factors []byte
		if err := s.DB.QueryRow(ctx, `SELECT risk_score::float8, COALESCE(risk_factors, '{}'::jsonb) FROM findings WHERE id = $1`, v.FindingID).
			Scan(&score, &factors); err != nil {
			s.fail(w, r, err)
			return
		}
		if score == nil {
			s.fail(w, r, httpx.E(http.StatusConflict, "not_scored", "the finding has no contextual risk score yet"))
			return
		}
		var f map[string]any
		_ = json.Unmarshal(factors, &f)
		in.RiskScore = map[string]any{"score": *score, "details": f}
	case "duplicate_candidates":
		cands, err := duplicateCandidates(ctx, s.DB, v.FindingID)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		if len(cands) == 0 {
			s.fail(w, r, httpx.E(http.StatusConflict, "no_candidates", "no other finding in the repository is close enough to compare"))
			return
		}
		in.Candidates = cands
	}
	if req.Kind == "assessment_summary" || req.Kind == "false_positive_indicators" {
		a, err := loadAssessment(ctx, s.DB, v.ID, v.Round)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		in.Assessment = map[string]any{"answers": a.Answers, "fields": a.Fields, "reproduction": a.Reproduction, "risk": a.Risk,
			"assessed_severity": v.AssessedSeverity, "status": v.Status}
	}
	fid, hid := v.FindingID, v.ID
	actx := ai.WithSubject(ctx, ai.Subject{Kind: "human_review", ID: &hid, FindingID: &fid, RequestedBy: &p.UserID,
		Related: map[string]any{"findings": []string{fid.String()}, "human_review": v.Key}})
	res, err := s.AI.Assist(actx, p.OrganizationID, req.Kind, in, st.AISendCode)
	if err != nil {
		switch {
		case errors.Is(err, ai.ErrNotConfigured):
			s.fail(w, r, httpx.E(http.StatusConflict, "ai_not_configured", "No AI provider is configured: an administrator must add one under AI settings"))
		case errors.Is(err, ai.ErrRateLimited):
			s.fail(w, r, httpx.E(http.StatusTooManyRequests, "rate_limited", "the AI provider rate limit was reached; try again later").WithDiag("PTH-AI-1004"))
		case errors.Is(err, ai.ErrRefused):
			s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "ai_refused", "the AI provider declined this request"))
		default:
			s.Log.Warn("ai assist failed", "review", v.Key, "err", err)
			s.fail(w, r, httpx.E(http.StatusBadGateway, "ai_failed", "the AI provider did not return a usable suggestion"))
		}
		return
	}
	var patchStatus *string
	if req.Kind == "patch" && res.Output.Code != "" {
		if err := ValidatePatch(res.Output.Code, v.FilePath); err != nil {
			s.Log.Warn("ai patch rejected", "review", v.Key, "err", err)
			s.fail(w, r, httpx.E(http.StatusBadGateway, "invalid_patch", "the AI did not return a usable patch: "+err.Error()))
			return
		}
		st := "proposed"
		patchStatus = &st
	}
	content, _ := json.Marshal(res.Output)
	rid := uuid.Must(uuid.NewV7())
	if _, err := s.DB.Exec(ctx, `INSERT INTO human_review_recommendations (id, organization_id, review_id, kind, provider, model, config_version_id,
		content, transmitted_sha256, input_tokens, output_tokens, requested_by, patch_status, evidence_record_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		rid, v.OrgID, v.ID, req.Kind, res.Provider, res.Model, res.ConfigVersionID, content, res.SHA256, res.InputTokens, res.OutputTokens, p.UserID,
		patchStatus, res.EvidenceID); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = hist(ctx, s.DB, v, &p.UserID, "ai.suggestion", "ai_recommendation_id", nil, rid, "AI suggestion requested: "+req.Kind)
	_ = s.audit(ctx, s.DB, p, "ai_suggestion", v, map[string]any{"kind": req.Kind, "recommendation_id": rid, "model": res.Model,
		"transmitted_sha256": res.SHA256})
	httpx.WriteJSON(w, http.StatusCreated, Recommendation{ID: rid, Kind: req.Kind, Provider: res.Provider, Model: res.Model, Content: content,
		TransmittedSHA: res.SHA256, RequestedBy: p.UserID, RequestedByName: p.DisplayName, CreatedAt: time.Now(), Label: "AI suggestion",
		PatchStatus: patchStatus})
}

// excerpt returns up to ±radius numbered lines around line.
func excerpt(src string, line *int, radius int) string {
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	center := 1
	if line != nil && *line > 0 {
		center = *line
	}
	from, to := max(1, center-radius), min(len(lines), center+radius)
	var b strings.Builder
	for i := from; i <= to; i++ {
		fmt.Fprintf(&b, "%d: %s\n", i, lines[i-1])
	}
	return b.String()
}
