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
		COALESCE(NULLIF(u.display_name, ''), u.email), x.created_at, 'AI suggestion'
		FROM human_review_recommendations x JOIN users u ON u.id = x.requested_by WHERE x.review_id = $1 ORDER BY x.created_at DESC LIMIT 200`, v.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (Recommendation, error) {
		var x Recommendation
		var content []byte
		err := row.Scan(&x.ID, &x.Kind, &x.Provider, &x.Model, &content, &x.TransmittedSHA, &x.RequestedBy, &x.RequestedByName, &x.CreatedAt, &x.Label)
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
		s.fail(w, r, httpx.E(http.StatusTooManyRequests, "rate_limited", fmt.Sprintf("the limit of %d AI suggestions per day was reached", aiDailyLimitPerUser)))
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
	if req.Kind == "assessment_summary" || req.Kind == "false_positive_indicators" {
		a, err := loadAssessment(ctx, s.DB, v.ID, v.Round)
		if err != nil {
			s.fail(w, r, err)
			return
		}
		in.Assessment = map[string]any{"answers": a.Answers, "fields": a.Fields, "reproduction": a.Reproduction, "risk": a.Risk,
			"assessed_severity": v.AssessedSeverity, "status": v.Status}
	}
	res, err := s.AI.Assist(ctx, p.OrganizationID, req.Kind, in, st.AISendCode)
	if err != nil {
		switch {
		case errors.Is(err, ai.ErrNotConfigured):
			s.fail(w, r, httpx.E(http.StatusConflict, "ai_not_configured", "No AI provider is configured: an administrator must add one under AI settings"))
		case errors.Is(err, ai.ErrRateLimited):
			s.fail(w, r, httpx.E(http.StatusTooManyRequests, "rate_limited", "the AI provider rate limit was reached; try again later"))
		case errors.Is(err, ai.ErrRefused):
			s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "ai_refused", "the AI provider declined this request"))
		default:
			s.Log.Warn("ai assist failed", "review", v.Key, "err", err)
			s.fail(w, r, httpx.E(http.StatusBadGateway, "ai_failed", "the AI provider did not return a usable suggestion"))
		}
		return
	}
	content, _ := json.Marshal(res.Output)
	rid := uuid.Must(uuid.NewV7())
	if _, err := s.DB.Exec(ctx, `INSERT INTO human_review_recommendations (id, organization_id, review_id, kind, provider, model, config_version_id,
		content, transmitted_sha256, input_tokens, output_tokens, requested_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		rid, v.OrgID, v.ID, req.Kind, res.Provider, res.Model, res.ConfigVersionID, content, res.SHA256, res.InputTokens, res.OutputTokens, p.UserID); err != nil {
		s.fail(w, r, err)
		return
	}
	_ = hist(ctx, s.DB, v, &p.UserID, "ai.suggestion", "ai_recommendation_id", nil, rid, "AI suggestion requested: "+req.Kind)
	_ = s.audit(ctx, s.DB, p, "ai_suggestion", v, map[string]any{"kind": req.Kind, "recommendation_id": rid, "model": res.Model,
		"transmitted_sha256": res.SHA256})
	httpx.WriteJSON(w, http.StatusCreated, Recommendation{ID: rid, Kind: req.Kind, Provider: res.Provider, Model: res.Model, Content: content,
		TransmittedSHA: res.SHA256, RequestedBy: p.UserID, RequestedByName: p.DisplayName, CreatedAt: time.Now(), Label: "AI suggestion"})
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
