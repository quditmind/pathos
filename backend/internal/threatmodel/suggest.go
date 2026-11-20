package threatmodel

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/ai"
	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
)

// AI threat suggestions (PATHOS 3.0 M7): the reserved AI path of M5.
// POST /api/v1/threat-models/{id}/suggest adds AI-inferred threats to a
// draft, each with its own AI evidence record (method 'ai', evidence type
// 'ai_inferred'). A suggestion stays a proposal until a person accepts it
// (POST /api/v1/ai/evidence/{id}/review); a rejected one is removed from
// the draft; the version cannot be submitted while any is pending.

// CodeAIPending is the error code of a submission blocked by pending
// AI suggestions; CodeNoDiagram of a suggestion request on an empty model.
const (
	CodeAIPending = "PTH-AI-1302"
	CodeNoDiagram = "PTH-AI-1301"
)

// ThreatSuggester is the AI service's threat-suggestion call.
type ThreatSuggester interface {
	SuggestThreats(ctx context.Context, orgID uuid.UUID, in ai.ThreatSuggestInput) (ai.ThreatSuggestResult, error)
}

type suggestRequest struct {
	MaxThreats int `json:"max_threats"`
}

func (s *Service) suggest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err == nil {
		err = featureflags.Require(ctx, s.DB, p.OrganizationID, ai.FlagIntelligence)
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in suggestRequest
	if r.ContentLength != 0 {
		if err := httpx.DecodeJSON(w, r, &in); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if in.MaxThreats < 0 || in.MaxThreats > 20 {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "max_threats must be between 1 and 20"))
		return
	}
	m, err := s.draftFor(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !p.HasAnywhere(authz.PermAIReview) {
		s.fail(w, r, authz.ErrForbidden)
		return
	}
	if s.AI == nil {
		s.fail(w, r, httpx.E(http.StatusServiceUnavailable, "ai_unavailable", "AI is not available on this server").WithDiag("PTH-AI-1007"))
		return
	}
	els, keys, err := modelElements(ctx, s.DB, m.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if len(els) == 0 {
		s.fail(w, r, httpx.E(http.StatusConflict, "threat_model_no_diagram",
			"the draft has no diagram elements: generate it from CodeGraph or add threats linked to CodeGraph elements first").WithDiag(CodeNoDiagram))
		return
	}
	existing := []string{}
	ts, err := listThreats(ctx, s.DB, m.ID, ThreatFilter{})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for _, t := range ts {
		existing = append(existing, t.Title)
	}
	snaps := []string{}
	for _, sid := range m.CodegraphSnapshotIDs {
		snaps = append(snaps, sid.String())
	}
	res, err := s.AI.SuggestThreats(ctx, p.OrganizationID, ai.ThreatSuggestInput{ModelID: m.ID, Application: m.ApplicationName, Elements: els,
		Existing: existing, Categories: append(slices.Clone(StrideCategories), LinddunCategories...), MaxThreats: in.MaxThreats,
		RequestedBy: &p.UserID, SnapshotIDs: snaps, ElementByKey: keys})
	if err != nil {
		code := ai.DiagCode(err)
		switch {
		case errors.Is(err, ai.ErrNotConfigured):
			err = httpx.E(http.StatusConflict, "ai_not_configured", "no AI configuration: an administrator must add a provider and a configuration").WithDiag(code)
		case errors.Is(err, ai.ErrCodeNotAllowed):
			err = httpx.E(http.StatusConflict, "ai_code_not_allowed", err.Error()).WithDiag(ai.CodeCodeNotAllowed)
		case errors.Is(err, ai.ErrRateLimited):
			err = httpx.E(http.StatusTooManyRequests, "rate_limited", "the AI provider rate limit was reached; try again later").WithDiag(code)
		default:
			s.Log.Warn("threat suggestion failed", "threat_model_id", m.ID, "err", err, "error_code", code)
			err = httpx.E(http.StatusBadGateway, "ai_failed", "the AI provider did not return usable threat suggestions").WithDiag(code)
		}
		s.fail(w, r, err)
		return
	}
	elemIDs := map[string]uuid.UUID{}
	rows, err := s.DB.Query(ctx, `SELECT element_key, id FROM threat_model_elements WHERE threat_model_id = $1`, m.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for rows.Next() {
		var k string
		var eid uuid.UUID
		if rows.Scan(&k, &eid) == nil {
			elemIDs[k] = eid
		}
	}
	rows.Close()
	var ids []uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		for _, t := range res.Threats {
			ev := t.EvidenceID
			row := threatRow{Title: t.Title, Description: t.Description, Category: t.Category, Method: MethodAI, EvidenceType: EvidenceAIInferred,
				Evidence: Evidence{}, Severity: t.Severity, SeverityReason: "AI-suggested (" + res.Model + "); awaiting a person's acceptance",
				Confidence: t.Confidence, ConfidenceReason: "the model's own confidence (AI-inferred)", Mitigation: t.Mitigation,
				CreatedBy: &p.UserID, AIEvidenceID: &ev}
			tid, err := insertThreat(ctx, tx, m.orgID, m.ID, row)
			if err != nil {
				return err
			}
			var link []uuid.UUID
			for _, k := range t.ElementKeys {
				if eid, ok := elemIDs[k]; ok {
					link = append(link, eid)
				}
			}
			if err := linkElements(ctx, tx, m.orgID, tid, link, false); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, m.orgID, tid, "created", "", "ai", "AI suggestion "+ev.String(), &p.UserID); err != nil {
				return err
			}
			ids = append(ids, tid)
		}
		return s.audit(ctx, tx, r, p, "threat_model.ai_suggest", m, map[string]any{"evidence_record_id": res.EvidenceID, "suggested": len(ids),
			"dropped": res.Dropped, "model": res.Model, "provider": res.Provider})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out := []ThreatOut{}
	if len(ids) > 0 {
		if out, err = listThreats(ctx, s.DB, m.ID, ThreatFilter{IDs: ids}); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": out, "evidence_record_id": res.EvidenceID, "dropped": res.Dropped,
		"model": res.Model, "label": "AI-inferred", "note": strconv.Itoa(len(out)) + " AI-inferred threat(s) added to the draft; each needs a person's acceptance"})
}

// modelElements returns the draft's diagram as the model sees it.
func modelElements(ctx context.Context, q db.Querier, modelID uuid.UUID) ([]ai.ThreatElement, map[string]bool, error) {
	rows, err := q.Query(ctx, `SELECT element_key, kind, name, node_type, source_key, target_key FROM threat_model_elements
		WHERE threat_model_id = $1 ORDER BY kind, element_key LIMIT 400`, modelID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []ai.ThreatElement
	keys := map[string]bool{}
	for rows.Next() {
		var e ai.ThreatElement
		if err := rows.Scan(&e.Key, &e.Kind, &e.Name, &e.NodeType, &e.Source, &e.Target); err != nil {
			return nil, nil, err
		}
		out = append(out, e)
		keys[e.Key] = true
	}
	return out, keys, rows.Err()
}

// EvidenceAccess lets the AI evidence log check threat-model subjects with
// this module's scope rules (threats.read, or threats.manage to act).
func (s *Service) EvidenceAccess(ctx context.Context, p *authz.Principal, subjectID uuid.UUID, manage bool) error {
	if on, err := featureflags.Enabled(ctx, s.DB, p.OrganizationID, flagName); err != nil || !on {
		return errNotFound
	}
	perm := authz.PermThreatsRead
	if manage {
		perm = authz.PermThreatsManage
	}
	// The subject is a model version or a threat.
	var modelID uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT id FROM threat_models WHERE organization_id = $1 AND id = $2
		UNION ALL SELECT threat_model_id FROM threats WHERE organization_id = $1 AND id = $2 LIMIT 1`, p.OrganizationID, subjectID).Scan(&modelID); err != nil {
		return errNotFound
	}
	_, err := s.model(ctx, p, modelID, perm)
	return err
}

// ReviewSuggestion applies a person's decision on an AI-suggested threat
// (inside the transaction that records it): accepted keeps the threat in
// the draft; rejected removes it. Only a draft can change.
func (s *Service) ReviewSuggestion(ctx context.Context, tx pgx.Tx, p *authz.Principal, rec ai.EvidenceRecord, accept bool, note string) error {
	var tid, modelID uuid.UUID
	var status string
	err := tx.QueryRow(ctx, `SELECT t.id, t.threat_model_id, m.status FROM threats t JOIN threat_models m ON m.id = t.threat_model_id
		WHERE t.organization_id = $1 AND t.ai_evidence_id = $2 AND t.method = 'ai'
		ORDER BY m.version DESC LIMIT 1 FOR UPDATE OF t`, p.OrganizationID, rec.ID).Scan(&tid, &modelID, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		// The threat was removed meanwhile: the decision is still recorded.
		return nil
	}
	if err != nil {
		return err
	}
	if status != "draft" {
		return stateErr("the threat's model version is " + status + "; decide AI suggestions on the draft")
	}
	if accept {
		return addEvent(ctx, tx, p.OrganizationID, tid, "ai_accepted", "pending", "accepted", note, &p.UserID)
	}
	_, err = tx.Exec(ctx, `DELETE FROM threats WHERE id = $1`, tid)
	return err
}
