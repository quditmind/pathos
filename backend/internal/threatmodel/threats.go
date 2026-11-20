package threatmodel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/codegraph"
	"pathos/internal/featureflags"
	"pathos/internal/gates"
	"pathos/internal/platform/db"
	"pathos/internal/platform/httpx"
	"pathos/internal/threatmodel/frameworks"
)

func (s *Service) threats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.model(ctx, p, id, authz.PermThreatsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	q := r.URL.Query()
	f := ThreatFilter{Status: q.Get("status"), Category: q.Get("category"), Severity: q.Get("severity"), ChangeState: q.Get("change_state"), Method: q.Get("method")}
	for _, c := range []struct {
		v    string
		list []string
	}{{f.Status, Statuses}, {f.Category, append(slices.Clone(StrideCategories), LinddunCategories...)}, {f.Severity, Severities},
		{f.ChangeState, []string{"new", "changed", "unchanged", "resolved"}}, {f.Method, []string{MethodRule, MethodAttackPath, MethodManual, MethodImported, MethodAI}}} {
		if c.v != "" && !slices.Contains(c.list, c.v) {
			s.fail(w, r, httpx.BadRequest("unknown filter value "+c.v))
			return
		}
	}
	ts, err := listThreats(ctx, s.DB, m.ID, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if ts == nil {
		ts = []ThreatOut{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"items": ts})
}

// elementKeyRef names a CodeGraph element in a request.
type elementKeyRef struct {
	RepositoryID *uuid.UUID `json:"repository_id"`
	Key          string     `json:"key"`
}

type mappingRef struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
}

type addThreatRequest struct {
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Category    string          `json:"category"`
	Severity    string          `json:"severity"`
	Confidence  *float64        `json:"confidence"`
	Mitigation  string          `json:"mitigation"`
	ElementKeys []elementKeyRef `json:"element_keys"`
	FindingIDs  []uuid.UUID     `json:"finding_ids"`
	Mappings    []mappingRef    `json:"mappings"`
}

func evidenceErr(msg string) error {
	return httpx.E(http.StatusUnprocessableEntity, "threat_evidence_not_found", msg).WithDiag(CodeEvidence)
}

// resolvedEvidence is evidence a person linked.
type resolvedEvidence struct {
	nodes    []EvNode
	elements []ElementRef
	repos    []uuid.UUID
	findings []uuid.UUID
	evFind   []EvFinding
	snapshot string
}

// resolveEvidence checks CodeGraph keys against the latest ready snapshot
// of their repository (a repository of the model's application) and
// findings against the application's repositories.
func (s *Service) resolveEvidence(ctx context.Context, m Model, keys []elementKeyRef, findingIDs []uuid.UUID) (resolvedEvidence, error) {
	var out resolvedEvidence
	if len(keys) > 50 || len(findingIDs) > 50 {
		return out, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "link at most 50 elements and 50 findings at once")
	}
	if len(keys) > 0 {
		snaps, err := latestSnapshots(ctx, s.DB, m.orgID, m.ApplicationID, m.RepositoryID)
		if err != nil {
			return out, err
		}
		for _, k := range keys {
			k.Key = strings.TrimSpace(k.Key)
			var snap *snapshotInfo
			for i := range snaps {
				if (k.RepositoryID == nil && len(snaps) == 1) || (k.RepositoryID != nil && snaps[i].RepositoryID == *k.RepositoryID) {
					snap = &snaps[i]
					break
				}
			}
			if snap == nil {
				return out, evidenceErr("no ready CodeGraph snapshot of that repository in this application (give repository_id when the application has several)")
			}
			var n EvNode
			var id uuid.UUID
			err := s.DB.QueryRow(ctx, `SELECT id, node_key, type, label, file_path, COALESCE(start_line, 0) FROM codegraph_nodes
				WHERE snapshot_id = $1 AND node_key = $2`, snap.ID, k.Key).Scan(&id, &n.Key, &n.Type, &n.Label, &n.File, &n.Line)
			if errors.Is(err, pgx.ErrNoRows) {
				return out, evidenceErr(fmt.Sprintf("CodeGraph element %q is not in the latest snapshot of %s", clip(k.Key, 200), snap.RepositoryName))
			}
			if err != nil {
				return out, err
			}
			n.ID, n.RepositoryID = id.String(), snap.RepositoryID.String()
			out.nodes = append(out.nodes, n)
			out.repos = append(out.repos, snap.RepositoryID)
			out.snapshot = snap.ID.String()
			kind := KindProcess
			switch n.Type {
			case "datastore", "queue", "secret_ref":
				kind = KindDataStore
			case "external_service":
				kind = KindExternalEntity
			case "trust_boundary":
				kind = KindTrustBoundary
			}
			out.elements = append(out.elements, ElementRef{Kind: kind, Key: n.Key, Name: n.Label, NodeType: n.Type})
		}
	}
	for _, f := range findingIDs {
		var ef EvFinding
		var cwe []string
		err := s.DB.QueryRow(ctx, `SELECT f.title, f.severity, f.cwe FROM findings f JOIN repositories r ON r.id = f.repository_id
			WHERE f.organization_id = $1 AND f.id = $2 AND r.application_id = $3 AND ($4::uuid IS NULL OR r.id = $4)`,
			m.orgID, f, m.ApplicationID, m.RepositoryID).Scan(&ef.Title, &ef.Severity, &cwe)
		if errors.Is(err, pgx.ErrNoRows) {
			return out, evidenceErr("finding " + f.String() + " is not a finding of this application")
		}
		if err != nil {
			return out, err
		}
		ef.ID, ef.CWE = f.String(), firstCWE(cwe)
		out.findings = append(out.findings, f)
		out.evFind = append(out.evFind, ef)
	}
	return out, nil
}

func validMappings(in []mappingRef) ([]Mapping, error) {
	var out []Mapping
	for _, m := range in {
		if _, ok := frameworks.Lookup(m.Framework, m.ID); !ok {
			return nil, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", fmt.Sprintf("%s %s is not in the bundled framework data", m.Framework, m.ID))
		}
		out = append(out, Mapping{Framework: m.Framework, ID: m.ID, Source: "user"})
	}
	return out, nil
}

func validCategory(c string) bool {
	return slices.Contains(StrideCategories, c) || slices.Contains(LinddunCategories, c)
}

func (s *Service) addThreat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in addThreatRequest
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	in.Title = strings.TrimSpace(in.Title)
	switch {
	case in.Title == "" || len(in.Title) > 300:
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "title must be 1 to 300 characters")
	case !validCategory(in.Category):
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "category must be a STRIDE or LINDDUN category")
	case !slices.Contains(Severities, in.Severity):
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "severity must be critical, high, medium, low or info")
	case in.Confidence != nil && (*in.Confidence <= 0 || *in.Confidence > 1):
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "confidence must be above 0 and at most 1")
	case len(in.Description) > 8000 || len(in.Mitigation) > 8000:
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "description and mitigation are at most 8000 characters")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	maps, err := validMappings(in.Mappings)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.draftFor(ctx, p, id)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	ev, err := s.resolveEvidence(ctx, m, in.ElementKeys, in.FindingIDs)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	conf := 0.5
	if in.Confidence != nil {
		conf = *in.Confidence
	}
	evType := EvidenceUnverified
	if len(ev.nodes) > 0 || len(ev.findings) > 0 {
		evType = EvidenceVerified
	}
	name := firstNonEmpty(p.DisplayName, p.Email)
	row := threatRow{Title: in.Title, Description: in.Description, Category: in.Category, Method: MethodManual, EvidenceType: evType,
		Evidence: Evidence{SnapshotID: ev.snapshot, Nodes: ev.nodes, Findings: ev.evFind}, Severity: in.Severity,
		SeverityReason: "set by " + name + " (manual threat)", SeverityOverridden: true, Confidence: conf,
		ConfidenceReason: "set by " + name + " (manual threat)", Mitigation: strings.TrimSpace(in.Mitigation),
		MitigationEdited: true, CreatedBy: &p.UserID}
	var tid uuid.UUID
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		var err error
		if tid, err = insertThreat(ctx, tx, m.orgID, m.ID, row); err != nil {
			return err
		}
		var els []uuid.UUID
		for i, e := range ev.elements {
			r := ev.repos[i]
			eid, err := upsertElement(ctx, tx, m.orgID, m.ID, &r, e, map[string]any{"linked": true})
			if err != nil {
				return err
			}
			els = append(els, eid)
		}
		if err := linkElements(ctx, tx, m.orgID, tid, els, false); err != nil {
			return err
		}
		if err := linkFindings(ctx, tx, m.orgID, tid, ev.findings, "user", false); err != nil {
			return err
		}
		if err := setMappings(ctx, tx, m.orgID, tid, maps); err != nil {
			return err
		}
		if err := addEvent(ctx, tx, m.orgID, tid, "created", "", "manual", "", &p.UserID); err != nil {
			return err
		}
		return s.audit(ctx, tx, r, p, "threat_model.threat.create", m, map[string]any{"threat_id": tid, "title": in.Title})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, err := getThreat(ctx, s.DB, p.OrganizationID, tid)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, t)
}

// threatFor loads a threat and its model with perm.
func (s *Service) threatFor(ctx context.Context, p *authz.Principal, r *http.Request, perm authz.Permission) (ThreatOut, Model, error) {
	id, err := pathUUID(r, "id")
	if err != nil {
		return ThreatOut{}, Model{}, err
	}
	t, err := getThreat(ctx, s.DB, p.OrganizationID, id)
	if err != nil {
		return t, Model{}, err
	}
	m, err := s.model(ctx, p, t.ThreatModelID, perm)
	return t, m, err
}

func (s *Service) getThreat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, _, err := s.threatFor(ctx, p, r, authz.PermThreatsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	evs, err := threatEvents(ctx, s.DB, t.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	items, err := s.remediationItems(ctx, p, t.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"threat": t, "events": evs, "remediation_items": items})
}

// RemediationRef is a remediation item that mitigates a threat (PATHOS
// 3.0 M9 link; the item side is internal/remediation).
type RemediationRef struct {
	ID       uuid.UUID `json:"id"`
	Title    string    `json:"title"`
	Status   string    `json:"status"`
	Priority string    `json:"priority"`
}

// remediationItems lists the items linked to a threat that the caller may
// read; empty without the remediation workspace or remediation.read.
func (s *Service) remediationItems(ctx context.Context, p *authz.Principal, threatID uuid.UUID) ([]RemediationRef, error) {
	out := []RemediationRef{}
	if !p.HasAnywhere(authz.PermRemediationRead) {
		return out, nil
	}
	if on, err := featureflags.Enabled(ctx, s.DB, p.OrganizationID, gates.Flag); err != nil || !on {
		return out, err
	}
	args := []any{p.OrganizationID, threatID}
	vis, vargs := gates.VisibilitySQL(p, authz.PermRemediationRead, "i.application_id", len(args)+1)
	// #nosec G202 -- vis is built from placeholders
	rows, err := s.DB.Query(ctx, `SELECT i.id, i.title, i.status, i.priority FROM remediation_items i LEFT JOIN repositories r ON r.id = i.repository_id
		WHERE i.organization_id = $1 AND i.threat_id = $2 AND `+vis+` ORDER BY i.created_at`, append(args, vargs...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var x RemediationRef
		if err := rows.Scan(&x.ID, &x.Title, &x.Status, &x.Priority); err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

type linkRequest struct {
	ElementKeys []elementKeyRef `json:"element_keys"`
	FindingIDs  []uuid.UUID     `json:"finding_ids"`
}

type patchThreatRequest struct {
	Title          *string      `json:"title"`
	Description    *string      `json:"description"`
	Severity       *string      `json:"severity"`
	Status         *string      `json:"status"`
	Reason         string       `json:"reason"`
	Mitigation     *string      `json:"mitigation"`
	OwnerID        *uuid.UUID   `json:"owner_id"`
	ClearOwner     bool         `json:"clear_owner"`
	Link           *linkRequest `json:"link"`
	UnlinkFindings []uuid.UUID  `json:"unlink_findings"`
	MappingsAdd    []mappingRef `json:"mappings_add"`
	MappingsRemove []mappingRef `json:"mappings_remove"`
}

func (s *Service) patchThreat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var in patchThreatRequest
	if err := httpx.DecodeJSON(w, r, &in); err != nil {
		s.fail(w, r, err)
		return
	}
	reason := strings.TrimSpace(in.Reason)
	switch {
	case in.Severity != nil && !slices.Contains(Severities, *in.Severity):
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "severity must be critical, high, medium, low or info")
	case in.Status != nil && !slices.Contains(Statuses, *in.Status):
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "status must be open, mitigated, accepted or not_applicable")
	case (in.Severity != nil || in.Status != nil) && reason == "":
		err = httpx.E(http.StatusUnprocessableEntity, "threat_reason_required", "give the reason for the severity or status change").WithDiag(CodeReason)
	case len(reason) > 2000:
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "reason is at most 2000 characters")
	case in.Mitigation != nil && len(*in.Mitigation) > 8000, in.Description != nil && len(*in.Description) > 8000:
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "mitigation and description are at most 8000 characters")
	case in.Title != nil && (strings.TrimSpace(*in.Title) == "" || len(*in.Title) > 300):
		err = httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "title must be 1 to 300 characters")
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	add, err := validMappings(in.MappingsAdd)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, m, err := s.threatFor(ctx, p, r, authz.PermThreatsManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if m.Status != "draft" {
		s.fail(w, r, stateErr("version is "+strings.ReplaceAll(m.Status, "_", " ")+"; only threats of a draft can be changed"))
		return
	}
	generatedThreat := t.Method == MethodRule || t.Method == MethodAttackPath
	if generatedThreat && (in.Title != nil || in.Description != nil) {
		s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid",
			"a generated threat keeps its rule's title and description; change its severity, status or mitigation"))
		return
	}
	var ev resolvedEvidence
	if in.Link != nil {
		if ev, err = s.resolveEvidence(ctx, m, in.Link.ElementKeys, in.Link.FindingIDs); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if in.OwnerID != nil {
		var ok bool
		if err := s.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users WHERE organization_id = $1 AND id = $2)`, p.OrganizationID, *in.OwnerID).Scan(&ok); err != nil || !ok {
			s.fail(w, r, httpx.E(http.StatusUnprocessableEntity, "threat_model_invalid", "owner_id is not a user of the organization"))
			return
		}
	}
	org, actor := m.orgID, &p.UserID
	name := firstNonEmpty(p.DisplayName, p.Email)
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		changes := map[string]any{}
		if in.Title != nil && strings.TrimSpace(*in.Title) != t.Title {
			if _, err := tx.Exec(ctx, `UPDATE threats SET title = $2, updated_at = now() WHERE id = $1`, t.ID, strings.TrimSpace(*in.Title)); err != nil {
				return err
			}
			changes["title"] = true
			if err := addEvent(ctx, tx, org, t.ID, "edited", t.Title, strings.TrimSpace(*in.Title), reason, actor); err != nil {
				return err
			}
		}
		if in.Description != nil && *in.Description != t.Description {
			if _, err := tx.Exec(ctx, `UPDATE threats SET description = $2, updated_at = now() WHERE id = $1`, t.ID, *in.Description); err != nil {
				return err
			}
			changes["description"] = true
		}
		if in.Severity != nil && *in.Severity != t.Severity {
			if _, err := tx.Exec(ctx, `UPDATE threats SET severity = $2, severity_reason = $3, severity_overridden = true, updated_at = now() WHERE id = $1`,
				t.ID, *in.Severity, clip("changed by "+name+": "+reason+" (was "+t.Severity+")", 2000)); err != nil {
				return err
			}
			changes["severity"] = *in.Severity
			if err := addEvent(ctx, tx, org, t.ID, "severity_changed", t.Severity, *in.Severity, reason, actor); err != nil {
				return err
			}
		}
		if in.Status != nil && *in.Status != t.Status {
			if _, err := tx.Exec(ctx, `UPDATE threats SET status = $2, status_reason = $3, updated_at = now() WHERE id = $1`, t.ID, *in.Status, reason); err != nil {
				return err
			}
			changes["status"] = *in.Status
			if err := addEvent(ctx, tx, org, t.ID, "status_changed", t.Status, *in.Status, reason, actor); err != nil {
				return err
			}
		}
		if in.Mitigation != nil && strings.TrimSpace(*in.Mitigation) != t.Mitigation {
			if _, err := tx.Exec(ctx, `UPDATE threats SET mitigation = $2, mitigation_edited = true, updated_at = now() WHERE id = $1`,
				t.ID, strings.TrimSpace(*in.Mitigation)); err != nil {
				return err
			}
			changes["mitigation"] = true
			if err := addEvent(ctx, tx, org, t.ID, "mitigation_changed", clip(t.Mitigation, 500), clip(strings.TrimSpace(*in.Mitigation), 500), reason, actor); err != nil {
				return err
			}
		}
		if in.OwnerID != nil || in.ClearOwner {
			if _, err := tx.Exec(ctx, `UPDATE threats SET owner_id = $2, updated_at = now() WHERE id = $1`, t.ID, in.OwnerID); err != nil {
				return err
			}
			changes["owner"] = in.OwnerID
		}
		if in.Link != nil && (len(ev.nodes) > 0 || len(ev.findings) > 0) {
			cur := t.Evidence
			for _, n := range ev.nodes {
				cur.Nodes = appendNode(cur.Nodes, n)
			}
			cur.Findings = append(cur.Findings, ev.evFind...)
			if cur.SnapshotID == "" {
				cur.SnapshotID = ev.snapshot
			}
			b, _ := json.Marshal(cur)
			// Linking evidence verifies a manual or imported threat.
			if _, err := tx.Exec(ctx, `UPDATE threats SET evidence = $2, evidence_type = CASE WHEN evidence_type = 'unverified' THEN 'verified' ELSE evidence_type END,
				updated_at = now() WHERE id = $1`, t.ID, b); err != nil {
				return err
			}
			var els []uuid.UUID
			for i, e := range ev.elements {
				r := ev.repos[i]
				eid, err := upsertElement(ctx, tx, org, m.ID, &r, e, map[string]any{"linked": true})
				if err != nil {
					return err
				}
				els = append(els, eid)
			}
			if err := linkElements(ctx, tx, org, t.ID, els, false); err != nil {
				return err
			}
			if err := linkFindings(ctx, tx, org, t.ID, ev.findings, "user", false); err != nil {
				return err
			}
			var what []string
			for _, n := range ev.nodes {
				what = append(what, n.Key)
			}
			for _, f := range ev.findings {
				what = append(what, "finding "+f.String())
			}
			changes["linked"] = what
			if err := addEvent(ctx, tx, org, t.ID, "linked", t.EvidenceType, strings.Join(what, ", "), reason, actor); err != nil {
				return err
			}
		}
		if len(in.UnlinkFindings) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM threat_findings WHERE threat_id = $1 AND finding_id = ANY($2) AND source = 'user'`, t.ID, in.UnlinkFindings); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, org, t.ID, "unlinked", "", fmt.Sprint(in.UnlinkFindings), reason, actor); err != nil {
				return err
			}
		}
		if len(add) > 0 {
			if err := setMappings(ctx, tx, org, t.ID, add); err != nil {
				return err
			}
			for _, a := range add {
				if err := addEvent(ctx, tx, org, t.ID, "mapping_added", "", a.Framework+" "+a.ID, reason, actor); err != nil {
					return err
				}
			}
		}
		for _, rm := range in.MappingsRemove {
			if _, err := tx.Exec(ctx, `DELETE FROM threat_framework_mappings WHERE threat_id = $1 AND framework = $2 AND entry_id = $3`, t.ID, rm.Framework, rm.ID); err != nil {
				return err
			}
			if err := addEvent(ctx, tx, org, t.ID, "mapping_removed", rm.Framework+" "+rm.ID, "", reason, actor); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE threat_models SET updated_at = now() WHERE id = $1`, m.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, r, p, "threat_model.threat.update", m, map[string]any{"threat_id": t.ID, "changes": changes, "reason": reason})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	out, err := getThreat(ctx, s.DB, p.OrganizationID, t.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) deleteThreat(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	t, m, err := s.threatFor(ctx, p, r, authz.PermThreatsManage)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if t.Method == MethodRule || t.Method == MethodAttackPath {
		s.fail(w, r, httpx.E(http.StatusConflict, "threat_generated", "a generated threat comes back at the next generation; set it not applicable with a reason instead").WithDiag(CodeGenerated))
		return
	}
	if m.Status != "draft" {
		s.fail(w, r, stateErr("only threats of a draft can be deleted"))
		return
	}
	err = db.InTx(ctx, s.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM threats WHERE id = $1`, t.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, r, p, "threat_model.threat.delete", m, map[string]any{"threat_id": t.ID, "title": t.Title})
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// --- diagram ---------------------------------------------------------------------

// DiagramNode and DiagramEdge follow the CodeGraph engine ↔ UI contract
// (the shared graph component).
type DiagramNode struct {
	ID            string         `json:"id"`
	Type          string         `json:"type"`
	Label         string         `json:"label"`
	Layer         string         `json:"layer"`
	Attrs         map[string]any `json:"attrs"`
	FindingCounts map[string]int `json:"finding_counts"`
}

// DiagramEdge is a data flow.
type DiagramEdge struct {
	ID           string `json:"id"`
	Source       string `json:"source"`
	Target       string `json:"target"`
	Type         string `json:"type"`
	Evidence     string `json:"evidence"`
	EvidenceRefs []Ref  `json:"evidence_refs"`
}

var kindNodeType = map[string]string{KindProcess: "container", KindDataStore: "datastore", KindExternalEntity: "external_service", KindTrustBoundary: "trust_boundary"}

var nodeLayer = map[string]string{"route": "api", "api_operation": "api", "function": "code", "class": "code", "file": "code", "datastore": "data",
	"queue": "data", "secret_ref": "data", "external_service": "deploy", "container": "deploy", "iac_resource": "deploy", "trust_boundary": "deploy",
	"component": "dependency", "repository": "ownership", "application": "ownership", "module": "code"}

func (s *Service) diagram(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, err := s.caller(r)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	id, err := pathUUID(r, "id")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	m, err := s.model(ctx, p, id, authz.PermThreatsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	els, err := listElements(ctx, s.DB, m.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	counts := map[uuid.UUID]map[string]int{}
	total := map[uuid.UUID]int{}
	rows, err := s.DB.Query(ctx, `SELECT te.element_id, t.severity, count(*) FROM threat_elements te JOIN threats t ON t.id = te.threat_id
		WHERE t.threat_model_id = $1 AND t.status IN ('open', 'accepted') GROUP BY 1, 2`, m.ID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	for rows.Next() {
		var eid uuid.UUID
		var sev string
		var n int
		if err := rows.Scan(&eid, &sev, &n); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		if counts[eid] == nil {
			counts[eid] = map[string]int{}
		}
		counts[eid][sev] += n
		total[eid] += n
	}
	rows.Close()
	nodes := []DiagramNode{}
	edges := []DiagramEdge{}
	unverified := []ElementOut{}
	byKey := map[string]string{}
	for _, e := range els {
		if e.Kind == KindDataFlow {
			continue
		}
		typ := e.NodeType
		if !slices.Contains(codegraph.NodeTypes, typ) {
			typ = kindNodeType[e.Kind]
		}
		attrs := map[string]any{"element_id": e.ID, "codegraph_key": e.CodegraphKey, "dfd_kind": e.Kind, "threats": total[e.ID]}
		if e.RepositoryID != nil {
			attrs["repository_id"] = *e.RepositoryID
		}
		fc := counts[e.ID]
		if fc == nil {
			fc = map[string]int{}
		}
		nodes = append(nodes, DiagramNode{ID: e.ID.String(), Type: typ, Label: e.Name, Layer: nodeLayer[typ], Attrs: attrs, FindingCounts: fc})
		byKey[e.ElementKey] = e.ID.String()
	}
	for _, e := range els {
		if e.Kind != KindDataFlow {
			continue
		}
		src, ok1 := byKey[elementKey(e.RepositoryID, e.SourceKey)]
		dst, ok2 := byKey[elementKey(e.RepositoryID, e.TargetKey)]
		evType, _ := e.Attrs["evidence"].(string)
		var refs []Ref
		if raw, ok := e.Attrs["refs"]; ok {
			b, _ := json.Marshal(raw)
			_ = json.Unmarshal(b, &refs)
		}
		typ := e.NodeType
		// Only flows with CodeGraph evidence are drawn (rule 5); imported
		// flows without evidence are listed separately.
		if !ok1 || !ok2 || len(refs) == 0 || (evType != EvidenceVerified && evType != EvidenceObserved) || !slices.Contains(codegraph.EdgeTypes, typ) {
			unverified = append(unverified, e)
			continue
		}
		edges = append(edges, DiagramEdge{ID: e.ID.String(), Source: src, Target: dst, Type: typ, Evidence: evType, EvidenceRefs: refs})
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"nodes": nodes, "edges": edges, "truncated": false, "unverified_flows": unverified})
}
