package threatmodel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
	"pathos/internal/platform/db"
	"pathos/internal/posture"
)

// Engines a generation can run.
var Engines = []string{"stride", "attack_paths"}

// snapshotInfo is a CodeGraph snapshot used by a generation.
type snapshotInfo struct {
	ID             uuid.UUID `json:"id"`
	RepositoryID   uuid.UUID `json:"repository_id"`
	RepositoryName string    `json:"repository_name"`
	CommitSHA      string    `json:"commit_sha"`
	Status         string    `json:"status"`
	exposure       string
}

var errNoSnapshot = errors.New("no ready CodeGraph snapshot")

// latestSnapshots returns the newest readable snapshot of each repository
// of the application (or of the given repository).
func latestSnapshots(ctx context.Context, q db.Querier, orgID, appID uuid.UUID, repoID *uuid.UUID) ([]snapshotInfo, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT ON (s.repository_id) s.id, s.repository_id, COALESCE(NULLIF(r.display_name, ''), r.full_name),
		s.commit_sha, s.status, r.public_exposure
		FROM codegraph_snapshots s JOIN repositories r ON r.id = s.repository_id
		WHERE s.organization_id = $1 AND s.application_id = $2 AND ($3::uuid IS NULL OR s.repository_id = $3)
		  AND r.archived_at IS NULL AND r.application_id = $2 AND s.status IN ('ready', 'partial') AND s.storage = 'rows'
		ORDER BY s.repository_id, s.created_at DESC, s.id DESC`, orgID, appID, repoID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (snapshotInfo, error) {
		var s snapshotInfo
		err := r.Scan(&s.ID, &s.RepositoryID, &s.RepositoryName, &s.CommitSHA, &s.Status, &s.exposure)
		return s, err
	})
}

// loadGraph reads a snapshot into the engine's graph (modules, the
// repository and containment-only edges are left out).
func loadGraph(ctx context.Context, q db.Querier, s snapshotInfo) (*Graph, error) {
	g := &Graph{SnapshotID: s.ID.String(), RepositoryID: s.RepositoryID.String(), RepositoryName: s.RepositoryName,
		Partial: s.Status == "partial", PublicExposure: s.exposure}
	rows, err := q.Query(ctx, `SELECT id, node_key, type, label, file_path, COALESCE(start_line, 0), attrs, finding_counts
		FROM codegraph_nodes WHERE snapshot_id = $1 AND type NOT IN ('module', 'repository', 'application')`, s.ID)
	if err != nil {
		return nil, err
	}
	keyOf := map[uuid.UUID]string{}
	for rows.Next() {
		var n Node
		var id uuid.UUID
		var attrs, counts []byte
		if err := rows.Scan(&id, &n.Key, &n.Type, &n.Label, &n.File, &n.Line, &attrs, &counts); err != nil {
			rows.Close()
			return nil, err
		}
		n.ID = id.String()
		_ = json.Unmarshal(attrs, &n.Attrs)
		_ = json.Unmarshal(counts, &n.Findings)
		keyOf[id] = n.Key
		g.Nodes = append(g.Nodes, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = q.Query(ctx, `SELECT id, edge_key, source_id, target_id, type, evidence FROM codegraph_edges
		WHERE snapshot_id = $1 AND type NOT IN ('defines', 'owns')`, s.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var e Edge
		var id, src, dst uuid.UUID
		if err := rows.Scan(&id, &e.Key, &src, &dst, &e.Type, &e.Evidence); err != nil {
			return nil, err
		}
		var ok1, ok2 bool
		e.ID = id.String()
		e.Source, ok1 = keyOf[src]
		e.Target, ok2 = keyOf[dst]
		if ok1 && ok2 {
			g.Edges = append(g.Edges, e)
		}
	}
	return g, rows.Err()
}

// fillRefs attaches up to three evidence references to every edge used as
// evidence by the threats.
func fillRefs(ctx context.Context, q db.Querier, threats []Threat) error {
	var ids []uuid.UUID
	for _, t := range threats {
		for _, e := range t.Evidence.Edges {
			if id, err := uuid.Parse(e.ID); err == nil {
				ids = append(ids, id)
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT edge_id, kind, ref, detail FROM (
		SELECT edge_id, kind, ref, detail, row_number() OVER (PARTITION BY edge_id ORDER BY evidence, id) AS n
		FROM codegraph_evidence WHERE edge_id = ANY($1)) x WHERE n <= 3 ORDER BY edge_id, n`, uniqueUUIDs(ids))
	if err != nil {
		return err
	}
	defer rows.Close()
	refs := map[string][]Ref{}
	for rows.Next() {
		var id uuid.UUID
		var r Ref
		if err := rows.Scan(&id, &r.Kind, &r.Ref, &r.Detail); err != nil {
			return err
		}
		refs[id.String()] = append(refs[id.String()], r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range threats {
		for j := range threats[i].Evidence.Edges {
			e := &threats[i].Evidence.Edges[j]
			e.Refs = refs[e.ID]
			if e.Refs == nil {
				e.Refs = []Ref{}
			}
		}
	}
	return nil
}

// flowRefs loads one evidence reference per data-flow element (diagram).
func flowRefs(ctx context.Context, q db.Querier, els []ElementRef) error {
	var ids []uuid.UUID
	for _, e := range els {
		if id, err := uuid.Parse(e.EdgeID); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT DISTINCT ON (edge_id) edge_id, kind, ref, detail FROM codegraph_evidence WHERE edge_id = ANY($1)
		ORDER BY edge_id, evidence, id`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	refs := map[string]Ref{}
	for rows.Next() {
		var id uuid.UUID
		var r Ref
		if err := rows.Scan(&id, &r.Kind, &r.Ref, &r.Detail); err != nil {
			return err
		}
		refs[id.String()] = r
	}
	for i := range els {
		if r, ok := refs[els[i].EdgeID]; ok {
			els[i].Refs = []Ref{r}
		}
	}
	return rows.Err()
}

// openFinding is an open finding of a repository, for linking.
type openFinding struct {
	ID       uuid.UUID
	Title    string
	Severity string
	File     string
	Line     int
	CWE      []string
}

// linkRuleFindings links the open findings located in the evidence nodes
// of each rule threat (file, and line within the node's span) and adds
// their CWE ids as mappings.
func linkRuleFindings(ctx context.Context, q db.Querier, g *Graph, threats []Threat) error {
	files := map[string]bool{}
	for _, t := range threats {
		for _, n := range t.Evidence.Nodes {
			if n.File != "" {
				files[n.File] = true
			}
		}
	}
	if len(files) == 0 {
		return nil
	}
	list := make([]string, 0, len(files))
	for f := range files {
		list = append(list, f)
	}
	repo, err := uuid.Parse(g.RepositoryID)
	if err != nil {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT id, title, severity, file_path, COALESCE(start_line, 0), cwe FROM findings
		WHERE repository_id = $1 AND file_path = ANY($2) AND status IN ('open', 'in_progress', 'needs_review')
		ORDER BY array_position(ARRAY['critical', 'high', 'medium', 'low', 'info'], severity), id LIMIT 2000`, repo, list)
	if err != nil {
		return err
	}
	fs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (openFinding, error) {
		var f openFinding
		err := r.Scan(&f.ID, &f.Title, &f.Severity, &f.File, &f.Line, &f.CWE)
		return f, err
	})
	if err != nil {
		return err
	}
	g.Index()
	for i := range threats {
		t := &threats[i]
		for _, en := range t.Evidence.Nodes {
			n, ok := g.node(en.Key)
			if !ok || n.File == "" {
				continue
			}
			end := attrInt(n, "end_line")
			for _, f := range fs {
				if f.File != n.File || len(t.FindingIDs) >= 10 || slices.Contains(t.FindingIDs, f.ID.String()) {
					continue
				}
				// Functions and routes: the finding's line is within the node.
				if (n.Type == "function" || n.Type == "class") && n.Line > 0 && (f.Line < n.Line || (end > 0 && f.Line > end)) {
					continue
				}
				if n.Type == "route" && f.Line != n.Line {
					continue
				}
				t.FindingIDs = append(t.FindingIDs, f.ID.String())
				t.Evidence.Findings = append(t.Evidence.Findings, EvFinding{ID: f.ID.String(), Title: f.Title, Severity: f.Severity, CWE: firstCWE(f.CWE)})
				for _, c := range f.CWE {
					if id := NormalizeCWE(c); id != "" {
						t.Mappings = append(t.Mappings, Mapping{Framework: "cwe", ID: id, Source: "finding"})
					}
				}
			}
		}
	}
	return nil
}

func attrInt(n *Node, k string) int {
	switch v := n.Attrs[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		i, _ := strconv.Atoi(v)
		return i
	}
	return 0
}

// nodeForFile is the innermost function (else the file node) holding a
// finding's location.
func nodeForFile(g *Graph, file string, line int) *Node {
	if file == "" {
		return nil
	}
	var best *Node
	span := 1 << 30
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.File != file || (n.Type != "function" && n.Type != "class") || n.Line == 0 {
			continue
		}
		end := attrInt(n, "end_line")
		if line < n.Line || (end > 0 && line > end) {
			continue
		}
		if s := end - n.Line; s < span {
			best, span = n, s
		}
	}
	if best != nil {
		return best
	}
	if n, ok := g.node("file:" + file); ok {
		return n
	}
	return nil
}

// GenResult summarises a generation.
type GenResult struct {
	New            int  `json:"new"`
	Changed        int  `json:"changed"`
	Unchanged      int  `json:"unchanged"`
	Resolved       int  `json:"resolved"`
	CreatedVersion bool `json:"created_version"`
}

type generated struct {
	threats   []Threat
	elements  map[uuid.UUID][]ElementRef // by repository
	snapshots []snapshotInfo
	notes     []string
	rules     map[string]int
}

// compute runs the engines for a model. p is the caller (nil: a system
// update, which reads attack paths organization-wide).
func compute(ctx context.Context, q db.Querier, m Model, p *authz.Principal, engines []string) (*generated, error) {
	snaps, err := latestSnapshots(ctx, q, m.orgID, m.ApplicationID, m.RepositoryID)
	if err != nil {
		return nil, err
	}
	if len(snaps) == 0 {
		return nil, errNoSnapshot
	}
	out := &generated{elements: map[uuid.UUID][]ElementRef{}, snapshots: snaps, rules: map[string]int{}}
	graphs := map[uuid.UUID]*Graph{}
	for _, s := range snaps {
		g, err := loadGraph(ctx, q, s)
		if err != nil {
			return nil, err
		}
		g.ApplicationID = m.ApplicationID.String()
		graphs[s.RepositoryID] = g
		res := Generate(g)
		if err := flowRefs(ctx, q, res.Elements); err != nil {
			return nil, err
		}
		out.elements[s.RepositoryID] = res.Elements
		for _, n := range res.Notes {
			out.notes = append(out.notes, s.RepositoryName+": "+n)
		}
		if !slices.Contains(engines, "stride") {
			continue
		}
		if err := fillRefs(ctx, q, res.Threats); err != nil {
			return nil, err
		}
		if err := linkRuleFindings(ctx, q, g, res.Threats); err != nil {
			return nil, err
		}
		for i := range res.Threats {
			res.Threats[i].Evidence.Links = append(res.Threats[i].Evidence.Links,
				Link{Label: "Open in CodeGraph", Href: "/codegraph/" + m.ApplicationID.String() + "?snapshot=" + s.ID.String()})
		}
		out.threats = append(out.threats, res.Threats...)
		for k, v := range res.RuleCounts {
			out.rules[k] += v
		}
	}
	if slices.Contains(engines, "attack_paths") {
		if p == nil {
			p = &authz.Principal{OrganizationID: m.orgID, Grants: []authz.Grant{{Permission: authz.PermFindingsRead,
				Scope: authz.Scope{Type: authz.ScopeOrganization, ID: m.orgID}}}}
		}
		paths, _, err := posture.QueryAttackPaths(ctx, q, p, posture.AttackPathQuery{MinRisk: 50, Limit: 200, ApplicationID: &m.ApplicationID, RepositoryID: m.RepositoryID})
		if err != nil && !errors.Is(err, authz.ErrForbidden) {
			return nil, err
		}
		for _, a := range paths {
			key, lbl, typ := "", "", ""
			if g := graphs[a.RepositoryID]; g != nil {
				g.Index()
				if n := nodeForFile(g, a.FilePath, a.Line); n != nil {
					key, lbl, typ = n.Key, n.Label, n.Type
				}
			}
			t := FromAttackPath(a, key, lbl, typ)
			if g := graphs[a.RepositoryID]; g != nil {
				t.Evidence.SnapshotID = g.SnapshotID
				if n, ok := g.node(key); ok {
					t.Evidence.Nodes[0].ID = n.ID
				}
			}
			out.threats = append(out.threats, t)
			out.rules[AttackPathRule.ID]++
			if key == "" {
				key, lbl, typ = "repository", "repository", "repository"
			}
			out.elements[a.RepositoryID] = append(out.elements[a.RepositoryID], ElementRef{Kind: KindProcess, Key: key, Name: lbl, NodeType: typ})
		}
		if len(paths) == 0 {
			out.notes = append(out.notes, "No attack path (internet → … → open finding with risk ≥ 50) for this application.")
		}
	}
	sort.SliceStable(out.threats, func(i, j int) bool { return out.threats[i].Fingerprint < out.threats[j].Fingerprint })
	return out, nil
}

type existingThreat struct {
	id                                uuid.UUID
	method, changeState, hash         string
	severityOverridden, mitigationEdt bool
}

// apply merges a generation into a draft model inside tx, keeping every
// human edit (status and its reason, owner, an overridden severity, an
// edited mitigation; manual and imported threats are never touched).
func apply(ctx context.Context, tx pgx.Tx, m Model, gen *generated, engines []string, actor *uuid.UUID) (GenResult, error) {
	var res GenResult
	org := m.orgID
	// Elements.
	elementIDs := map[string]uuid.UUID{}
	keep := map[string]bool{}
	for repo, els := range gen.elements {
		r := repo
		for _, e := range els {
			ek := elementKey(&r, e.Key)
			if keep[ek] {
				continue
			}
			keep[ek] = true
			attrs := map[string]any{"generated": true}
			if e.Kind == KindDataFlow {
				attrs["evidence"], attrs["refs"] = e.Evidence, e.Refs
			}
			id, err := upsertElement(ctx, tx, org, m.ID, &r, e, attrs)
			if err != nil {
				return res, err
			}
			elementIDs[ek] = id
		}
	}
	// Existing generated threats.
	rows, err := tx.Query(ctx, `SELECT id, fingerprint, method, change_state, evidence_hash, severity_overridden, mitigation_edited
		FROM threats WHERE threat_model_id = $1 AND fingerprint <> '' FOR UPDATE`, m.ID)
	if err != nil {
		return res, err
	}
	existing := map[string]existingThreat{}
	for rows.Next() {
		var fp string
		var x existingThreat
		if err := rows.Scan(&x.id, &fp, &x.method, &x.changeState, &x.hash, &x.severityOverridden, &x.mitigationEdt); err != nil {
			rows.Close()
			return res, err
		}
		existing[fp] = x
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return res, err
	}
	seen := map[string]bool{}
	for _, t := range gen.threats {
		if seen[t.Fingerprint] {
			continue
		}
		seen[t.Fingerprint] = true
		repo, _ := uuid.Parse(t.Evidence.RepositoryID)
		var els []uuid.UUID
		for _, e := range t.Elements {
			ek := elementKey(&repo, e.Key)
			id, ok := elementIDs[ek]
			if !ok {
				r := repo
				id, err = upsertElement(ctx, tx, org, m.ID, &r, e, map[string]any{"generated": true})
				if err != nil {
					return res, err
				}
				elementIDs[ek], keep[ek] = id, true
			}
			els = append(els, id)
		}
		var findings []uuid.UUID
		for _, f := range t.FindingIDs {
			if id, err := uuid.Parse(f); err == nil {
				findings = append(findings, id)
			}
		}
		hash := t.Evidence.Hash()
		x, ok := existing[t.Fingerprint]
		var tid uuid.UUID
		if ok {
			tid = x.id
			state := "unchanged"
			if x.hash != hash || x.changeState == "resolved" {
				state = "changed"
			}
			ev, _ := json.Marshal(t.Evidence)
			if _, err := tx.Exec(ctx, `UPDATE threats SET title = $2, description = $3, category = $4, rule_id = $5, rule_version = $6,
				evidence_type = $7, evidence = $8, confidence = $9, confidence_reason = $10, evidence_hash = $11, change_state = $12,
				severity = CASE WHEN severity_overridden THEN severity ELSE $13 END,
				severity_reason = CASE WHEN severity_overridden THEN severity_reason ELSE $14 END,
				mitigation = CASE WHEN mitigation_edited THEN mitigation ELSE $15 END, updated_at = now()
				WHERE id = $1`, tid, clip(t.Title, 300), clip(t.Description, 8000), t.Category, t.RuleID, t.RuleVersion, t.EvidenceType, ev,
				t.Confidence, clip(t.ConfidenceReason, 2000), hash, state, t.Severity, clip(t.SeverityReason, 2000), clip(t.Mitigation, 8000)); err != nil {
				return res, err
			}
			if state == "changed" {
				res.Changed++
				if err := addEvent(ctx, tx, org, tid, "regenerated", x.changeState, "changed", "", actor); err != nil {
					return res, err
				}
			} else {
				res.Unchanged++
			}
		} else {
			tid, err = insertThreat(ctx, tx, org, m.ID, threatRow{Fingerprint: t.Fingerprint, Title: t.Title, Description: t.Description,
				Category: t.Category, Method: t.Method, RuleID: t.RuleID, RuleVersion: t.RuleVersion, EvidenceType: t.EvidenceType,
				Evidence: t.Evidence, Severity: t.Severity, SeverityReason: t.SeverityReason, Confidence: t.Confidence,
				ConfidenceReason: t.ConfidenceReason, Mitigation: t.Mitigation, ChangeState: "new", CreatedBy: actor})
			if err != nil {
				return res, err
			}
			res.New++
			if err := addEvent(ctx, tx, org, tid, "created", "", t.RuleID+" v"+t.RuleVersion, "", actor); err != nil {
				return res, err
			}
		}
		if err := linkElements(ctx, tx, org, tid, els, true); err != nil {
			return res, err
		}
		if err := setMappings(ctx, tx, org, tid, t.Mappings, "rule", "finding"); err != nil {
			return res, err
		}
		if err := linkFindings(ctx, tx, org, tid, findings, "generated", true); err != nil {
			return res, err
		}
	}
	// Generated threats not found again: resolved (only for the engines run).
	for fp, x := range existing {
		if seen[fp] || x.changeState == "resolved" {
			continue
		}
		if (x.method == MethodRule && !slices.Contains(engines, "stride")) || (x.method == MethodAttackPath && !slices.Contains(engines, "attack_paths")) {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE threats SET change_state = 'resolved', updated_at = now() WHERE id = $1`, x.id); err != nil {
			return res, err
		}
		if err := addEvent(ctx, tx, org, x.id, "regenerated", x.changeState, "resolved", "", actor); err != nil {
			return res, err
		}
		res.Resolved++
	}
	// Generated elements no longer in the graph and not used by a threat.
	if _, err := tx.Exec(ctx, `DELETE FROM threat_model_elements e WHERE e.threat_model_id = $1 AND e.attrs ? 'generated'
		AND NOT (e.element_key = ANY($2)) AND NOT EXISTS (SELECT 1 FROM threat_elements te WHERE te.element_id = e.id)`, m.ID, keys(keep)); err != nil {
		return res, err
	}
	snapIDs := make([]uuid.UUID, len(gen.snapshots))
	for i, s := range gen.snapshots {
		snapIDs[i] = s.ID
	}
	rules := []map[string]any{}
	for _, r := range append(slices.Clone(Rules), AttackPathRule) {
		if n := gen.rules[r.ID]; n > 0 {
			rules = append(rules, map[string]any{"id": r.ID, "version": r.Version, "threats": n})
		}
	}
	genJSON, _ := json.Marshal(map[string]any{"engines": engines, "rules": rules, "snapshots": gen.snapshots, "notes": gen.notes,
		"counts": map[string]int{"new": res.New, "changed": res.Changed, "unchanged": res.Unchanged, "resolved": res.Resolved},
		"at":     time.Now().UTC()})
	method := m.Method
	if method == MethodManual {
		method = "stride"
	}
	if _, err := tx.Exec(ctx, `UPDATE threat_models SET codegraph_snapshot_ids = $2, generated_at = now(), generation = $3, method = $4, updated_at = now()
		WHERE id = $1`, m.ID, snapIDs, genJSON, method); err != nil {
		return res, err
	}
	return res, nil
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ErrGenerate wraps a storage failure of a generation (PTH-TM-1010).
type ErrGenerate struct{ Err error }

func (e *ErrGenerate) Error() string {
	return fmt.Sprintf("threat generation could not be stored: %v", e.Err)
}
func (e *ErrGenerate) Unwrap() error { return e.Err }
