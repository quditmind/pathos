// Package correlation joins a finding to the other phases of the
// lifecycle (PATHOS 3.0 M7): the CodeGraph elements at its location, the
// threat-model threats linked to it, the SBOM components of its package,
// its runtime context and related findings. The join is deterministic
// (SQL over stored facts, no AI); each item carries its rule 5 evidence
// label. The AI may then explain and prioritise the correlation
// (POST .../correlation/explain), with an AI evidence record; its
// conclusion is AI-inferred and only proposes: no finding is suppressed or
// closed by it (a person decides in triage or Human Eye).
package correlation

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"pathos/internal/ai"
	"pathos/internal/audit"
	"pathos/internal/authz"
	"pathos/internal/featureflags"
	"pathos/internal/org"
	"pathos/internal/platform/httpx"
)

// Explainer is the AI service's correlation call.
type Explainer interface {
	ExplainCorrelation(ctx context.Context, orgID, findingID uuid.UUID, by *uuid.UUID, correlation any, related map[string]any) (ai.CorrelationResult, error)
}

// Service serves the correlation API (ai_intelligence flag).
type Service struct {
	DB        *pgxpool.Pool
	Authz     *authz.Authorizer
	Log       *slog.Logger
	Principal func(context.Context) *authz.Principal
	AI        Explainer
	// ThreatAccess checks read access to a threat model (threat module).
	ThreatAccess func(ctx context.Context, p *authz.Principal, modelID uuid.UUID, manage bool) error
}

// Register mounts the API.
func (s *Service) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/findings/{id}/correlation", s.get)
	mux.HandleFunc("POST /api/v1/findings/{id}/correlation/explain", s.explain)
}

var errNotFound = errors.New("not found")

func (s *Service) fail(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		err = httpx.ErrForbidden
	case errors.Is(err, errNotFound), errors.Is(err, pgx.ErrNoRows), errors.Is(err, org.ErrScopeNotFound):
		err = httpx.ErrNotFound
	}
	httpx.WriteError(w, r, s.Log, err)
}

// Labels (rule 5).
const (
	Verified = "verified"
	Observed = "observed"
)

// FindingRef is the finding being correlated.
type FindingRef struct {
	ID          uuid.UUID `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	Category    string    `json:"category"`
	RuleID      string    `json:"rule_id"`
	CWE         []string  `json:"cwe"`
	CVE         string    `json:"cve"`
	FilePath    string    `json:"file_path"`
	StartLine   *int      `json:"start_line"`
	PackageName string    `json:"package_name"`
	PackageVer  string    `json:"package_version"`
	repoID      uuid.UUID
	appID       *uuid.UUID
}

// Node is a CodeGraph element at the finding.
type Node struct {
	Key       string `json:"key"`
	Type      string `json:"type"`
	Label     string `json:"label"`
	FilePath  string `json:"file_path"`
	StartLine *int   `json:"start_line"`
	EndLine   *int   `json:"end_line"`
	// Match: location (file and line range) or component (package name).
	Match    string `json:"match"`
	Evidence string `json:"evidence"`
}

// Edge is a CodeGraph edge touching a matched node.
type Edge struct {
	Key      string `json:"key"`
	Type     string `json:"type"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Evidence string `json:"evidence"`
}

// Graph is the CodeGraph part.
type Graph struct {
	SnapshotID *uuid.UUID `json:"snapshot_id"`
	Status     string     `json:"snapshot_status"`
	Nodes      []Node     `json:"nodes"`
	Edges      []Edge     `json:"edges"`
	Note       string     `json:"note,omitempty"`
}

// Threat is a threat-model threat linked to the finding.
type Threat struct {
	ID            uuid.UUID `json:"id"`
	ThreatModelID uuid.UUID `json:"threat_model_id"`
	ModelStatus   string    `json:"model_status"`
	ModelVersion  int       `json:"model_version"`
	Title         string    `json:"title"`
	Category      string    `json:"category"`
	Severity      string    `json:"severity"`
	Status        string    `json:"status"`
	// Link: finding (the threat names this finding) or element (the
	// threat affects a CodeGraph element at the finding).
	Link     string `json:"link"`
	Evidence string `json:"evidence"`
}

// Component is an SBOM component of the finding's package.
type Component struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Purl     string   `json:"purl"`
	Type     string   `json:"type"`
	Licenses []string `json:"licenses"`
	Evidence string   `json:"evidence"`
}

// Runtime is the finding's runtime context.
type Runtime struct {
	Status     string          `json:"status"`
	Exposed    bool            `json:"exposed"`
	Privileged bool            `json:"privileged"`
	Alert      bool            `json:"alert"`
	Context    json.RawMessage `json:"context"`
	Evidence   string          `json:"evidence"`
}

// RelatedFinding is a finding at the same place or of the same CVE.
type RelatedFinding struct {
	ID       uuid.UUID `json:"id"`
	Relation string    `json:"relation"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	Status   string    `json:"status"`
	Evidence string    `json:"evidence"`
}

// Correlation is the deterministic join.
type Correlation struct {
	Finding       FindingRef       `json:"finding"`
	Deterministic bool             `json:"deterministic"`
	CodeGraph     *Graph           `json:"codegraph"`
	Threats       []Threat         `json:"threats"`
	ThreatsNote   string           `json:"threats_note,omitempty"`
	Components    []Component      `json:"components"`
	Runtime       *Runtime         `json:"runtime"`
	Related       []RelatedFinding `json:"related_findings"`
}

func (s *Service) caller(r *http.Request, perm authz.Permission) (*authz.Principal, FindingRef, error) {
	ctx := r.Context()
	p := s.Principal(ctx)
	if p == nil {
		return nil, FindingRef{}, httpx.ErrUnauthenticated
	}
	if err := featureflags.Require(ctx, s.DB, p.OrganizationID, ai.FlagIntelligence); err != nil {
		return nil, FindingRef{}, err
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		return nil, FindingRef{}, errNotFound
	}
	var f FindingRef
	err = s.DB.QueryRow(ctx, `SELECT f.id, f.title, f.severity, f.status, f.category, f.rule_id, f.cwe, f.cve, f.file_path, f.start_line,
		f.package_name, f.package_version, f.repository_id, r.application_id
		FROM findings f JOIN repositories r ON r.id = f.repository_id WHERE f.organization_id = $1 AND f.id = $2`, p.OrganizationID, id).
		Scan(&f.ID, &f.Title, &f.Severity, &f.Status, &f.Category, &f.RuleID, &f.CWE, &f.CVE, &f.FilePath, &f.StartLine,
			&f.PackageName, &f.PackageVer, &f.repoID, &f.appID)
	if err != nil {
		return nil, f, errNotFound
	}
	for _, pm := range []authz.Permission{authz.PermFindingsRead, perm} {
		err := s.Authz.Require(ctx, p, pm, authz.Scope{Type: authz.ScopeRepository, ID: f.repoID})
		if errors.Is(err, org.ErrScopeNotFound) || (errors.Is(err, authz.ErrForbidden) && p.HasAnywhere(pm)) {
			return nil, f, errNotFound
		}
		if err != nil {
			return nil, f, err
		}
	}
	if f.CWE == nil {
		f.CWE = []string{}
	}
	return p, f, nil
}

// Build joins the finding to the other phases.
func (s *Service) Build(ctx context.Context, p *authz.Principal, f FindingRef) (Correlation, error) {
	c := Correlation{Finding: f, Deterministic: true, Threats: []Threat{}, Components: []Component{}, Related: []RelatedFinding{}}
	// CodeGraph: the latest ready snapshot of the repository; the
	// elements whose file and line range hold the finding, or the
	// component of its package.
	if on, _ := featureflags.Enabled(ctx, s.DB, p.OrganizationID, "codegraph"); on {
		g := &Graph{Nodes: []Node{}, Edges: []Edge{}}
		var sid uuid.UUID
		err := s.DB.QueryRow(ctx, `SELECT id, status FROM codegraph_snapshots WHERE organization_id = $1 AND repository_id = $2
			AND status IN ('ready', 'partial') AND storage = 'rows' AND kind = 'source' ORDER BY created_at DESC LIMIT 1`, p.OrganizationID, f.repoID).Scan(&sid, &g.Status)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			g.Note = "the repository has no ready CodeGraph snapshot"
		case err != nil:
			return c, err
		default:
			g.SnapshotID = &sid
			rows, err := s.DB.Query(ctx, `SELECT id, node_key, type, label, file_path, start_line, end_line,
				CASE WHEN type = 'component' THEN 'component' ELSE 'location' END FROM codegraph_nodes
				WHERE snapshot_id = $1 AND (
					($2 <> '' AND type = 'component' AND (lower(label) = lower($2) OR lower(attrs->>'name') = lower($2)))
					OR ($3 <> '' AND file_path = $3 AND (type = 'file'
						OR ($4::int IS NOT NULL AND start_line IS NOT NULL AND end_line IS NOT NULL AND $4::int BETWEEN start_line AND end_line))))
				ORDER BY (type = 'file'), COALESCE(end_line - start_line, 0) LIMIT 20`, sid, f.PackageName, f.FilePath, f.StartLine)
			if err != nil {
				return c, err
			}
			var ids []uuid.UUID
			for rows.Next() {
				var n Node
				var nid uuid.UUID
				if err := rows.Scan(&nid, &n.Key, &n.Type, &n.Label, &n.FilePath, &n.StartLine, &n.EndLine, &n.Match); err != nil {
					rows.Close()
					return c, err
				}
				n.Evidence = Verified
				g.Nodes = append(g.Nodes, n)
				ids = append(ids, nid)
			}
			rows.Close()
			if len(ids) > 0 {
				erows, err := s.DB.Query(ctx, `SELECT e.edge_key, e.type, sn.node_key, tn.node_key, e.evidence FROM codegraph_edges e
					JOIN codegraph_nodes sn ON sn.id = e.source_id JOIN codegraph_nodes tn ON tn.id = e.target_id
					WHERE e.snapshot_id = $1 AND (e.source_id = ANY($2) OR e.target_id = ANY($2)) AND e.type <> 'defines'
					ORDER BY (e.evidence = 'verified') DESC, e.edge_key LIMIT 30`, sid, ids)
				if err != nil {
					return c, err
				}
				for erows.Next() {
					var e Edge
					if err := erows.Scan(&e.Key, &e.Type, &e.Source, &e.Target, &e.Evidence); err != nil {
						erows.Close()
						return c, err
					}
					g.Edges = append(g.Edges, e)
				}
				erows.Close()
			}
			if len(g.Nodes) == 0 {
				g.Note = "no CodeGraph element at the finding's location"
			}
		}
		c.CodeGraph = g
	}
	// Threats: linked to the finding, or affecting an element at it, in
	// models the caller can read (latest version of each model).
	if on, _ := featureflags.Enabled(ctx, s.DB, p.OrganizationID, "threat_models"); !on {
		c.ThreatsNote = "threat modelling is not enabled"
	} else {
		keys := []string{}
		if c.CodeGraph != nil {
			for _, n := range c.CodeGraph.Nodes {
				keys = append(keys, n.Key)
			}
		}
		rows, err := s.DB.Query(ctx, `SELECT DISTINCT ON (t.id) t.id, m.id, m.status, m.version, t.title, t.category, t.severity, t.status,
				CASE WHEN tf.finding_id IS NOT NULL THEN 'finding' ELSE 'element' END, t.evidence_type
			FROM threats t JOIN threat_models m ON m.id = t.threat_model_id
			LEFT JOIN threat_findings tf ON tf.threat_id = t.id AND tf.finding_id = $2
			WHERE t.organization_id = $1 AND m.status <> 'superseded' AND m.status <> 'archived'
			  AND (tf.finding_id IS NOT NULL OR EXISTS (SELECT 1 FROM threat_elements te JOIN threat_model_elements el ON el.id = te.element_id
			       WHERE te.threat_id = t.id AND el.repository_id = $3 AND el.codegraph_key = ANY($4)))
			ORDER BY t.id, (tf.finding_id IS NOT NULL) DESC LIMIT 50`, p.OrganizationID, f.ID, f.repoID, keys)
		if err != nil {
			return c, err
		}
		var all []Threat
		for rows.Next() {
			var t Threat
			if err := rows.Scan(&t.ID, &t.ThreatModelID, &t.ModelStatus, &t.ModelVersion, &t.Title, &t.Category, &t.Severity, &t.Status, &t.Link, &t.Evidence); err != nil {
				rows.Close()
				return c, err
			}
			all = append(all, t)
		}
		rows.Close()
		hidden := 0
		seen := map[uuid.UUID]bool{}
		for _, t := range all {
			ok, done := seen[t.ThreatModelID]
			if !done {
				ok = s.ThreatAccess != nil && s.ThreatAccess(ctx, p, t.ThreatModelID, false) == nil
				seen[t.ThreatModelID] = ok
			}
			if !ok {
				hidden++
				continue
			}
			c.Threats = append(c.Threats, t)
		}
		if hidden > 0 {
			c.ThreatsNote = "some linked threats are in threat models outside your access"
		}
	}
	// SBOM: the package's components in the repository's latest SBOM.
	if f.PackageName != "" {
		rows, err := s.DB.Query(ctx, `SELECT name, version, purl, type, licenses FROM sbom_components
			WHERE organization_id = $1 AND repository_id = $2 AND lower(name) = lower($3)
			  AND scan_job_id = (SELECT scan_job_id FROM sbom_components WHERE organization_id = $1 AND repository_id = $2 ORDER BY created_at DESC LIMIT 1)
			ORDER BY (version = $4) DESC, version LIMIT 20`, p.OrganizationID, f.repoID, f.PackageName, f.PackageVer)
		if err != nil {
			return c, err
		}
		for rows.Next() {
			var x Component
			if err := rows.Scan(&x.Name, &x.Version, &x.Purl, &x.Type, &x.Licenses); err != nil {
				rows.Close()
				return c, err
			}
			x.Evidence = Verified
			c.Components = append(c.Components, x)
		}
		rows.Close()
	}
	// Runtime context (observed in a cluster).
	var rt Runtime
	var raw []byte
	if err := s.DB.QueryRow(ctx, `SELECT runtime_status, runtime_exposed, runtime_privileged, runtime_alert, runtime_context FROM findings WHERE id = $1`, f.ID).
		Scan(&rt.Status, &rt.Exposed, &rt.Privileged, &rt.Alert, &raw); err == nil && (rt.Status != "" || len(raw) > 0) {
		rt.Context, rt.Evidence = raw, Observed
		if len(raw) == 0 {
			rt.Context = json.RawMessage("null")
		}
		c.Runtime = &rt
	}
	// Related findings (the existing cross-tool logic: same location or
	// same CVE, never merged).
	rows, err := s.DB.Query(ctx, `
		WITH me AS (SELECT * FROM findings WHERE id = $1)
		SELECT o.id, CASE WHEN me.cve <> '' AND o.cve = me.cve THEN 'same_vulnerability' ELSE 'same_location' END, o.title, o.severity, o.status
		FROM me JOIN findings o ON o.repository_id = me.repository_id AND o.id <> me.id
		WHERE (me.cve <> '' AND o.cve = me.cve)
		   OR (me.category NOT IN ('sca', 'container') AND o.category NOT IN ('sca', 'container')
		       AND o.file_path = me.file_path AND me.file_path <> ''
		       AND me.start_line IS NOT NULL AND o.start_line IS NOT NULL AND abs(o.start_line - me.start_line) <= 3
		       AND NOT (o.scanner_keys && me.scanner_keys)
		       AND (o.cwe && me.cwe OR (cardinality(o.cwe) = 0 AND cardinality(me.cwe) = 0 AND o.category = me.category)))
		ORDER BY 2, o.risk_score DESC NULLS LAST LIMIT 25`, f.ID)
	if err != nil {
		return c, err
	}
	for rows.Next() {
		var x RelatedFinding
		if err := rows.Scan(&x.ID, &x.Relation, &x.Title, &x.Severity, &x.Status); err != nil {
			rows.Close()
			return c, err
		}
		x.Evidence = Verified
		c.Related = append(c.Related, x)
	}
	rows.Close()
	return c, nil
}

// References returns the record's related references (ids and keys).
func (c Correlation) References() map[string]any {
	out := map[string]any{"findings": []string{c.Finding.ID.String()}}
	if c.CodeGraph != nil && c.CodeGraph.SnapshotID != nil {
		var nodes []map[string]string
		for _, n := range c.CodeGraph.Nodes {
			nodes = append(nodes, map[string]string{"snapshot_id": c.CodeGraph.SnapshotID.String(), "key": n.Key, "type": n.Type})
		}
		var edges []map[string]string
		for _, e := range c.CodeGraph.Edges {
			edges = append(edges, map[string]string{"snapshot_id": c.CodeGraph.SnapshotID.String(), "key": e.Key, "type": e.Type})
		}
		out["codegraph_nodes"], out["codegraph_edges"] = nodes, edges
	}
	var threats, comps, rel []string
	for _, t := range c.Threats {
		threats = append(threats, t.ID.String())
	}
	for _, x := range c.Components {
		comps = append(comps, x.Purl+"|"+x.Name+"@"+x.Version)
	}
	for _, x := range c.Related {
		rel = append(rel, x.ID.String())
	}
	out["threats"], out["components"], out["related_findings"] = threats, comps, rel
	return out
}

func (s *Service) get(w http.ResponseWriter, r *http.Request) {
	p, f, err := s.caller(r, authz.PermFindingsRead)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c, err := s.Build(r.Context(), p, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

// explain asks the AI to explain and prioritise the correlation. The
// answer is AI-inferred and proposes only: the finding is not changed.
func (s *Service) explain(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p, f, err := s.caller(r, authz.PermAIReview)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if s.AI == nil {
		s.fail(w, r, httpx.E(http.StatusServiceUnavailable, "ai_unavailable", "AI is not available on this server").WithDiag("PTH-AI-1007"))
		return
	}
	c, err := s.Build(ctx, p, f)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	res, err := s.AI.ExplainCorrelation(ctx, p.OrganizationID, f.ID, &p.UserID, c, c.References())
	if err != nil {
		code := ai.DiagCode(err)
		switch {
		case errors.Is(err, ai.ErrNotConfigured):
			err = httpx.E(http.StatusConflict, "ai_not_configured", "no AI configuration: an administrator must add a provider and a configuration").WithDiag(code)
		case errors.Is(err, ai.ErrRateLimited):
			err = httpx.E(http.StatusTooManyRequests, "rate_limited", "the AI provider rate limit was reached; try again later").WithDiag(code)
		default:
			s.Log.Warn("correlation explanation failed", "finding_id", f.ID, "err", err, "error_code", code)
			err = httpx.E(http.StatusBadGateway, "ai_failed", "the AI provider did not return a usable explanation").WithDiag(code)
		}
		s.fail(w, r, err)
		return
	}
	_ = audit.Write(ctx, s.DB, audit.Entry{OrganizationID: p.OrganizationID, ActorID: &p.UserID, ActorEmail: p.Email, Action: "ai.correlation_explain",
		TargetType: "finding", TargetID: f.ID.String(), RequestID: httpx.RequestID(r),
		Metadata: map[string]any{"evidence_record_id": res.EvidenceID, "exploitability": res.Output.Exploitability, "priority": res.Output.Priority}})
	note := "AI-inferred: a proposal only. The finding is unchanged; a person decides in triage or Human Eye."
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"correlation": c, "explanation": res.Output, "evidence_record_id": res.EvidenceID,
		"label": "ai_inferred", "review_decision": ai.ReviewPending, "provider_location": res.Location, "model": res.Model,
		"proposes_suppression": res.Output.Exploitability == ai.NotExploitable, "note": note})
}
