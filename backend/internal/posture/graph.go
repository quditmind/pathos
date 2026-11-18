package posture

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"pathos/internal/authz"
	"pathos/internal/platform/httpx"
)

// --- dependency graph ------------------------------------------------------

// Component is a node of a repository's dependency graph.
type Component struct {
	Ref      string   `json:"ref"`
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	PURL     string   `json:"purl"`
	Type     string   `json:"type"`
	Licenses []string `json:"licenses"`
	// Depth: 0 root, 1 direct, 2+ transitive, nil unknown.
	Depth *int `json:"depth"`
	// Open vulnerability findings for this package version in the repository.
	OpenVulns   int     `json:"open_vulnerabilities"`
	MaxSeverity *string `json:"max_severity"`
	// Package health (deps.dev), when known.
	LatestVersion string   `json:"latest_version,omitempty"`
	Outdated      bool     `json:"outdated"`
	Deprecated    bool     `json:"deprecated"`
	Scorecard     *float64 `json:"scorecard,omitempty"`
	// Provenance of this version: "verified" (SLSA provenance verified by
	// deps.dev), "unverified", "none" (checked, no attestation) or "" (not
	// checked; only direct dependencies are).
	Provenance       string `json:"provenance,omitempty"`
	ProvenanceSource string `json:"provenance_source,omitempty"`
	// End of life (endoflife.date): eol, approaching or supported when the
	// package is a tracked framework or runtime; its cycle and end date.
	EOLStatus string  `json:"eol_status,omitempty"`
	EOLCycle  string  `json:"eol_cycle,omitempty"`
	EOLDate   *string `json:"eol_date,omitempty"`
}

type edge struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
}

const maxGraphNodes = 5000

type repoGraph struct {
	comps   []Component
	byRef   map[string]int
	edges   []edge
	parents map[string][]string
}

func (s *Service) loadGraph(ctx context.Context, repoID uuid.UUID) (repoGraph, error) {
	g := repoGraph{byRef: map[string]int{}, parents: map[string][]string{}}
	rows, err := s.DB.Query(ctx, `
	SELECT c.bom_ref, c.name, c.version, c.purl, c.type, c.licenses, c.depth,
	       count(f.id), (array_agg(f.severity ORDER BY array_position(ARRAY['critical','high','medium','low','info'], f.severity)))[1],
	       COALESCE(min(h.latest_version), ''), COALESCE(bool_or(c.version = ANY(h.deprecated_versions)), false), min(h.scorecard)::float8,
	       CASE WHEN NOT COALESCE(bool_or(h.provenance ? c.version), false) THEN ''
	            WHEN bool_or(jsonb_typeof(h.provenance -> c.version) = 'null') THEN 'none'
	            WHEN bool_or((h.provenance -> c.version ->> 'verified')::boolean) THEN 'verified' ELSE 'unverified' END,
	       COALESCE(min(h.provenance -> c.version ->> 'source'), ''),
	       (SELECT jsonb_build_object('status', e.status, 'cycle', e.product_label || ' ' || e.cycle, 'date', e.eol_date)
	          FROM component_eol e WHERE e.repository_id = c.repository_id AND e.source = 'sbom' AND e.purl = c.purl
	          ORDER BY array_position(ARRAY['eol','approaching','supported'], e.status) LIMIT 1)
	FROM sbom_components c
	LEFT JOIN package_health h ON h.found AND h.purl_base = regexp_replace(split_part(c.purl, '?', 1), '@[^@/]*$', '')
	LEFT JOIN findings f ON f.repository_id = c.repository_id AND f.scan_target_id IS NULL AND f.category = 'sca'
	     AND f.status IN `+openStatuses+` AND lower(f.package_name) = lower(c.name) AND f.package_version = c.version
	WHERE c.repository_id = $1
	GROUP BY c.id ORDER BY c.depth NULLS LAST, lower(c.name), c.version LIMIT $2`, repoID, maxGraphNodes)
	if err != nil {
		return g, err
	}
	for rows.Next() {
		var c Component
		var sev *string
		var eolRaw []byte
		if err := rows.Scan(&c.Ref, &c.Name, &c.Version, &c.PURL, &c.Type, &c.Licenses, &c.Depth, &c.OpenVulns, &sev,
			&c.LatestVersion, &c.Deprecated, &c.Scorecard, &c.Provenance, &c.ProvenanceSource, &eolRaw); err != nil {
			rows.Close()
			return g, err
		}
		if len(eolRaw) > 0 {
			var e struct {
				Status string  `json:"status"`
				Cycle  string  `json:"cycle"`
				Date   *string `json:"date"`
			}
			if json.Unmarshal(eolRaw, &e) == nil {
				c.EOLStatus, c.EOLCycle, c.EOLDate = e.Status, e.Cycle, e.Date
			}
		}
		if c.OpenVulns > 0 {
			c.MaxSeverity = sev
		}
		if c.Depth != nil && *c.Depth == 0 && c.LatestVersion != "" && VersionLess(c.LatestVersion, c.Version) {
			// A root (often the application itself) newer than the public
			// package of the same name: that package is someone else's.
			c.LatestVersion, c.Deprecated, c.Scorecard, c.Provenance, c.ProvenanceSource = "", false, nil, "", ""
		}
		c.Outdated = c.LatestVersion != "" && VersionLess(c.Version, c.LatestVersion)
		if c.Licenses == nil {
			c.Licenses = []string{}
		}
		if c.Ref != "" {
			g.byRef[c.Ref] = len(g.comps)
		}
		g.comps = append(g.comps, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return g, err
	}
	erows, err := s.DB.Query(ctx, `SELECT parent_ref, child_ref FROM sbom_dependencies WHERE repository_id = $1 LIMIT 200000`, repoID)
	if err != nil {
		return g, err
	}
	for erows.Next() {
		var e edge
		if err := erows.Scan(&e.Parent, &e.Child); err != nil {
			erows.Close()
			return g, err
		}
		g.edges = append(g.edges, e)
		g.parents[e.Child] = append(g.parents[e.Child], e.Parent)
	}
	erows.Close()
	return g, erows.Err()
}

// paths returns up to limit shortest paths from a root to ref (each path
// starts at the root and ends at ref).
func (g repoGraph) paths(ref string, limit int) [][]string {
	// Walk up from ref breadth-first; the first layer that reaches roots
	// gives the shortest paths.
	type item struct {
		node string
		path []string
	}
	queue := []item{{ref, []string{ref}}}
	var out [][]string
	visited := map[string]int{ref: 0}
	for len(queue) > 0 && len(out) < limit {
		it := queue[0]
		queue = queue[1:]
		ps := g.parents[it.node]
		if len(ps) == 0 {
			if len(it.path) > 1 || len(g.edges) > 0 {
				rev := make([]string, len(it.path))
				for i, n := range it.path {
					rev[len(it.path)-1-i] = n
				}
				out = append(out, rev)
			}
			continue
		}
		for _, p := range ps {
			if d, ok := visited[p]; ok && d < len(it.path) {
				continue // a shorter way to p is already queued
			}
			if containsStr(it.path, p) || len(it.path) > 50 {
				continue // cycle or runaway depth
			}
			visited[p] = len(it.path)
			np := append(append([]string{}, it.path...), p)
			queue = append(queue, item{p, np})
		}
	}
	return out
}

func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// pathNode is a component on a dependency path.
type pathNode struct {
	Ref     string `json:"ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func (g repoGraph) describe(path []string) []pathNode {
	out := make([]pathNode, 0, len(path))
	for _, ref := range path {
		n := pathNode{Ref: ref, Name: ref}
		if i, ok := g.byRef[ref]; ok {
			n.Name, n.Version = g.comps[i].Name, g.comps[i].Version
		}
		out = append(out, n)
	}
	return out
}

func (s *Service) repoFromPath(w http.ResponseWriter, r *http.Request, perm authz.Permission) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return uuid.Nil, false
	}
	if err := s.requireRepo(r.Context(), s.Principal(r.Context()), perm, id); err != nil {
		s.fail(w, r, err)
		return uuid.Nil, false
	}
	return id, true
}

func (s *Service) dependencies(w http.ResponseWriter, r *http.Request) {
	repoID, ok := s.repoFromPath(w, r, authz.PermSBOMRead)
	if !ok {
		return
	}
	g, err := s.loadGraph(r.Context(), repoID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	stats := map[string]int{"components": len(g.comps), "edges": len(g.edges)}
	for _, c := range g.comps {
		switch {
		case c.Depth == nil:
			stats["unknown"]++
		case *c.Depth == 0:
			stats["roots"]++
		case *c.Depth == 1:
			stats["direct"]++
		default:
			stats["transitive"]++
		}
		if c.Outdated {
			stats["outdated"]++
		}
		if c.Deprecated {
			stats["deprecated"]++
		}
		if c.OpenVulns > 0 {
			stats["vulnerable"]++
			if c.Depth != nil && *c.Depth >= 2 {
				stats["vulnerable_transitive"]++
			}
		}
	}
	edges := g.edges
	if edges == nil {
		edges = []edge{}
	}
	comps := g.comps
	if comps == nil {
		comps = []Component{}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"components": comps, "edges": edges, "stats": stats,
		"truncated": len(g.comps) >= maxGraphNodes})
}

func (s *Service) dependencyPaths(w http.ResponseWriter, r *http.Request) {
	repoID, ok := s.repoFromPath(w, r, authz.PermSBOMRead)
	if !ok {
		return
	}
	ref := r.URL.Query().Get("ref")
	if ref == "" || len(ref) > 1000 {
		s.fail(w, r, httpx.BadRequest("ref is required"))
		return
	}
	g, err := s.loadGraph(r.Context(), repoID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if _, ok := g.byRef[ref]; !ok {
		s.fail(w, r, errNotFound)
		return
	}
	out := [][]pathNode{}
	for _, p := range g.paths(ref, 5) {
		out = append(out, g.describe(p))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ref": ref, "paths": out})
}

// findingPaths explains how a vulnerable package reaches the repository.
func (s *Service) findingPaths(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		s.fail(w, r, errNotFound)
		return
	}
	var repoID uuid.UUID
	var pkg, version, category string
	var target *uuid.UUID
	if err := s.DB.QueryRow(ctx, `SELECT repository_id, package_name, package_version, category, scan_target_id FROM findings
		WHERE organization_id = $1 AND id = $2`, p.OrganizationID, id).Scan(&repoID, &pkg, &version, &category, &target); err != nil {
		s.fail(w, r, err)
		return
	}
	if err := s.requireRepo(ctx, p, authz.PermFindingsRead, repoID); err != nil {
		s.fail(w, r, err)
		return
	}
	resp := map[string]any{"package_name": pkg, "package_version": version, "components": []any{}}
	if pkg == "" || target != nil {
		resp["reason"] = "the finding is not about a dependency of the repository's code"
		httpx.WriteJSON(w, http.StatusOK, resp)
		return
	}
	g, err := s.loadGraph(ctx, repoID)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	type match struct {
		Component Component    `json:"component"`
		Relation  string       `json:"relation"` // root | direct | transitive | unknown
		Paths     [][]pathNode `json:"paths"`
	}
	var out []match
	for _, c := range g.comps {
		if !strings.EqualFold(c.Name, pkg) || (version != "" && c.Version != version) {
			continue
		}
		m := match{Component: c, Relation: relation(c.Depth), Paths: [][]pathNode{}}
		if c.Ref != "" {
			for _, path := range g.paths(c.Ref, 3) {
				m.Paths = append(m.Paths, g.describe(path))
			}
		}
		out = append(out, m)
		if len(out) >= 5 {
			break
		}
	}
	if len(out) == 0 {
		resp["reason"] = "the package is not in the repository's latest SBOM"
	} else {
		resp["components"] = out
	}
	httpx.WriteJSON(w, http.StatusOK, resp)
}

func relation(depth *int) string {
	switch {
	case depth == nil:
		return "unknown"
	case *depth == 0:
		return "root"
	case *depth == 1:
		return "direct"
	}
	return "transitive"
}

// --- blast radius ------------------------------------------------------------

var cveParam = regexp.MustCompile(`^(?i)(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3})$`)

// Affected is one repository affected by a vulnerability or package.
type Affected struct {
	RepositoryID    uuid.UUID  `json:"repository_id"`
	RepositoryName  string     `json:"repository_name"`
	RepositoryKey   string     `json:"repository_key"`
	ApplicationID   *uuid.UUID `json:"application_id"`
	ApplicationName *string    `json:"application_name"`
	BusinessUnit    *string    `json:"business_unit"`
	Owner           *string    `json:"owner"`
	Team            *string    `json:"team"`
	Criticality     string     `json:"criticality"`
	PublicExposure  string     `json:"public_exposure"`
	// Versions of the package (package search) or vulnerable packages (CVE).
	Packages     []string `json:"packages"`
	Relation     string   `json:"relation"` // closest: root, direct, transitive, unknown, none
	OpenFindings int      `json:"open_findings"`
	MaxRisk      *float64 `json:"max_risk"`
	KEV          bool     `json:"kev"`
	// Targets: scan targets (images, ...) where the vulnerability was found.
	Targets []string `json:"targets"`
}

func (s *Service) blastRadius(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	q := r.URL.Query()
	cve := strings.ToUpper(strings.TrimSpace(q.Get("cve")))
	pkg := strings.TrimSpace(q.Get("package"))
	version := strings.TrimSpace(q.Get("version"))
	if (cve == "") == (pkg == "") {
		s.fail(w, r, httpx.BadRequest("give either cve or package"))
		return
	}
	if cve != "" && !cveParam.MatchString(cve) {
		s.fail(w, r, httpx.BadRequest("cve must be a CVE or GHSA identifier"))
		return
	}
	if len(pkg) > 300 || len(version) > 100 {
		s.fail(w, r, httpx.BadRequest("package or version too long"))
		return
	}
	cond, args, err := scope(p, authz.PermFindingsRead, 4)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	// $2: CVE or package, $3: version ("" = any).
	args = append([]any{p.OrganizationID, firstNonEmpty(cve, pkg), version}, args...)
	// $3 (version) only filters package searches; typed here so the CVE
	// query, which does not use it, still prepares.
	match := `(f.cve = $2 OR f.rule_id = $2) AND $3::text IS NOT NULL`
	inv := `false`
	// compMatch selects the repository's SBOM components concerned.
	compMatch := `EXISTS (SELECT 1 FROM hit WHERE hit.repository_id = c.repository_id AND hit.scan_target_id IS NULL
	                 AND lower(hit.package_name) = lower(c.name) AND hit.package_version = c.version)`
	if pkg != "" {
		match = `lower(f.package_name) = lower($2) AND ($3 = '' OR f.package_version = $3)`
		compMatch = `lower(c.name) = lower($2) AND ($3 = '' OR c.version = $3)`
		inv = `EXISTS (SELECT 1 FROM sbom_components c WHERE c.repository_id = r.id AND ` + compMatch + `)`
	}
	// #nosec G202 -- match, compMatch, inv and cond are fixed SQL with placeholders
	rows, err := s.DB.Query(ctx, `
	WITH hit AS (
	  SELECT f.repository_id, f.package_name, f.package_version, f.risk_score, f.kev, f.scan_target_id
	  FROM findings f WHERE f.organization_id = $1 AND f.status IN `+openStatuses+` AND (`+match+`))
	SELECT r.id, COALESCE(NULLIF(r.display_name, ''), r.full_name), r.repository_key, r.application_id, a.name, bu.name,
	       COALESCE(NULLIF(u.display_name, ''), u.email), t.name, r.criticality, r.public_exposure,
	       (SELECT count(*) FROM hit WHERE hit.repository_id = r.id),
	       (SELECT max(hit.risk_score)::float8 FROM hit WHERE hit.repository_id = r.id),
	       COALESCE((SELECT bool_or(hit.kev) FROM hit WHERE hit.repository_id = r.id), false),
	       COALESCE((SELECT array_agg(DISTINCT y.x ORDER BY y.x) FROM (
	          SELECT hit.package_name || CASE WHEN hit.package_version <> '' THEN '@' || hit.package_version ELSE '' END AS x
	          FROM hit WHERE hit.repository_id = r.id AND hit.package_name <> ''
	          UNION SELECT c.name || '@' || c.version FROM sbom_components c WHERE c.repository_id = r.id AND `+compMatch+`) y), '{}'),
	       (SELECT min(c.depth) FROM sbom_components c WHERE c.repository_id = r.id AND `+compMatch+`),
	       EXISTS (SELECT 1 FROM sbom_components c WHERE c.repository_id = r.id AND `+compMatch+`),
	       COALESCE((SELECT array_agg(DISTINCT st.name) FROM hit JOIN scan_targets st ON st.id = hit.scan_target_id
	          WHERE hit.repository_id = r.id), '{}')
	FROM repositories r
	LEFT JOIN applications a ON a.id = r.application_id LEFT JOIN business_units bu ON bu.id = r.business_unit_id
	LEFT JOIN users u ON u.id = COALESCE(r.application_owner_id, r.technical_owner_id, r.business_owner_id)
	LEFT JOIN teams t ON t.id = r.responsible_team_id
	WHERE r.organization_id = $1 AND r.archived_at IS NULL AND `+cond+`
	  AND (EXISTS (SELECT 1 FROM hit WHERE hit.repository_id = r.id) OR `+inv+`)
	ORDER BY 12 DESC NULLS LAST, array_position(ARRAY['critical', 'high', 'medium', 'low'], r.criticality), lower(r.full_name)
	LIMIT 1000`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	defer rows.Close()
	out := []Affected{}
	apps, bus, exposed := map[uuid.UUID]bool{}, map[string]bool{}, 0
	for rows.Next() {
		var a Affected
		var depth *int
		var inInventory bool
		if err := rows.Scan(&a.RepositoryID, &a.RepositoryName, &a.RepositoryKey, &a.ApplicationID, &a.ApplicationName, &a.BusinessUnit,
			&a.Owner, &a.Team, &a.Criticality, &a.PublicExposure, &a.OpenFindings, &a.MaxRisk, &a.KEV, &a.Packages, &depth, &inInventory,
			&a.Targets); err != nil {
			s.fail(w, r, err)
			return
		}
		// none: not in the repository's SBOM (e.g. found only in an image).
		a.Relation = "none"
		if inInventory {
			a.Relation = relation(depth)
		}
		if a.ApplicationID != nil {
			apps[*a.ApplicationID] = true
		}
		if a.BusinessUnit != nil {
			bus[*a.BusinessUnit] = true
		}
		if a.PublicExposure == "yes" {
			exposed++
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{
		"query":   map[string]string{"cve": cve, "package": pkg, "version": version},
		"summary": map[string]int{"repositories": len(out), "applications": len(apps), "business_units": len(bus), "internet_exposed": exposed},
		"items":   out,
	})
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// --- context graph -------------------------------------------------------------

// Node is a node of the security context graph.
type Node struct {
	ID    string   `json:"id"`
	Type  string   `json:"type"` // application, repository, owner, team, business_unit, target, component, finding
	Label string   `json:"label"`
	Sub   string   `json:"sub,omitempty"`
	Risk  *float64 `json:"risk,omitempty"`
	// Severity for findings, exposure for repositories.
	Severity string `json:"severity,omitempty"`
	// Link is the PATHOS page of the node.
	Link string `json:"link,omitempty"`
}

// GraphEdge connects two nodes.
type GraphEdge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"` // owns, contains, scans, depends_on, affects, member_of
}

type graphBuilder struct {
	nodes []Node
	seen  map[string]bool
	edges []GraphEdge
}

func (b *graphBuilder) node(n Node) string {
	if !b.seen[n.ID] {
		b.seen[n.ID] = true
		b.nodes = append(b.nodes, n)
	}
	return n.ID
}

func (b *graphBuilder) edge(from, to, kind string) {
	b.edges = append(b.edges, GraphEdge{From: from, To: to, Kind: kind})
}

// contextGraph returns the graph around an application or repository:
// owners, teams and business unit; repositories; scan targets; the riskiest
// open findings and the vulnerable components they come from.
func (s *Service) contextGraph(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := s.Principal(ctx)
	kind, rawID, _ := strings.Cut(r.URL.Query().Get("node"), ":")
	id, err := uuid.Parse(rawID)
	if err != nil || (kind != "application" && kind != "repository") {
		s.fail(w, r, httpx.BadRequest("node must be application:<id> or repository:<id>"))
		return
	}
	cond, args, err := scope(p, authz.PermFindingsRead, 3)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	args = append([]any{p.OrganizationID, id}, args...)
	filter := "r.application_id = $2"
	if kind == "repository" {
		filter = "r.id = $2"
	}
	b := &graphBuilder{seen: map[string]bool{}}
	// #nosec G202 -- filter and cond are fixed SQL with placeholders
	rows, err := s.DB.Query(ctx, `
	SELECT r.id, COALESCE(NULLIF(r.display_name, ''), r.full_name), r.repository_key, r.public_exposure, r.criticality,
	       a.id, a.name, a.application_key, bu.id, bu.name,
	       ou.id, COALESCE(NULLIF(ou.display_name, ''), ou.email), t.id, t.name
	FROM repositories r
	LEFT JOIN applications a ON a.id = r.application_id LEFT JOIN business_units bu ON bu.id = COALESCE(a.business_unit_id, r.business_unit_id)
	LEFT JOIN users ou ON ou.id = COALESCE(r.application_owner_id, r.technical_owner_id, r.business_owner_id)
	LEFT JOIN teams t ON t.id = r.responsible_team_id
	WHERE r.organization_id = $1 AND r.archived_at IS NULL AND `+filter+` AND `+cond+`
	ORDER BY lower(r.full_name) LIMIT 50`, args...)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var repoIDs []uuid.UUID
	for rows.Next() {
		var rid uuid.UUID
		var rname, rkey, exposure, crit string
		var aid, buid, uid, tid *uuid.UUID
		var aname, akey, buname, uname, tname *string
		if err := rows.Scan(&rid, &rname, &rkey, &exposure, &crit, &aid, &aname, &akey, &buid, &buname, &uid, &uname, &tid, &tname); err != nil {
			rows.Close()
			s.fail(w, r, err)
			return
		}
		repoIDs = append(repoIDs, rid)
		rn := b.node(Node{ID: "repository:" + rid.String(), Type: "repository", Label: rname, Sub: rkey + " · " + crit,
			Severity: exposure, Link: "/repositories?repo=" + rid.String()})
		if aid != nil {
			an := b.node(Node{ID: "application:" + aid.String(), Type: "application", Label: *aname, Sub: deref(akey),
				Link: "/applications?app=" + aid.String()})
			b.edge(an, rn, "contains")
			if buid != nil {
				b.edge(b.node(Node{ID: "business_unit:" + buid.String(), Type: "business_unit", Label: *buname}), an, "owns")
			}
		} else if buid != nil {
			b.edge(b.node(Node{ID: "business_unit:" + buid.String(), Type: "business_unit", Label: *buname}), rn, "owns")
		}
		if uid != nil {
			b.edge(b.node(Node{ID: "owner:" + uid.String(), Type: "owner", Label: *uname}), rn, "owns")
		}
		if tid != nil {
			b.edge(b.node(Node{ID: "team:" + tid.String(), Type: "team", Label: *tname}), rn, "owns")
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		s.fail(w, r, err)
		return
	}
	if len(repoIDs) == 0 {
		s.fail(w, r, errNotFound)
		return
	}
	if err := s.addTargetsAndFindings(ctx, b, repoIDs); err != nil {
		s.fail(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"root": kind + ":" + id.String(), "nodes": b.nodes, "edges": b.edges})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (s *Service) addTargetsAndFindings(ctx context.Context, b *graphBuilder, repoIDs []uuid.UUID) error {
	trows, err := s.DB.Query(ctx, `SELECT id, repository_id, kind, name, reference FROM scan_targets WHERE repository_id = ANY($1) AND enabled
		ORDER BY kind, lower(name) LIMIT 100`, repoIDs)
	if err != nil {
		return err
	}
	for trows.Next() {
		var tid, rid uuid.UUID
		var kind, name, ref string
		if err := trows.Scan(&tid, &rid, &kind, &name, &ref); err != nil {
			trows.Close()
			return err
		}
		tn := b.node(Node{ID: "target:" + tid.String(), Type: "target", Label: name, Sub: kind + " · " + ref, Link: "/scans/targets"})
		b.edge("repository:"+rid.String(), tn, "scans")
	}
	trows.Close()
	// The riskiest open findings per repository (up to 8), with the
	// component each dependency finding comes from.
	frows, err := s.DB.Query(ctx, `
	SELECT x.id, x.repository_id, x.title, x.severity, x.risk_score::float8, x.package_name, x.package_version, x.scan_target_id,
	       (SELECT c.depth FROM sbom_components c WHERE c.repository_id = x.repository_id AND lower(c.name) = lower(x.package_name)
	          AND c.version = x.package_version ORDER BY c.depth NULLS LAST LIMIT 1)
	FROM (SELECT f.*, row_number() OVER (PARTITION BY f.repository_id ORDER BY f.risk_score DESC NULLS LAST,
	        array_position(ARRAY['critical','high','medium','low','info'], f.severity)) AS rn
	      FROM findings f WHERE f.repository_id = ANY($1) AND f.status IN `+openStatuses+`) x
	WHERE x.rn <= 8`, repoIDs)
	if err != nil {
		return err
	}
	defer frows.Close()
	for frows.Next() {
		var fid, rid uuid.UUID
		var title, sev, pkg, ver string
		var riskScore *float64
		var target *uuid.UUID
		var depth *int
		if err := frows.Scan(&fid, &rid, &title, &sev, &riskScore, &pkg, &ver, &target, &depth); err != nil {
			return err
		}
		fn := b.node(Node{ID: "finding:" + fid.String(), Type: "finding", Label: title, Severity: sev, Risk: riskScore,
			Link: "/findings?finding=" + fid.String()})
		parent := "repository:" + rid.String()
		if target != nil && b.seen["target:"+target.String()] {
			parent = "target:" + target.String()
		}
		if pkg != "" {
			sub := relation(depth)
			if target != nil {
				sub = "in scan target"
			}
			cn := b.node(Node{ID: fmt.Sprintf("component:%s:%s@%s", rid, strings.ToLower(pkg), ver), Type: "component",
				Label: pkg + "@" + ver, Sub: sub})
			if !hasEdge(b, parent, cn) {
				b.edge(parent, cn, "depends_on")
			}
			b.edge(cn, fn, "affects")
		} else {
			b.edge(parent, fn, "affects")
		}
	}
	return frows.Err()
}

func hasEdge(b *graphBuilder, from, to string) bool {
	for _, e := range b.edges {
		if e.From == from && e.To == to {
			return true
		}
	}
	return false
}

// VersionLess reports whether version a is lower than b, comparing the
// numeric release parts (1.2.10 > 1.2.9); a pre-release sorts before its
// release. Unparseable versions are never reported as lower.
func VersionLess(a, b string) bool {
	pa, preA, okA := splitVersion(a)
	pb, preB, okB := splitVersion(b)
	if !okA || !okB {
		return false
	}
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x < y
		}
	}
	return preA && !preB
}

func splitVersion(v string) ([]int, bool, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	pre := false
	if i := strings.IndexAny(v, "-"); i >= 0 {
		v, pre = v[:i], true
	}
	if v == "" {
		return nil, false, false
	}
	var out []int
	for _, p := range strings.Split(v, ".") {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false, false
		}
		out = append(out, n)
	}
	return out, pre, true
}
