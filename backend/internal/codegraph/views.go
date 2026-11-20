package codegraph

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// viewDef is one of the 15 named views: a filter over node and edge types
// with optional lifting (edges of hidden nodes move to their nearest shown
// ancestor), pruning of unconnected nodes, a seed set, or a findings or
// change filter.
type viewDef struct {
	Name        string   `json:"name"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	NodeTypes   []string `json:"node_types"`
	EdgeTypes   []string `json:"edge_types"`
	// lift: an edge whose end is not shown attaches to the nearest shown
	// containment ancestor (module-level architecture from function calls).
	Lift bool `json:"lift"`
	// prune: node types dropped when no shown edge touches them.
	Prune []string `json:"-"`
	// edgeOK further restricts edges (e.g. calls to external services only).
	edgeOK func(sk *skeleton, e *sedge) bool
	// seeded: nodes within 3 hops of the internet trust boundaries.
	seeded bool
	// findings: nodes with open findings and their ancestors.
	findings bool
	// change: nodes changed since a base snapshot and their neighbours.
	change bool
}

// targetIs keeps calls to the given node types, and calls from a route to
// its handler (discovery links a route to its handler with "calls").
func targetIs(t ...string) func(sk *skeleton, e *sedge) bool {
	return func(sk *skeleton, e *sedge) bool {
		return e.typ != "calls" || slices.Contains(t, sk.nodes[e.dst].typ) || sk.nodes[e.src].typ == "route"
	}
}

// Views are the 15 views of the contract, in display order.
var Views = []viewDef{
	{Name: "architecture", Title: "Architecture", Description: "Modules, containers, data stores, queues and external services, with module-level dependencies lifted from calls and imports.",
		NodeTypes: []string{"application", "repository", "module", "container", "datastore", "queue", "external_service"},
		EdgeTypes: []string{"owns", "imports", "calls", "reads", "writes", "publishes", "consumes", "depends_on", "deployed_as"}, Lift: true},
	{Name: "call_graph", Title: "Call graph", Description: "Functions and the calls between them (aggregated by directory when large).",
		NodeTypes: []string{"function"}, EdgeTypes: []string{"calls"}},
	{Name: "data_flow", Title: "Data flow", Description: "Routes, handlers, data stores, queues, secrets and external services, and how data moves between them.",
		NodeTypes: []string{"route", "function", "datastore", "queue", "secret_ref", "external_service"},
		EdgeTypes: []string{"exposes", "reads", "writes", "publishes", "consumes", "calls"},
		Prune:     []string{"function", "secret_ref"}, edgeOK: targetIs("external_service")},
	{Name: "api", Title: "API", Description: "Declared routes and API operations, their handlers and the trust boundaries they cross.",
		NodeTypes: []string{"route", "api_operation", "function", "trust_boundary"}, EdgeTypes: []string{"exposes", "crosses_boundary", "calls"},
		Prune: []string{"function", "trust_boundary"}, edgeOK: targetIs()},
	{Name: "dependencies", Title: "Dependencies", Description: "Modules and the internal modules and third-party components they import or depend on.",
		NodeTypes: []string{"repository", "module", "component"}, EdgeTypes: []string{"imports", "depends_on"}, Lift: true},
	{Name: "deployment", Title: "Deployment", Description: "Containers, infrastructure resources and what they are built from, depend on and expose.",
		NodeTypes: []string{"repository", "module", "container", "iac_resource", "datastore", "queue", "trust_boundary"},
		EdgeTypes: []string{"deployed_as", "depends_on", "crosses_boundary", "exposes"}, Prune: []string{"module"}},
	{Name: "ownership", Title: "Ownership", Description: "The application that owns the repository (the full ownership layer is the context graph).",
		NodeTypes: []string{"application", "repository"}, EdgeTypes: []string{"owns"}},
	{Name: "trust_boundaries", Title: "Trust boundaries", Description: "Trust boundaries and the routes, containers, resources and services that cross them.",
		NodeTypes: []string{"trust_boundary", "route", "container", "iac_resource", "external_service", "function"},
		EdgeTypes: []string{"crosses_boundary", "exposes", "deployed_as", "calls"}, Prune: []string{"function", "route", "container", "iac_resource", "external_service"},
		edgeOK: targetIs("external_service")},
	{Name: "internet_exposure", Title: "Internet exposure", Description: "Everything within three hops of the internet and HTTP ingress boundaries.",
		NodeTypes: []string{"trust_boundary", "route", "api_operation", "function", "container", "iac_resource", "datastore", "queue"},
		EdgeTypes: []string{"crosses_boundary", "exposes", "deployed_as", "reads", "writes", "publishes", "calls", "depends_on"}, seeded: true},
	{Name: "findings_overlay", Title: "Findings overlay", Description: "Code, dependencies and deployment units with open findings, in their containment context.",
		NodeTypes: []string{"repository", "module", "file", "class", "function", "route", "container", "iac_resource", "component"},
		EdgeTypes: []string{"calls", "imports", "depends_on", "deployed_as"}, Lift: true, findings: true},
	{Name: "sbom", Title: "SBOM", Description: "Software components and their dependency tree.",
		NodeTypes: []string{"repository", "component"}, EdgeTypes: []string{"depends_on"}},
	{Name: "datastores", Title: "Data stores", Description: "Databases and caches, and the code and containers that read, write or depend on them.",
		NodeTypes: []string{"datastore", "function", "container", "iac_resource"}, EdgeTypes: []string{"reads", "writes", "depends_on", "deployed_as"},
		Prune: []string{"function", "container", "iac_resource"}},
	{Name: "external_services", Title: "External services", Description: "Third-party services and queues the code calls, publishes to or consumes from.",
		NodeTypes: []string{"external_service", "queue", "function", "container", "trust_boundary"},
		EdgeTypes: []string{"calls", "publishes", "consumes", "depends_on", "crosses_boundary"},
		Prune:     []string{"function", "container", "trust_boundary"}, edgeOK: targetIs("external_service")},
	{Name: "secrets_and_config", Title: "Secrets and configuration", Description: "References to secrets and credentials in code and configuration (names and locations only, never values).",
		NodeTypes: []string{"secret_ref", "function", "file", "container", "iac_resource"}, EdgeTypes: []string{"reads"},
		Prune: []string{"function", "file", "container", "iac_resource"}},
	{Name: "change_impact", Title: "Change impact", Description: "Nodes and edges added, removed or changed since a base snapshot, with their direct neighbours.",
		NodeTypes: NodeTypes, EdgeTypes: EdgeTypes, change: true},
}

// ViewByName returns a view definition.
func ViewByName(name string) (viewDef, bool) {
	i := slices.IndexFunc(Views, func(v viewDef) bool { return v.Name == name })
	if i < 0 {
		return viewDef{}, false
	}
	return Views[i], true
}

// viewParams are the parsed query parameters of a view request.
type viewParams struct {
	focus    string
	depth    int
	layers   []string
	types    []string
	langs    []string
	techs    []string
	sevs     []string
	evidence []string
	q        string
	limit    int
	// change_impact: the diff against the base snapshot.
	diff *diffResult
}

// unit is a node or an aggregate in a view result.
type unit struct {
	node    int32 // -1 for an aggregate
	group   string
	members []int32
}

func (u unit) id(sk *skeleton) string {
	if u.node >= 0 {
		return sk.nodes[u.node].id.String()
	}
	return "agg:" + u.group
}

// vedge is an edge of a view result (original, lifted or aggregated).
type vedge struct {
	a, b     int // unit indexes
	typ      string
	count    int
	evidence string
	samples  []int32 // original edge indexes (evidence is read from these)
	original bool    // exactly one original edge between two shown nodes
}

type viewResult struct {
	units     []unit
	edges     []vedge
	truncated bool
	removed   []int32 // change_impact: nodes of the base snapshot that are gone
	changed   map[int32]string
}

const (
	defaultLimit = 500
	maxLimit     = 2000
	maxDepth     = 3
)

// compute evaluates a view over the skeleton.
func (sk *skeleton) compute(def viewDef, p viewParams) (*viewResult, error) {
	n := len(sk.nodes)
	cand := make([]bool, n)
	for i := range sk.nodes {
		nd := &sk.nodes[i]
		cand[i] = slices.Contains(def.NodeTypes, nd.typ) && sk.nodeMatches(nd, p)
	}
	if def.findings || len(p.sevs) > 0 {
		marked := make([]bool, n)
		for i := range sk.nodes {
			nd := &sk.nodes[i]
			if nd.total == 0 {
				continue
			}
			if len(p.sevs) > 0 && !slices.ContainsFunc(p.sevs, func(s string) bool { return nd.sev[s] > 0 }) {
				continue
			}
			for j := int32(i); j >= 0 && !marked[j]; j = sk.nodes[j].parent {
				marked[j] = true
			}
		}
		for i := range cand {
			cand[i] = cand[i] && marked[i]
		}
	}
	if def.seeded {
		reach := sk.reach(sk.seeds(), def, maxDepth)
		for i := range cand {
			cand[i] = cand[i] && reach[i]
		}
	}
	res := &viewResult{}
	if def.change && p.diff != nil {
		touched := make([]bool, n)
		res.changed = map[int32]string{}
		for _, k := range p.diff.addedNodes {
			if i, ok := sk.byKey[k]; ok {
				touched[i] = true
				res.changed[i] = "added"
			}
		}
		for _, k := range p.diff.changedNodes {
			if i, ok := sk.byKey[k]; ok {
				touched[i] = true
				res.changed[i] = "changed"
			}
		}
		for _, k := range p.diff.addedEdges {
			if i, ok := sk.edgeByKey(k); ok {
				touched[sk.edges[i].src], touched[sk.edges[i].dst] = true, true
			}
		}
		near := slices.Clone(touched)
		for i := range touched {
			if !touched[i] {
				continue
			}
			for _, e := range sk.out[i] {
				near[sk.edges[e].dst] = true
			}
			for _, e := range sk.in[i] {
				near[sk.edges[e].src] = true
			}
		}
		for i := range cand {
			cand[i] = cand[i] && near[i]
		}
	}

	// Focus: a node (expanded: its children join the view) or an aggregate.
	focusNode := int32(-1)
	focusGroup := ""
	switch {
	case strings.HasPrefix(p.focus, "agg:"):
		focusGroup = strings.TrimPrefix(p.focus, "agg:")
	case p.focus != "":
		id, err := uuid.Parse(p.focus)
		if err != nil {
			return nil, errBadQuery("focus must be a node id or an aggregate id (agg:...)")
		}
		i, ok := sk.byID[id]
		if !ok {
			return nil, errNotFound
		}
		focusNode = i
		cand[i] = true
		for _, c := range sk.childs[i] {
			if sk.nodeMatches(&sk.nodes[c], p) {
				cand[c] = true
			}
		}
	}

	// Representatives: a node shows itself, or (lift) its nearest shown
	// ancestor.
	rep := make([]int32, n)
	for i := range rep {
		rep[i] = -2
	}
	var repOf func(i int32) int32
	repOf = func(i int32) int32 {
		if rep[i] != -2 {
			return rep[i]
		}
		// Iterative walk with path compression.
		var chain []int32
		j := i
		r := int32(-1)
		for j >= 0 {
			if rep[j] != -2 {
				r = rep[j]
				break
			}
			chain = append(chain, j)
			if cand[j] {
				r = j
				break
			}
			if !def.Lift {
				break
			}
			j = sk.nodes[j].parent
		}
		for _, c := range chain {
			if cand[c] {
				rep[c] = c
			} else {
				rep[c] = r
			}
		}
		return rep[i]
	}

	type ekey struct {
		a, b int32
		t    string
	}
	agg := map[ekey]*vedge{}
	var order []ekey
	degree := make([]int, n)
	for ei := range sk.edges {
		e := &sk.edges[ei]
		if !slices.Contains(def.EdgeTypes, e.typ) || (def.edgeOK != nil && !def.edgeOK(sk, e)) {
			continue
		}
		if len(p.evidence) > 0 && !slices.Contains(p.evidence, e.evidence) {
			continue
		}
		a, b := repOf(e.src), repOf(e.dst)
		if a < 0 || b < 0 || a == b {
			continue
		}
		k := ekey{a, b, e.typ}
		ve := agg[k]
		if ve == nil {
			ve = &vedge{a: int(a), b: int(b), typ: e.typ, evidence: e.evidence, original: a == e.src && b == e.dst}
			agg[k] = ve
			order = append(order, k)
			degree[a]++
			degree[b]++
		} else {
			ve.original = false
		}
		ve.count++
		if evidenceRank(e.evidence) < evidenceRank(ve.evidence) {
			ve.evidence = e.evidence
		}
		if len(ve.samples) < 3 {
			ve.samples = append(ve.samples, int32(ei))
		}
	}
	for i := range cand {
		if cand[i] && degree[i] == 0 && int32(i) != focusNode && slices.Contains(def.Prune, sk.nodes[i].typ) {
			cand[i] = false
		}
	}

	// Focus restriction: neighbourhood of the focus node (and its
	// children) up to depth hops, or the members of an aggregate and their
	// direct neighbours.
	keep := cand
	if focusNode >= 0 || focusGroup != "" {
		adj := make(map[int32][]int32)
		for _, k := range order {
			adj[k.a] = append(adj[k.a], k.b)
			adj[k.b] = append(adj[k.b], k.a)
		}
		keep = make([]bool, n)
		var frontier []int32
		if focusNode >= 0 {
			keep[focusNode] = true
			frontier = append(frontier, focusNode)
			for _, c := range sk.childs[focusNode] {
				if cand[c] {
					keep[c] = true
					frontier = append(frontier, c)
				}
			}
		} else {
			for i := range cand {
				if cand[i] && inGroup(sk.nodes[i].group, focusGroup) {
					keep[i] = true
					frontier = append(frontier, int32(i))
				}
			}
		}
		depth := p.depth
		if focusGroup != "" {
			depth = 1
		}
		for d := 0; d < depth && len(frontier) > 0; d++ {
			var next []int32
			for _, x := range frontier {
				for _, y := range adj[x] {
					if cand[y] && !keep[y] {
						keep[y] = true
						next = append(next, y)
					}
				}
			}
			frontier = next
		}
	}
	var shown []int32
	for i := range keep {
		if keep[i] && cand[i] {
			shown = append(shown, int32(i))
		}
	}

	// Aggregation when over the limit: group by directory, coarsening one
	// path level at a time until the units fit.
	unitOf := make(map[int32]int, len(shown))
	if len(shown) <= p.limit {
		for _, i := range shown {
			unitOf[i] = len(res.units)
			res.units = append(res.units, unit{node: i})
		}
	} else {
		minLevel := 0
		if strings.HasPrefix(focusGroup, "dir:") {
			minLevel = segments(strings.TrimPrefix(focusGroup, "dir:"))
		}
		level := 0
		for i := range shown {
			level = max(level, segments(strings.TrimPrefix(sk.nodes[shown[i]].group, "dir:")))
		}
		// At each level (deepest first), collapse the largest groups until
		// the result fits, so as many real nodes as possible stay visible;
		// go one level coarser when collapsing every group is not enough.
		var groups map[string][]int32
		var keys []string
		collapse := map[string]bool{}
		for ; ; level-- {
			groups = map[string][]int32{}
			keys = keys[:0]
			for _, i := range shown {
				g := "node"
				if i != focusNode {
					g = groupAt(sk.nodes[i].group, max(level, minLevel+1))
				}
				if _, ok := groups[g]; !ok {
					keys = append(keys, g)
				}
				groups[g] = append(groups[g], i)
			}
			bySize := slices.Clone(keys)
			sort.SliceStable(bySize, func(a, b int) bool {
				if len(groups[bySize[a]]) != len(groups[bySize[b]]) {
					return len(groups[bySize[a]]) > len(groups[bySize[b]])
				}
				return bySize[a] < bySize[b]
			})
			units := len(shown)
			collapse = map[string]bool{}
			for _, g := range bySize {
				if units <= p.limit {
					break
				}
				if g == "node" || len(groups[g]) < 2 {
					continue
				}
				collapse[g] = true
				units -= len(groups[g]) - 1
			}
			if units <= p.limit || level <= minLevel+1 {
				break
			}
		}
		sort.Strings(keys)
		for _, g := range keys {
			members := groups[g]
			if !collapse[g] {
				for _, i := range members {
					unitOf[i] = len(res.units)
					res.units = append(res.units, unit{node: i})
				}
				continue
			}
			for _, i := range members {
				unitOf[i] = len(res.units)
			}
			res.units = append(res.units, unit{node: -1, group: g, members: members})
		}
		if len(res.units) > p.limit {
			res.units = res.units[:p.limit]
			res.truncated = true
		}
	}

	// Edges between units.
	type ukey struct {
		a, b int
		t    string
	}
	merged := map[ukey]*vedge{}
	for _, k := range order {
		ve := agg[k]
		ua, ok1 := unitOf[k.a]
		ub, ok2 := unitOf[k.b]
		if !ok1 || !ok2 || ua == ub || ua >= len(res.units) || ub >= len(res.units) {
			continue
		}
		uk := ukey{ua, ub, k.t}
		m := merged[uk]
		if m == nil {
			m = &vedge{a: ua, b: ub, typ: k.t, evidence: ve.evidence, original: ve.original}
			merged[uk] = m
		} else {
			m.original = false
		}
		m.count += ve.count
		if evidenceRank(ve.evidence) < evidenceRank(m.evidence) {
			m.evidence = ve.evidence
		}
		for _, s := range ve.samples {
			if len(m.samples) < 3 {
				m.samples = append(m.samples, s)
			}
		}
	}
	for _, m := range merged {
		m.original = m.original && m.count == 1 && res.units[m.a].node >= 0 && res.units[m.b].node >= 0
		res.edges = append(res.edges, *m)
	}
	sort.Slice(res.edges, func(i, j int) bool {
		if res.edges[i].count != res.edges[j].count {
			return res.edges[i].count > res.edges[j].count
		}
		if res.edges[i].a != res.edges[j].a {
			return res.edges[i].a < res.edges[j].a
		}
		if res.edges[i].b != res.edges[j].b {
			return res.edges[i].b < res.edges[j].b
		}
		return res.edges[i].typ < res.edges[j].typ
	})
	if maxEdges := p.limit * 5; len(res.edges) > maxEdges {
		res.edges = res.edges[:maxEdges]
		res.truncated = true
	}
	if def.change && p.diff != nil {
		res.removed = p.diff.removedIdx
	}
	return res, nil
}

// nodeMatches applies the type, layer, language, technology and text filters.
func (sk *skeleton) nodeMatches(nd *snode, p viewParams) bool {
	if len(p.layers) > 0 && !slices.Contains(p.layers, nd.layer) {
		return false
	}
	if len(p.types) > 0 && !slices.Contains(p.types, nd.typ) {
		return false
	}
	if len(p.langs) > 0 && !slices.ContainsFunc(p.langs, func(l string) bool { return strings.EqualFold(l, nd.language) }) {
		return false
	}
	if len(p.techs) > 0 && !slices.ContainsFunc(p.techs, func(t string) bool {
		return t != "" && strings.Contains(strings.ToLower(nd.tech), strings.ToLower(t))
	}) {
		return false
	}
	if p.q != "" && !strings.Contains(strings.ToLower(nd.label), strings.ToLower(p.q)) &&
		!strings.Contains(strings.ToLower(nd.key), strings.ToLower(p.q)) {
		return false
	}
	return true
}

// seeds are the internet-facing trust boundaries.
func (sk *skeleton) seeds() []int32 {
	var out []int32
	for i := range sk.nodes {
		nd := &sk.nodes[i]
		if nd.typ == "trust_boundary" && (nd.key == "tb:internet" || nd.key == "tb:http-ingress" ||
			strings.Contains(strings.ToLower(nd.label), "internet")) {
			out = append(out, int32(i))
		}
	}
	return out
}

// reach marks nodes within hops of the seeds over the view's edge types
// (both directions).
func (sk *skeleton) reach(seeds []int32, def viewDef, hops int) []bool {
	seen := make([]bool, len(sk.nodes))
	frontier := slices.Clone(seeds)
	for _, s := range seeds {
		seen[s] = true
	}
	for d := 0; d < hops && len(frontier) > 0; d++ {
		var next []int32
		visit := func(e *sedge, other int32) {
			if !slices.Contains(def.EdgeTypes, e.typ) || seen[other] {
				return
			}
			seen[other] = true
			next = append(next, other)
		}
		for _, x := range frontier {
			for _, ei := range sk.out[x] {
				visit(&sk.edges[ei], sk.edges[ei].dst)
			}
			for _, ei := range sk.in[x] {
				visit(&sk.edges[ei], sk.edges[ei].src)
			}
		}
		frontier = next
	}
	return seen
}

func (sk *skeleton) edgeByKey(k string) (int32, bool) {
	parts := strings.SplitN(k, "|", 3)
	if len(parts) != 3 {
		return 0, false
	}
	s, ok := sk.byKey[parts[0]]
	if !ok {
		return 0, false
	}
	for _, ei := range sk.out[s] {
		if sk.edges[ei].key == k {
			return ei, true
		}
	}
	return 0, false
}

// segments counts the path segments of a directory ("." has none).
func segments(dir string) int {
	if dir == "" || dir == "." {
		return 0
	}
	return strings.Count(dir, "/") + 1
}

// groupAt truncates a "dir:" group to its first level segments; other
// groups are kept.
func groupAt(g string, level int) string {
	if !strings.HasPrefix(g, "dir:") {
		return g
	}
	dir := strings.TrimPrefix(g, "dir:")
	if dir == "." || segments(dir) <= level {
		return g
	}
	if level <= 0 {
		return "dir:."
	}
	parts := strings.SplitN(dir, "/", level+1)
	return "dir:" + strings.Join(parts[:level], "/")
}

// inGroup reports whether a node's group lies in the aggregate group g.
func inGroup(nodeGroup, g string) bool {
	if nodeGroup == g {
		return true
	}
	if strings.HasPrefix(g, "dir:") && strings.HasPrefix(nodeGroup, "dir:") {
		d := strings.TrimPrefix(g, "dir:")
		return d == "." || strings.HasPrefix(strings.TrimPrefix(nodeGroup, "dir:"), d+"/")
	}
	return false
}

// syntheticEdgeID identifies a lifted or aggregated edge.
func syntheticEdgeID(a, typ, b string) string {
	h := sha256.Sum256([]byte(a + "|" + typ + "|" + b))
	return "e:" + hex.EncodeToString(h[:12])
}

// childTypes counts the node types of an aggregate's members.
func (sk *skeleton) childTypes(members []int32) map[string]int {
	out := map[string]int{}
	for _, m := range members {
		out[sk.nodes[m].typ]++
	}
	return out
}

func (sk *skeleton) sumCounts(members []int32) map[string]int {
	out := map[string]int{}
	for _, m := range members {
		for k, v := range sk.nodes[m].sev {
			out[k] += int(v)
		}
	}
	return out
}
