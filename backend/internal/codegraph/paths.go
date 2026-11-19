package codegraph

import (
	"slices"
	"sort"
)

// pathResult is a bounded path search result: paths as lists of edge
// indexes, the edges of the explored shortest-path DAG and whether a
// budget cut the search.
type pathResult struct {
	paths     [][]int32
	edges     []int32
	nodes     []int32
	truncated bool
	budget    bool // the visit budget was exhausted
}

const (
	defaultHops  = 6
	maxHops      = 8
	defaultPaths = 20
	maxPaths     = 50
	visitBudget  = 200_000
)

// paths runs a bounded breadth-first search from `from` along edges in
// direction out (source → target) or in (target → source), over the given
// edge types (all when empty), up to hops. With to ≥ 0 it returns up to
// limit shortest paths to it; otherwise one shortest path to each reached
// node (farthest first, up to limit) and the reached subgraph.
func (sk *skeleton) paths(from, to int32, dir string, hops, limit int, types []string) pathResult {
	var res pathResult
	dist := map[int32]int{from: 0}
	preds := map[int32][]int32{} // node → edges reaching it at its shortest distance
	frontier := []int32{from}
	visited := 1
	for d := 1; d <= hops && len(frontier) > 0; d++ {
		var next []int32
		for _, x := range frontier {
			adj := sk.out[x]
			if dir == "in" {
				adj = sk.in[x]
			}
			for _, ei := range adj {
				e := &sk.edges[ei]
				if len(types) > 0 && !slices.Contains(types, e.typ) {
					continue
				}
				y := e.dst
				if dir == "in" {
					y = e.src
				}
				if dy, seen := dist[y]; seen {
					if dy == d {
						preds[y] = append(preds[y], ei)
					}
					continue
				}
				if visited >= visitBudget {
					res.truncated, res.budget = true, true
					continue
				}
				visited++
				dist[y] = d
				preds[y] = append(preds[y], ei)
				next = append(next, y)
			}
		}
		frontier = next
		if to >= 0 {
			if _, ok := dist[to]; ok {
				break
			}
		}
	}
	if len(frontier) > 0 && to < 0 {
		// More nodes lie beyond the hop limit.
		for _, x := range frontier {
			adj := sk.out[x]
			if dir == "in" {
				adj = sk.in[x]
			}
			if len(adj) > 0 {
				res.truncated = true
				break
			}
		}
	}
	other := func(ei int32) int32 {
		if dir == "in" {
			return sk.edges[ei].dst
		}
		return sk.edges[ei].src
	}
	// enumerate walks back from a node to `from` over the predecessor DAG.
	enumerate := func(target int32, max int) [][]int32 {
		var out [][]int32
		var walk func(n int32, acc []int32)
		walk = func(n int32, acc []int32) {
			if len(out) >= max {
				return
			}
			if n == from {
				p := slices.Clone(acc)
				slices.Reverse(p)
				out = append(out, p)
				return
			}
			for _, ei := range preds[n] {
				walk(other(ei), append(acc, ei))
				if len(out) >= max {
					return
				}
			}
		}
		walk(target, nil)
		return out
	}
	if to >= 0 {
		if _, ok := dist[to]; ok {
			res.paths = enumerate(to, limit)
			if len(res.paths) == limit {
				res.truncated = true
			}
		}
	} else {
		reached := make([]int32, 0, len(dist))
		for n := range dist {
			if n != from {
				reached = append(reached, n)
			}
		}
		sort.Slice(reached, func(i, j int) bool {
			if dist[reached[i]] != dist[reached[j]] {
				return dist[reached[i]] > dist[reached[j]]
			}
			return sk.nodes[reached[i]].key < sk.nodes[reached[j]].key
		})
		// One path to each leaf (nodes no further node was reached from).
		isPred := map[int32]bool{}
		for _, es := range preds {
			for _, ei := range es {
				isPred[other(ei)] = true
			}
		}
		for _, n := range reached {
			if isPred[n] {
				continue
			}
			if len(res.paths) >= limit {
				res.truncated = true
				break
			}
			res.paths = append(res.paths, enumerate(n, 1)...)
		}
	}
	// Nodes and edges of the returned paths.
	seenE := map[int32]bool{}
	seenN := map[int32]bool{from: true}
	res.nodes = append(res.nodes, from)
	for _, p := range res.paths {
		for _, ei := range p {
			if !seenE[ei] {
				seenE[ei] = true
				res.edges = append(res.edges, ei)
			}
			for _, n := range []int32{sk.edges[ei].src, sk.edges[ei].dst} {
				if !seenN[n] {
					seenN[n] = true
					res.nodes = append(res.nodes, n)
				}
			}
		}
	}
	return res
}

// diffResult compares two snapshots by stable node and edge keys.
type diffResult struct {
	addedNodes, removedNodes, changedNodes []string
	addedEdges, removedEdges, changedEdges []string
	removedIdx                             []int32 // removed nodes in the base skeleton
}

// diff compares base with head. A node changed when its label, type,
// layer, file, language, technology, parent or open finding count
// differs; an edge changed when its evidence type differs.
func diff(base, head *skeleton) *diffResult {
	d := &diffResult{}
	parentKey := func(sk *skeleton, i int32) string {
		if p := sk.nodes[i].parent; p >= 0 {
			return sk.nodes[p].key
		}
		return ""
	}
	for i := range head.nodes {
		h := &head.nodes[i]
		j, ok := base.byKey[h.key]
		if !ok {
			d.addedNodes = append(d.addedNodes, h.key)
			continue
		}
		b := &base.nodes[j]
		if b.label != h.label || b.typ != h.typ || b.layer != h.layer || b.file != h.file || b.language != h.language ||
			b.tech != h.tech || b.total != h.total || parentKey(base, j) != parentKey(head, int32(i)) {
			d.changedNodes = append(d.changedNodes, h.key)
		}
	}
	for j := range base.nodes {
		if _, ok := head.byKey[base.nodes[j].key]; !ok {
			d.removedNodes = append(d.removedNodes, base.nodes[j].key)
			d.removedIdx = append(d.removedIdx, int32(j))
		}
	}
	headEdges := make(map[string]string, len(head.edges))
	for i := range head.edges {
		headEdges[head.edges[i].key] = head.edges[i].evidence
	}
	baseEdges := make(map[string]string, len(base.edges))
	for i := range base.edges {
		baseEdges[base.edges[i].key] = base.edges[i].evidence
	}
	for k, ev := range headEdges {
		bev, ok := baseEdges[k]
		switch {
		case !ok:
			d.addedEdges = append(d.addedEdges, k)
		case bev != ev:
			d.changedEdges = append(d.changedEdges, k)
		}
	}
	for k := range baseEdges {
		if _, ok := headEdges[k]; !ok {
			d.removedEdges = append(d.removedEdges, k)
		}
	}
	for _, l := range [][]string{d.addedNodes, d.removedNodes, d.changedNodes, d.addedEdges, d.removedEdges, d.changedEdges} {
		sort.Strings(l)
	}
	return d
}
