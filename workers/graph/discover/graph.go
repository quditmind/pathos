package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Schema is the output format identifier (the contract with the PATHOS API).
const Schema = "pathos.codegraph/v1"

// Node and edge types of the contract. "application" nodes and "owns"
// edges are added by the API (ownership), never by discovery.
var (
	nodeTypes = map[string]string{ // type -> layer
		"repository": "ownership", "module": "code", "file": "code", "function": "code", "class": "code",
		"route": "api", "api_operation": "api", "datastore": "data", "queue": "data", "secret_ref": "data",
		"external_service": "deploy", "container": "deploy", "iac_resource": "deploy", "trust_boundary": "deploy",
		"component": "dependency",
	}
	edgeTypes = map[string]bool{
		"calls": true, "imports": true, "defines": true, "exposes": true, "reads": true, "writes": true,
		"publishes": true, "consumes": true, "depends_on": true, "deployed_as": true, "crosses_boundary": true,
	}
	refKinds = map[string]bool{"file_line": true, "sbom": true, "scan": true}
)

const (
	maxKey        = 300
	maxLabel      = 500
	maxDetail     = 300
	maxRefsByEdge = 5
	maxAttrString = 500
)

// Ref is one piece of evidence of an edge.
type Ref struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Detail string `json:"detail,omitempty"`
}

// Node is a graph node.
type Node struct {
	Key    string         `json:"key"`
	Type   string         `json:"type"`
	Label  string         `json:"label"`
	Parent string         `json:"parent"`
	Layer  string         `json:"layer"`
	Attrs  map[string]any `json:"attrs"`
}

// Edge is a graph edge. Discovery only produces verified (static) edges.
type Edge struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Type     string `json:"type"`
	Evidence string `json:"evidence"`
	Refs     []Ref  `json:"evidence_refs"`
}

// Skipped records a file or engine that was not analysed.
type Skipped struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

// Stats summarises a run.
type Stats struct {
	FilesScanned int            `json:"files_scanned"`
	DurationMS   int64          `json:"duration_ms"`
	Languages    map[string]int `json:"languages"`
	Skipped      []Skipped      `json:"skipped"`
	Truncated    bool           `json:"truncated"`
	NodeCount    int            `json:"node_count"`
	EdgeCount    int            `json:"edge_count"`
}

// Output is the document written by `pathos-graph discover`.
type Output struct {
	Schema    string            `json:"schema"`
	Generator map[string]string `json:"generator"`
	Engines   map[string]string `json:"engines"`
	Stats     Stats             `json:"stats"`
	Nodes     []*Node           `json:"nodes"`
	Edges     []*Edge           `json:"edges"`
}

// Graph collects nodes and edges with de-duplication and limits.
type Graph struct {
	nodes     map[string]*Node
	edges     map[string]*Edge
	maxNodes  int
	maxEdges  int
	truncated bool
}

func newGraph(maxNodes, maxEdges int) *Graph {
	return &Graph{nodes: map[string]*Node{}, edges: map[string]*Edge{}, maxNodes: maxNodes, maxEdges: maxEdges}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && n < len(s) && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

// AddNode adds a node (or merges the attributes it lacks into an existing
// one) and reports whether the node exists afterwards.
func (g *Graph) AddNode(key, typ, label, parent string, attrs map[string]any) bool {
	if key == "" || len(key) > maxKey {
		return false
	}
	layer, ok := nodeTypes[typ]
	if !ok {
		return false
	}
	if n, ok := g.nodes[key]; ok {
		for k, v := range attrs {
			if _, has := n.Attrs[k]; !has && v != nil && v != "" {
				n.Attrs[k] = cleanAttr(v)
			}
		}
		if n.Parent == "" && parent != "" && parent != key {
			n.Parent = parent
		}
		return true
	}
	if len(g.nodes) >= g.maxNodes {
		g.truncated = true
		return false
	}
	if label == "" {
		label = key
	}
	a := map[string]any{}
	for k, v := range attrs {
		if v == nil || v == "" {
			continue
		}
		a[k] = cleanAttr(v)
	}
	if parent == key {
		parent = ""
	}
	g.nodes[key] = &Node{Key: key, Type: typ, Label: clip(label, maxLabel), Parent: parent, Layer: layer, Attrs: a}
	return true
}

func cleanAttr(v any) any {
	switch x := v.(type) {
	case string:
		return clip(x, maxAttrString)
	case int, int64, float64, bool:
		return x
	}
	return clip(fmt.Sprint(v), maxAttrString)
}

// Has reports whether a node exists.
func (g *Graph) Has(key string) bool { _, ok := g.nodes[key]; return ok }

// Node returns a node (nil when absent).
func (g *Graph) Node(key string) *Node { return g.nodes[key] }

// AddEdge adds a verified edge with one piece of evidence. Edges between
// unknown nodes, self-loops and edges without evidence are dropped.
func (g *Graph) AddEdge(src, typ, dst string, ref Ref) bool {
	if src == "" || dst == "" || src == dst || !edgeTypes[typ] || !g.Has(src) || !g.Has(dst) {
		return false
	}
	if !refKinds[ref.Kind] || ref.Ref == "" {
		return false
	}
	ref.Ref = clip(ref.Ref, maxKey)
	ref.Detail = clip(ref.Detail, maxDetail)
	id := src + "\x00" + typ + "\x00" + dst
	if e, ok := g.edges[id]; ok {
		if len(e.Refs) < maxRefsByEdge {
			for _, r := range e.Refs {
				if r.Kind == ref.Kind && r.Ref == ref.Ref {
					return true
				}
			}
			e.Refs = append(e.Refs, ref)
		}
		return true
	}
	if len(g.edges) >= g.maxEdges {
		g.truncated = true
		return false
	}
	g.edges[id] = &Edge{Source: src, Target: dst, Type: typ, Evidence: "verified", Refs: []Ref{ref}}
	return true
}

// Validate checks the invariants of the contract: one repository node,
// known types, existing parents and endpoints, evidence on every edge.
func (g *Graph) Validate() error {
	repos := 0
	for _, n := range g.nodes {
		if n.Type == "repository" {
			repos++
			if n.Key != "repository" {
				return fmt.Errorf("repository node has key %q", n.Key)
			}
		}
		if n.Parent != "" && !g.Has(n.Parent) {
			return fmt.Errorf("node %q: parent %q does not exist", n.Key, n.Parent)
		}
	}
	if repos != 1 {
		return fmt.Errorf("%d repository nodes, want 1", repos)
	}
	for _, e := range g.edges {
		if len(e.Refs) == 0 {
			return fmt.Errorf("edge %s -%s-> %s has no evidence", e.Source, e.Type, e.Target)
		}
		if e.Evidence != "verified" {
			return fmt.Errorf("edge %s -%s-> %s: discovery produces verified edges only", e.Source, e.Type, e.Target)
		}
		if !g.Has(e.Source) || !g.Has(e.Target) {
			return errors.New("edge endpoint missing: " + e.Source + " -> " + e.Target)
		}
	}
	return nil
}

// fixParents drops parents that do not exist (a parent may have been
// refused by the node limit) so the containment tree stays valid.
func (g *Graph) fixParents() {
	for _, n := range g.nodes {
		if n.Parent != "" && !g.Has(n.Parent) {
			if n.Type == "component" || n.Type == "datastore" || n.Type == "queue" || n.Type == "external_service" ||
				n.Type == "trust_boundary" || n.Type == "secret_ref" || n.Type == "repository" {
				n.Parent = ""
			} else {
				n.Parent = "repository"
			}
		}
	}
}

// Sorted returns nodes by key and edges by (source, type, target).
func (g *Graph) Sorted() ([]*Node, []*Edge) {
	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Key < nodes[j].Key })
	edges := make([]*Edge, 0, len(g.edges))
	for _, e := range g.edges {
		sort.SliceStable(e.Refs, func(i, j int) bool {
			if e.Refs[i].Kind != e.Refs[j].Kind {
				return e.Refs[i].Kind < e.Refs[j].Kind
			}
			return e.Refs[i].Ref < e.Refs[j].Ref
		})
		edges = append(edges, e)
	}
	sort.Slice(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		return a.Target < b.Target
	})
	return nodes, edges
}

// Write encodes the output document.
func (o *Output) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(o)
}

// fileLine is a file_line evidence reference.
func fileLine(path string, line int, detail string) Ref {
	return Ref{Kind: "file_line", Ref: fmt.Sprintf("%s:%d", path, max(line, 1)), Detail: oneLine(detail)}
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return clip(s, maxDetail)
}
