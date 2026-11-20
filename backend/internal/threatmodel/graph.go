package threatmodel

import (
	"pathos/internal/codegraph"
)

// GraphFromDoc builds an engine graph from a CodeGraph discovery document
// (tests and fixtures: node and edge ids are their keys).
func GraphFromDoc(d *codegraph.Doc, repositoryID string) *Graph {
	g := &Graph{SnapshotID: "fixture", RepositoryID: repositoryID}
	for _, n := range d.Nodes {
		node := Node{ID: n.Key, Key: n.Key, Type: n.Type, Label: n.Label, Attrs: n.Attrs}
		if n.Label == "" {
			node.Label = n.Key
		}
		if f, ok := n.Attrs["file"].(string); ok {
			node.File = f
		}
		switch l := n.Attrs["line"].(type) {
		case float64:
			node.Line = int(l)
		case int:
			node.Line = l
		}
		g.Nodes = append(g.Nodes, node)
	}
	for _, e := range d.Edges {
		ev := e.Evidence
		if ev == "" {
			ev = EvidenceVerified
		}
		key := codegraph.EdgeKey(e.Source, e.Type, e.Target)
		edge := Edge{ID: key, Key: key, Source: e.Source, Target: e.Target, Type: e.Type, Evidence: ev}
		for _, r := range e.EvidenceRefs {
			edge.Refs = append(edge.Refs, Ref{Kind: r.Kind, Ref: r.Ref, Detail: r.Detail})
		}
		g.Edges = append(g.Edges, edge)
	}
	return g
}
