package vuln

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Dependency graph of an SBOM: which component depends on which.
//
// CycloneDX: the "dependencies" list ({ref, dependsOn}). SPDX 2.x:
// DEPENDS_ON and *DEPENDENCY_OF relationships (CONTAINS is ignored: it
// means "is part of the scanned directory", not "is a dependency of").
//
// Each component gets a depth: 0 for a root (a package nothing depends on,
// typically the project itself), 1 for a direct dependency of a root, 2+
// for transitive ones, and none when the SBOM has no edge for it.

// Edge is "Parent depends on Child" (component refs).
type Edge struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
}

// Graph is the dependency information of one SBOM.
type Graph struct {
	Edges []Edge
	// Roots declared by the document (CycloneDX metadata.component, SPDX
	// DESCRIBES); used when they have dependencies of their own.
	Roots []string
}

const maxEdges = 200000

// ParseGraph extracts the dependency graph of a CycloneDX or SPDX JSON SBOM.
// Refs match Component.Ref. An SBOM without dependency data has no edges.
func ParseGraph(raw []byte) Graph {
	switch DetectSBOM(raw) {
	case "cyclonedx":
		return cyclonedxGraph(raw)
	case "spdx":
		return spdxGraph(raw)
	}
	return Graph{}
}

func cyclonedxGraph(raw []byte) Graph {
	var doc struct {
		Metadata struct {
			Component struct {
				Ref string `json:"bom-ref"`
			} `json:"component"`
		} `json:"metadata"`
		Dependencies []struct {
			Ref       string   `json:"ref"`
			DependsOn []string `json:"dependsOn"`
		} `json:"dependencies"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return Graph{}
	}
	var g Graph
	if r := doc.Metadata.Component.Ref; r != "" {
		g.Roots = []string{r}
	}
	for _, d := range doc.Dependencies {
		for _, c := range d.DependsOn {
			if len(g.Edges) >= maxEdges {
				return g
			}
			if d.Ref != "" && c != "" && c != d.Ref {
				g.Edges = append(g.Edges, Edge{Parent: clip(d.Ref, 1000), Child: clip(c, 1000)})
			}
		}
	}
	return g
}

func spdxGraph(raw []byte) Graph {
	var doc struct {
		DocumentDescribes []string `json:"documentDescribes"`
		Relationships     []struct {
			Element string `json:"spdxElementId"`
			Type    string `json:"relationshipType"`
			Related string `json:"relatedSpdxElement"`
		} `json:"relationships"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return Graph{}
	}
	g := Graph{Roots: doc.DocumentDescribes}
	for _, r := range doc.Relationships {
		if len(g.Edges) >= maxEdges {
			break
		}
		t := strings.ToUpper(r.Type)
		switch {
		case t == "DESCRIBES" && r.Element == "SPDXRef-DOCUMENT":
			g.Roots = append(g.Roots, r.Related)
		case t == "DEPENDS_ON":
			g.Edges = append(g.Edges, Edge{Parent: clip(r.Element, 1000), Child: clip(r.Related, 1000)})
		case strings.HasSuffix(t, "DEPENDENCY_OF"):
			g.Edges = append(g.Edges, Edge{Parent: clip(r.Related, 1000), Child: clip(r.Element, 1000)})
		}
	}
	return g
}

// Depths computes each ref's shortest distance from a root. Declared roots
// count only when they have dependencies; otherwise the roots are the refs
// that depend on something and that nothing depends on.
func Depths(g Graph) map[string]int {
	out := map[string]int{}
	children := map[string][]string{}
	hasParent := map[string]bool{}
	for _, e := range g.Edges {
		children[e.Parent] = append(children[e.Parent], e.Child)
		hasParent[e.Child] = true
	}
	var roots []string
	for _, r := range g.Roots {
		if len(children[r]) > 0 {
			roots = append(roots, r)
		}
	}
	if len(roots) == 0 {
		for p := range children {
			if !hasParent[p] {
				roots = append(roots, p)
			}
		}
	}
	queue := make([]string, 0, len(roots))
	for _, r := range roots {
		if _, ok := out[r]; !ok {
			out[r] = 0
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, c := range children[n] {
			if _, ok := out[c]; !ok {
				out[c] = out[n] + 1
				queue = append(queue, c)
			}
		}
	}
	return out
}

// storeGraph writes a repository's dependency edges and component depths
// (after its components were replaced). aliases maps refs of duplicate
// components to the kept component's ref.
func storeGraph(ctx context.Context, tx pgx.Tx, orgID, repoID uuid.UUID, g Graph, aliases map[string]string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM sbom_dependencies WHERE repository_id = $1`, repoID); err != nil {
		return err
	}
	if len(g.Edges) == 0 {
		return nil
	}
	resolve := func(r string) string {
		if a, ok := aliases[r]; ok {
			return a
		}
		return r
	}
	seen := map[Edge]bool{}
	rows := make([][]any, 0, len(g.Edges))
	for i, e := range g.Edges {
		e = Edge{Parent: resolve(e.Parent), Child: resolve(e.Child)}
		g.Edges[i] = e
		if e.Parent == e.Child || seen[e] {
			continue
		}
		seen[e] = true
		rows = append(rows, []any{orgID, repoID, e.Parent, e.Child})
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"sbom_dependencies"}, []string{"organization_id", "repository_id", "parent_ref", "child_ref"},
		pgx.CopyFromRows(rows)); err != nil {
		return err
	}
	depths := Depths(g)
	refs := make([]string, 0, len(depths))
	ds := make([]int32, 0, len(depths))
	for r, d := range depths {
		refs = append(refs, r)
		ds = append(ds, int32(min(d, 1000))) // #nosec G115 -- bounded above
	}
	_, err := tx.Exec(ctx, `UPDATE sbom_components c SET depth = x.d
		FROM unnest($2::text[], $3::int[]) AS x(ref, d)
		WHERE c.repository_id = $1 AND c.bom_ref = x.ref AND c.bom_ref <> ''`, repoID, refs, ds)
	return err
}
