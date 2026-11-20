package codegraph

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"pathos/internal/authz"
)

// Binary graphs (PATHOS 3.0 M10): the facts of a reverse-engineering
// analysis (package rea) stored in the same store as source graphs, as a
// snapshot of kind "binary" (trigger "rea"). They are read only through the
// rea package's API, never through the CodeGraph views of an application,
// and threat models never use them. Every edge is verified, with evidence of
// kind "binary": the file offset in the artifact (ref "0x…") and the tool
// that found it (detail).

// Snapshot kinds.
const (
	KindSource = "source"
	KindBinary = "binary"
)

// Binary node types: the artifact, its functions, imported functions or
// packages, referenced strings and sections.
var BinaryNodeTypes = []string{"binary", "binary_function", "import", "string_ref", "section"}

// Binary edge types: defines (artifact → section → function), calls
// (function → function or import), imports (artifact → import) and
// references (function → string).
var BinaryEdgeTypes = []string{"defines", "calls", "imports", "references"}

var binaryLayer = map[string]string{"binary": "code", "binary_function": "code", "section": "code", "import": "dependency", "string_ref": "data"}

// BinaryViews are the views of a binary graph.
var BinaryViews = []viewDef{
	{Name: "binary_call_graph", Title: "Call graph", Description: "Functions of the artifact, the calls between them and the imported functions they call.",
		NodeTypes: []string{"binary_function", "import"}, EdgeTypes: []string{"calls"}, Prune: []string{"import"}},
	{Name: "binary_imports", Title: "Imports", Description: "Libraries, packages and functions the artifact imports.",
		NodeTypes: []string{"binary", "import"}, EdgeTypes: []string{"imports"}},
	{Name: "binary_layout", Title: "Layout", Description: "Sections of the artifact and the functions they contain.",
		NodeTypes: []string{"binary", "section", "binary_function"}, EdgeTypes: []string{"defines"}},
	{Name: "binary_strings", Title: "String references", Description: "Functions and the strings they reference (secrets redacted).",
		NodeTypes: []string{"binary_function", "string_ref"}, EdgeTypes: []string{"references"}, Prune: []string{"binary_function", "string_ref"}},
}

var binaryRefRe = regexp.MustCompile(`^0x[0-9a-f]{1,16}$`)

// BinaryRef is the artifact a binary graph belongs to.
type BinaryRef struct {
	OrgID, RepoID uuid.UUID
	AppID         *uuid.UUID
	CommitSHA     string
	Partial       bool
	Engines       map[string]string
	Stats         map[string]any
}

// ValidateBinary checks a binary graph: binary node types only, exactly
// one binary root, edges between existing nodes of the binary edge types,
// every edge verified with binary evidence (ref 0x<offset>). Duplicate
// edges are merged.
func ValidateBinary(d *Doc) error {
	if len(d.Nodes) == 0 {
		return invalid("no nodes")
	}
	if len(d.Nodes) > maxNodes || len(d.Edges) > maxEdges {
		return invalid("%d nodes and %d edges exceed the store limits (%d, %d)", len(d.Nodes), len(d.Edges), maxNodes, maxEdges)
	}
	keys := make(map[string]int, len(d.Nodes))
	roots := 0
	for i := range d.Nodes {
		n := &d.Nodes[i]
		if n.Key == "" || len(n.Key) > maxKeyLen {
			return invalid("node %d: key must be 1 to %d characters", i, maxKeyLen)
		}
		if !slices.Contains(BinaryNodeTypes, n.Type) {
			return invalid("node %q: type %q is not a binary node type", n.Key, n.Type)
		}
		if _, dup := keys[n.Key]; dup {
			return invalid("duplicate node key %q", n.Key)
		}
		keys[n.Key] = i
		if n.Type == "binary" {
			roots++
		}
		n.Layer = binaryLayer[n.Type]
		n.Label = clip(strings.TrimSpace(n.Label), maxLabelLen)
		if n.Label == "" {
			n.Label = clip(n.Key, maxLabelLen)
		}
	}
	if roots != 1 {
		return invalid("%d binary nodes, want exactly 1", roots)
	}
	for i := range d.Nodes {
		n := &d.Nodes[i]
		if n.Parent == "" {
			continue
		}
		if _, ok := keys[n.Parent]; !ok || n.Parent == n.Key {
			return invalid("node %q: parent %q does not exist", n.Key, n.Parent)
		}
	}
	if err := checkAcyclic(d.Nodes, keys); err != nil {
		return err
	}
	merged := make(map[string]int, len(d.Edges))
	out := d.Edges[:0]
	for i := range d.Edges {
		e := d.Edges[i]
		if _, ok := keys[e.Source]; !ok {
			return invalid("edge %d: source %q does not exist", i, e.Source)
		}
		if _, ok := keys[e.Target]; !ok {
			return invalid("edge %d: target %q does not exist", i, e.Target)
		}
		if !slices.Contains(BinaryEdgeTypes, e.Type) {
			return invalid("edge %s→%s: type %q is not a binary edge type", e.Source, e.Target, e.Type)
		}
		if e.Evidence != EvidenceVerified {
			return invalid("edge %s→%s: evidence %q, static analysis produces verified edges only", e.Source, e.Target, e.Evidence)
		}
		if len(e.EvidenceRefs) == 0 {
			return invalid("edge %s -%s-> %s has no evidence_refs", e.Source, e.Type, e.Target)
		}
		for j := range e.EvidenceRefs {
			r := &e.EvidenceRefs[j]
			if r.Kind != "binary" || !binaryRefRe.MatchString(r.Ref) {
				return invalid("edge %s→%s: evidence must be binary offsets (0x…), got %s %q", e.Source, e.Target, r.Kind, r.Ref)
			}
			r.Detail = clip(r.Detail, maxDetailLen)
		}
		k := EdgeKey(e.Source, e.Type, e.Target)
		if j, ok := merged[k]; ok {
			for _, r := range e.EvidenceRefs {
				if len(out[j].EvidenceRefs) < maxRefsPerEdge && !slices.Contains(out[j].EvidenceRefs, r) {
					out[j].EvidenceRefs = append(out[j].EvidenceRefs, r)
				}
			}
			continue
		}
		if len(e.EvidenceRefs) > maxRefsPerEdge {
			e.EvidenceRefs = e.EvidenceRefs[:maxRefsPerEdge]
		}
		merged[k] = len(out)
		out = append(out, e)
	}
	d.Edges = out
	return nil
}

// StoreBinary validates a binary graph and stores it as a new ready (or
// partial) binary snapshot in the caller's transaction. It returns the
// snapshot id and the node keys mapped to their stored ids.
func StoreBinary(ctx context.Context, tx pgx.Tx, ref BinaryRef, d *Doc) (uuid.UUID, map[string]uuid.UUID, error) {
	if err := ValidateBinary(d); err != nil {
		return uuid.Nil, nil, err
	}
	sref := snapshotRef{ID: uuid.Must(uuid.NewV7()), OrgID: ref.OrgID, RepoID: ref.RepoID}
	byKey := make(map[string]*node, len(d.Nodes))
	nodes := make([]*node, 0, len(d.Nodes))
	for _, dn := range d.Nodes {
		n := &node{DocNode: dn, id: uuid.Must(uuid.NewV7())}
		n.Attrs = cleanAttrs(n.Attrs)
		n.language = clip(attrString(n.Attrs, "language"), 64)
		n.tech = clip(attrString(n.Attrs, "tool"), 200)
		byKey[n.Key] = n
		nodes = append(nodes, n)
	}
	var root *node
	for _, n := range nodes {
		if n.Type == "binary" {
			root = n
		}
	}
	for _, n := range nodes {
		if n.Parent == "" && n != root {
			n.Parent = root.Key
		}
		if p := byKey[n.Parent]; p != nil {
			n.parentID = &p.id
		}
	}
	for _, n := range nodes {
		n.depth = min(depthOf(n, byKey), 64)
		// Aggregation: functions by package (Go) or section, the rest by type.
		switch {
		case n.Type == "binary_function" && attrString(n.Attrs, "package") != "":
			n.group = "pkg:" + clip(attrString(n.Attrs, "package"), 280)
		case n.Type == "binary_function" && attrString(n.Attrs, "section") != "":
			n.group = "section:" + clip(attrString(n.Attrs, "section"), 280)
		case n.Type == "import" && attrString(n.Attrs, "library") != "":
			n.group = "lib:" + clip(attrString(n.Attrs, "library"), 280)
		default:
			n.group = "type:" + n.Type
		}
	}
	sort.SliceStable(nodes, func(i, j int) bool { return nodes[i].depth < nodes[j].depth })
	edges := make([]*edge, 0, len(d.Edges))
	for _, de := range d.Edges {
		edges = append(edges, &edge{id: uuid.Must(uuid.NewV7()), key: EdgeKey(de.Source, de.Type, de.Target),
			source: byKey[de.Source].id, target: byKey[de.Target].id, typ: de.Type, evidence: de.Evidence, refs: de.EvidenceRefs})
	}
	status := "ready"
	if ref.Partial {
		status = "partial"
	}
	engines, _ := json.Marshal(nonNilMap(ref.Engines))
	stats, _ := json.Marshal(trimStats(nonNilAny(ref.Stats)))
	if _, err := tx.Exec(ctx, `INSERT INTO codegraph_snapshots (id, organization_id, application_id, repository_id, commit_sha, trigger,
		status, kind, engines, stats, node_count, edge_count, started_at, finished_at)
		VALUES ($1, $2, $3, $4, $5, 'rea', $6, 'binary', $7, $8, $9, $10, now(), now())`,
		sref.ID, ref.OrgID, ref.AppID, ref.RepoID, ref.CommitSHA, status, engines, stats, len(nodes), len(edges)); err != nil {
		return uuid.Nil, nil, fmt.Errorf("binary snapshot: %w", err)
	}
	if err := insertNodes(ctx, tx, sref, nodes); err != nil {
		return uuid.Nil, nil, err
	}
	if err := insertEdges(ctx, tx, sref, edges); err != nil {
		return uuid.Nil, nil, err
	}
	ids := make(map[string]uuid.UUID, len(nodes))
	for _, n := range nodes {
		ids[n.Key] = n.id
	}
	return sref.ID, ids, nil
}

func nonNilMap(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

func nonNilAny(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// binarySnapshot loads a binary snapshot of the organization.
func (s *Service) binarySnapshot(ctx context.Context, p *authz.Principal, id uuid.UUID) (Snapshot, error) {
	sn, err := scanSnapshot(s.DB.QueryRow(ctx, snapshotSelect+` WHERE s.organization_id = $1 AND s.id = $2 AND s.kind = 'binary'`,
		p.OrganizationID, id))
	if err != nil {
		return sn, err
	}
	return sn, s.requireRepo(ctx, p, authz.PermFindingsRead, sn.RepositoryID)
}

// BinaryGraph computes a view of a binary snapshot (query parameters as
// the CodeGraph graph endpoint, views BinaryViews). The caller (rea) has
// checked the feature flag; access is checked on the repository.
func (s *Service) BinaryGraph(ctx context.Context, p *authz.Principal, snapshotID uuid.UUID, q url.Values) (map[string]any, error) {
	sn, err := s.binarySnapshot(ctx, p, snapshotID)
	if err != nil {
		return nil, err
	}
	def, vp, err := parseViewParamsIn(q, BinaryViews, BinaryNodeTypes, "binary_call_graph")
	if err != nil {
		return nil, err
	}
	return s.graphOf(ctx, p, sn, def, vp, "")
}

// BinaryNode is the node inspector of a binary snapshot.
func (s *Service) BinaryNode(ctx context.Context, p *authz.Principal, snapshotID, nodeID uuid.UUID) (map[string]any, error) {
	sn, err := s.binarySnapshot(ctx, p, snapshotID)
	if err != nil {
		return nil, err
	}
	return s.nodeOf(ctx, sn, nodeID)
}

// IsNotFound reports a missing snapshot or node (callers answer 404).
func IsNotFound(err error) bool { return errors.Is(err, errNotFound) || errors.Is(err, pgx.ErrNoRows) }
