// Package codegraph is the CodeGraph store, service and API (PATHOS 3.0
// M4, docs/aspm/PATHOS_CODEGRAPH_ARCHITECTURE.md).
//
// A discovery job (the pathos-graph tool in the worker-graph family image,
// run as a scan execution with trigger "codegraph") uploads a graph
// document (schema pathos.codegraph/v1). The API validates it, adds the
// ownership layer (application → repository, from the PATHOS inventory),
// observed runtime edges (Kubernetes runtime context) and the open findings
// of the repository (attached by file and line), and stores it as one
// snapshot per application, repository and commit in PostgreSQL (ADR-004).
//
// Every edge carries evidence (rule 5): verified (static: a file and line,
// an SBOM record, a rule match, an inventory record), observed (runtime)
// or ai_inferred (an AI evidence record; discovery never produces these).
// The database refuses an edge without evidence (deferred constraint
// trigger, migration 00049).
package codegraph

import (
	"fmt"
	"slices"
	"strings"
)

// Schema is the discovery document schema this package accepts.
const Schema = "pathos.codegraph/v1"

// ExportSchema is the schema of GET .../export?format=json.
const ExportSchema = "pathos.codegraph.export/v1"

// Node types of the engine ↔ UI contract.
var NodeTypes = []string{"repository", "module", "file", "function", "class", "route", "api_operation", "datastore", "queue",
	"external_service", "container", "iac_resource", "component", "secret_ref", "trust_boundary", "application"}

// Edge types of the contract.
var EdgeTypes = []string{"calls", "imports", "defines", "exposes", "reads", "writes", "publishes", "consumes", "depends_on",
	"deployed_as", "crosses_boundary", "owns"}

// Layers of the contract.
var Layers = []string{"code", "api", "data", "deploy", "dependency", "ownership"}

// Evidence types (rule 5), strongest first.
const (
	EvidenceVerified   = "verified"
	EvidenceObserved   = "observed"
	EvidenceAIInferred = "ai_inferred"
)

// EvidenceTypes lists the three evidence types, strongest first.
var EvidenceTypes = []string{EvidenceVerified, EvidenceObserved, EvidenceAIInferred}

// Evidence reference kinds. registry (an inventory record of PATHOS, the
// ownership layer) extends the contract's file_line|sbom|scan|runtime|ai_record.
var RefKinds = []string{"file_line", "sbom", "scan", "registry", "runtime", "ai_record"}

// refEvidence is the evidence type each reference kind proves.
var refEvidence = map[string]string{"file_line": EvidenceVerified, "sbom": EvidenceVerified, "scan": EvidenceVerified,
	"registry": EvidenceVerified, "runtime": EvidenceObserved, "ai_record": EvidenceAIInferred,
	// binary: a file offset in an analysed artifact (binary graphs only,
	// binary.go; never accepted in a discovery document).
	"binary": EvidenceVerified}

// defaultLayer is the layer of a node type when the document gives none.
var defaultLayer = map[string]string{"repository": "ownership", "application": "ownership", "module": "code", "file": "code",
	"function": "code", "class": "code", "route": "api", "api_operation": "api", "datastore": "data", "queue": "data",
	"secret_ref": "data", "external_service": "deploy", "container": "deploy", "iac_resource": "deploy", "trust_boundary": "deploy",
	"component": "dependency"}

// evidenceRank orders evidence types (lower is stronger).
func evidenceRank(e string) int {
	if i := slices.Index(EvidenceTypes, e); i >= 0 {
		return i
	}
	return len(EvidenceTypes)
}

// Doc is a discovery document (pathos.codegraph/v1).
type Doc struct {
	Schema    string            `json:"schema"`
	Generator map[string]string `json:"generator"`
	Engines   map[string]string `json:"engines"`
	Stats     map[string]any    `json:"stats"`
	Nodes     []DocNode         `json:"nodes"`
	Edges     []DocEdge         `json:"edges"`
}

// DocNode is a node of a discovery document.
type DocNode struct {
	Key    string         `json:"key"`
	Type   string         `json:"type"`
	Label  string         `json:"label"`
	Parent string         `json:"parent"`
	Layer  string         `json:"layer"`
	Attrs  map[string]any `json:"attrs"`
}

// DocEdge is an edge of a discovery document.
type DocEdge struct {
	Source       string        `json:"source"`
	Target       string        `json:"target"`
	Type         string        `json:"type"`
	Evidence     string        `json:"evidence"`
	EvidenceRefs []EvidenceRef `json:"evidence_refs"`
}

// EvidenceRef is one piece of evidence of an edge.
type EvidenceRef struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Detail string `json:"detail"`
}

// Limits of a stored snapshot (the discovery engine caps its own output
// lower; these protect the store).
const (
	maxNodes        = 400_000
	maxEdges        = 600_000
	maxRefsPerEdge  = 5
	maxKeyLen       = 300
	maxLabelLen     = 500
	maxRefLen       = 1000
	maxDetailLen    = 500
	maxAttrBytes    = 4096
	maxDocBytesHint = 256 << 20
)

// ValidationError is a discovery document that cannot be stored
// (PTH-DISC-1004).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return "invalid CodeGraph document: " + e.Msg }

func invalid(format string, a ...any) error { return &ValidationError{Msg: fmt.Sprintf(format, a...)} }

// Validate checks a discovery document against the contract: known
// schema, node and edge types and layers, unique keys, edges between
// existing nodes, and evidence on every edge whose type matches its
// references. Discovery is static only, so an ai_inferred edge is refused.
// It normalises what it can (default layer, truncated labels, merged
// duplicate edges).
func Validate(d *Doc) error {
	if d.Schema != Schema {
		return invalid("schema %q, want %q", d.Schema, Schema)
	}
	if len(d.Nodes) == 0 {
		return invalid("no nodes")
	}
	if len(d.Nodes) > maxNodes || len(d.Edges) > maxEdges {
		return invalid("%d nodes and %d edges exceed the store limits (%d, %d)", len(d.Nodes), len(d.Edges), maxNodes, maxEdges)
	}
	keys := make(map[string]int, len(d.Nodes))
	repos := 0
	for i := range d.Nodes {
		n := &d.Nodes[i]
		switch {
		case n.Key == "" || len(n.Key) > maxKeyLen:
			return invalid("node %d: key must be 1 to %d characters", i, maxKeyLen)
		case !slices.Contains(NodeTypes, n.Type) || n.Type == "application":
			return invalid("node %q: unknown type %q", n.Key, n.Type)
		}
		if _, dup := keys[n.Key]; dup {
			return invalid("duplicate node key %q", n.Key)
		}
		keys[n.Key] = i
		if n.Type == "repository" {
			repos++
		}
		if n.Layer == "" {
			n.Layer = defaultLayer[n.Type]
		}
		if !slices.Contains(Layers, n.Layer) {
			return invalid("node %q: unknown layer %q", n.Key, n.Layer)
		}
		n.Label = clip(strings.TrimSpace(n.Label), maxLabelLen)
		if n.Label == "" {
			n.Label = clip(n.Key, maxLabelLen)
		}
	}
	if repos != 1 {
		return invalid("%d repository nodes, want exactly 1", repos)
	}
	for i := range d.Nodes {
		n := &d.Nodes[i]
		if n.Parent == "" {
			continue
		}
		if n.Parent == n.Key {
			return invalid("node %q is its own parent", n.Key)
		}
		if _, ok := keys[n.Parent]; !ok {
			return invalid("node %q: parent %q does not exist", n.Key, n.Parent)
		}
	}
	if err := checkAcyclic(d.Nodes, keys); err != nil {
		return err
	}
	// Merge duplicate edges (same source, type, target), keeping the
	// strongest evidence type and up to maxRefsPerEdge references.
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
		if !slices.Contains(EdgeTypes, e.Type) || e.Type == "owns" {
			return invalid("edge %s→%s: unknown type %q", e.Source, e.Target, e.Type)
		}
		if e.Evidence != EvidenceVerified {
			// Discovery is static: observed edges come from the runtime
			// context and AI-inferred ones from AI evidence records, both
			// added by PATHOS, never by the document.
			return invalid("edge %s→%s: evidence %q, discovery produces verified edges only", e.Source, e.Target, e.Evidence)
		}
		if len(e.EvidenceRefs) == 0 {
			return invalid("edge %s -%s-> %s has no evidence_refs", e.Source, e.Type, e.Target)
		}
		refs := e.EvidenceRefs[:0:0]
		for _, r := range e.EvidenceRefs {
			if !slices.Contains(RefKinds, r.Kind) || refEvidence[r.Kind] != EvidenceVerified {
				return invalid("edge %s→%s: evidence ref kind %q is not static evidence", e.Source, e.Target, r.Kind)
			}
			r.Ref = clip(strings.TrimSpace(r.Ref), maxRefLen)
			r.Detail = clip(r.Detail, maxDetailLen)
			if r.Ref == "" {
				return invalid("edge %s→%s: empty evidence ref", e.Source, e.Target)
			}
			if r.Kind == "file_line" {
				if p, _ := splitFileLine(r.Ref); p == "" {
					return invalid("edge %s→%s: file_line ref %q is not <path>:<line>", e.Source, e.Target, r.Ref)
				}
			}
			refs = append(refs, r)
		}
		e.EvidenceRefs = refs
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

// checkAcyclic rejects a containment cycle (aggregation walks parents).
func checkAcyclic(nodes []DocNode, keys map[string]int) error {
	state := make([]uint8, len(nodes)) // 0 new, 1 on the current chain, 2 done
	for i := range nodes {
		var chain []int
		j := i
		for j >= 0 && state[j] == 0 {
			state[j] = 1
			chain = append(chain, j)
			p := nodes[j].Parent
			if p == "" {
				j = -1
				break
			}
			j = keys[p]
		}
		if j >= 0 && state[j] == 1 {
			return invalid("containment cycle at node %q", nodes[j].Key)
		}
		for _, c := range chain {
			state[c] = 2
		}
	}
	return nil
}

// EdgeKey is the stable key of an edge (diffs between snapshots).
func EdgeKey(source, typ, target string) string { return source + "|" + typ + "|" + target }

// splitFileLine splits "<path>:<line>" (line optional).
func splitFileLine(ref string) (string, int) {
	i := strings.LastIndexByte(ref, ':')
	if i == 0 {
		return "", 0
	}
	if i < 0 {
		return ref, 0
	}
	n := 0
	for _, c := range ref[i+1:] {
		if c < '0' || c > '9' {
			return ref, 0
		}
		n = n*10 + int(c-'0')
		if n > 1<<30 {
			return ref, 0
		}
	}
	if i+1 == len(ref) {
		return ref[:i], 0
	}
	return ref[:i], n
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Do not cut a UTF-8 sequence.
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
