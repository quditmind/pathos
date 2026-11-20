// Package threatmodel is the threat-modelling module (PATHOS 3.0 M5,
// ADR-007, docs/aspm/PATHOS_THREAT_MODELLING.md): a deterministic STRIDE
// rule engine over CodeGraph snapshots, attack-path integration, framework
// mappings (ATT&CK, CAPEC, CWE, D3FEND; LINDDUN categories), editable and
// approvable versioned models, and Threat Dragon / PATHOS / pytm import and
// export. Behind the threat_models feature flag.
//
// No AI takes part in generation (rule 4 and 5): every generated threat
// names its rule and version and carries the CodeGraph nodes and edges
// (with their evidence references), the findings and the runtime facts it
// was derived from.
package threatmodel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
)

// STRIDE and LINDDUN categories.
const (
	Spoofing              = "spoofing"
	Tampering             = "tampering"
	Repudiation           = "repudiation"
	InformationDisclosure = "information_disclosure"
	DenialOfService       = "denial_of_service"
	ElevationOfPrivilege  = "elevation_of_privilege"
)

// StrideCategories in STRIDE order.
var StrideCategories = []string{Spoofing, Tampering, Repudiation, InformationDisclosure, DenialOfService, ElevationOfPrivilege}

// LinddunCategories (manual and imported threats only).
var LinddunCategories = []string{"linking", "identifying", "non_repudiation", "detecting", "data_disclosure", "unawareness", "non_compliance"}

// CategoryLabels are the display names.
var CategoryLabels = map[string]string{Spoofing: "Spoofing", Tampering: "Tampering", Repudiation: "Repudiation",
	InformationDisclosure: "Information disclosure", DenialOfService: "Denial of service", ElevationOfPrivilege: "Elevation of privilege",
	"linking": "Linking", "identifying": "Identifying", "non_repudiation": "Non-repudiation", "detecting": "Detecting",
	"data_disclosure": "Data disclosure", "unawareness": "Unawareness", "non_compliance": "Non-compliance"}

// Severities, highest first.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// Statuses of a threat.
var Statuses = []string{"open", "mitigated", "accepted", "not_applicable"}

// Evidence types of a threat (rule 5; unverified: manual or imported
// threats not yet linked to evidence, §8.6 of the assessment).
const (
	EvidenceVerified   = "verified"
	EvidenceObserved   = "observed"
	EvidenceAIInferred = "ai_inferred"
	EvidenceUnverified = "unverified"
)

// Methods of a threat.
const (
	MethodRule       = "rule"
	MethodAttackPath = "attack_path"
	MethodManual     = "manual"
	MethodImported   = "imported"
	MethodAI         = "ai"
)

// DFD element kinds.
const (
	KindProcess        = "process"
	KindDataStore      = "data_store"
	KindExternalEntity = "external_entity"
	KindDataFlow       = "data_flow"
	KindTrustBoundary  = "trust_boundary"
)

// Graph is the engine's input: one CodeGraph snapshot of one repository.
type Graph struct {
	SnapshotID     string
	RepositoryID   string
	RepositoryName string
	ApplicationID  string
	// Partial: the snapshot is "partial" (some engines failed).
	Partial bool
	// PublicExposure is the repository's registered exposure (yes, no,
	// unknown): an inventory record (verified).
	PublicExposure string
	Nodes          []Node
	Edges          []Edge

	byKey map[string]int
	out   [][]int
	in    [][]int
}

// Node is a CodeGraph node.
type Node struct {
	ID       string
	Key      string
	Type     string
	Label    string
	File     string
	Line     int
	Attrs    map[string]any
	Findings map[string]int // open findings by severity (ingest)
}

// Edge is a CodeGraph edge with its evidence references (Refs may be
// filled after the rules ran, for the edges used only).
type Edge struct {
	ID       string
	Key      string
	Source   string // node key
	Target   string // node key
	Type     string
	Evidence string
	Refs     []Ref
}

// Ref is a CodeGraph evidence reference.
type Ref struct {
	Kind   string `json:"kind"`
	Ref    string `json:"ref"`
	Detail string `json:"detail,omitempty"`
}

// Index prepares the graph for the rules (Generate calls it).
func (g *Graph) Index() {
	g.byKey = make(map[string]int, len(g.Nodes))
	for i, n := range g.Nodes {
		g.byKey[n.Key] = i
	}
	g.out = make([][]int, len(g.Nodes))
	g.in = make([][]int, len(g.Nodes))
	for i, e := range g.Edges {
		// AI-inferred edges are never used by the rules: generated threats
		// rest on verified or observed evidence only.
		if e.Evidence == EvidenceAIInferred {
			continue
		}
		s, ok1 := g.byKey[e.Source]
		t, ok2 := g.byKey[e.Target]
		if !ok1 || !ok2 {
			continue
		}
		g.out[s] = append(g.out[s], i)
		g.in[t] = append(g.in[t], i)
	}
}

func (g *Graph) node(key string) (*Node, bool) {
	i, ok := g.byKey[key]
	if !ok {
		return nil, false
	}
	return &g.Nodes[i], true
}

// outEdges returns the edges of the given types leaving key.
func (g *Graph) outEdges(key string, types ...string) []*Edge {
	i, ok := g.byKey[key]
	if !ok {
		return nil
	}
	var out []*Edge
	for _, ei := range g.out[i] {
		if len(types) == 0 || slices.Contains(types, g.Edges[ei].Type) {
			out = append(out, &g.Edges[ei])
		}
	}
	return out
}

// inEdges returns the edges of the given types reaching key.
func (g *Graph) inEdges(key string, types ...string) []*Edge {
	i, ok := g.byKey[key]
	if !ok {
		return nil
	}
	var out []*Edge
	for _, ei := range g.in[i] {
		if len(types) == 0 || slices.Contains(types, g.Edges[ei].Type) {
			out = append(out, &g.Edges[ei])
		}
	}
	return out
}

// Threat is a generated threat.
type Threat struct {
	Fingerprint string
	// Subject is the fingerprint's element part (default: the first
	// element's key).
	Subject          string
	RuleID           string
	RuleVersion      string
	Method           string
	Category         string
	Title            string
	Description      string
	Severity         string
	SeverityReason   string
	Confidence       float64
	ConfidenceReason string
	EvidenceType     string
	Evidence         Evidence
	Elements         []ElementRef
	Mitigation       string
	Mappings         []Mapping
	// FindingIDs are linked findings (attack paths; rule threats get the
	// open findings of their elements at store time).
	FindingIDs []string
}

// Evidence is the evidence object of a threat.
type Evidence struct {
	SnapshotID   string         `json:"snapshot_id,omitempty"`
	RepositoryID string         `json:"repository_id,omitempty"`
	Rule         *RuleRef       `json:"rule,omitempty"`
	Nodes        []EvNode       `json:"nodes,omitempty"`
	Edges        []EvEdge       `json:"edges,omitempty"`
	Absent       []string       `json:"absent,omitempty"`
	Exposure     *Exposure      `json:"exposure,omitempty"`
	Runtime      []string       `json:"runtime,omitempty"`
	AttackPath   map[string]any `json:"attack_path,omitempty"`
	Findings     []EvFinding    `json:"findings,omitempty"`
	Links        []Link         `json:"links,omitempty"`
	Imported     map[string]any `json:"imported,omitempty"`
}

// RuleRef names the rule of a generated threat.
type RuleRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Logic   string `json:"logic"`
}

// EvNode is a CodeGraph node used as evidence.
type EvNode struct {
	ID    string `json:"id,omitempty"`
	Key   string `json:"key"`
	Type  string `json:"type"`
	Label string `json:"label"`
	File  string `json:"file,omitempty"`
	Line  int    `json:"line,omitempty"`
	// RepositoryID: set on manual links (several repositories).
	RepositoryID string `json:"repository_id,omitempty"`
}

// EvEdge is a CodeGraph edge used as evidence.
type EvEdge struct {
	ID       string `json:"id,omitempty"`
	Key      string `json:"key"`
	Source   string `json:"source"`
	Target   string `json:"target"`
	Type     string `json:"type"`
	Evidence string `json:"evidence"`
	Refs     []Ref  `json:"refs"`
}

// EvFinding is a finding used as evidence.
type EvFinding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	CWE      string `json:"cwe,omitempty"`
}

// Exposure is how far an element is reachable.
type Exposure struct {
	Level   string   `json:"level"` // internet, network, unknown
	Reasons []string `json:"reasons,omitempty"`
}

// Link is a link shown with the evidence.
type Link struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

// ElementRef is a DFD element affected by a threat.
type ElementRef struct {
	Kind     string `json:"kind"`
	Key      string `json:"key"` // CodeGraph node key, or edge key for a data flow
	Name     string `json:"name"`
	NodeType string `json:"node_type,omitempty"`
	// Source and Target: node keys of a data flow.
	Source string `json:"source,omitempty"`
	Target string `json:"target,omitempty"`
	// EdgeID and Evidence: the CodeGraph edge of a data flow.
	EdgeID   string `json:"edge_id,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Refs     []Ref  `json:"refs,omitempty"`
}

// Mapping is a framework mapping of a threat.
type Mapping struct {
	Framework string `json:"framework"`
	ID        string `json:"id"`
	Source    string `json:"source"` // rule, finding, user, imported
}

// Hash is a stable digest of the evidence (regeneration: changed or not).
// Snapshot-specific ids are left out: the same element and the same
// references in a new snapshot are unchanged evidence.
func (e Evidence) Hash() string {
	c := e
	c.Links, c.SnapshotID = nil, ""
	c.Nodes = append([]EvNode(nil), e.Nodes...)
	for i := range c.Nodes {
		c.Nodes[i].ID = ""
	}
	c.Edges = append([]EvEdge(nil), e.Edges...)
	for i := range c.Edges {
		c.Edges[i].ID = ""
	}
	b, _ := json.Marshal(c)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:8])
}

// Result is the output of a generation over one graph.
type Result struct {
	Threats []Threat
	// Elements: every DFD element of the graph (the diagram), threatened or not.
	Elements []ElementRef
	// Notes say what the graph does not cover.
	Notes []string
	// RuleCounts: threats per rule.
	RuleCounts map[string]int
}

// Generate runs every rule over the graph. Deterministic: the same graph
// gives the same threats in the same order.
func Generate(g *Graph) Result {
	g.Index()
	c := newContext(g)
	res := Result{RuleCounts: map[string]int{}}
	for _, r := range Rules {
		for _, t := range r.run(c) {
			t.RuleID, t.RuleVersion, t.Method, t.Category = r.ID, r.Version, MethodRule, r.Category
			if t.Subject == "" {
				t.Subject = t.Elements[0].Key
			}
			t.Fingerprint = Fingerprint(r.ID, g.RepositoryID, t.Subject)
			if t.Mitigation == "" {
				t.Mitigation = r.Mitigation
			}
			t.Mappings = append(t.Mappings, r.Mappings...)
			t.Evidence.SnapshotID, t.Evidence.RepositoryID = g.SnapshotID, g.RepositoryID
			t.Evidence.Rule = &RuleRef{ID: r.ID, Version: r.Version, Logic: r.Logic}
			t.EvidenceType = evidenceTypeOf(t.Evidence.Edges)
			res.Threats = append(res.Threats, t)
			res.RuleCounts[r.ID]++
		}
	}
	res.Elements = c.dfdElements()
	res.Notes = c.notes()
	sort.SliceStable(res.Threats, func(i, j int) bool { return res.Threats[i].Fingerprint < res.Threats[j].Fingerprint })
	return res
}

// Fingerprint is the stable identity of a generated threat.
func Fingerprint(ruleID, repositoryID, elementKey string) string {
	return ruleID + "|" + repositoryID + "|" + elementKey
}

// evidenceTypeOf: observed when a runtime edge was used, else verified.
func evidenceTypeOf(edges []EvEdge) string {
	for _, e := range edges {
		if e.Evidence == EvidenceObserved {
			return EvidenceObserved
		}
	}
	return EvidenceVerified
}

// raise moves a severity up (n > 0) or down (n < 0), within critical..info.
func raise(sev string, n int) string {
	i := slices.Index(Severities, sev)
	if i < 0 {
		i = 2
	}
	i -= n
	i = max(0, min(i, len(Severities)-1))
	return Severities[i]
}

func clamp(c float64) float64 {
	return max(0.1, min(c, 0.99))
}

func evNode(n *Node) EvNode {
	return EvNode{ID: n.ID, Key: n.Key, Type: n.Type, Label: n.Label, File: n.File, Line: n.Line}
}

func evEdge(e *Edge) EvEdge {
	return EvEdge{ID: e.ID, Key: e.Key, Source: e.Source, Target: e.Target, Type: e.Type, Evidence: e.Evidence, Refs: e.Refs}
}

// refText is the first reference of an edge, for reasons.
func refText(e *Edge) string {
	if len(e.Refs) == 0 {
		return ""
	}
	return e.Refs[0].Ref
}

func attrString(n *Node, k string) string {
	if n == nil || n.Attrs == nil {
		return ""
	}
	switch v := n.Attrs[k].(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	}
	return ""
}
