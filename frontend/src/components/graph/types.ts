/**
 * Types of the shared graph component. They follow the CodeGraph engine ↔ UI
 * contract (docs/aspm/PATHOS_API_DESIGN.md, M4) but the component itself is
 * API-agnostic: threat models, reverse engineering and the context graph can
 * feed it the same shapes.
 */

export const nodeTypes = [
  "repository",
  "module",
  "file",
  "function",
  "class",
  "route",
  "api_operation",
  "datastore",
  "queue",
  "external_service",
  "container",
  "iac_resource",
  "component",
  "secret_ref",
  "trust_boundary",
  "application",
  // Binary graphs (reverse engineering, M10): the artifact, its sections,
  // functions, imports and the strings they reference.
  "binary",
  "binary_function",
  "import",
  "string_ref",
  "section",
] as const;
export type NodeType = (typeof nodeTypes)[number];

export const layers = ["code", "api", "data", "deploy", "dependency", "ownership"] as const;
export type Layer = (typeof layers)[number];

export const edgeTypes = [
  "calls",
  "imports",
  "defines",
  "exposes",
  "reads",
  "writes",
  "publishes",
  "consumes",
  "depends_on",
  "deployed_as",
  "crosses_boundary",
  "owns",
  // Binary graphs: a function references a string.
  "references",
] as const;
export type EdgeType = (typeof edgeTypes)[number];

/** Rule 5: every edge is verified (static), observed (runtime) or AI-inferred. */
export const evidenceKinds = ["verified", "observed", "ai_inferred"] as const;
export type Evidence = (typeof evidenceKinds)[number];

export const severities = ["critical", "high", "medium", "low", "info"] as const;
export type GraphSeverity = (typeof severities)[number];

/** binary: a file offset in an analysed artifact (reverse engineering). */
export type EvidenceRefKind = "file_line" | "sbom" | "scan" | "registry" | "runtime" | "ai_record" | "binary";
export interface EvidenceRef {
  kind: EvidenceRefKind;
  /** file:line, SBOM or scan id, runtime fact id, AI evidence record id, binary offset (0x…). */
  ref: string;
  detail?: string;
}

export interface NodeAttrs {
  language?: string;
  framework?: string;
  file?: string;
  line?: number;
  technology?: string;
  /** "internet" marks an internet-exposed node. */
  exposure?: string;
  [k: string]: unknown;
}

export interface GraphNode {
  id: string;
  /** Stable across snapshots (type and qualified name); diffs compare keys. */
  key?: string;
  type: NodeType;
  label: string;
  attrs?: NodeAttrs;
  finding_counts?: Partial<Record<GraphSeverity, number>>;
  layer: Layer;
  /** Containment: a trust boundary (or another group) holding this node. */
  parent?: string;
  /** The server aggregate this node belongs to (`agg:dir:…` or `agg:type:…`). */
  group?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  evidence: Evidence;
  evidence_refs: EvidenceRef[];
  /**
   * Stored edges this edge stands for: 1 for a stored edge, more for a lifted
   * or aggregated edge (its id starts with `e:` and its evidence_refs are
   * samples). Absent means 1.
   */
  count?: number;
  /** Stable key (`<source key>|<type>|<target key>`), from diffs and exports. */
  key?: string;
  /** Diff edges name their ends by node key. */
  source_key?: string;
  target_key?: string;
}

/** A server-side group standing in for many nodes; expand it by requesting focus on its id. */
export interface AggregateNode {
  id: string;
  label: string;
  count: number;
  child_types: NodeType[] | Record<string, number>;
  /** Open findings of the members, by severity. */
  finding_counts?: Partial<Record<GraphSeverity, number>>;
  layer?: Layer;
  parent?: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  aggregated?: AggregateNode[];
  truncated?: boolean;
  /** What the server answered for (graph endpoint). */
  snapshot_id?: string;
  view?: string;
  focus?: string;
  depth?: number;
  limit?: number;
  /** change_impact: the snapshot compared with (null: none before this one). */
  base_snapshot_id?: string | null;
}

/** Version compare: what changed between two snapshots. */
export interface GraphDiff {
  added: { nodes: GraphNode[]; edges: GraphEdge[] };
  removed: { nodes: GraphNode[]; edges: GraphEdge[] };
  changed: { nodes: GraphNode[]; edges: GraphEdge[] };
}
export type DiffStatus = "added" | "removed" | "changed" | "unchanged";

/** Node inspector payload (GET …/nodes/{nid}). Never carries secret values. */
export interface NodeDetail {
  node: GraphNode;
  findings?: { id: string; title: string; severity: GraphSeverity; rule?: string; href?: string }[];
  /** Every incoming and outgoing edge of the node (may reach nodes not loaded). */
  edges?: GraphEdge[];
  /** Labels of the nodes at the other end of `edges`. */
  labels?: Record<string, string>;
  /** Links to the source (href empty: no web view, the label is shown as text). */
  source_links?: { label: string; href: string; kind?: EvidenceRefKind }[];
}

export interface GraphFilters {
  query: string;
  types: NodeType[];
  technologies: string[];
  /** Only nodes with open findings. */
  hasFindings: boolean;
  /** Minimum severity of an open finding. */
  minSeverity: GraphSeverity | "";
  internetExposed: boolean;
  evidence: Evidence[];
}

export const emptyFilters: GraphFilters = {
  query: "",
  types: [],
  technologies: [],
  hasFindings: false,
  minSeverity: "",
  internetExposed: false,
  evidence: [],
};

export type TraceDirection = "in" | "out";
