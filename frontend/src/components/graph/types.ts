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
] as const;
export type EdgeType = (typeof edgeTypes)[number];

/** Rule 5: every edge is verified (static), observed (runtime) or AI-inferred. */
export const evidenceKinds = ["verified", "observed", "ai_inferred"] as const;
export type Evidence = (typeof evidenceKinds)[number];

export const severities = ["critical", "high", "medium", "low", "info"] as const;
export type GraphSeverity = (typeof severities)[number];

export type EvidenceRefKind = "file_line" | "sbom" | "scan" | "registry" | "runtime" | "ai_record";
export interface EvidenceRef {
  kind: EvidenceRefKind;
  /** file:line, SBOM or scan id, runtime fact id, AI evidence record id. */
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
  type: NodeType;
  label: string;
  attrs?: NodeAttrs;
  finding_counts?: Partial<Record<GraphSeverity, number>>;
  layer: Layer;
  /** Containment: a trust boundary (or another group) holding this node. */
  parent?: string;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  evidence: Evidence;
  evidence_refs: EvidenceRef[];
}

/** A server-side group standing in for many nodes; expand it by requesting focus on its id. */
export interface AggregateNode {
  id: string;
  label: string;
  count: number;
  child_types: NodeType[] | Record<string, number>;
  layer?: Layer;
  parent?: string;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  aggregated?: AggregateNode[];
  truncated?: boolean;
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
  edges?: GraphEdge[];
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
