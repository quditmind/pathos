import type {
  AggregateNode,
  DiffStatus,
  EdgeType,
  Evidence,
  GraphData,
  GraphDiff,
  GraphEdge,
  GraphFilters,
  GraphNode,
  GraphSeverity,
  Layer,
  NodeType,
  TraceDirection,
} from "./types";
import { severities } from "./types";

// Pure graph logic of the shared component: labels, filtering, search, path
// tracing and diff classification. No React here, so it is unit-tested directly.

export const nodeTypeLabel: Record<NodeType, string> = {
  repository: "Repository",
  module: "Module",
  file: "File",
  function: "Function",
  class: "Class",
  route: "Route",
  api_operation: "API operation",
  datastore: "Data store",
  queue: "Queue",
  external_service: "External service",
  container: "Container",
  iac_resource: "Infrastructure resource",
  component: "Component (SBOM)",
  secret_ref: "Secret reference",
  trust_boundary: "Trust boundary",
  application: "Application",
};

export const layerLabel: Record<Layer, string> = {
  code: "Code",
  api: "API",
  data: "Data",
  deploy: "Deployment",
  dependency: "Dependencies",
  ownership: "Ownership",
};

export const edgeTypeLabel: Record<EdgeType, string> = {
  calls: "calls",
  imports: "imports",
  defines: "defines",
  exposes: "exposes",
  reads: "reads",
  writes: "writes",
  publishes: "publishes to",
  consumes: "consumes",
  depends_on: "depends on",
  deployed_as: "deployed as",
  crosses_boundary: "crosses boundary",
  owns: "owns",
};

/**
 * Evidence styling (design, rule 5): verified is a solid green line, observed a
 * dashed blue line, AI-inferred a dotted purple line.
 */
export const evidenceStyle: Record<Evidence, { label: string; description: string; color: string; dash: string }> = {
  verified: { label: "Verified", description: "Static: verified from code", color: "var(--evidence-verified)", dash: "" },
  observed: { label: "Observed", description: "Dynamic: observed at runtime", color: "var(--evidence-observed)", dash: "6 3" },
  ai_inferred: { label: "AI-inferred", description: "AI-inferred: needs confirmation", color: "var(--evidence-ai)", dash: "2 3" },
};

/** Trust boundaries: dashed red containers. */
export const trustBoundaryStyle = { color: "var(--danger)", dash: "5 4", label: "Trust boundary" };

export const diffStyle: Record<Exclude<DiffStatus, "unchanged">, { label: string; color: string }> = {
  added: { label: "Added", color: "var(--success)" },
  removed: { label: "Removed", color: "var(--danger)" },
  changed: { label: "Changed", color: "var(--warning)" },
};

export const sevRank = (s: GraphSeverity): number => severities.length - severities.indexOf(s);

/** Highest severity with at least one open finding, or undefined. */
export function topSeverity(n: Pick<GraphNode, "finding_counts">): GraphSeverity | undefined {
  for (const s of severities) if ((n.finding_counts?.[s] ?? 0) > 0) return s;
  return undefined;
}

export const findingTotal = (n: Pick<GraphNode, "finding_counts">): number =>
  Object.values(n.finding_counts ?? {}).reduce((a, b) => a + (b ?? 0), 0);

export function isInternetExposed(n: GraphNode): boolean {
  const e = String(n.attrs?.exposure ?? "").toLowerCase();
  return e === "internet" || e === "public" || e === "internet_exposed";
}

export function technologyOf(n: GraphNode): string | undefined {
  const t = n.attrs?.technology ?? n.attrs?.framework ?? n.attrs?.language;
  return typeof t === "string" && t ? t : undefined;
}

export function technologies(nodes: GraphNode[]): string[] {
  return [...new Set(nodes.map(technologyOf).filter((t): t is string => !!t))].sort((a, b) => a.localeCompare(b));
}

/** Does the node pass the type, technology and security filters (search is a highlight, not a filter)? */
export function nodeMatches(n: GraphNode, f: GraphFilters): boolean {
  if (n.type === "trust_boundary") return true;
  if (f.types.length && !f.types.includes(n.type)) return false;
  if (f.technologies.length) {
    const t = technologyOf(n);
    if (!t || !f.technologies.includes(t)) return false;
  }
  if (f.hasFindings && findingTotal(n) === 0) return false;
  if (f.minSeverity) {
    const top = topSeverity(n);
    if (!top || sevRank(top) < sevRank(f.minSeverity)) return false;
  }
  if (f.internetExposed && !isInternetExposed(n)) return false;
  return true;
}

export interface VisibleGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  aggregated: AggregateNode[];
}

/**
 * Applies layer toggles and filters. Edges stay only when both ends are
 * visible and the evidence filter allows them. A trust boundary stays while it
 * holds a visible node.
 */
export function filterGraph(data: GraphData, f: GraphFilters, activeLayers: ReadonlySet<Layer>): VisibleGraph {
  const inner = data.nodes.filter((n) => n.type !== "trust_boundary" && activeLayers.has(n.layer) && nodeMatches(n, f));
  const aggregated = (data.aggregated ?? []).filter((a) => !a.layer || activeLayers.has(a.layer));
  const usedParents = new Set([...inner, ...aggregated].map((n) => n.parent).filter((p): p is string => !!p));
  const boundaries = data.nodes.filter((n) => n.type === "trust_boundary" && usedParents.has(n.id));
  const nodes = [...boundaries, ...inner];
  const ids = new Set([...nodes.map((n) => n.id), ...aggregated.map((a) => a.id)]);
  const edges = data.edges.filter(
    (e) => ids.has(e.source) && ids.has(e.target) && (!f.evidence.length || f.evidence.includes(e.evidence)),
  );
  return { nodes, edges, aggregated };
}

/** Nodes whose label, id, file or technology contains the query (case-insensitive). */
export function searchNodes(nodes: GraphNode[], query: string): GraphNode[] {
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return nodes.filter((n) =>
    [n.label, n.id, n.attrs?.file, technologyOf(n)].some((v) => typeof v === "string" && v.toLowerCase().includes(q)),
  );
}

export interface TraceResult {
  nodes: Set<string>;
  edges: Set<string>;
}

/**
 * Client-side path tracing over the loaded edges: everything reachable from
 * `start` following edges forwards ("out") or backwards ("in"), up to maxHops.
 */
export function tracePaths(edges: GraphEdge[], start: string, direction: TraceDirection, maxHops = 8): TraceResult {
  const adj = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    const k = direction === "out" ? e.source : e.target;
    const list = adj.get(k);
    if (list) list.push(e);
    else adj.set(k, [e]);
  }
  const nodes = new Set([start]);
  const out = new Set<string>();
  let frontier = [start];
  for (let hop = 0; hop < maxHops && frontier.length; hop++) {
    const next: string[] = [];
    for (const id of frontier) {
      for (const e of adj.get(id) ?? []) {
        out.add(e.id);
        const other = direction === "out" ? e.target : e.source;
        if (!nodes.has(other)) {
          nodes.add(other);
          next.push(other);
        }
      }
    }
    frontier = next;
  }
  return { nodes, edges: out };
}

/**
 * Converts a server path answer ({paths: [[edge_id…]]}) into a highlight set.
 * `extra` are the edges the server sent with the paths (they may lie outside
 * the loaded view).
 */
export function traceFromPaths(edges: GraphEdge[], paths: string[][], start: string, extra: GraphEdge[] = []): TraceResult {
  const byId = new Map([...extra, ...edges].map((e) => [e.id, e]));
  const r: TraceResult = { nodes: new Set([start]), edges: new Set() };
  for (const p of paths)
    for (const id of p) {
      const e = byId.get(id);
      if (!e) continue;
      r.edges.add(id);
      r.nodes.add(e.source);
      r.nodes.add(e.target);
    }
  return r;
}

export interface DiffIndex {
  nodes: Map<string, DiffStatus>;
  edges: Map<string, DiffStatus>;
  counts: Record<Exclude<DiffStatus, "unchanged">, number>;
}

/** Node id → stable key of a graph (nodes without a key are left out). */
export function nodeKeys(g: Pick<GraphData, "nodes">): Map<string, string> {
  const m = new Map<string, string>();
  for (const n of g.nodes) if (n.key) m.set(n.id, n.key);
  return m;
}

/** Stable key of an edge: its own, or `<source key>|<type>|<target key>` from the node keys. */
export function edgeKeyOf(e: GraphEdge, keys: Map<string, string>): string | undefined {
  if (e.key) return e.key;
  const s = keys.get(e.source);
  const t = keys.get(e.target);
  return s && t ? `${s}|${e.type}|${t}` : undefined;
}

/**
 * Diff status by id. Diffs compare snapshots by stable keys, so with the head
 * graph the statuses also reach its elements whose ids differ (stored edges
 * matched by key; lifted `e:` edges are not stored edges and stay unmarked).
 */
export function diffIndex(diff: GraphDiff, head?: GraphData): DiffIndex {
  const nodes = new Map<string, DiffStatus>();
  const edges = new Map<string, DiffStatus>();
  const headNodeByKey = new Map<string, string>();
  const headEdgeByKey = new Map<string, string>();
  if (head) {
    const keys = nodeKeys(head);
    for (const [id, k] of keys) headNodeByKey.set(k, id);
    for (const e of head.edges) {
      const k = edgeKeyOf(e, keys);
      if (k) headEdgeByKey.set(k, e.id);
    }
  }
  for (const s of ["added", "removed", "changed"] as const) {
    for (const n of diff[s].nodes) {
      nodes.set(n.id, s);
      const h = n.key ? headNodeByKey.get(n.key) : undefined;
      if (h && s !== "removed") nodes.set(h, s);
    }
    for (const e of diff[s].edges) {
      edges.set(e.id, s);
      const h = e.key ? headEdgeByKey.get(e.key) : undefined;
      if (h && s !== "removed") edges.set(h, s);
    }
  }
  const counts = { added: 0, removed: 0, changed: 0 };
  for (const s of ["added", "removed", "changed"] as const) counts[s] = diff[s].nodes.length + diff[s].edges.length;
  return { nodes, edges, counts };
}

/** The head graph plus the removed nodes and edges, so a compare view shows all three states. */
export function mergeDiff(head: GraphData, diff: GraphDiff): GraphData {
  const ids = new Set(head.nodes.map((n) => n.id));
  const eids = new Set(head.edges.map((e) => e.id));
  const nodes = [...head.nodes, ...diff.removed.nodes.filter((n) => !ids.has(n.id))];
  // Removed edges name their ends by key: a removed node, or a head node with that key.
  const byKey = new Map<string, string>();
  for (const n of nodes) if (n.key && !byKey.has(n.key)) byKey.set(n.key, n.id);
  const all = new Set(nodes.map((n) => n.id));
  for (const a of head.aggregated ?? []) all.add(a.id);
  const end = (id: string, key?: string) => (all.has(id) ? id : (key && byKey.get(key)) || id);
  const removed = diff.removed.edges
    .filter((e) => !eids.has(e.id))
    .map((e) => ({ ...e, source: end(e.source, e.source_key), target: end(e.target, e.target_key) }))
    .filter((e) => all.has(e.source) && all.has(e.target));
  return { ...head, nodes, edges: [...head.edges, ...removed] };
}

/** A diff as a graph on its own (when no head graph is loaded). */
export function diffAsGraph(diff: GraphDiff): GraphData {
  const nodes = new Map<string, GraphNode>();
  for (const s of ["added", "changed", "removed"] as const) for (const n of diff[s].nodes) nodes.set(n.id, n);
  const ids = new Set(nodes.keys());
  const edges = [...diff.added.edges, ...diff.changed.edges, ...diff.removed.edges].filter((e) => ids.has(e.source) && ids.has(e.target));
  return { nodes: [...nodes.values()], edges };
}

/** Child types of an aggregate as "12 functions, 3 classes" (both contract shapes). */
export function aggregateSummary(a: AggregateNode): string {
  if (Array.isArray(a.child_types)) return a.child_types.map((t) => nodeTypeLabel[t] ?? t).join(", ");
  return Object.entries(a.child_types)
    .map(([t, n]) => `${n} ${(nodeTypeLabel[t as NodeType] ?? t).toLowerCase()}`)
    .join(", ");
}

/** Accessible name of a node: label, type, findings, exposure. */
export function nodeAriaLabel(n: GraphNode, diff?: DiffStatus): string {
  const parts = [n.label, nodeTypeLabel[n.type] ?? n.type];
  const total = findingTotal(n);
  if (total) parts.push(`${total} open finding${total === 1 ? "" : "s"}, highest ${topSeverity(n)}`);
  if (isInternetExposed(n)) parts.push("internet-exposed");
  if (diff && diff !== "unchanged") parts.push(diff);
  return parts.join(", ");
}

export function edgeAriaLabel(e: GraphEdge, labelOf: (id: string) => string, diff?: DiffStatus): string {
  let s = `${labelOf(e.source)} ${edgeTypeLabel[e.type] ?? e.type} ${labelOf(e.target)}, evidence ${evidenceStyle[e.evidence].label}`;
  if ((e.count ?? 1) > 1) s += `, ${e.count} connections`;
  return diff && diff !== "unchanged" ? `${s}, ${diff}` : s;
}

/**
 * Keyboard navigation: the nearest node in the arrow's direction (a 90° cone),
 * or undefined when there is none.
 */
export function neighbourInDirection(
  positions: Map<string, { x: number; y: number }>,
  from: string,
  key: "ArrowUp" | "ArrowDown" | "ArrowLeft" | "ArrowRight",
): string | undefined {
  const p = positions.get(from);
  if (!p) return undefined;
  let best: string | undefined;
  let bestD = Infinity;
  for (const [id, q] of positions) {
    if (id === from) continue;
    const dx = q.x - p.x;
    const dy = q.y - p.y;
    const ok =
      key === "ArrowRight" ? dx > 0 && Math.abs(dy) <= dx : key === "ArrowLeft" ? dx < 0 && Math.abs(dy) <= -dx : key === "ArrowDown" ? dy > 0 && Math.abs(dx) <= dy : dy < 0 && Math.abs(dx) <= -dy;
    if (!ok) continue;
    const d = dx * dx + dy * dy;
    if (d < bestD) {
      bestD = d;
      best = id;
    }
  }
  return best;
}

/** Evidence refs that may be shown: secret values never are (only their reference). */
export function safeDetail(kind: string, detail: string | undefined): string | undefined {
  if (!detail) return undefined;
  if (kind === "secret_ref" || /(?:password|secret|token|api[_-]?key)\s*[:=]\s*\S+/i.test(detail)) return "Value hidden";
  return detail;
}
