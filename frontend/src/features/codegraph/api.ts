import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { AggregateNode, EvidenceRef, GraphData, GraphDiff, GraphEdge, GraphNode, Layer, NodeDetail, TraceDirection } from "@/components/graph";
import type { CodeGraphView } from "./views";

/**
 * Typed client for the CodeGraph API (contract in docs/aspm/PATHOS_API_DESIGN.md,
 * M4; all routes behind the `codegraph` flag). Responses are normalised so the
 * shared graph component gets its own shapes.
 */

export type SnapshotStatus = "queued" | "building" | "ready" | "partial" | "failed" | "archived";

export interface CodeGraphSnapshot {
  id: string;
  application_id: string;
  repository_id?: string;
  repository_name?: string;
  ref?: string;
  commit_sha?: string;
  trigger?: "manual" | "scan";
  status: SnapshotStatus;
  node_count?: number;
  edge_count?: number;
  engines?: Record<string, string>;
  stats?: Record<string, unknown>;
  error_code?: string;
  error?: string;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
}

export const base = (appId: string) => `/api/v1/codegraph/applications/${encodeURIComponent(appId)}`;

/** Lists come as an array or as {items}. */
function items<T>(r: T[] | { items?: T[] } | null | undefined): T[] {
  if (Array.isArray(r)) return r;
  return r?.items ?? [];
}

type RawNode = Partial<GraphNode> & {
  id: string;
  parent_id?: string | null;
  language?: string;
  technology?: string;
  file_path?: string;
  start_line?: number | null;
  exposure?: string;
  [k: string]: unknown;
};
type RawEdge = Partial<GraphEdge> & { id: string; source?: string; target?: string; source_id?: string; target_id?: string; from?: string; to?: string };

/** Accepts both the contract shape and the store's column names (parent_id, file_path, start_line…). */
export function normaliseNode(n: RawNode): GraphNode {
  const attrs = { ...(n.attrs ?? {}) };
  if (n.language && !attrs.language) attrs.language = n.language;
  if (n.technology && !attrs.technology) attrs.technology = n.technology;
  if (n.file_path && !attrs.file) attrs.file = n.file_path;
  if (n.start_line != null && attrs.line == null) attrs.line = n.start_line;
  if (n.exposure && !attrs.exposure) attrs.exposure = n.exposure;
  return {
    id: n.id,
    type: n.type ?? "module",
    label: n.label ?? n.id,
    layer: (n.layer ?? "code") as Layer,
    attrs,
    finding_counts: n.finding_counts ?? {},
    parent: n.parent ?? n.parent_id ?? undefined,
  };
}

export function normaliseEdge(e: RawEdge): GraphEdge {
  return {
    id: e.id,
    source: e.source ?? e.source_id ?? e.from ?? "",
    target: e.target ?? e.target_id ?? e.to ?? "",
    type: e.type ?? "calls",
    evidence: e.evidence ?? "verified",
    evidence_refs: (e.evidence_refs ?? []) as EvidenceRef[],
  };
}

export function normaliseGraph(r: { nodes?: RawNode[]; edges?: RawEdge[]; aggregated?: (AggregateNode & { parent_id?: string })[] | boolean; truncated?: boolean }): GraphData {
  return {
    nodes: (r.nodes ?? []).map(normaliseNode),
    edges: (r.edges ?? []).map(normaliseEdge),
    aggregated: Array.isArray(r.aggregated) ? r.aggregated.map((a) => ({ ...a, parent: a.parent ?? a.parent_id ?? undefined })) : [],
    truncated: !!r.truncated,
  };
}

function normaliseDiff(r: Partial<Record<"added" | "removed" | "changed", { nodes?: RawNode[]; edges?: RawEdge[] }>>): GraphDiff {
  const part = (p?: { nodes?: RawNode[]; edges?: RawEdge[] }) => ({ nodes: (p?.nodes ?? []).map(normaliseNode), edges: (p?.edges ?? []).map(normaliseEdge) });
  return { added: part(r.added), removed: part(r.removed), changed: part(r.changed) };
}

export interface GraphQuery {
  view: CodeGraphView;
  focus?: string;
  depth?: number;
  limit?: number;
}

export function graphUrl(appId: string, sid: string, q: GraphQuery): string {
  const p = new URLSearchParams({ view: q.view });
  if (q.focus) p.set("focus", q.focus);
  if (q.depth) p.set("depth", String(q.depth));
  if (q.limit) p.set("limit", String(q.limit));
  return `${base(appId)}/snapshots/${encodeURIComponent(sid)}/graph?${p}`;
}

export const codegraphKeys = {
  snapshots: (appId: string) => ["codegraph", appId, "snapshots"] as const,
  graph: (appId: string, sid: string, q: GraphQuery) => ["codegraph", appId, "graph", sid, q.view, q.focus ?? "", q.depth ?? 0] as const,
  diff: (appId: string, from: string, to: string) => ["codegraph", appId, "diff", from, to] as const,
};

export function useSnapshots(appId: string, enabled = true) {
  return useQuery({
    queryKey: codegraphKeys.snapshots(appId),
    queryFn: () => api<CodeGraphSnapshot[] | { items: CodeGraphSnapshot[] }>(`${base(appId)}/snapshots`).then(items),
    enabled: enabled && !!appId,
    // Poll while a build is queued or running.
    refetchInterval: (q) => (q.state.data?.some((s) => s.status === "queued" || s.status === "building") ? 5000 : false),
  });
}

export function useGraph(appId: string, sid: string | undefined, q: GraphQuery) {
  return useQuery({
    queryKey: codegraphKeys.graph(appId, sid ?? "", q),
    queryFn: () => api<Parameters<typeof normaliseGraph>[0]>(graphUrl(appId, sid!, q)).then(normaliseGraph),
    enabled: !!sid,
    staleTime: 60_000,
  });
}

export function useDiff(appId: string, from: string | undefined, to: string | undefined) {
  return useQuery({
    queryKey: codegraphKeys.diff(appId, from ?? "", to ?? ""),
    queryFn: () => api<Parameters<typeof normaliseDiff>[0]>(`${base(appId)}/diff?from=${encodeURIComponent(from!)}&to=${encodeURIComponent(to!)}`).then(normaliseDiff),
    enabled: !!from && !!to && from !== to,
    staleTime: 5 * 60_000,
  });
}

export function fetchNodeDetail(appId: string, sid: string, nid: string): Promise<NodeDetail> {
  return api<NodeDetail & { node?: RawNode; edges?: RawEdge[] } & RawNode>(`${base(appId)}/snapshots/${encodeURIComponent(sid)}/nodes/${encodeURIComponent(nid)}`).then((r) => ({
    node: normaliseNode(r.node ?? r),
    findings: r.findings ?? [],
    edges: (r.edges ?? []).map(normaliseEdge),
    source_links: r.source_links ?? [],
  }));
}

export function fetchPaths(appId: string, sid: string, from: string, direction: TraceDirection, max = 8): Promise<string[][]> {
  const p = new URLSearchParams({ from, direction, max: String(max) });
  return api<{ paths?: (string[] | { edges?: string[] })[] }>(`${base(appId)}/snapshots/${encodeURIComponent(sid)}/paths?${p}`).then((r) =>
    (r.paths ?? []).map((x) => (Array.isArray(x) ? x : (x.edges ?? []))),
  );
}

export function exportUrl(appId: string, sid: string): string {
  return `${base(appId)}/snapshots/${encodeURIComponent(sid)}/export?format=json`;
}

export function useRebuild(appId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api<{ snapshot_id?: string; id?: string; status?: string }>(`${base(appId)}/build`, { method: "POST", body: {} }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: codegraphKeys.snapshots(appId) }),
  });
}
