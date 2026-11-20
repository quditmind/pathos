import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { AggregateNode, EvidenceRef, GraphData, GraphSeverity, GraphDiff, GraphEdge, GraphNode, Layer, NodeDetail, TraceDirection } from "@/components/graph";
import { redactToolNames } from "@/lib/checkKinds";
import type { CodeGraphView } from "./views";

/**
 * Rule 3: CodeGraph never names scanner tools. Discovery engines can surface
 * in errors, evidence details, rule references and engine-reported
 * attributes; those are redacted here ("engine"). Repository content (file
 * paths, qualified names, package URLs, images, versions) is shown as is.
 */
const verbatimAttrs = new Set(["file", "path", "qualified_name", "purl", "image", "version", "method", "line", "end_line"]);
const redactAttrs = (a: Record<string, unknown>) =>
  Object.fromEntries(Object.entries(a).map(([k, v]) => [k, typeof v === "string" && !verbatimAttrs.has(k) ? redactToolNames(v) : v]));
export const redactRef = (r: EvidenceRef): EvidenceRef => ({
  ...r,
  ref: r.kind === "scan" ? redactToolNames(r.ref) : r.ref,
  ...(r.detail ? { detail: redactToolNames(r.detail) } : {}),
});
/** A snapshot as shown: error texts without tool names; the engine versions map is not shown. */
export const displaySnapshot = (s: CodeGraphSnapshot): CodeGraphSnapshot => ({ ...s, error: s.error ? redactToolNames(s.error) : s.error, engines: undefined });

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
  scan_job_id?: string;
  trigger?: "manual" | "scan";
  status: SnapshotStatus;
  /** rows, object (archived; the export is in object storage) or none. */
  storage?: "rows" | "object" | "none";
  node_count?: number;
  edge_count?: number;
  engines?: Record<string, string>;
  stats?: Record<string, unknown>;
  error_code?: string;
  error?: string;
  created_at: string;
  started_at?: string | null;
  finished_at?: string | null;
  archived_at?: string | null;
}

export const base = (appId: string) => `/api/v1/codegraph/applications/${encodeURIComponent(appId)}`;

/** Lists come as an array, {snapshots} (the engine) or {items}. */
function items<T>(r: T[] | { items?: T[]; snapshots?: T[] } | null | undefined): T[] {
  if (Array.isArray(r)) return r;
  return r?.snapshots ?? r?.items ?? [];
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
type RawEdge = Partial<GraphEdge> & { id: string; source?: string; target?: string; source_id?: string; target_id?: string; from?: string; to?: string; previous_evidence?: string };

/** Accepts both the contract shape and the store's column names (parent_id, file_path, start_line…). */
export function normaliseNode(n: RawNode): GraphNode {
  const attrs = redactAttrs({ ...(n.attrs ?? {}) });
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
    ...(n.key ? { key: n.key } : {}),
    ...(n.group ? { group: n.group } : {}),
  };
}

export function normaliseEdge(e: RawEdge): GraphEdge {
  return {
    id: e.id,
    source: e.source ?? e.source_id ?? e.from ?? "",
    target: e.target ?? e.target_id ?? e.to ?? "",
    type: e.type ?? "calls",
    evidence: e.evidence ?? "verified",
    evidence_refs: ((e.evidence_refs ?? []) as EvidenceRef[]).map(redactRef),
    // Lifted and aggregated edges (ids starting with "e:") stand for `count` stored edges.
    ...(e.count != null ? { count: e.count } : {}),
    ...(e.key ? { key: e.key } : {}),
    ...(e.source_key ? { source_key: e.source_key } : {}),
    ...(e.target_key ? { target_key: e.target_key } : {}),
  };
}

/** The graph endpoint's answer (contract: PATHOS_API_DESIGN.md, docs/api-reference/codegraph.md#views). */
export interface RawGraph {
  snapshot_id?: string;
  view?: string;
  focus?: string;
  depth?: number;
  limit?: number;
  base_snapshot_id?: string | null;
  nodes?: RawNode[];
  edges?: RawEdge[];
  aggregated?: (AggregateNode & { parent_id?: string })[] | boolean;
  truncated?: boolean;
}

export function normaliseGraph(r: RawGraph): GraphData {
  const g: GraphData = {
    nodes: (r.nodes ?? []).map(normaliseNode),
    edges: (r.edges ?? []).map(normaliseEdge),
    // Aggregates keep their finding_counts; edges may target their `agg:` ids.
    aggregated: Array.isArray(r.aggregated)
      ? r.aggregated.map(({ parent_id, ...a }) => ({ ...a, finding_counts: a.finding_counts ?? {}, parent: a.parent ?? parent_id ?? undefined }))
      : [],
    truncated: !!r.truncated,
  };
  if (r.snapshot_id) g.snapshot_id = r.snapshot_id;
  if (r.view) g.view = r.view;
  if (r.focus) g.focus = r.focus;
  if (r.depth != null) g.depth = r.depth;
  if (r.limit != null) g.limit = r.limit;
  if (r.base_snapshot_id !== undefined) g.base_snapshot_id = r.base_snapshot_id;
  return g;
}

type RawDiffNode = RawNode & { file?: string };
/**
 * GET …/diff: nodes carry their snapshot's id and stable key (and `file`);
 * edges name their ends by key (source_key, target_key). Ends are resolved to
 * the ids of the diff's nodes where possible; the graph component resolves
 * the rest against the head graph's keys.
 */
export function normaliseDiff(r: Partial<Record<"added" | "removed" | "changed", { nodes?: RawDiffNode[]; edges?: RawEdge[] }>>): GraphDiff {
  const idByKey = new Map<string, string>();
  for (const s of ["added", "removed", "changed"] as const) for (const n of r[s]?.nodes ?? []) if (n.key) idByKey.set(n.key, n.id);
  const node = (n: RawDiffNode) => normaliseNode(n.file && !n.file_path ? { ...n, file_path: n.file } : n);
  const edge = (e: RawEdge) => {
    const x = normaliseEdge(e);
    if (!x.source && e.source_key) x.source = idByKey.get(e.source_key) ?? e.source_key;
    if (!x.target && e.target_key) x.target = idByKey.get(e.target_key) ?? e.target_key;
    return x;
  };
  const part = (p?: { nodes?: RawDiffNode[]; edges?: RawEdge[] }) => ({ nodes: (p?.nodes ?? []).map(node), edges: (p?.edges ?? []).map(edge) });
  return { added: part(r.added), removed: part(r.removed), changed: part(r.changed) };
}

export interface GraphQuery {
  view: CodeGraphView;
  /** change_impact: the base snapshot (default: the previous one of the same repository). */
  compare?: string;
  focus?: string;
  depth?: number;
  limit?: number;
}

export function graphUrl(appId: string, sid: string, q: GraphQuery): string {
  const p = new URLSearchParams({ view: q.view });
  if (q.focus) p.set("focus", q.focus);
  if (q.compare) p.set("compare", q.compare);
  if (q.depth) p.set("depth", String(q.depth));
  if (q.limit) p.set("limit", String(q.limit));
  return `${base(appId)}/snapshots/${encodeURIComponent(sid)}/graph?${p}`;
}

export const codegraphKeys = {
  snapshots: (appId: string) => ["codegraph", appId, "snapshots"] as const,
  graph: (appId: string, sid: string, q: GraphQuery) => ["codegraph", appId, "graph", sid, q.view, q.focus ?? "", q.compare ?? "", q.depth ?? 0] as const,
  diff: (appId: string, from: string, to: string) => ["codegraph", appId, "diff", from, to] as const,
};

export function useSnapshots(appId: string, enabled = true) {
  return useQuery({
    queryKey: codegraphKeys.snapshots(appId),
    queryFn: () => api<CodeGraphSnapshot[] | { items: CodeGraphSnapshot[] }>(`${base(appId)}/snapshots`).then((r) => items(r).map(displaySnapshot)),
    enabled: enabled && !!appId,
    // Poll while a build is queued or running.
    refetchInterval: (q) => (q.state.data?.some((s) => s.status === "queued" || s.status === "building") ? 5000 : false),
  });
}

export function useGraph(appId: string, sid: string | undefined, q: GraphQuery) {
  return useQuery({
    queryKey: codegraphKeys.graph(appId, sid ?? "", q),
    queryFn: () => api<RawGraph>(graphUrl(appId, sid!, q)).then(normaliseGraph),
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

type RawDetail = {
  node?: RawNode;
  findings?: { id: string; title: string; severity: GraphSeverity; rule_id?: string; href?: string; file_path?: string; start_line?: number | null }[];
  source_links?: ({ label: string; href: string } | { file: string; line?: number; url?: string })[];
  edges?: RawEdge[];
  edges_out?: (RawEdge & { other?: { id: string; label: string } })[];
  edges_in?: (RawEdge & { other?: { id: string; label: string } })[];
} & RawNode;

/** The inspector payload; accepts the engine's shape (edges_in/out with `other`, source links with file/line/url). */
export function normaliseDetail(r: RawDetail): NodeDetail {
  const rels = [...(r.edges_out ?? []), ...(r.edges_in ?? [])];
  const labels: Record<string, string> = {};
  for (const e of rels) if (e.other) labels[e.other.id] = e.other.label;
  return {
    node: normaliseNode(r.node ?? r),
    findings: (r.findings ?? []).map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      rule: f.rule_id ? redactToolNames(f.rule_id) : undefined,
      href: f.href ?? `/findings?finding=${encodeURIComponent(f.id)}`,
    })),
    edges: [...(r.edges ?? []), ...rels].map(normaliseEdge),
    labels,
    source_links: (r.source_links ?? []).map((l) =>
      "file" in l ? { label: `${l.file}${l.line ? `:${l.line}` : ""}`, href: l.url ?? "", kind: "file_line" as const } : l,
    ),
  };
}

export function fetchNodeDetail(appId: string, sid: string, nid: string): Promise<NodeDetail> {
  return api<RawDetail>(`${base(appId)}/snapshots/${encodeURIComponent(sid)}/nodes/${encodeURIComponent(nid)}`).then(normaliseDetail);
}

/** GET …/snapshots/{sid}/paths: edge-id paths plus the nodes and edges they use (possibly outside the view). */
export interface PathAnswer {
  paths: string[][];
  nodes: GraphNode[];
  edges: GraphEdge[];
  truncated: boolean;
  budgetExceeded: boolean;
}

export function fetchPaths(appId: string, sid: string, from: string, direction: TraceDirection, max = 8): Promise<PathAnswer> {
  const p = new URLSearchParams({ from, direction, max: String(max) });
  return api<{ paths?: (string[] | { edges?: string[] })[]; nodes?: RawNode[]; edges?: RawEdge[]; truncated?: boolean; budget_exceeded?: boolean }>(
    `${base(appId)}/snapshots/${encodeURIComponent(sid)}/paths?${p}`,
  ).then((r) => ({
    paths: (r.paths ?? []).map((x) => (Array.isArray(x) ? x : (x.edges ?? []))),
    nodes: (r.nodes ?? []).map(normaliseNode),
    edges: (r.edges ?? []).map(normaliseEdge),
    truncated: !!r.truncated,
    budgetExceeded: !!r.budget_exceeded,
  }));
}

export function exportUrl(appId: string, sid: string): string {
  return `${base(appId)}/snapshots/${encodeURIComponent(sid)}/export?format=json`;
}

/** POST …/build: one snapshot per repository of the application; per-repository errors. */
export interface BuildAnswer {
  snapshots?: { snapshot_id: string; repository_id: string; scan_job_id?: string; status: SnapshotStatus; coalesced?: boolean }[];
  errors?: { repository_id: string; code: string; message: string }[];
}

export function useRebuild(appId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api<BuildAnswer>(`${base(appId)}/build`, { method: "POST", body: {} }).then((r) => ({
        ...r,
        errors: r?.errors?.map((e) => ({ ...e, message: redactToolNames(e.message) })),
      })),
    onSuccess: () => void qc.invalidateQueries({ queryKey: codegraphKeys.snapshots(appId) }),
  });
}

/** GET /api/v1/codegraph/views: the views and the vocabularies the server accepts. */
export interface ViewCatalogue {
  views: { name: string; title?: string; description?: string; node_types?: string[]; edge_types?: string[]; lift?: boolean }[];
  node_types?: string[];
  edge_types?: string[];
  layers?: string[];
  evidence_types?: string[];
  evidence_ref_kinds?: string[];
}

export function useCodeGraphViews(enabled = true) {
  return useQuery({
    queryKey: ["codegraph", "views"],
    queryFn: () => api<ViewCatalogue>("/api/v1/codegraph/views"),
    enabled,
    staleTime: Infinity,
  });
}

/** GET/PUT /api/v1/codegraph/settings (organization-wide; PUT needs settings.manage). */
export interface CodeGraphSettings {
  auto_rebuild: boolean;
  min_interval_minutes: number;
  keep_snapshots: number;
  updated_at?: string | null;
}

export function useCodeGraphSettings(enabled = true) {
  return useQuery({ queryKey: ["codegraph", "settings"], queryFn: () => api<CodeGraphSettings>("/api/v1/codegraph/settings"), enabled });
}

export function useSaveCodeGraphSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (s: Omit<CodeGraphSettings, "updated_at">) => api<CodeGraphSettings>("/api/v1/codegraph/settings", { method: "PUT", body: s }),
    onSuccess: (s) => qc.setQueryData(["codegraph", "settings"], s),
  });
}
