import type { ElkExtendedEdge, ElkNode } from "elkjs/lib/elk-api";

import { fastLayered, PAD as CONTAINER_PAD } from "./fastLayout";
import type { LayoutEdge, LayoutNode, Placed } from "./layoutTypes";

export type { LayoutEdge, LayoutNode, Placed } from "./layoutTypes";

export interface LayoutResult {
  /** Positions relative to the parent container (React Flow's convention). */
  positions: Map<string, Placed>;
  engine: LayoutEngine;
  ms: number;
}

/** elk: ELK layered (quality); fast-layered: linear-time layered layout for large graphs. */
export type LayoutEngine = "elk" | "fast-layered";

/**
 * Above these sizes ELK layered takes longer than the 2 s first-render budget
 * (measured, docs/PERFORMANCE.md#graph-rendering), so the worker uses the
 * fast layered layout instead.
 */
export const ELK_MAX_NODES = 250;
export const ELK_MAX_EDGES = 500;
export const engineFor = (nodes: number, edges: number): LayoutEngine => (nodes <= ELK_MAX_NODES && edges <= ELK_MAX_EDGES ? "elk" : "fast-layered");

/** ELK layered options (quality settings; ELK only runs up to ELK_MAX_NODES). */
export function elkOptions(): Record<string, string> {
  return {
    "elk.algorithm": "layered",
    "elk.direction": "RIGHT",
    "elk.hierarchyHandling": "INCLUDE_CHILDREN",
    "elk.spacing.nodeNode": "22",
    "elk.layered.spacing.nodeNodeBetweenLayers": "64",
    "elk.padding": `[top=${CONTAINER_PAD.top},left=${CONTAINER_PAD.side},bottom=${CONTAINER_PAD.bottom},right=${CONTAINER_PAD.side}]`,
    "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
  };
}

/** Builds the ELK hierarchy (containers hold their children). */
export function toElk(nodes: LayoutNode[], edges: LayoutEdge[]): ElkNode {
  const byId = new Map<string, ElkNode>();
  for (const n of nodes) byId.set(n.id, n.container ? { id: n.id, children: [], layoutOptions: { "elk.padding": elkOptions()["elk.padding"]! } } : { id: n.id, width: n.width, height: n.height });
  const root: ElkNode = { id: "__root", layoutOptions: elkOptions(), children: [], edges: [] };
  for (const n of nodes) {
    const parent = n.parent ? byId.get(n.parent) : undefined;
    (parent ?? root).children!.push(byId.get(n.id)!);
  }
  root.edges = edges
    .filter((e) => byId.has(e.source) && byId.has(e.target) && e.source !== e.target)
    .map((e): ElkExtendedEdge => ({ id: e.id, sources: [e.source], targets: [e.target] }));
  return root;
}

function flatten(n: ElkNode, out: Map<string, Placed>) {
  for (const c of n.children ?? []) {
    out.set(c.id, { x: c.x ?? 0, y: c.y ?? 0, width: c.width ?? 0, height: c.height ?? 0 });
    flatten(c, out);
  }
}

/** Same-thread layout (tests, browsers without workers, worker failure). */
export const layeredFallback = (nodes: LayoutNode[], edges: LayoutEdge[]) => fastLayered(nodes, edges);

let worker: Worker | undefined;
let seq = 0;
type WorkerAnswer = { id: number; ok: boolean; result?: ElkNode; positions?: [string, Placed][]; error?: string };
const pending = new Map<number, { resolve: (a: WorkerAnswer) => void; reject: (e: Error) => void }>();

function getWorker(): Worker | undefined {
  if (typeof Worker === "undefined") return undefined;
  if (!worker) {
    worker = new Worker(new URL("./layout.worker.ts", import.meta.url), { type: "module", name: "pathos-graph-layout" });
    worker.onmessage = (ev: MessageEvent<WorkerAnswer>) => {
      const p = pending.get(ev.data.id);
      if (!p) return;
      pending.delete(ev.data.id);
      if (ev.data.ok) p.resolve(ev.data);
      else p.reject(new Error(ev.data.error ?? "layout failed"));
    };
    worker.onerror = (ev) => {
      for (const p of pending.values()) p.reject(new Error(ev.message || "layout worker failed"));
      pending.clear();
      worker?.terminate();
      worker = undefined;
    };
  }
  return worker;
}

// Small cache: the same snapshot, view and filters are not laid out twice.
const cache = new Map<string, Map<string, Placed>>();
const CACHE_MAX = 12;

export function layoutKey(nodes: LayoutNode[], edges: LayoutEdge[]): string {
  let h = 0x811c9dc5;
  const add = (s: string) => {
    for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193);
  };
  for (const n of nodes) add(`${n.id}|${n.parent ?? ""}|${n.width}x${n.height};`);
  for (const e of edges) add(`${e.source}>${e.target};`);
  return `${nodes.length}:${edges.length}:${(h >>> 0).toString(36)}`;
}

/**
 * Lays the graph out in a web worker: ELK layered up to ELK_MAX_NODES, the
 * fast layered layout above. Same thread when no worker is available.
 */
export async function layoutGraph(nodes: LayoutNode[], edges: LayoutEdge[]): Promise<LayoutResult> {
  const t0 = performance.now();
  const engine = engineFor(nodes.length, edges.length);
  const key = `${engine}:${layoutKey(nodes, edges)}`;
  const hit = cache.get(key);
  if (hit) return { positions: hit, engine, ms: 0 };
  const w = getWorker();
  if (!w) return { positions: fastLayered(nodes, edges), engine: "fast-layered", ms: performance.now() - t0 };
  try {
    const id = ++seq;
    const answer = await new Promise<WorkerAnswer>((resolve, reject) => {
      pending.set(id, { resolve, reject });
      w.postMessage(engine === "elk" ? { id, engine, graph: toElk(nodes, edges) } : { id, engine, nodes, edges });
    });
    let positions: Map<string, Placed>;
    if (answer.result) {
      positions = new Map();
      flatten(answer.result, positions);
    } else positions = new Map(answer.positions ?? []);
    cache.set(key, positions);
    if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value!);
    return { positions, engine, ms: performance.now() - t0 };
  } catch {
    return { positions: fastLayered(nodes, edges), engine: "fast-layered", ms: performance.now() - t0 };
  }
}
