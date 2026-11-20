/// <reference lib="webworker" />
// Graph layout in a web worker (ADR-005): the main thread stays responsive
// while graphs are laid out. ELK layered for graphs up to ELK_MAX_NODES, the
// fast layered layout above (layout.ts). elkjs is EPL-2.0 OR GPL-3.0-or-later
// and is bundled unmodified (docs/DEPENDENCIES.md, NOTICE).
import ELK from "elkjs/lib/elk.bundled.js";
import type { ElkNode } from "elkjs/lib/elk-api";
import { fastLayered } from "./fastLayout";
import type { LayoutEdge, LayoutNode } from "./layoutTypes";

const elk = new ELK();
const post = (m: unknown) => (self as unknown as DedicatedWorkerGlobalScope).postMessage(m);

type Request = { id: number; engine: "elk"; graph: ElkNode } | { id: number; engine: "fast-layered"; nodes: LayoutNode[]; edges: LayoutEdge[] };

self.onmessage = async (ev: MessageEvent<Request>) => {
  const req = ev.data;
  try {
    if (req.engine === "elk") post({ id: req.id, ok: true, result: await elk.layout(req.graph) });
    else post({ id: req.id, ok: true, positions: [...fastLayered(req.nodes, req.edges)] });
  } catch (e) {
    post({ id: req.id, ok: false, error: e instanceof Error ? e.message : String(e) });
  }
};
