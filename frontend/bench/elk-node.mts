// Diagnostics for the ADR-005 benchmark: ELK layered alone, in Node, on the
// synthetic test graphs (example data). Mirrors toElk() in layout.ts.
//   node bench/elk-node.mts <nodes> [edgeRatio]
import ELK from "elkjs/lib/elk.bundled.js";
import { generateGraph } from "../src/components/graph/testdata.ts";

const n = Number(process.argv[2] ?? 300);
const ratio = Number(process.argv[3] ?? 1.5);
const g = generateGraph(n, ratio, 42);
const pad = "[top=34,left=16,bottom=16,right=16]";
const byId = new Map<string, { id: string; width?: number; height?: number; children?: unknown[]; layoutOptions?: Record<string, string> }>();
for (const x of g.nodes) byId.set(x.id, x.type === "trust_boundary" ? { id: x.id, children: [], layoutOptions: { "elk.padding": pad } } : { id: x.id, width: 200, height: 52 });
const root = {
  id: "__root",
  layoutOptions: {
    "elk.algorithm": "layered",
    "elk.direction": "RIGHT",
    "elk.hierarchyHandling": "INCLUDE_CHILDREN",
    "elk.spacing.nodeNode": "22",
    "elk.layered.spacing.nodeNodeBetweenLayers": "64",
    "elk.layered.considerModelOrder.strategy": "NODES_AND_EDGES",
  },
  children: [] as unknown[],
  edges: g.edges.map((e) => ({ id: e.id, sources: [e.source], targets: [e.target] })),
};
for (const x of g.nodes) (x.parent ? byId.get(x.parent)!.children! : root.children).push(byId.get(x.id));
const t = performance.now();
await new ELK().layout(root as never);
console.log(`ELK layered: ${n} nodes, ratio ${ratio}: ${Math.round(performance.now() - t)} ms`);
