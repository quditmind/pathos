// TEST DATA ONLY (rule 4): synthetic graphs for unit tests and the ADR-005
// render benchmark. Nothing here describes a real application; every label
// says "example". Never import this from product code paths.
import type { Evidence, GraphData, GraphEdge, GraphNode, Layer, NodeType } from "./types";

/** A small hand-written example graph (labelled example data). */
export const exampleGraph: GraphData = {
  nodes: [
    { id: "tb", type: "trust_boundary", label: "example internal network", layer: "deploy" },
    { id: "web", type: "module", label: "example-web", layer: "code", parent: "tb", attrs: { technology: "React", language: "TypeScript" } },
    {
      id: "route",
      type: "route",
      label: "POST /example/payments",
      layer: "api",
      parent: "tb",
      attrs: { file: "example/handler.go", line: 88, technology: "chi", exposure: "internet" },
      finding_counts: { critical: 1 },
    },
    { id: "fn", type: "function", label: "exampleCharge()", layer: "code", parent: "tb", attrs: { file: "example/charge.go", line: 41, language: "Go" }, finding_counts: { high: 2 } },
    { id: "db", type: "datastore", label: "example-db", layer: "data", parent: "tb", attrs: { technology: "PostgreSQL" } },
    { id: "psp", type: "external_service", label: "Example PSP", layer: "api" },
    { id: "topic", type: "queue", label: "example-events", layer: "data", attrs: { technology: "Kafka" } },
    { id: "secret", type: "secret_ref", label: "EXAMPLE_DB_URL", layer: "deploy", attrs: { source: "env", value: "postgres://user:pw@example" } },
    { id: "lib", type: "component", label: "example-lib@1.0.0", layer: "dependency", attrs: { technology: "npm" } },
  ],
  edges: [
    { id: "e1", source: "web", target: "route", type: "calls", evidence: "verified", evidence_refs: [{ kind: "file_line", ref: "example/web/api.ts:12" }] },
    { id: "e2", source: "route", target: "fn", type: "calls", evidence: "verified", evidence_refs: [{ kind: "file_line", ref: "example/handler.go:90" }] },
    { id: "e3", source: "fn", target: "db", type: "writes", evidence: "verified", evidence_refs: [{ kind: "file_line", ref: "example/charge.go:52" }] },
    { id: "e4", source: "fn", target: "psp", type: "calls", evidence: "observed", evidence_refs: [{ kind: "runtime", ref: "example-runtime-fact" }] },
    { id: "e5", source: "route", target: "topic", type: "publishes", evidence: "ai_inferred", evidence_refs: [{ kind: "ai_record", ref: "example-ai-record", detail: "producer config" }] },
    { id: "e6", source: "db", target: "secret", type: "depends_on", evidence: "verified", evidence_refs: [{ kind: "file_line", ref: "example/config.go:7", detail: "password=hunter2" }] },
    { id: "e7", source: "web", target: "lib", type: "depends_on", evidence: "verified", evidence_refs: [{ kind: "sbom", ref: "pkg:npm/example-lib@1.0.0" }] },
  ],
  aggregated: [],
};

/** Deterministic PRNG (mulberry32) so benchmark runs are comparable. */
export function prng(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const types: [NodeType, Layer][] = [
  ["module", "code"],
  ["file", "code"],
  ["function", "code"],
  ["class", "code"],
  ["route", "api"],
  ["api_operation", "api"],
  ["datastore", "data"],
  ["queue", "data"],
  ["container", "deploy"],
  ["component", "dependency"],
  ["external_service", "api"],
];
const evidence: Evidence[] = ["verified", "verified", "verified", "observed", "ai_inferred"];

/**
 * A synthetic layered graph (ADR-005 measurement plan): `nodes` nodes,
 * `edgeRatio` edges per node, a few trust boundaries holding a share of the
 * nodes. Labelled as example data.
 */
export function generateGraph(nodes: number, edgeRatio = 1.5, seed = 42, boundaries = 3): GraphData {
  const r = prng(seed);
  const out: GraphNode[] = [];
  for (let b = 0; b < boundaries; b++) out.push({ id: `tb${b}`, type: "trust_boundary", label: `example zone ${b}`, layer: "deploy" });
  for (let i = 0; i < nodes; i++) {
    const [type, layer] = types[Math.floor(r() * types.length)]!;
    const sev = r();
    out.push({
      id: `n${i}`,
      type,
      layer,
      label: `example-${type}-${i}`,
      parent: boundaries && r() < 0.3 ? `tb${Math.floor(r() * boundaries)}` : undefined,
      attrs: { technology: ["Go", "TypeScript", "Python", "Java"][i % 4], file: `example/pkg${i % 50}/file${i}.go`, line: (i % 300) + 1, exposure: r() < 0.03 ? "internet" : undefined },
      finding_counts: sev < 0.05 ? { critical: 1 } : sev < 0.15 ? { high: 1 } : sev < 0.3 ? { medium: 2 } : {},
    });
  }
  const edges: GraphEdge[] = [];
  const total = Math.round(nodes * edgeRatio);
  for (let k = 0; k < total; k++) {
    // Mostly forward edges (a layered system), a few back edges.
    const a = Math.floor(r() * nodes);
    const span = 1 + Math.floor(r() * Math.min(60, nodes - 1));
    const b = r() < 0.9 ? Math.min(nodes - 1, a + span) : Math.max(0, a - span);
    if (a === b) continue;
    const ev = evidence[Math.floor(r() * evidence.length)]!;
    edges.push({
      id: `e${k}`,
      source: `n${a}`,
      target: `n${b}`,
      type: "calls",
      evidence: ev,
      evidence_refs: [{ kind: ev === "verified" ? "file_line" : ev === "observed" ? "runtime" : "ai_record", ref: `example/ref/${k}` }],
    });
  }
  return { nodes: out, edges, aggregated: [] };
}
