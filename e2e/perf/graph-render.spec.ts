import { test, expect, type Page } from "@playwright/test";
import { mkdirSync, writeFileSync } from "node:fs";

// ADR-005 measurement: first render of the shared graph component (React
// Flow; layout in a web worker: ELK up to 250 nodes, fast layered above) with SYNTHETIC TEST DATA from generateGraph()
// (every label starts with "example"). Budget (prompt §4): 2,000 nodes,
// data received → laid out and placed, p95 < 2 s on the reference client.
//
//   scripts/graph-bench.sh            (BENCH_RUNS=10 by default)
//
// Results: e2e/perf/results/graph-render.json and the console table.

const RUNS = Number(process.env.BENCH_RUNS ?? 10);
const BUDGET_MS = 2000;

type Run = { totalMs: number; layoutMs: number; engine: string; nodes: number; edges: number; domNodes: number; heapMB?: number };

async function once(page: Page, nodes: number, ratio: number): Promise<Run> {
  await page.goto(`/index.html?nodes=${nodes}&ratio=${ratio}&seed=42`);
  await page.waitForFunction(() => window.__bench?.done === true, undefined, { timeout: 120_000, polling: 50 });
  const r = await page.evaluate(() => ({ ...window.__bench, heap: (performance as unknown as { memory?: { usedJSHeapSize: number } }).memory?.usedJSHeapSize }));
  return {
    totalMs: r.totalMs!,
    layoutMs: r.layoutMs!,
    engine: r.engine!,
    nodes: r.nodes!,
    edges: r.edges!,
    domNodes: r.domNodes!,
    heapMB: r.heap ? Math.round(r.heap / 1048576) : undefined,
  };
}

const pct = (xs: number[], p: number) => {
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)]!;
};

const cases: { nodes: number; ratio: number; throttle?: number; gate?: boolean }[] = [
  { nodes: 200, ratio: 1.5 },
  { nodes: 500, ratio: 1.5 },
  { nodes: 1000, ratio: 1.5 },
  { nodes: 2000, ratio: 1.5, gate: true },
  { nodes: 2000, ratio: 3 },
  { nodes: 5000, ratio: 1.5 },
  { nodes: 2000, ratio: 1.5, throttle: 4 },
];

declare global {
  interface Window {
    __bench: { done: boolean; totalMs?: number; layoutMs?: number; engine?: string; nodes?: number; edges?: number; domNodes?: number };
  }
}

test("graph first render stays within the 2 s budget for 2,000 nodes (example data)", async ({ page, browserName }) => {
  const rows: Record<string, unknown>[] = [];
  for (const c of cases) {
    if (c.throttle) {
      const cdp = await page.context().newCDPSession(page);
      await cdp.send("Emulation.setCPUThrottlingRate", { rate: c.throttle });
    }
    // One warm-up run (worker and code caches), then the measured runs.
    await once(page, c.nodes, c.ratio);
    const runs: Run[] = [];
    for (let i = 0; i < RUNS; i++) runs.push(await once(page, c.nodes, c.ratio));
    if (c.throttle) {
      const cdp = await page.context().newCDPSession(page);
      await cdp.send("Emulation.setCPUThrottlingRate", { rate: 1 });
    }
    const total = runs.map((r) => r.totalMs);
    const layout = runs.map((r) => r.layoutMs);
    const row = {
      nodes: c.nodes,
      edge_ratio: c.ratio,
      cpu_throttle: c.throttle ?? 1,
      runs: RUNS,
      engine: runs[0]!.engine,
      edges: runs[0]!.edges,
      dom_nodes: runs[0]!.domNodes,
      layout_median_ms: Math.round(pct(layout, 50)),
      layout_p95_ms: Math.round(pct(layout, 95)),
      total_median_ms: Math.round(pct(total, 50)),
      total_p95_ms: Math.round(pct(total, 95)),
      heap_mb: runs.at(-1)!.heapMB,
    };
    rows.push(row);
    console.log(JSON.stringify(row));
    if (c.gate) {
      // Above ELK_MAX_NODES the worker uses the fast layered layout (layout.ts).
      expect(row.engine).toBe("fast-layered");
      expect(row.dom_nodes).toBeGreaterThan(0);
    }
  }
  mkdirSync("perf/results", { recursive: true });
  const report = { measured_at: new Date().toISOString(), browser: browserName, viewport: "1440x900", budget_ms: BUDGET_MS, data: "synthetic test data (generateGraph, seed 42)", rows };
  writeFileSync("perf/results/graph-render.json", JSON.stringify(report, null, 2));
  const gate = rows.find((r) => r.nodes === 2000 && r.edge_ratio === 1.5 && r.cpu_throttle === 1)!;
  expect(gate.total_p95_ms as number, "2,000 nodes: p95 first render (ms)").toBeLessThan(BUDGET_MS);
});
