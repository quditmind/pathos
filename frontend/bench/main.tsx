// ADR-005 render benchmark harness. NOT part of the product build: built only
// by scripts/graph-bench.sh (vite.bench.config.ts) and driven by Playwright
// (e2e/perf). It renders the shared graph component with SYNTHETIC TEST DATA
// (generateGraph: every label starts with "example").
//
//   ?nodes=2000&ratio=1.5&seed=42&theme=light
//
// window.__bench = { done, nodes, edges, totalMs, layoutMs, engine, domNodes }
// totalMs: data handed to the component → layout done → nodes placed and fitted
// (two animation frames after fitView).
import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createRootRoute, createRouter, RouterProvider } from "@tanstack/react-router";
import { GraphExplorer, type RenderMetrics } from "@/components/graph";
import { generateGraph } from "@/components/graph/testdata";
import type { GraphData } from "@/components/graph";
import "@/index.css";

type Bench = Partial<RenderMetrics> & { done: boolean; domNodes?: number; generateMs?: number; error?: string };
declare global {
  interface Window {
    __bench: Bench;
  }
}
window.__bench = { done: false };

const q = new URLSearchParams(location.search);
const nodes = Number(q.get("nodes") ?? 2000);
const ratio = Number(q.get("ratio") ?? 1.5);
const seed = Number(q.get("seed") ?? 42);
document.documentElement.classList.toggle("dark", q.get("theme") === "dark");

function Bench() {
  const [data, setData] = useState<GraphData>();
  const [t0, setT0] = useState(0);
  useEffect(() => {
    const g0 = performance.now();
    const g = generateGraph(nodes, ratio, seed);
    window.__bench.generateMs = performance.now() - g0;
    // "Data received" starts here, as when the API answer arrives.
    setT0(performance.now());
    setData(g);
  }, []);
  if (!data) return <p>Generating example data…</p>;
  return (
    <div style={{ padding: 16 }}>
      <p style={{ fontSize: 12 }}>Synthetic test data: {nodes} example nodes, edge ratio {ratio}, seed {seed}.</p>
      <GraphExplorer
        data={data}
        title="Benchmark graph (example data)"
        height={820}
        onRendered={(m) => {
          window.__bench = {
            ...window.__bench,
            ...m,
            totalMs: performance.now() - t0,
            domNodes: document.querySelectorAll(".react-flow__node").length,
            done: true,
          };
        }}
      />
    </div>
  );
}

const root = createRootRoute({ component: Bench });
const router = createRouter({ routeTree: root });
const qc = new QueryClient();
createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={qc}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
);
