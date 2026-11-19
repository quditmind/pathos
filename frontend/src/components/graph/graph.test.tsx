import { beforeAll, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { renderApp } from "@/test/harness";
import { mockReactFlowDom } from "./testing";
import { GraphExplorer } from "./GraphExplorer";
import { GraphLegend } from "./Legend";
import { engineFor, layeredFallback, toElk } from "./layout";
import { fastLayered } from "./fastLayout";
import {
  diffAsGraph,
  diffIndex,
  edgeAriaLabel,
  evidenceStyle,
  filterGraph,
  mergeDiff,
  neighbourInDirection,
  nodeAriaLabel,
  safeDetail,
  searchNodes,
  tracePaths,
  traceFromPaths,
} from "./model";
import { exampleGraph, generateGraph } from "./testdata";
import { emptyFilters, layers, type GraphDiff, type Layer } from "./types";

beforeAll(mockReactFlowDom);

const all = new Set<Layer>(layers);

describe("graph model", () => {
  it("filters by type, technology, findings, severity, exposure and evidence", () => {
    const f = (patch: Partial<typeof emptyFilters>) => filterGraph(exampleGraph, { ...emptyFilters, ...patch }, all);
    const ids = (g: ReturnType<typeof f>) => g.nodes.map((n) => n.id).filter((id) => id !== "tb");
    expect(ids(f({ types: ["datastore", "queue"] }))).toEqual(["db", "topic"]);
    expect(ids(f({ technologies: ["Kafka"] }))).toEqual(["topic"]);
    expect(ids(f({ hasFindings: true }))).toEqual(["route", "fn"]);
    expect(ids(f({ minSeverity: "critical" }))).toEqual(["route"]);
    expect(ids(f({ minSeverity: "high" }))).toEqual(["route", "fn"]);
    expect(ids(f({ internetExposed: true }))).toEqual(["route"]);
    const ev = f({ evidence: ["ai_inferred"] });
    expect(ev.edges.map((e) => e.id)).toEqual(["e5"]);
    expect(ev.nodes).toHaveLength(exampleGraph.nodes.length);
  });

  it("drops edges whose ends are filtered out, and empty trust boundaries", () => {
    const g = filterGraph(exampleGraph, { ...emptyFilters, types: ["external_service", "queue"] }, all);
    expect(g.edges).toEqual([]);
    expect(g.nodes.some((n) => n.id === "tb")).toBe(false);
    const withDb = filterGraph(exampleGraph, { ...emptyFilters, types: ["datastore"] }, all);
    expect(withDb.nodes.map((n) => n.id)).toEqual(["tb", "db"]);
  });

  it("applies layer toggles", () => {
    const g = filterGraph(exampleGraph, emptyFilters, new Set<Layer>(["data"]));
    expect(g.nodes.map((n) => n.id).sort()).toEqual(["db", "tb", "topic"]);
    expect(filterGraph(exampleGraph, emptyFilters, new Set<Layer>(["ownership"])).nodes).toEqual([]);
  });

  it("searches label, file and technology", () => {
    expect(searchNodes(exampleGraph.nodes, "charge.go").map((n) => n.id)).toEqual(["fn"]);
    expect(searchNodes(exampleGraph.nodes, "postgresql").map((n) => n.id)).toEqual(["db"]);
    expect(searchNodes(exampleGraph.nodes, "  ")).toEqual([]);
  });

  it("traces paths out of and into a node", () => {
    const out = tracePaths(exampleGraph.edges, "route", "out");
    expect([...out.nodes].sort()).toEqual(["db", "fn", "psp", "route", "secret", "topic"]);
    expect([...out.edges].sort()).toEqual(["e2", "e3", "e4", "e5", "e6"]);
    const into = tracePaths(exampleGraph.edges, "db", "in");
    expect([...into.nodes].sort()).toEqual(["db", "fn", "route", "web"]);
    expect(tracePaths(exampleGraph.edges, "route", "out", 1).nodes.size).toBe(3);
    const server = traceFromPaths(exampleGraph.edges, [["e2", "e3"]], "route");
    expect([...server.nodes].sort()).toEqual(["db", "fn", "route"]);
  });

  it("classifies a diff and merges removed elements into the head graph", () => {
    const diff: GraphDiff = {
      added: { nodes: [exampleGraph.nodes[6]!], edges: [exampleGraph.edges[4]!] },
      removed: { nodes: [{ id: "old", type: "function", label: "removedFn()", layer: "code" }], edges: [{ id: "eold", source: "fn", target: "old", type: "calls", evidence: "verified", evidence_refs: [{ kind: "file_line", ref: "x:1" }] }] },
      changed: { nodes: [exampleGraph.nodes[3]!], edges: [] },
    };
    const idx = diffIndex(diff);
    expect(idx.counts).toEqual({ added: 2, removed: 2, changed: 1 });
    expect(idx.nodes.get("topic")).toBe("added");
    expect(idx.nodes.get("old")).toBe("removed");
    expect(idx.edges.get("e5")).toBe("added");
    const merged = mergeDiff(exampleGraph, diff);
    expect(merged.nodes.some((n) => n.id === "old")).toBe(true);
    expect(merged.edges.some((e) => e.id === "eold")).toBe(true);
    expect(diffAsGraph(diff).nodes.map((n) => n.id).sort()).toEqual(["fn", "old", "topic"]);
  });

  it("names nodes and edges for assistive technology", () => {
    expect(nodeAriaLabel(exampleGraph.nodes[2]!)).toBe("POST /example/payments, Route, 1 open finding, highest critical, internet-exposed");
    expect(nodeAriaLabel(exampleGraph.nodes[6]!, "added")).toBe("example-events, Queue, added");
    const labelOf = (id: string) => exampleGraph.nodes.find((n) => n.id === id)!.label;
    expect(edgeAriaLabel(exampleGraph.edges[3]!, labelOf)).toBe("exampleCharge() calls Example PSP, evidence Observed");
  });

  it("evidence styles follow the design: verified solid green, observed dashed blue, AI-inferred dotted purple", () => {
    expect(evidenceStyle.verified).toMatchObject({ color: "var(--evidence-verified)", dash: "" });
    expect(evidenceStyle.observed).toMatchObject({ color: "var(--evidence-observed)", dash: "6 3" });
    expect(evidenceStyle.ai_inferred).toMatchObject({ color: "var(--evidence-ai)", dash: "2 3" });
  });

  it("finds the neighbour in an arrow direction", () => {
    const pos = new Map([
      ["a", { x: 0, y: 0 }],
      ["b", { x: 100, y: 10 }],
      ["c", { x: 0, y: 100 }],
      ["d", { x: 300, y: 0 }],
    ]);
    expect(neighbourInDirection(pos, "a", "ArrowRight")).toBe("b");
    expect(neighbourInDirection(pos, "a", "ArrowDown")).toBe("c");
    expect(neighbourInDirection(pos, "a", "ArrowLeft")).toBeUndefined();
    expect(neighbourInDirection(pos, "b", "ArrowLeft")).toBe("a");
  });

  it("never shows secret values in evidence details", () => {
    expect(safeDetail("file_line", "password=hunter2")).toBe("Value hidden");
    expect(safeDetail("file_line", "producer config")).toBe("producer config");
  });

  it("lays out with containers (fallback) and builds the ELK hierarchy", () => {
    const nodes = [
      { id: "tb", width: 0, height: 0, container: true },
      { id: "a", width: 200, height: 52, parent: "tb" },
      { id: "b", width: 200, height: 52 },
    ];
    const edges = [{ id: "e", source: "a", target: "b" }];
    const pos = layeredFallback(nodes, edges);
    expect(pos.get("b")!.x).toBeGreaterThan(pos.get("a")!.x + pos.get("tb")!.x);
    expect(pos.get("tb")!.width).toBeGreaterThanOrEqual(200);
    const elk = toElk(nodes, edges);
    expect(elk.children!.map((c) => c.id)).toEqual(["tb", "b"]);
    expect(elk.children![0]!.children!.map((c) => c.id)).toEqual(["a"]);
    expect(elk.layoutOptions!["elk.algorithm"]).toBe("layered");
  });

  it("uses ELK up to its size limit and the fast layered layout above", () => {
    expect(engineFor(200, 300)).toBe("elk");
    expect(engineFor(2000, 3000)).toBe("fast-layered");
    expect(engineFor(200, 4000)).toBe("fast-layered");
  });

  it("fast layered layout: every node placed, containers hold only their children, edges point right", () => {
    const g = generateGraph(400, 1.5, 3);
    const nodes = g.nodes.map((n) => (n.type === "trust_boundary" ? { id: n.id, width: 0, height: 0, container: true } : { id: n.id, width: 200, height: 52, parent: n.parent }));
    const pos = fastLayered(nodes, g.edges);
    expect(pos.size).toBe(nodes.length);
    const abs = (id: string) => {
      const p = pos.get(id)!;
      const parent = nodes.find((n) => n.id === id)!.parent;
      const c = parent ? pos.get(parent)! : { x: 0, y: 0 };
      return { x: p.x + c.x, y: p.y + c.y, w: p.width, h: p.height };
    };
    for (const c of nodes.filter((n) => n.container)) {
      const box = pos.get(c.id)!;
      for (const n of nodes.filter((x) => !x.container)) {
        const a = abs(n.id);
        const inside = a.x >= box.x && a.y >= box.y && a.x + a.w <= box.x + box.width && a.y + a.h <= box.y + box.height;
        expect(inside, `${n.id} vs ${c.id}`).toBe(n.parent === c.id);
      }
    }
    const forward = g.edges.filter((e) => abs(e.target).x > abs(e.source).x).length;
    expect(forward / g.edges.length).toBeGreaterThan(0.75);
  });

  it("generates labelled, deterministic test graphs with evidence on every edge", () => {
    const g = generateGraph(500, 1.5, 7);
    expect(g.nodes.filter((n) => n.type !== "trust_boundary")).toHaveLength(500);
    expect(g.edges.length).toBeGreaterThan(600);
    expect(g.edges.every((e) => e.evidence_refs.length > 0)).toBe(true);
    expect(g.nodes.every((n) => n.label.startsWith("example"))).toBe(true);
    expect(generateGraph(50, 1.5, 7)).toEqual(generateGraph(50, 1.5, 7));
  });
});

describe("GraphLegend", () => {
  it("shows the three evidence line styles and trust boundaries", () => {
    const { container } = renderApp(<GraphLegend />);
    const line = (k: string) => container.querySelector(`[data-legend="${k}"] line`)!;
    return waitFor(() => {
      expect(line("verified").getAttribute("stroke")).toBe("var(--evidence-verified)");
      expect(line("verified").getAttribute("stroke-dasharray")).toBeNull();
      expect(line("observed").getAttribute("stroke-dasharray")).toBe("6 3");
      expect(line("ai_inferred").getAttribute("stroke-dasharray")).toBe("2 3");
      expect(screen.getByText("Static: verified from code")).toBeInTheDocument();
      expect(screen.getByText("Dynamic: observed at runtime")).toBeInTheDocument();
      expect(screen.getByText("AI-inferred: needs confirmation")).toBeInTheDocument();
      expect(container.querySelector('[data-legend="trust_boundary"] rect')!.getAttribute("stroke")).toBe("var(--danger)");
      expect(screen.queryByRole("group", { name: "Compare legend" })).toBeNull();
    });
  });

  it("adds the diff colours with counts in compare mode", async () => {
    renderApp(<GraphLegend diffCounts={{ added: 3, removed: 1, changed: 2 }} />);
    const g = await screen.findByRole("group", { name: "Compare legend" });
    expect(within(g).getByText("Added (3)")).toBeInTheDocument();
    expect(within(g).getByText("Removed (1)")).toBeInTheDocument();
    expect(within(g).getByText("Changed (2)")).toBeInTheDocument();
  });
});

describe("GraphExplorer", () => {
  const renderExplorer = (props: Partial<Parameters<typeof GraphExplorer>[0]> = {}) =>
    renderApp(<GraphExplorer data={exampleGraph} title="Example graph" {...props} />);

  it("renders nodes with ARIA labels and evidence-styled edges", async () => {
    const { container } = renderExplorer();
    expect(await screen.findByRole("button", { name: /^POST \/example\/payments, Route/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "example-db, Data store" })).toBeInTheDocument();
    expect(container.querySelector("[data-trust-boundary]")).not.toBeNull();
    await waitFor(() => expect(container.querySelectorAll(".pathos-evidence-edge").length).toBe(7));
    const edge = (ev: string) => container.querySelector<SVGPathElement>(`.pathos-evidence-edge[data-evidence="${ev}"]`)!;
    expect(edge("ai_inferred").style.strokeDasharray).toBe("2 3");
    expect(edge("observed").style.strokeDasharray).toBe("6 3");
    expect(edge("verified").style.strokeDasharray).toBe("");
    expect(edge("verified").style.stroke).toBe("var(--evidence-verified)");
    expect(container.querySelector('[aria-label="exampleCharge() calls Example PSP, evidence Observed"]')).not.toBeNull();
    expect(screen.getByTestId("graph-canvas")).toHaveAttribute("data-layout-engine", "fast-layered");
  });

  it("hides a layer when its toggle is switched off", async () => {
    renderExplorer();
    await screen.findByRole("button", { name: /^example-db, Data store/ });
    const toggle = screen.getByRole("button", { name: "Data layer" });
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-pressed", "false");
    await waitFor(() => expect(screen.queryByRole("button", { name: /^example-db, Data store/ })).toBeNull());
    expect(screen.getByText("2 nodes hidden by filters or layers.")).toBeInTheDocument();
  });

  it("filters by security status from the filter panel", async () => {
    renderExplorer();
    await screen.findByRole("button", { name: /^example-db/ });
    await userEvent.click(screen.getByRole("button", { name: "Filters" }));
    await userEvent.click(screen.getByLabelText("Internet-exposed"));
    await waitFor(() => expect(screen.queryByRole("button", { name: /^example-db/ })).toBeNull());
    expect(screen.getByRole("button", { name: /^POST \/example\/payments/ })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Filters, 1 active" })).toBeInTheDocument();
  });

  it("searches and counts matches", async () => {
    renderExplorer();
    await screen.findByRole("button", { name: /^example-db/ });
    await userEvent.type(screen.getByRole("searchbox", { name: "Search nodes" }), "example-");
    expect(await screen.findByText(/^4 matches/)).toBeInTheDocument();
  });

  it("opens the inspector with evidence references and hides secret values", async () => {
    renderExplorer();
    fireEvent.click(await screen.findByRole("button", { name: /^EXAMPLE_DB_URL, Secret reference/ }));
    const insp = screen.getByLabelText("Node inspector");
    expect(within(insp).getByRole("heading", { name: "EXAMPLE_DB_URL" })).toBeInTheDocument();
    expect(within(insp).getByText("value never shown")).toBeInTheDocument();
    expect(insp.textContent).not.toContain("postgres://user:pw@example");
    expect(insp.textContent).not.toContain("hunter2");
    expect(within(insp).getByText("example/config.go:7")).toBeInTheDocument();
  });

  it("traces paths out of the selected node and highlights them", async () => {
    const { container } = renderExplorer();
    fireEvent.click(await screen.findByRole("button", { name: /^POST \/example\/payments/ }));
    await userEvent.click(screen.getByRole("button", { name: "Trace out" }));
    expect(await screen.findByText(/Tracing out of POST \/example\/payments: 5 nodes, 5 edges/)).toBeInTheDocument();
    await waitFor(() => {
      const e1 = container.querySelector<SVGPathElement>('.pathos-evidence-edge[id="e1"]') ?? container.querySelectorAll<SVGPathElement>(".pathos-evidence-edge")[0]!;
      expect(e1).toBeDefined();
      const widths = [...container.querySelectorAll<SVGPathElement>(".pathos-evidence-edge")].map((p) => p.style.strokeWidth);
      expect(widths.filter((w) => w === "3")).toHaveLength(5);
    });
    await userEvent.click(screen.getByRole("button", { name: "Clear the path trace" }));
    expect(screen.queryByText(/Tracing out of/)).toBeNull();
  });

  it("uses the server path search when given", async () => {
    const loadPaths = vi.fn().mockResolvedValue([["e2", "e3"]]);
    renderExplorer({ loadPaths });
    fireEvent.click(await screen.findByRole("button", { name: /^POST \/example\/payments/ }));
    await userEvent.click(screen.getByRole("button", { name: "Trace in" }));
    expect(loadPaths).toHaveBeenCalledWith("route", "in");
    expect(await screen.findByText(/Tracing into POST \/example\/payments: 2 nodes, 2 edges/)).toBeInTheDocument();
  });

  it("offers an accessible list view of the same data", async () => {
    renderExplorer();
    await userEvent.click(await screen.findByRole("button", { name: "List view" }));
    const list = screen.getByTestId("graph-list-view");
    expect(within(list).getByRole("heading", { name: "Nodes (8)" })).toBeInTheDocument();
    expect(within(list).getByRole("heading", { name: "Relationships (7)" })).toBeInTheDocument();
    expect(within(list).getByText("Internet")).toBeInTheDocument();
    expect(within(list).getAllByText("AI-inferred").length).toBeGreaterThan(0);
    await userEvent.click(within(list).getByRole("button", { name: "Inspect example-db" }));
    expect(within(screen.getByLabelText("Node inspector")).getByRole("heading", { name: "example-db" })).toBeInTheDocument();
  });

  it("moves focus between nodes with the arrow keys", async () => {
    renderExplorer();
    const web = await screen.findByRole("button", { name: /^example-web, Module/ });
    web.focus();
    fireEvent.keyDown(web, { key: "ArrowRight" });
    // The fallback layout puts the route and the component one layer to the right.
    await waitFor(() => expect(document.activeElement?.getAttribute("aria-label")).toMatch(/^(POST \/example\/payments|example-lib@1\.0\.0),/));
    const label = document.activeElement!.getAttribute("aria-label")!.split(",")[0]!;
    fireEvent.keyDown(document.activeElement!, { key: "Enter" });
    expect(within(screen.getByLabelText("Node inspector")).getByRole("heading", { name: label })).toBeInTheDocument();
  });

  it("colours a compare view and shows the diff legend", async () => {
    const diff: GraphDiff = {
      added: { nodes: [exampleGraph.nodes[6]!], edges: [] },
      removed: { nodes: [{ id: "gone", type: "function", label: "removedFn()", layer: "code" }], edges: [] },
      changed: { nodes: [exampleGraph.nodes[4]!], edges: [] },
    };
    renderExplorer({ diff });
    expect(await screen.findByRole("button", { name: "removedFn(), Function, removed" })).toBeInTheDocument();
    expect((await screen.findByRole("button", { name: "example-events, Queue, added" })).querySelector('[data-diff="added"]')).not.toBeNull();
    expect((await screen.findByRole("button", { name: "example-db, Data store, changed" })).querySelector('[data-diff="changed"]')).not.toBeNull();
    expect(screen.getByRole("group", { name: "Compare legend" })).toHaveTextContent("Added (1)");
  });

  it("expands an aggregate node", async () => {
    const onExpand = vi.fn();
    renderExplorer({
      data: { ...exampleGraph, aggregated: [{ id: "agg:pkg", label: "example/pkg", count: 120, child_types: { function: 100, class: 20 } }] },
      onExpand,
    });
    const agg = await screen.findByRole("button", { name: "example/pkg, group of 120 nodes, press Enter to expand" });
    fireEvent.keyDown(agg, { key: "Enter" });
    expect(onExpand).toHaveBeenCalledWith("agg:pkg");
  });

  it("reports render metrics once laid out", async () => {
    const onRendered = vi.fn();
    renderApp(<GraphExplorer data={generateGraph(200)} title="Example generated graph" onRendered={onRendered} />);
    await waitFor(() => expect(onRendered).toHaveBeenCalled());
    expect(onRendered.mock.calls[0]![0]).toMatchObject({ engine: "fast-layered" });
  });
});
