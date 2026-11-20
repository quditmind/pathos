import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { mockReactFlowDom } from "@/components/graph/testing";
import { exampleGraph } from "@/components/graph/testdata";
import { CodeGraphPanel, relativeTime } from "./CodeGraphPanel";
import { CodeGraphIndexPage } from "./CodeGraphPage";
import { validateCodeGraphSearch } from "./search";
import { fetchPaths, normaliseDiff, normaliseEdge, normaliseGraph } from "./api";
import { CodeGraphSettingsCard } from "./CodeGraphSettings";
import { codegraphViews, viewInfo } from "./views";

// Example data for tests only (labelled): no real application.
const APP = "0190a000-0000-7000-8000-000000000001";
const S1 = "0190a000-0000-7000-8000-0000000000a1";
const S0 = "0190a000-0000-7000-8000-0000000000a0";
const meta = (codegraph: boolean) => () => ({ product: "PATHOS", vendor: "Quditmind", version: "3.0.0-test", feature_flags: { codegraph } });
const snap = (id: string, created_at: string, status = "ready") => ({
  id,
  application_id: APP,
  commit_sha: id === S1 ? "a41c9e2aaaaaaaaaaaaa" : "9be010fbbbbbbbbbbbbb",
  ref: "main",
  status,
  node_count: 9,
  edge_count: 7,
  created_at,
  finished_at: created_at,
});
const base = `/api/v1/codegraph/applications/${APP}`;

beforeEach(mockReactFlowDom);
afterEach(() => vi.unstubAllGlobals());

describe("CodeGraph helpers", () => {
  it("has the 15 views with labels", () => {
    expect(codegraphViews).toHaveLength(15);
    for (const v of codegraphViews) expect(viewInfo[v].label).toBeTruthy();
  });

  it("validates the URL state", () => {
    expect(validateCodeGraphSearch({ view: "api", snapshot: S1, node: "x y" })).toEqual({ view: "api", snapshot: S1, compare: undefined, focus: undefined, node: undefined });
    expect(validateCodeGraphSearch({ view: "nope" }).view).toBeUndefined();
  });

  it("normalises the store's column names", () => {
    const g = normaliseGraph({
      nodes: [{ id: "n1", type: "function", label: "f", layer: "code", parent_id: "tb", file_path: "a.go", start_line: 3, technology: "Go" }],
      edges: [{ id: "e1", source_id: "n1", target_id: "n2", type: "calls", evidence: "verified", evidence_refs: [{ kind: "file_line", ref: "a.go:3" }] }],
      aggregated: true,
    });
    expect(g.nodes[0]).toMatchObject({ parent: "tb", attrs: { file: "a.go", line: 3, technology: "Go" } });
    expect(g.edges[0]).toMatchObject({ source: "n1", target: "n2" });
    expect(g.aggregated).toEqual([]);
  });

  it("formats relative build times", () => {
    const now = Date.parse("2026-11-20T12:00:00Z");
    expect(relativeTime("2026-11-20T11:48:00Z", now)).toBe("12 min ago");
    expect(relativeTime("2026-11-20T11:59:50Z", now)).toBe("just now");
  });
});

describe("CodeGraphPanel", () => {
  it("shows the feature-disabled state while the flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta(false) });
    renderApp(<CodeGraphPanel applicationId={APP} />);
    expect(await screen.findByText("CodeGraph is not enabled")).toBeInTheDocument();
  });

  it("offers the first build when there is no snapshot", async () => {
    const { calls } = mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ items: [] }),
      [`POST ${base}/build`]: () => jsonResponse({ snapshot_id: S1, status: "queued" }, 202),
    });
    renderApp(<CodeGraphPanel applicationId={APP} />, { permissions: ["findings.read", "scans.run"] });
    expect(await screen.findByText("No CodeGraph yet")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Build CodeGraph" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path === `${base}/build`)).toBe(true));
  });

  it("shows the error panel when the snapshots cannot be loaded", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () =>
        jsonResponse({ error: { code: "internal", error_code: "PTH-GRAPH-1001", title: "Graph store unavailable", message: "The graph store did not answer." } }, 500),
    });
    renderApp(<CodeGraphPanel applicationId={APP} />);
    const alert = await screen.findByRole("alert", { name: "Graph store unavailable" });
    expect(within(alert).getByText("PTH-GRAPH-1001")).toBeInTheDocument();
  });

  it("shows a running build", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), [`GET ${base}/snapshots`]: () => ({ items: [snap(S1, new Date().toISOString(), "building")] }) });
    renderApp(<CodeGraphPanel applicationId={APP} />, { permissions: ["findings.read", "scans.run"] });
    expect(await screen.findByText(/A CodeGraph build is running/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Rebuild" })).toBeDisabled();
  });

  it("renders the latest snapshot with commit, build time, the view switcher and the graph", async () => {
    const { calls } = mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ items: [snap(S0, "2026-11-18T10:00:00Z"), snap(S1, new Date(Date.now() - 12 * 60_000).toISOString())] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => exampleGraph,
      [`POST ${base}/build`]: () => jsonResponse({ snapshot_id: "x", status: "queued" }, 202),
    });
    renderApp(<CodeGraphPanel applicationId={APP} applicationName="example-app" />, { permissions: ["findings.read", "scans.run"] });
    expect(await screen.findByTestId("codegraph-commit")).toHaveTextContent("main @ a41c9e2aaaaa");
    expect(screen.getByText("Graph built 12 min ago")).toBeInTheDocument();
    const views = screen.getByRole("group", { name: "CodeGraph views" });
    expect(within(views).getAllByRole("button")).toHaveLength(15);
    expect(within(views).getByRole("button", { name: "Architecture" })).toHaveAttribute("aria-pressed", "true");
    expect(await screen.findByRole("button", { name: /^POST \/example\/payments, Route/ })).toBeInTheDocument();
    expect(calls.find((c) => c.path.endsWith("/graph"))!.url.searchParams.get("view")).toBe("architecture");

    await userEvent.click(within(views).getByRole("button", { name: "API & endpoints" }));
    await waitFor(() => expect(calls.filter((c) => c.path.endsWith("/graph")).map((c) => c.url.searchParams.get("view"))).toContain("api"));

    await userEvent.click(screen.getByRole("button", { name: "Rebuild" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST")).toBe(true));
  });

  it("loads the inspector from the API (engine shape)", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ snapshots: [snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => exampleGraph,
      [`GET ${base}/snapshots/${S1}/nodes/route`]: () => ({
        node: exampleGraph.nodes[2],
        findings: [{ id: "f1", title: "Example SQL injection", severity: "critical", status: "open", rule_id: "example-rule" }],
        source_links: [{ file: "example/handler.go", line: 88, url: "https://example.invalid/blob/a41c9e2/example/handler.go#L88" }],
        edges_out: [{ id: "e9", source: "route", target: "far", type: "calls", evidence: "verified", count: 1, evidence_refs: [{ kind: "file_line", ref: "example/handler.go:95" }], other: { id: "far", type: "function", label: "farAway()" } }],
        edges_in: [],
      }),
    });
    renderApp(<CodeGraphPanel applicationId={APP} />);
    fireEvent.click(await screen.findByRole("button", { name: /^POST \/example\/payments, Route/ }));
    const insp = screen.getByLabelText("Node inspector");
    expect(await within(insp).findByRole("link", { name: "Example SQL injection" })).toHaveAttribute("href", "/findings?finding=f1");
    expect(within(insp).getByRole("link", { name: "example/handler.go:88" })).toHaveAttribute("href", "https://example.invalid/blob/a41c9e2/example/handler.go#L88");
    expect(within(insp).getByText("farAway()")).toBeInTheDocument();
  });

  it("colours the change impact view from the server's change marks", async () => {
    const { calls } = mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ snapshots: [snap(S0, "2026-11-18T10:00:00Z"), snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => ({
        nodes: [
          { ...exampleGraph.nodes[3], attrs: { change: "changed" } },
          { ...exampleGraph.nodes[6], attrs: { change: "added" } },
          { id: "gone", type: "function", label: "removedFn()", layer: "code", attrs: { change: "removed" } },
        ],
        edges: [],
        aggregated: [],
      }),
    });
    renderApp(<CodeGraphPanel applicationId={APP} state={{ view: "change_impact" }} onStateChange={() => {}} />);
    const legend = await screen.findByRole("group", { name: "Compare legend" });
    expect(legend).toHaveTextContent("Added (1)");
    expect(legend).toHaveTextContent("Removed (1)");
    expect(legend).toHaveTextContent("Changed (1)");
    expect(calls.find((c) => c.path.endsWith("/graph"))!.url.searchParams.get("view")).toBe("change_impact");
    expect(calls.some((c) => c.path === `${base}/diff`)).toBe(false);
  });

  it("compares another view with a chosen snapshot through the diff endpoint", async () => {
    const { calls } = mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ snapshots: [snap(S0, "2026-11-18T10:00:00Z"), snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => exampleGraph,
      [`GET ${base}/diff`]: () => ({
        added: { nodes: [exampleGraph.nodes[6]], edges: [] },
        removed: { nodes: [], edges: [{ id: "x", key: "k", source_key: "a", target_key: "b", type: "calls", evidence: "verified" }] },
        changed: { nodes: [exampleGraph.nodes[4]], edges: [] },
      }),
    });
    renderApp(<CodeGraphPanel applicationId={APP} state={{ view: "architecture", compare: S0 }} onStateChange={() => {}} />);
    expect(await screen.findByRole("group", { name: "Compare legend" })).toHaveTextContent("Changed (1)");
    const d = calls.find((c) => c.path === `${base}/diff`)!;
    expect([d.url.searchParams.get("from"), d.url.searchParams.get("to")]).toEqual([S0, S1]);
  });

  it("explains an empty view", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ items: [snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => ({ nodes: [], edges: [], aggregated: [], truncated: false }),
    });
    renderApp(<CodeGraphPanel applicationId={APP} state={{ view: "secrets_and_config" }} onStateChange={() => {}} />);
    expect(await screen.findByText("Nothing in the Secrets & configuration view")).toBeInTheDocument();
  });
});

describe("CodeGraph index pages", () => {
  it("lets the user choose an application", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/applications": () => ({ items: [{ id: APP, name: "example-app" }] }),
    });
    renderApp(<CodeGraphIndexPage view="api" />);
    expect(await screen.findByRole("heading", { name: "API & endpoints" })).toBeInTheDocument();
    expect(await screen.findByRole("option", { name: "example-app" })).toBeInTheDocument();
  });

  it("is disabled while the flag is off", async () => {
    mockApi({ "GET /api/v1/meta": meta(false) });
    renderApp(<CodeGraphIndexPage />);
    expect(await screen.findByText("CodeGraph is not enabled")).toBeInTheDocument();
  });
});

describe("Engine contract (docs/api-reference/codegraph.md)", () => {
  it("keeps node key, parent and group, edge count and the response's metadata", () => {
    const g = normaliseGraph({
      snapshot_id: S1,
      view: "call_graph",
      focus: "",
      depth: 1,
      limit: 500,
      base_snapshot_id: null,
      nodes: [{ id: "n1", key: "fn:go:example.Run", type: "function", label: "Run", layer: "code", parent: "m1", group: "agg:dir:example", attrs: { file: "example/run.go", line: 3 } }],
      edges: [
        { id: "e:abc", source: "n1", target: "agg:dir:example/store", type: "calls", evidence: "verified", count: 7, evidence_refs: [{ kind: "file_line", ref: "example/run.go:9" }] },
        { id: "e2", source: "app", target: "repo", type: "owns", evidence: "verified", count: 1, evidence_refs: [{ kind: "registry", ref: "application:example" }] },
      ],
      aggregated: [{ id: "agg:dir:example/store", label: "example/store", count: 12, child_types: { function: 12 }, finding_counts: { high: 2 } }],
      truncated: false,
    });
    expect(g.nodes[0]).toMatchObject({ key: "fn:go:example.Run", parent: "m1", group: "agg:dir:example" });
    expect(g.edges[0]).toMatchObject({ id: "e:abc", target: "agg:dir:example/store", count: 7 });
    expect(g.edges[1]!.evidence_refs[0]!.kind).toBe("registry");
    expect(g.aggregated![0]!.finding_counts).toEqual({ high: 2 });
    expect(g).toMatchObject({ snapshot_id: S1, view: "call_graph", depth: 1, limit: 500, base_snapshot_id: null });
  });

  it("resolves diff edges by node key", () => {
    const d = normaliseDiff({
      added: { nodes: [{ id: "h1", key: "route:POST /x", type: "route", label: "POST /x", layer: "api", file: "example/x.go" }], edges: [] },
      removed: {
        nodes: [{ id: "b1", key: "fn:go:old", type: "function", label: "old()", layer: "code" }],
        edges: [{ id: "be1", key: "fn:go:old|calls|fn:go:kept", source_key: "fn:go:old", target_key: "fn:go:kept", type: "calls", evidence: "verified" }],
      },
      changed: { nodes: [], edges: [] },
    });
    expect(d.added.nodes[0]!.attrs?.file).toBe("example/x.go");
    expect(d.removed.edges[0]).toMatchObject({ source: "b1", target: "fn:go:kept", source_key: "fn:go:old", target_key: "fn:go:kept", key: "fn:go:old|calls|fn:go:kept" });
  });

  it("reads paths with the nodes and edges they use", async () => {
    const { calls } = mockApi({
      [`GET ${base}/snapshots/${S1}/paths`]: () => ({
        from: "n1", direction: "out", max: 8, paths: [["e1", "e2"]],
        nodes: [{ id: "n2", type: "function", label: "far()", layer: "code" }],
        edges: [{ id: "e2", source: "n1", target: "n2", type: "calls", evidence: "verified", evidence_refs: [{ kind: "file_line", ref: "a.go:1" }] }],
        truncated: true, budget_exceeded: false,
      }),
    });
    const r = await fetchPaths(APP, S1, "n1", "out");
    expect(calls[0]!.path).toBe(`${base}/snapshots/${S1}/paths`);
    expect(calls[0]!.url.searchParams.get("direction")).toBe("out");
    expect(r.paths).toEqual([["e1", "e2"]]);
    expect(r.edges[0]!.id).toBe("e2");
    expect(r.truncated).toBe(true);
  });

  it("redacts engine names in evidence details and scan references (rule 3)", () => {
    const e = normaliseEdge({
      id: "e1", source: "a", target: "b", type: "exposes", evidence: "verified",
      evidence_refs: [{ kind: "scan", ref: "opengrep:pathos.graph.route", detail: "matched by Opengrep" }, { kind: "file_line", ref: "tools/trivy/main.go:3" }],
    });
    expect(e.evidence_refs[0]).toEqual({ kind: "scan", ref: "engine:pathos.graph.route", detail: "matched by engine" });
    // Repository content (a file path) is shown as is.
    expect(e.evidence_refs[1]!.ref).toBe("tools/trivy/main.go:3");
  });
});

describe("CodeGraph permissions (no dead buttons)", () => {
  it("hides Build without scans.run", async () => {
    mockApi({ "GET /api/v1/meta": meta(true), [`GET ${base}/snapshots`]: () => ({ snapshots: [] }) });
    renderApp(<CodeGraphPanel applicationId={APP} />, { permissions: ["findings.read"] });
    expect(await screen.findByText("No CodeGraph yet")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Build CodeGraph" })).toBeNull();
    expect(screen.getByText(/built after the next scan, or by someone who can run scans/)).toBeInTheDocument();
  });

  it("hides Rebuild without scans.run and shows it with scans.run", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ snapshots: [snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => exampleGraph,
    });
    const { unmount } = renderApp(<CodeGraphPanel applicationId={APP} />, { permissions: ["findings.read"] });
    expect(await screen.findByTestId("codegraph-commit")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Rebuild" })).toBeNull();
    unmount();
    renderApp(<CodeGraphPanel applicationId={APP} />, { permissions: ["findings.read", "scans.run"] });
    expect(await screen.findByRole("button", { name: "Rebuild" })).toBeEnabled();
  });

  it("offers the JSON export only with findings.export", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ snapshots: [snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => exampleGraph,
    });
    const { unmount } = renderApp(<CodeGraphPanel applicationId={APP} />, { permissions: ["findings.read"] });
    await userEvent.click(await screen.findByRole("button", { name: /Export/ }));
    expect(await screen.findByRole("menuitem", { name: "PNG image" })).toBeInTheDocument();
    expect(screen.queryByRole("menuitem", { name: "JSON (graph data)" })).toBeNull();
    unmount();
    renderApp(<CodeGraphPanel applicationId={APP} />, { permissions: ["findings.read", "findings.export"] });
    await userEvent.click(await screen.findByRole("button", { name: /Export/ }));
    expect(await screen.findByRole("menuitem", { name: "JSON (graph data)" })).toBeInTheDocument();
  });
});

describe("CodeGraph views and settings", () => {
  it("offers only the views the server lists", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/codegraph/views": () => ({ views: [{ name: "architecture" }, { name: "api" }, { name: "call_graph" }], node_types: [], edge_types: [] }),
      [`GET ${base}/snapshots`]: () => ({ snapshots: [snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => exampleGraph,
    });
    renderApp(<CodeGraphPanel applicationId={APP} />, { permissions: ["findings.read"] });
    const views = await screen.findByRole("group", { name: "CodeGraph views" });
    await waitFor(() => expect(within(views).getAllByRole("button").map((b) => b.textContent)).toEqual(["Architecture", "Call graph", "API & endpoints"]));
  });

  it("names the snapshot change impact compares with", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ snapshots: [snap(S0, "2026-11-18T10:00:00Z"), snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => ({ snapshot_id: S1, view: "change_impact", base_snapshot_id: S0, nodes: [{ ...exampleGraph.nodes[3], attrs: { change: "added" } }], edges: [], aggregated: [] }),
    });
    renderApp(<CodeGraphPanel applicationId={APP} state={{ view: "change_impact" }} onStateChange={() => {}} />);
    expect(await screen.findByText(/Compared with the snapshot of/)).toHaveTextContent("9be010fbbbbb");
  });

  it("reads and saves the organization settings", async () => {
    const { calls } = mockApi({
      "GET /api/v1/codegraph/settings": () => ({ auto_rebuild: true, min_interval_minutes: 60, keep_snapshots: 10, updated_at: null }),
      "PUT /api/v1/codegraph/settings": (_u, init) => init.json as object,
    });
    renderApp(<CodeGraphSettingsCard />, { permissions: ["settings.manage"] });
    const keep = await screen.findByLabelText(/Snapshots kept per repository/);
    expect(keep).toHaveValue(10);
    await userEvent.clear(keep);
    await userEvent.type(keep, "25");
    await userEvent.click(screen.getByRole("checkbox", { name: /Rebuild the graph after each successful scan/ }));
    await userEvent.click(screen.getByRole("button", { name: "Save settings" }));
    await waitFor(() => expect(calls.find((c) => c.method === "PUT")?.body).toEqual({ auto_rebuild: false, min_interval_minutes: 60, keep_snapshots: 25 }));
  });

  it("shows the settings to administrators only", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      "GET /api/v1/applications": () => ({ items: [{ id: APP, name: "example-app" }] }),
      "GET /api/v1/codegraph/settings": () => ({ auto_rebuild: true, min_interval_minutes: 60, keep_snapshots: 10 }),
    });
    const { unmount } = renderApp(<CodeGraphIndexPage />, { permissions: ["findings.read"] });
    await screen.findByRole("option", { name: "example-app" });
    expect(screen.queryByRole("heading", { name: "CodeGraph settings" })).toBeNull();
    unmount();
    renderApp(<CodeGraphIndexPage />, { permissions: ["findings.read", "settings.manage"] });
    expect(await screen.findByRole("heading", { name: "CodeGraph settings" })).toBeInTheDocument();
  });
});
