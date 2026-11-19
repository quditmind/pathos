import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import { mockReactFlowDom } from "@/components/graph/testing";
import { exampleGraph } from "@/components/graph/testdata";
import { CodeGraphPanel, relativeTime } from "./CodeGraphPanel";
import { CodeGraphIndexPage } from "./CodeGraphPage";
import { validateCodeGraphSearch } from "./search";
import { normaliseGraph } from "./api";
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
    renderApp(<CodeGraphPanel applicationId={APP} />);
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
    renderApp(<CodeGraphPanel applicationId={APP} />);
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
    renderApp(<CodeGraphPanel applicationId={APP} applicationName="example-app" />);
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

  it("loads the inspector from the API", async () => {
    mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ items: [snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => exampleGraph,
      [`GET ${base}/snapshots/${S1}/nodes/route`]: () => ({
        node: exampleGraph.nodes[2],
        findings: [{ id: "f1", title: "Example SQL injection", severity: "critical", href: "/findings?finding=f1" }],
        source_links: [{ label: "example/handler.go:88", href: "/scans/0190a000-0000-7000-8000-0000000000ff", kind: "scan" }],
      }),
    });
    renderApp(<CodeGraphPanel applicationId={APP} />);
    fireEvent.click(await screen.findByRole("button", { name: /^POST \/example\/payments, Route/ }));
    const insp = screen.getByLabelText("Node inspector");
    expect(await within(insp).findByText("Example SQL injection")).toBeInTheDocument();
    expect(within(insp).getByRole("link", { name: "example/handler.go:88" })).toHaveAttribute("href", "/scans/0190a000-0000-7000-8000-0000000000ff");
  });

  it("compares two snapshots in the change impact view", async () => {
    const { calls } = mockApi({
      "GET /api/v1/meta": meta(true),
      [`GET ${base}/snapshots`]: () => ({ items: [snap(S0, "2026-11-18T10:00:00Z"), snap(S1, "2026-11-19T10:00:00Z")] }),
      [`GET ${base}/snapshots/${S1}/graph`]: () => exampleGraph,
      [`GET ${base}/diff`]: () => ({
        added: { nodes: [exampleGraph.nodes[6]], edges: [] },
        removed: { nodes: [{ id: "gone", type: "function", label: "removedFn()", layer: "code" }], edges: [] },
        changed: { nodes: [], edges: [] },
      }),
    });
    renderApp(<CodeGraphPanel applicationId={APP} state={{ view: "change_impact" }} onStateChange={() => {}} />);
    expect(await screen.findByRole("group", { name: "Compare legend" })).toHaveTextContent("Removed (1)");
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
