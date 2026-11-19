import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import type { Finding } from "@/api/types";
import { mockApi, renderApp } from "@/test/harness";
import { FindingsPage } from "./FindingsPage";
import { ReachabilitySection } from "./Reachability";

afterEach(() => vi.unstubAllGlobals());

const evidence: Finding["reachability_evidence"] = {
  tool: "pathos-reach",
  scan_job_id: "job-1",
  analysed_at: "2026-11-19T15:50:00Z",
  symbols: ["lodash.template"],
  paths: [[
    { file: "src/index.js", line: 12, function: "<top level>" },
    { file: "src/index.js", line: 8, function: "main" },
    { file: "src/views.js", line: 5, function: "renderGreeting" },
  ]],
  unresolved: [],
  dynamic: [],
  limits: "pathos-reach reads the repository's own code, not the dependencies.",
};

describe("reachability evidence", () => {
  it("shows the answer, the method and the call path frame by frame", async () => {
    renderApp(<ReachabilitySection f={{ reachability: "reachable", reachability_basis: "the code calls lodash.template at src/views.js:5",
      reachability_method: "symbol_calls", reachability_evidence: evidence }} />);
    expect(await screen.findByText("Reachable")).toBeInTheDocument();
    expect(screen.getByText(/the code calls lodash\.template/)).toBeInTheDocument();
    expect(screen.getByText(/function level: calls in the code/)).toBeInTheDocument();
    expect(screen.getByText("lodash.template")).toBeInTheDocument();
    const path = screen.getByRole("list", { name: "Call path 1" });
    const frames = within(path).getAllByRole("listitem").map((li) => li.textContent);
    expect(frames).toEqual([expect.stringContaining("src/index.js:12"), expect.stringContaining("src/index.js:8"), expect.stringContaining("src/views.js:5")]);
    expect(within(path).getByText("renderGreeting")).toBeInTheDocument();
    expect(screen.getByText(/Limits: pathos-reach reads/)).toBeInTheDocument();
  });

  it("says why an answer is unknown", async () => {
    renderApp(<ReachabilitySection f={{ reachability: "unknown", reachability_basis: "dynamic use", reachability_method: "symbol_calls",
      reachability_evidence: { ...evidence, paths: [], dynamic: [{ ecosystem: "npm", module: "underscore", reason: "member selected by a computed name", file: "src/plugin.js", line: 6, test: false }] } }} />);
    expect(await screen.findByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText(/member selected by a computed name/)).toBeInTheDocument();
    expect(screen.getByText("src/plugin.js:6")).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: "Call path 1" })).not.toBeInTheDocument();
  });

  it("labels package-level answers without evidence", async () => {
    renderApp(<ReachabilitySection f={{ reachability: "reachable", reachability_basis: "a dependency of express, which the code uses", reachability_method: "import" }} />);
    expect(await screen.findByText(/package level: the code's imports/)).toBeInTheDocument();
    expect(screen.queryByText(/Vulnerable functions checked/)).not.toBeInTheDocument();
  });

  it("filters the findings list by reachability and method on the server", async () => {
    const api = mockApi({
      "GET /api/v1/findings": () => ({ items: [], next_cursor: null }),
      "GET /api/v1/findings/summary": () => ({ critical: 0, high: 0, medium: 0, low: 0, info: 0 }),
      "GET /api/v1/scanners": () => ({ items: [] }),
      "GET /api/v1/repositories": () => ({ items: [] }),
    });
    renderApp(<FindingsPage />, { permissions: ["findings.read"], path: "/findings" });
    fireEvent.change(await screen.findByRole("combobox", { name: "Reachability" }), { target: { value: "not_reachable" } });
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/findings" && c.url.searchParams.get("reachability") === "not_reachable")).toBe(true));
    fireEvent.change(screen.getByRole("combobox", { name: "Reachability method" }), { target: { value: "call_graph" } });
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/findings" && c.url.searchParams.get("reachability_method") === "call_graph")).toBe(true));
  });
});
