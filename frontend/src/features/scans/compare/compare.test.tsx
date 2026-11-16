import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import type { ScanComparison, ScanJob } from "@/api/types";
import { mockApi, renderApp } from "@/test/harness";
import { ComparePage } from "./ComparePage";
import { dateRange, filterFindings, parseIds, signedDuration } from "./model";

const perms = ["scans.read", "scans.compare"];

function job(i: number, extra: Partial<ScanJob> = {}): ScanJob {
  return {
    id: `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`, repository_id: "r1", repository_name: "payments-api", repository_key: "QD-REPO-000001",
    profile_name: "Default", profile_version: 1, trigger: "manual", priority: 70, status: "succeeded", ref: "main", commit_sha: "abc", attempts: 1,
    worker_name: null, requested_by: null, error: "", findings_new: 0, findings_fixed: 0, gate_failed: false, queued_at: "2026-11-01T10:00:00Z",
    started_at: "2026-11-01T10:00:00Z", finished_at: "2026-11-01T10:05:00Z", scan_key: `QD-SCAN-${String(i).padStart(6, "0")}`, name: "", asset_type: "repository",
    profile_id: "p1", progress: 100, stage: "finished", retry_of: null, retry_count: 0, schedule_id: null, schedule_run_id: null, snapshot_id: null,
    duration_ms: 300000, findings_total: 3, severity: { critical: 1, high: 1, medium: 1, low: 0, info: 0 }, ...extra,
  };
}

const base = {
  "GET /api/v1/scan-profiles": () => ({ items: [] }),
  "GET /api/v1/scanners": () => ({ items: [] }),
};

describe("ScanComparison selection", () => {
  it("allows 2–10 executions", async () => {
    const { calls } = mockApi({ ...base, "GET /api/v1/scans": () => ({ items: Array.from({ length: 12 }, (_, i) => job(i + 1)), next_cursor: null }) });
    renderApp(<ComparePage />, { permissions: perms });
    await screen.findByLabelText("Select QD-SCAN-000001");
    const compare = screen.getByRole("button", { name: /compare selected/i });
    expect(compare).toBeDisabled();
    expect(screen.getByText(/select at least 2/i)).toBeInTheDocument();

    fireEvent.click(screen.getByLabelText("Select QD-SCAN-000001"));
    expect(compare).toBeDisabled();
    fireEvent.click(screen.getByLabelText("Select QD-SCAN-000002"));
    expect(compare).toBeEnabled();

    for (let i = 3; i <= 10; i++) fireEvent.click(screen.getByLabelText(`Select QD-SCAN-${String(i).padStart(6, "0")}`));
    expect(screen.getByText("10 of 10 selected")).toBeInTheDocument();
    const eleventh = screen.getByLabelText("Select QD-SCAN-000011");
    expect(eleventh).toBeDisabled();
    fireEvent.click(eleventh);
    expect(screen.getByText("10 of 10 selected")).toBeInTheDocument();
    expect(compare).toBeEnabled();

    // The list query carries the default 360-day range and asset type.
    const list = calls.find((c) => c.path === "/api/v1/scans")!;
    expect(list.url.searchParams.get("asset_type")).toBe("repository");
    expect(list.url.searchParams.get("from")).toBeTruthy();
    expect(list.url.searchParams.get("to")).toBeTruthy();
  });

  it("requires scans.compare", async () => {
    mockApi(base);
    renderApp(<ComparePage />, { permissions: ["scans.read"] });
    expect(await screen.findByText("Comparison not available")).toBeInTheDocument();
  });
});

describe("ScanComparison view", () => {
  it("renders per-scan metrics and finding states", async () => {
    const a = job(1);
    const b = job(2, { status: "partial", findings_total: 2, severity: { critical: 0, high: 1, medium: 1, low: 0, info: 0 }, duration_ms: 240000 });
    const cmp: ScanComparison = {
      scans: [
        { ...a, scanners: [], succeeded_scanners: ["semgrep", "trivy"], complete: true, new: 0, fixed: 0, recurring: 0, unchanged: 0, not_covered: 0, profile_changed: false, engine_changes: [], duration_delta_ms: null },
        { ...b, scanners: [], succeeded_scanners: ["semgrep"], complete: false, new: 1, fixed: 1, recurring: 0, unchanged: 0, not_covered: 1, profile_changed: true, engine_changes: ["trivy failed"], duration_delta_ms: -60000 },
      ],
      findings: [
        { id: "f1", title: "SQL injection", severity: "critical", scanners: ["semgrep"], states: { [a.id]: "present", [b.id]: "fixed" } },
        { id: "f2", title: "Vulnerable lodash", severity: "high", scanners: ["trivy"], states: { [a.id]: "present", [b.id]: "not_covered" } },
        { id: "f3", title: "Hard-coded secret", severity: "medium", scanners: ["semgrep"], states: { [b.id]: "new" } },
      ],
    };
    const { calls } = mockApi({ ...base, "GET /api/v1/scans": () => ({ items: [a, b] }), "GET /api/v1/scans/compare": () => cmp });
    renderApp(<ComparePage />, { permissions: perms, path: `/?ids=${a.id},${b.id}` });

    const matrix = await screen.findByRole("table", { name: "Finding matrix" });
    expect(calls.find((c) => c.path === "/api/v1/scans/compare")!.url.searchParams.get("ids")).toBe(`${a.id},${b.id}`);
    const lodash = within(matrix).getByText("Vulnerable lodash").closest("tr")!;
    expect(within(lodash).getByText("Not covered")).toBeInTheDocument();
    expect(within(lodash).getByText("Present")).toBeInTheDocument();
    const sqli = within(matrix).getByText("SQL injection").closest("tr")!;
    expect(within(sqli).getByText("Fixed")).toBeInTheDocument();
    expect(within(within(matrix).getByText("Hard-coded secret").closest("tr")!).getByText("New")).toBeInTheDocument();

    const summary = screen.getByRole("table", { name: "Per-scan comparison" });
    expect(within(summary).getByText("Profile changed")).toBeInTheDocument();
    expect(within(summary).getByText("trivy failed")).toBeInTheDocument();
    expect(within(summary).getByText("incomplete")).toBeInTheDocument();
    expect(within(summary).getByText("(−1m 0s)")).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent(/fixed only when the later scan completed with the scanner that covers it/i);

    fireEvent.change(screen.getByLabelText("Filter by state"), { target: { value: "not_covered" } });
    await waitFor(() => expect(within(matrix).queryByText("SQL injection")).not.toBeInTheDocument());
    expect(within(matrix).getByText("Vulnerable lodash")).toBeInTheDocument();
  });
});

describe("compare model", () => {
  it("parses ids and clamps date ranges", () => {
    expect(parseIds("a, b,a,,c")).toEqual(["a", "b", "c"]);
    expect(parseIds(Array.from({ length: 12 }, (_, i) => `x${i}`).join(","))).toHaveLength(10);
    const now = new Date("2026-11-17T12:00:00Z");
    expect(dateRange(undefined, undefined, now)).toEqual({ from: "2025-11-22", to: "2026-11-17", clamped: false });
    expect(dateRange("2024-01-01", "2026-11-17", now)).toEqual({ from: "2025-11-22", to: "2026-11-17", clamped: true });
    expect(signedDuration(65000, () => "1m 5s")).toBe("+1m 5s");
  });
  it("filters findings by state and severity", () => {
    const fs = [
      { id: "1", title: "a", severity: "high" as const, scanners: [], states: { s1: "new" } },
      { id: "2", title: "b", severity: "low" as const, scanners: [], states: { s1: "fixed" } },
    ];
    expect(filterFindings(fs, { state: "fixed" }).map((f) => f.id)).toEqual(["2"]);
    expect(filterFindings(fs, { severity: "high" }).map((f) => f.id)).toEqual(["1"]);
  });
});
