import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import type { ScanJob, ScanLogLine } from "@/api/types";
import { mockApi, renderApp } from "@/test/harness";
import { AppShell, groups } from "@/components/layout/AppShell";
import { ScansPage } from "./ScansPage";
import { StartScanDialog } from "./StartScanDialog";
import { detailTabs, ScanDetails } from "./details/ScanDetailsPage";
import { LogsTab } from "./details/LogsTab";
import { ConfigurationTab } from "./details/ConfigurationTab";
import { stageLabel } from "./api";

const job = (over: Partial<ScanJob> = {}): ScanJob => ({
  id: "j1", repository_id: "r1", repository_name: "acme/payments", repository_key: "QD-REPO-000042", profile_name: "Default", profile_version: 3,
  trigger: "manual", priority: 70, status: "succeeded", ref: "main", commit_sha: "abcdef1234567890", attempts: 1, worker_name: "w1", requested_by: "ada@example.com",
  error: "", findings_new: 2, findings_fixed: 1, gate_failed: false, queued_at: "2026-11-01T10:00:00Z", started_at: "2026-11-01T10:00:05Z", finished_at: "2026-11-01T10:02:05Z",
  results: [{ scanner_key: "semgrep", scanner_version: "1.90.0", status: "succeeded", duration_ms: 1000, findings_count: 3, error: "", has_artifact: false }],
  scan_key: "QD-SCAN-000007", name: "Nightly", asset_type: "repository", profile_id: "p1", progress: 100, stage: "finished", retry_of: null, retry_count: 0,
  schedule_id: null, schedule_run_id: null, snapshot_id: null, duration_ms: 120000, findings_total: 5, severity: { critical: 1, high: 2, medium: 1, low: 1, info: 0 },
  ...over,
});

const baseRoutes = {
  "GET /api/v1/workers": () => ({ items: [] }),
  "GET /api/v1/scan-profiles": () => ({ items: [{ id: "p1", name: "Default", description: "", is_default: true, repository_count: 1, current: { id: "v3", version: 3 } }] }),
  "GET /api/v1/scanners": () => ({ items: [{ key: "semgrep", name: "Semgrep" }] }),
  "GET /api/v1/schedules": () => ({ items: [] }),
};

afterEach(() => vi.unstubAllGlobals());

describe("navigation", () => {
  it("Scanning and Configurations have their entries", () => {
    const scanning = groups.find((g) => g.label === "Scanning")!;
    expect(scanning.items.map((i) => [i.label, i.to])).toEqual([
      ["Scan Overview", "/scans/overview"],
      ["Scans", "/scans"],
      ["Scan Schedules", "/scans/schedules"],
      ["Scan Comparison", "/scans/compare"],
      ["Scan targets", "/scans/targets"],
      ["Pull request checks", "/pull-requests"],
      ["Import Results", "/scans/imports"],
    ]);
    const conf = groups.find((g) => g.label === "Configurations")!;
    expect(conf.items.map((i) => [i.label, i.to])).toEqual([
      ["Scan profiles", "/configurations/scan-profiles"],
      ["Scanners & workers", "/configurations/scanners"],
      ["Custom rules", "/configurations/custom-rules"],
    ]);
    expect(groups.flatMap((g) => g.items).filter((i) => i.label === "Scanners & workers")).toHaveLength(1);
  });

  it("renders both sections in the sidebar", async () => {
    mockApi({});
    renderApp(<AppShell><div /></AppShell>, { permissions: ["scans.read", "scans.compare", "scanners.read"] });
    const nav = await screen.findByRole("navigation", { name: "Main" });
    for (const l of ["Scan Overview", "Scans", "Scan Schedules", "Scan Comparison", "Scan profiles", "Scanners & workers"]) {
      expect(within(nav).getByRole("link", { name: l })).toBeInTheDocument();
    }
    expect(within(nav).getByText("Configurations")).toBeInTheDocument();
  });
});

describe("scans list", () => {
  it("renders the new columns and actions by permission", async () => {
    mockApi({
      ...baseRoutes,
      "GET /api/v1/scans": () => ({ items: [job(), job({ id: "j2", scan_key: "QD-SCAN-000008", status: "failed", progress: 60 }), job({ id: "j3", scan_key: "QD-SCAN-000009", status: "running", progress: 40, stage: "scanning:semgrep", finished_at: null, duration_ms: null })] }),
    });
    renderApp(<ScansPage />, { permissions: ["scans.read", "scans.run"] });
    expect(await screen.findByText("QD-SCAN-000007")).toBeInTheDocument();
    for (const h of ["Scan ID", "Scan name", "Asset", "Asset type", "Scan profile", "Execution status", "Progress", "Findings", "Severity", "Started at", "Duration", "Trigger source", "Actions"]) {
      expect(screen.getByRole("columnheader", { name: h })).toBeInTheDocument();
    }
    expect(screen.getAllByText("QD-REPO-000042").length).toBeGreaterThan(0);
    expect(screen.getByText("Scanning (semgrep)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel QD-SCAN-000009" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry QD-SCAN-000008" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Retry QD-SCAN-000007" })).toBeNull();
    expect(screen.getByRole("button", { name: /Start scan/ })).toBeInTheDocument();
  });

  it("hides run actions without scans.run", async () => {
    mockApi({ ...baseRoutes, "GET /api/v1/scans": () => ({ items: [job({ status: "failed" })] }) });
    renderApp(<ScansPage />, { permissions: ["scans.read"] });
    expect(await screen.findByText("QD-SCAN-000007")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Retry/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Start scan/ })).toBeNull();
  });

  it("passes filters to the API", async () => {
    const api = mockApi({ ...baseRoutes, "GET /api/v1/scans": () => ({ items: [] }) });
    renderApp(<ScansPage />, { permissions: ["scans.read"], path: "/?status=active&trigger=schedule&from=2026-10-01" });
    await screen.findByText("No executions match");
    const call = api.calls.find((c) => c.path === "/api/v1/scans")!;
    expect(call.url.searchParams.get("status")).toBe("active");
    expect(call.url.searchParams.get("trigger")).toBe("schedule");
    expect(call.url.searchParams.get("from")).toBe("2026-10-01");
  });
});

describe("start scan dialog", () => {
  it("sends repository_ids, profile_id and name and shows per-asset results", async () => {
    const api = mockApi({
      ...baseRoutes,
      "GET /api/v1/repositories": () => ({
        items: [
          { id: "r1", full_name: "acme/payments", repository_key: "QD-REPO-000042", scan_enabled: true, archived_at: null },
          { id: "r2", full_name: "acme/web", repository_key: "QD-REPO-000043", scan_enabled: true, archived_at: null },
        ],
      }),
      "POST /api/v1/scans": () => ({ items: [{ repository_id: "r1", job_id: "j9" }, { repository_id: "r2", job_id: "j8", coalesced: true }] }),
    });
    renderApp(<StartScanDialog open onOpenChange={() => {}} />, { permissions: ["scans.run"] });
    fireEvent.click(await screen.findByRole("checkbox", { name: "Select acme/payments" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Select acme/web" }));
    const profile = screen.getByLabelText(/Scan profile/);
    expect(within(profile).getByRole("option", { name: "Repository's own profile" })).toBeInTheDocument();
    expect(screen.getByText("Compatible with repositories")).toBeInTheDocument();
    fireEvent.change(profile, { target: { value: "p1" } });
    fireEvent.change(screen.getByLabelText(/Scan name/), { target: { value: "Release audit" } });
    fireEvent.click(screen.getByRole("button", { name: "Start 2 scans" }));
    expect(await screen.findByText("already queued")).toBeInTheDocument();
    expect(api.calls.find((c) => c.method === "POST")!.body).toEqual({ repository_ids: ["r1", "r2"], profile_id: "p1", name: "Release audit" });
    expect(screen.getAllByRole("link", { name: /Open execution/ })).toHaveLength(2);
  });
});

describe("scan details", () => {
  const routes = (j: ScanJob) => ({
    "GET /api/v1/scans/j1": () => j,
    "GET /api/v1/scans/j1/findings": () => ({ items: [] }),
    "GET /api/v1/scans/j1/stages": () => ({ stages: [{ key: "source", label: "Fetch source", scanner: "", scanner_version: "", status: "succeeded", started_at: null, finished_at: null, duration_ms: 1200, findings: null, error: "" }], events: [] }),
    "GET /api/v1/scans/j1/history": () => ({ items: [j, job({ id: "j0", scan_key: "QD-SCAN-000001" })] }),
    "GET /api/v1/scans/j1/logs": () => ({ items: [], sources: [], next_after_id: null }),
  });

  it("has exactly seven tabs and follows the URL", async () => {
    mockApi(routes(job()));
    const { router } = renderApp(<ScanDetails id="j1" />, { permissions: ["scans.read", "scans.compare", "findings.read"], path: "/?tab=stages" });
    const tabs = await screen.findAllByRole("tab");
    expect(tabs.map((t) => t.textContent)).toEqual(["Overview", "Findings", "Material changes", "Execution Logs", "Stages", "Configuration", "History"]);
    expect(detailTabs).toHaveLength(7);
    expect(screen.getByRole("tab", { name: "Stages" })).toHaveAttribute("aria-selected", "true");
    expect(await screen.findByText("Fetch source")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "History" }));
    await waitFor(() => expect(router.state.location.search).toEqual({ tab: "history" }));
    expect(await screen.findByRole("link", { name: "Compare with this scan" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: "Overview" }));
    await waitFor(() => expect(screen.getByText("Findings summary")).toBeInTheDocument());
    expect(router.state.location.search).toEqual({});
  });

  it("limits history comparison to 2-10 selections", async () => {
    mockApi(routes(job()));
    renderApp(<ScanDetails id="j1" />, { permissions: ["scans.read", "scans.compare"], path: "/?tab=history" });
    const compare = await screen.findByRole("button", { name: /Compare selected/ });
    expect(compare).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select QD-SCAN-000007" }));
    expect(compare).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: "Select QD-SCAN-000001" }));
    expect(compare).toBeEnabled();
  });
});

describe("execution logs", () => {
  const line = (id: number, level: ScanLogLine["level"], source: string, message: string): ScanLogLine => ({ id, at: "2026-11-01T10:00:00Z", level, source, message });

  it("filters by source and level and tails with after_id while running", async () => {
    let n = 0;
    const api = mockApi({
      "GET /api/v1/scans/j1/logs": (url) => {
        const after = Number(url.searchParams.get("after_id") ?? 0);
        n++;
        const all = [line(1, "info", "worker", "lease acquired"), line(2, "warn", "semgrep", "slow rule"), ...(n > 1 ? [line(3, "error", "semgrep", "boom")] : [])];
        return { items: all.filter((l) => l.id > after), sources: ["semgrep", "worker"], next_after_id: null };
      },
    });
    renderApp(<LogsTab job={job({ status: "running", finished_at: null })} pollMs={40} />);
    expect(await screen.findByText("lease acquired")).toBeInTheDocument();
    expect(await screen.findByText("boom")).toBeInTheDocument();
    const polls = api.calls.filter((c) => c.url.searchParams.get("after_id"));
    expect(polls.length).toBeGreaterThan(0);
    expect(polls[0]!.url.searchParams.get("after_id")).toBe("2");
    expect(screen.getAllByTestId("log-line")).toHaveLength(3);

    fireEvent.change(screen.getByRole("combobox", { name: "Log source" }), { target: { value: "semgrep" } });
    fireEvent.change(screen.getByRole("combobox", { name: "Minimum level" }), { target: { value: "warn" } });
    await waitFor(() => {
      const c = api.calls.filter((x) => x.url.searchParams.get("source") === "semgrep" && x.url.searchParams.get("level") === "warn");
      expect(c.length).toBeGreaterThan(0);
      expect(c[0]!.url.searchParams.get("after_id")).toBeNull();
    });
  });
});

describe("configuration tab", () => {
  it("renders the snapshot read-only without inputs", () => {
    const j = job({
      config_snapshot: {
        profile_id: "p1", profile_name: "Default", profile_version_id: "v3", profile_version: 3, change_note: "Tighter rules", severity_threshold: "low",
        exclusions: ["vendor/**"], timeout_seconds: 1800, sbom: true, fail_on_critical: false, retention_days: 90,
        scanners: [{ key: "semgrep", config: { rules: ["p/default"] } }, { key: "gitleaks" }], captured_at: "2026-11-01T10:00:00Z",
      },
    });
    const { container } = renderApp(<ConfigurationTab job={j} />);
    return waitFor(() => {
      expect(screen.getByText(/Snapshot — read-only; profiles are managed in Configurations/)).toBeInTheDocument();
      expect(screen.getByText("Tighter rules")).toBeInTheDocument();
      expect(screen.getByLabelText("semgrep configuration").textContent).toContain('"p/default"');
      expect(container.querySelectorAll("input, select, textarea, button")).toHaveLength(0);
    });
  });
});

describe("helpers", () => {
  it("labels stages", () => {
    expect(stageLabel("scanning:trivy")).toBe("Scanning (trivy)");
    expect(stageLabel("fetching_source")).toBe("Fetching source");
  });
});
