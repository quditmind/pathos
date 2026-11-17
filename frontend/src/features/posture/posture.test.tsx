import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { groups } from "@/components/layout/AppShell";
import { PosturePage } from "./PosturePage";
import { CoveragePage } from "./CoveragePage";
import { UnmanagedPage } from "./UnmanagedPage";
import { BenchmarkPage } from "./BenchmarkPage";
import { DependencyPanel } from "./DependencyPanel";
import type { AppPosture, PostureGroup } from "./api";

afterEach(() => vi.unstubAllGlobals());

const group = (over: Partial<PostureGroup>): PostureGroup => ({
  id: "a1", label: "Payments", repositories: 2, open: { critical: 1, high: 2, medium: 0, low: 0, info: 0 }, open_total: 3, kev_open: 1,
  sla_breached: 0, high_risk_open: 4, max_risk: 90, avg_risk: 60, risk_score: 93, risk_band: "critical",
  risk_basis: { max_finding_risk: 90, other_high_risk_findings: 3, uplift: 3 }, fixed: 4, mttr_days: 6.5, sla_compliance: 75,
  last_scan_at: "2026-11-17T10:00:00Z", coverage: 66.7, ...over,
});

describe("posture navigation", () => {
  it("has a Posture section", () => {
    const g = groups.find((x) => x.label === "Posture")!;
    expect(g.items.map((i) => i.to)).toEqual(["/posture", "/posture/coverage", "/posture/unmanaged", "/posture/benchmark", "/posture/attack-paths", "/compliance", "/posture/blast-radius", "/posture/graph"]);
  });
});

describe("application posture", () => {
  it("shows rollup risk with its explanation, KEV and coverage, and the unassigned group", async () => {
    const app: AppPosture = { ...group({}), application_key: "QD-APP-000001", criticality: "critical", lifecycle: "active", environment: "production",
      business_unit: "Retail", owner: "Ada", scan_targets: 2 };
    const none: AppPosture = { ...group({ id: null, label: "No application", max_risk: null, risk_score: 0, risk_band: "none", kev_open: 0,
      open: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, open_total: 0 }), application_key: "", criticality: "", lifecycle: "", environment: "",
      business_unit: null, owner: null, scan_targets: 0 };
    mockApi({ "GET /api/v1/posture/applications": () => ({ items: [app, none] }) });
    renderApp(<PosturePage />, { permissions: ["findings.read"] });
    expect(await screen.findByText("Payments")).toBeInTheDocument();
    expect(screen.getByText("QD-APP-000001")).toBeInTheDocument();
    expect(screen.getByTitle(/Riskiest open finding 90, plus 3 for 3 more findings/)).toBeInTheDocument();
    expect(screen.getAllByText("66.7%").length).toBe(2);
    expect(screen.getByText("+ 2 targets")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Map these repositories" })).toHaveAttribute("href", "/posture/unmanaged");
  });

  it("groups by another dimension", async () => {
    const api = mockApi({
      "GET /api/v1/posture/applications": () => ({ items: [] }),
      "GET /api/v1/posture/aggregate": () => ({ items: [group({ id: "t1", label: "Platform team" })] }),
    });
    renderApp(<PosturePage />, { permissions: ["findings.read"] });
    fireEvent.change(await screen.findByLabelText("Group by"), { target: { value: "team" } });
    expect(await screen.findByText("Platform team")).toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/api/v1/posture/aggregate" && c.url.searchParams.get("by") === "team")).toBe(true);
  });
});

describe("coverage", () => {
  it("shows per-category status with explanations", async () => {
    mockApi({
      "GET /api/v1/posture/coverage": () => ({
        days: 30, categories: ["sast", "dast"], truncated: false,
        summary: [{ category: "sast", covered: 1, percent: 50 }, { category: "dast", covered: 0, percent: 0 }],
        items: [{ repository_id: "r1", repository_name: "acme/api", repository_key: "QD-REPO-000001", application_id: null, application_name: null, scan_enabled: true,
          cells: { sast: { status: "covered", last_at: "2026-11-17T10:00:00Z", scanners: ["opengrep"] }, dast: { status: "not_configured", last_at: null, scanners: [] } } }],
      }),
    });
    renderApp(<CoveragePage />, { permissions: ["repos.read"] });
    expect(await screen.findByText("acme/api")).toBeInTheDocument();
    expect(screen.getByLabelText(/Code \(SAST\): Covered: last success .*\(opengrep\)/)).toBeInTheDocument();
    expect(screen.getByLabelText("Web and API (DAST): No target")).toBeInTheDocument();
    expect(screen.getByText("50%")).toBeInTheDocument();
  });
});

describe("unmanaged assets", () => {
  const base = {
    stale_days: 30, active_days: 90,
    issue_labels: { no_application: "Not mapped to an application", no_owner: "No owner or responsible team", never_scanned: "Never scanned successfully",
      stale_scan: "Not scanned successfully recently", scanning_disabled: "Scanning disabled", sync_failing: "SCM synchronization failing", archived_in_scm: "Archived in the SCM" },
    counts: { no_application: 1, no_owner: 1, shadow: 1 },
    repositories: [
      { id: "r1", name: "acme/orphan", repository_key: "QD-REPO-000002", issues: ["no_application", "no_owner"], last_scan_at: null, last_pushed_at: null, open_findings: 0, criticality: "medium" },
      { id: "r2", name: "acme/old", repository_key: "QD-REPO-000003", issues: ["stale_scan"], last_scan_at: null, last_pushed_at: null, open_findings: 2, criticality: "high" },
    ],
  };

  it("lists gaps, filters by gap and shows shadow repositories with the inventory", async () => {
    mockApi({
      "GET /api/v1/posture/unmanaged": () => ({
        ...base, shadow_visible: true,
        shadow: [{ scm_connection_id: "c1", scm_connection_name: "GitHub", provider: "github", external_id: "9", full_name: "acme/shadow", url: "https://github.com/acme/shadow",
          visibility: "private", pushed_at: "2026-11-10T10:00:00Z", first_seen_at: "2026-11-17T10:00:00Z" }],
        inventory: [{ scm_connection_id: "c1", scm_connection_name: "GitHub", status: "succeeded", finished_at: "2026-11-17T10:00:00Z", repositories: 42, truncated: false, error: "" }],
      }),
    });
    renderApp(<UnmanagedPage />, { permissions: ["repos.read", "repos.manage"] });
    expect(await screen.findByText("acme/orphan")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "acme/shadow" })).toHaveAttribute("href", "https://github.com/acme/shadow");
    expect(screen.getByText(/42 repositories/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Refresh inventory of GitHub" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Not scanned successfully recently/ }));
    await waitFor(() => expect(screen.queryByText("acme/orphan")).toBeNull());
    expect(screen.getByText("acme/old")).toBeInTheDocument();
  });

  it("hides shadow repositories from scoped users", async () => {
    mockApi({ "GET /api/v1/posture/unmanaged": () => ({ ...base, shadow_visible: false }) });
    renderApp(<UnmanagedPage />, { permissions: ["repos.read"] });
    expect(await screen.findByText(/shown to people who can see every repository/)).toBeInTheDocument();
  });
});

describe("benchmarking", () => {
  it("marks the best and worst value per metric", async () => {
    mockApi({
      "GET /api/v1/posture/benchmark": () => ({
        metrics: [{ key: "mttr_days", label: "Mean time to remediate (days)", lower_is_better: true }],
        items: [{ ...group({ id: "a", label: "Fast", mttr_days: 2 }), rank: 1, open_per_repository: 1, critical_high_per_repository: 0 },
          { ...group({ id: "b", label: "Slow", mttr_days: 30 }), rank: 2, open_per_repository: 1, critical_high_per_repository: 0 }],
      }),
    });
    renderApp(<BenchmarkPage />, { permissions: ["findings.read"] });
    const fast = (await screen.findByText("Fast")).closest("tr")!;
    expect(within(fast).getByText("best")).toBeInTheDocument();
    expect(within(screen.getByText("Slow").closest("tr")!).getByText("worst")).toBeInTheDocument();
    expect(screen.getByText("Median")).toBeInTheDocument();
  });
});

describe("dependency panel", () => {
  it("shows direct and transitive dependencies and explains a path", async () => {
    mockApi({
      "GET /api/v1/repositories/r1/dependencies": () => ({
        components: [
          { ref: "app", name: "app", version: "1", purl: "", type: "library", licenses: [], depth: 0, open_vulnerabilities: 0, max_severity: null },
          { ref: "mid", name: "express", version: "4", purl: "", type: "library", licenses: ["MIT"], depth: 1, open_vulnerabilities: 0, max_severity: null },
          { ref: "deep", name: "qs", version: "6.5", purl: "", type: "library", licenses: [], depth: 2, open_vulnerabilities: 1, max_severity: "high" },
        ],
        edges: [{ parent: "app", child: "mid" }, { parent: "mid", child: "deep" }],
        stats: { components: 3, edges: 2, roots: 1, direct: 1, transitive: 1, vulnerable: 1, vulnerable_transitive: 1 },
        truncated: false,
      }),
      "GET /api/v1/repositories/r1/dependencies/paths": () => ({
        paths: [[{ ref: "app", name: "app", version: "1" }, { ref: "mid", name: "express", version: "4" }, { ref: "deep", name: "qs", version: "6.5" }]],
      }),
    });
    renderApp(<DependencyPanel repoId="r1" />, { permissions: ["sbom.read"] });
    expect(await screen.findByText("Vulnerable, transitive")).toBeInTheDocument();
    fireEvent.click(screen.getByLabelText("Vulnerable only"));
    expect(screen.queryByText("express")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /qs/ }));
    expect(await screen.findByText("How it gets here")).toBeInTheDocument();
    expect(await screen.findByText("express")).toBeInTheDocument();
  });
});
