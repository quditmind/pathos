import { describe, expect, it, afterEach, vi } from "vitest";
import { screen, within } from "@testing-library/react";
import { router } from "@/app/router";
import { mockApi, renderApp } from "@/test/harness";
import { AppShell, groups, navGroupsFor } from "./AppShell";

afterEach(() => vi.unstubAllGlobals());

// Every item of the 2.2 sidebar (label, route), captured from AppShell.tsx at
// f3c5efd before the 3.0 regroup. None may be lost.
const oldMenu: [string, string][] = [
  ["Dashboard", "/"],
  ["Executive overview", "/executive"],
  ["Reports", "/reports"],
  ["Developer insights", "/insights/developers"],
  ["Repositories", "/repositories"],
  ["Import history", "/repositories/imports"],
  ["Applications", "/applications"],
  ["Runtime", "/runtime"],
  ["Application posture", "/posture"],
  ["Coverage", "/posture/coverage"],
  ["Unmanaged assets", "/posture/unmanaged"],
  ["Benchmarking", "/posture/benchmark"],
  ["Attack paths", "/posture/attack-paths"],
  ["Compliance", "/compliance"],
  ["Blast radius", "/posture/blast-radius"],
  ["Context graph", "/posture/graph"],
  ["Scan Overview", "/scans/overview"],
  ["Scans", "/scans"],
  ["Scan Schedules", "/scans/schedules"],
  ["Scan Comparison", "/scans/compare"],
  ["Scan targets", "/scans/targets"],
  ["Pull request checks", "/pull-requests"],
  ["Import Results", "/scans/imports"],
  ["Scan profiles", "/configurations/scan-profiles"],
  ["Scanners & workers", "/configurations/scanners"],
  ["Scan coverage", "/configurations/scan-coverage"],
  ["Custom rules", "/configurations/custom-rules"],
  ["Findings", "/findings"],
  ["Risk acceptances", "/risk"],
  ["Suppression rules", "/suppression-rules"],
  ["SBOM inventory", "/sbom"],
  ["Component portfolio", "/portfolio"],
  ["Component policies", "/sbom/policies"],
  ["VEX statements", "/vex"],
  ["Overview", "/human-review"],
  ["Review Queue", "/human-review/queue"],
  ["Assessments", "/human-review/assessments"],
  ["Assignments", "/human-review/assignments"],
  ["Review Reports", "/human-review/reports"],
  ["Review Configurations", "/human-review/configurations"],
  ["AI Security Analyst", "/ai/analyst"],
  ["AI reviews", "/ai"],
  ["AI reports", "/ai/reports"],
  ["AI settings", "/admin/ai"],
  ["AI usage", "/admin/ai-usage"],
  ["MCP registry", "/admin/mcp"],
  ["Users", "/admin/users"],
  ["Organization", "/admin/organization"],
  ["SCM connections", "/admin/scm"],
  ["Tags", "/admin/tags"],
  ["Asset settings", "/admin/assets"],
  ["Policies", "/admin/policies"],
  ["Integrations", "/admin/integrations"],
  ["Risk & intelligence", "/admin/risk-intelligence"],
  ["Developer attribution", "/admin/developer-attribution"],
  ["Secret validation", "/admin/secret-validation"],
  ["Notifications", "/admin/notifications"],
  ["Audit log", "/admin/audit"],
];

describe("sidebar regroup (prompt §5)", () => {
  it("captures all 58 items of the old menu", () => {
    expect(oldMenu).toHaveLength(58);
  });

  it("keeps every old menu route in the new menu", () => {
    const routes = new Set(groups.flatMap((g) => g.items.map((i) => i.to)).filter(Boolean));
    const missing = oldMenu.filter(([, to]) => !routes.has(to));
    expect(missing).toEqual([]);
  });

  it("keeps Installation › Organizations, first in Administration, on multi-tenant installs", () => {
    expect(groups.flatMap((g) => g.items).some((i) => i.to === "/installation/organizations")).toBe(false);
    const admin = navGroupsFor(true).find((g) => g.label === "Administration")!;
    expect(admin.items[0]).toMatchObject({ label: "Organizations", to: "/installation/organizations" });
  });

  it("every old route still resolves to a page (no router redirect; SCM connections and Integrations redirect in their component only while the connectors flag is on)", () => {
    const byPath = router.routesByPath as Record<string, { options: { component?: unknown; beforeLoad?: unknown } }>;
    const all: [string, string][] = [...oldMenu, ["Organizations", "/installation/organizations"]];
    for (const [, to] of all) {
      const r = byPath[to];
      expect(r, to).toBeDefined();
      expect(r!.options.component, to).toBeDefined();
      expect(r!.options.beforeLoad, `${to} must not redirect yet`).toBeUndefined();
    }
  });

  it("has the §5 groups in order", () => {
    expect(groups.map((g) => g.label)).toEqual([
      "Home",
      "1 · Connect",
      "2 · Inventory",
      "3 · Discover",
      "4 · Threat model",
      "5 · Reverse engineering",
      "6 · Assess",
      "7 · Validate & intelligence",
      "8 · Remediate & gate",
      "9 · Report & monitor",
      "Configurations",
      "Administration",
    ]);
  });

  it("places the items the §5 table does not list as decided by the lead", () => {
    const labels = (g: string) => groups.find((x) => x.label === g)!.items.map((i) => i.label);
    const disc = labels("3 · Discover");
    expect(disc.indexOf("Runtime")).toBe(disc.indexOf("Context graph") + 1);
    const conf = labels("Configurations");
    expect(conf.indexOf("Scan coverage")).toBe(conf.indexOf("Scanners & workers") + 1);
    expect(conf.indexOf("Secret validation")).toBe(conf.indexOf("Risk & intelligence") + 1);
  });

  it("new modules are roadmap items with a phase and a feature flag; only built ones have a route", () => {
    const roadmap = groups.flatMap((g) => g.items).filter((i) => i.phase);
    // Built modules (M2: Connectors; M3: Lifecycle overview, Onboard an
    // application) carry their route and still their phase and flag.
    expect(roadmap.filter((i) => i.to).map((i) => [i.label, i.to, i.flag])).toEqual([
      ["Lifecycle overview", "/lifecycle", "lifecycle_overview"],
      ["Connectors", "/connectors", "connectors"],
      ["Onboard an application", "/onboarding", "onboarding"],
    ]);
    // Not-yet-built modules have no route at all.
    expect(roadmap.filter((i) => !i.to).map((i) => i.label).sort()).toEqual(
      [
        "API & endpoints",
        "Binary analysis",
        "CodeGraph",
        "Continuous monitoring",
        "Remediation workspace",
        "Reverse engineering tools",
        "Threat models",
      ].sort(),
    );
    expect(groups.flatMap((g) => g.items).filter((i) => !i.to).map((i) => i.label).sort()).toEqual(
      roadmap.filter((i) => !i.to).map((i) => i.label).sort(),
    );
    for (const i of roadmap) {
      expect(i.phase, i.label).toBeGreaterThan(0);
      expect(i.flag, i.label).toBeTruthy();
    }
  });

  it("every flagged module with a route carries a phase and a flag", () => {
    const flagged = groups.flatMap((g) => g.items).filter((i) => i.to && i.flag);
    expect(flagged.map((i) => [i.label, i.to, i.flag])).toEqual([
      ["Lifecycle overview", "/lifecycle", "lifecycle_overview"],
      ["Connectors", "/connectors", "connectors"],
      ["Onboard an application", "/onboarding", "onboarding"],
    ]);
    for (const i of flagged) expect(i.phase, i.label).toBeGreaterThan(0);
  });

  it("enables flagged items only when their flag is on", async () => {
    mockApi({ "GET /api/v1/meta": () => ({ product: "PATHOS", vendor: "Quditmind", version: "dev", feature_flags: { onboarding: true, lifecycle_overview: false } }) });
    renderApp(
      <AppShell>
        <div />
      </AppShell>,
      { permissions: ["repos.read", "repos.manage"] },
    );
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(await within(nav).findByRole("link", { name: "Onboard an application" })).toHaveAttribute("href", "/onboarding");
    const life = within(nav).getByText("Lifecycle overview").closest("[aria-disabled]")!;
    expect(life).toHaveAttribute("title", "Lifecycle overview: arrives in roadmap phase 3");
  });

  it("renders roadmap items disabled with their phase", async () => {
    mockApi({});
    renderApp(
      <AppShell>
        <div />
      </AppShell>,
      { permissions: ["repos.read"] },
    );
    const nav = await screen.findByRole("navigation", { name: "Main" });
    expect(within(nav).queryByRole("link", { name: /^Connectors/ })).toBeInTheDocument();
    const connectors = within(nav).getByText("Connectors").closest("[aria-disabled]")!;
    expect(connectors).toHaveAttribute("aria-disabled", "true");
    expect(connectors).toHaveAttribute("title", "Connectors: arrives in roadmap phase 2");
    expect(within(connectors as HTMLElement).getByText("arrives in roadmap phase 2")).toBeInTheDocument();
    expect(within(nav).getByRole("link", { name: "Repositories" })).toHaveAttribute("href", "/repositories");
  });

  it("makes Connectors a link only while the connectors flag is on", async () => {
    mockApi({ "GET /api/v1/meta": () => ({ product: "PATHOS", vendor: "Quditmind", version: "dev", feature_flags: { connectors: true } }) });
    renderApp(
      <AppShell>
        <div />
      </AppShell>,
      { permissions: ["repos.read"] },
    );
    const nav = await screen.findByRole("navigation", { name: "Main" });
    const link = await within(nav).findByRole("link", { name: "Connectors" });
    expect(link).toHaveAttribute("href", "/connectors");
    expect(within(nav).queryByText("arrives in roadmap phase 2")).not.toBeInTheDocument();
    // Other roadmap items stay disabled.
    expect(within(nav).getByText("Lifecycle overview").closest("[aria-disabled]")).toHaveAttribute("aria-disabled", "true");
  });
});
