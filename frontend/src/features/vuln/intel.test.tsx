import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import type { Finding, IntelFeed } from "@/api/types";
import { mockApi, renderApp } from "@/test/harness";
import { LifecycleBadge, RiskBadge, RiskPanel, riskBand } from "./intel";
import { RiskIntelPage } from "./RiskIntelPage";
import { FindingsPage } from "@/features/findings/FindingsPage";
import type { RiskWeights } from "@/api/types";

afterEach(() => vi.unstubAllGlobals());

const defaults: RiskWeights = {
  severity: { critical: 9.5, high: 7.5, medium: 5, low: 2.5, info: 0 }, use_cvss: true, kev: 1, exploit_available: 0.8, epss_weight: 1, likelihood_unknown: 0.5,
  criticality: { critical: 1.3, high: 1.15, medium: 1, low: 0.8 }, exposure: { yes: 1.3, unknown: 1.1, no: 0.85 },
  reachability: { reachable: 1.2, unknown: 1, not_reachable: 0.6 }, confidence: { high: 1, medium: 0.9, low: 0.75, unknown: 0.9 },
  human_confirmed: 1.1, compensating_controls: 0.7, fix_available: 1.05, deployment: { deployed: 1.1, not_deployed: 0.7 }, runtime_exposed: 1.3, privileged_workload: 1.15, runtime_alert: 1.3,
};

describe("risk display", () => {
  it("maps scores to bands with text, not colour alone", () => {
    expect([riskBand(90), riskBand(60), riskBand(30), riskBand(5), riskBand(0)]).toEqual(["critical", "high", "medium", "low", "none"]);
    render(<RiskBadge score={81.4} />);
    expect(screen.getByText("81")).toBeInTheDocument();
    expect(screen.getByText("critical")).toBeInTheDocument();
    render(<LifecycleBadge value="under_review" />);
    expect(screen.getByText("Under review")).toBeInTheDocument();
  });

  it("explains a score factor by factor", async () => {
    mockApi({
      "GET /api/v1/findings/f1/risk": () => ({
        risk_score: 81.4, band: "critical", scored_at: "2026-11-17T10:00:00Z", pending: false, cve: "CVE-2021-44228", epss: 0.94, epss_percentile: 0.999,
        kev: true, kev_due_date: "2021-12-24", confidence: "high", reachability: "unknown", cvss_version: "3.1", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        explanation: { score: 81.4, base: 9.5, model_version: 2, factors: [
          { key: "base", label: "Scanner severity", value: "critical", weight: 9.5 },
          { key: "likelihood", label: "Exploit likelihood", value: "listed in CISA KEV (exploited in the wild)", weight: 1.5 },
        ] },
      }),
    });
    renderApp(<RiskPanel findingId="f1" />);
    expect(await screen.findByText("listed in CISA KEV (exploited in the wild)")).toBeInTheDocument();
    expect(screen.getByText("× 1.50")).toBeInTheDocument();
    expect(screen.getByText(/Exploited in the wild · federal due date 2021-12-24/)).toBeInTheDocument();
    expect(screen.getByText(/Model v2/)).toBeInTheDocument();
  });
});

const feed = (over: Partial<IntelFeed> = {}): IntelFeed => ({
  feed: "kev", label: "CISA Known Exploited Vulnerabilities", enabled: true, url: "https://www.cisa.gov/kev.json", interval_hours: 24, records: 1450,
  last_run: { id: "r1", feed: "kev", mode: "online", status: "failed", records: 0, as_of: "", error: "download failed: HTTP 503", started_at: "2026-11-17T09:00:00Z", finished_at: null },
  last_success: null, next_due: "2026-11-17T10:00:00Z", updated_at: "2026-11-17T08:00:00Z", ...over,
});

describe("risk & intelligence page", () => {
  it("shows feed health and lets administrators download now", async () => {
    const api = mockApi({
      "GET /api/v1/intel/feeds": () => ({ items: [feed()] }),
      "POST /api/v1/intel/feeds/kev/run": () => ({ id: "r2", status: "succeeded", records: 1451 }),
      "GET /api/v1/risk-model": () => ({ model: { version: 0, is_default: true, change_note: "", created_by: null, created_at: "", weights: defaults }, defaults, pending_recompute: 0 }),
      "GET /api/v1/risk-model/history": () => ({ items: [] }),
    });
    renderApp(<RiskIntelPage />, { permissions: ["settings.manage", "findings.read"] });
    expect(await screen.findByText(/download failed: HTTP 503/)).toBeInTheDocument();
    expect(screen.getByText("Online updates on")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Download now/ }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path.endsWith("/kev/run"))).toBe(true));
    expect(await screen.findByText(/Risk model \(built-in default\)/)).toBeInTheDocument();
  });

  it("is read-only without settings.manage", async () => {
    mockApi({
      "GET /api/v1/intel/feeds": () => ({ items: [feed()] }),
      "GET /api/v1/risk-model": () => ({ model: { version: 3, is_default: false, change_note: "", created_by: "Ada", created_at: "", weights: defaults }, defaults, pending_recompute: 0 }),
      "GET /api/v1/risk-model/history": () => ({ items: [] }),
    });
    renderApp(<RiskIntelPage />, { permissions: ["findings.read"] });
    expect(await screen.findByText("Risk model v3")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Download now/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Save as new version/ })).toBeNull();
  });
});

const finding = (over: Partial<Finding> = {}): Finding => ({
  id: "f1", repository_id: "r1", repository_name: "acme/api", repository_key: "QD-REPO-000001", category: "sca", scanner_keys: ["grype"], rule_id: "CVE-2021-44228",
  title: "Log4Shell", description: "", severity: "critical", cwe: [], cve: "CVE-2021-44228", cvss: 10, package_name: "log4j-core", package_version: "2.14.0",
  fixed_version: "2.17.1", file_path: "pom.xml", start_line: null, status: "open", first_seen_at: "2026-11-01T00:00:00Z", last_seen_at: "2026-11-17T00:00:00Z",
  resolved_at: null, assignee_id: null, assignee_name: null, sla_due_at: null, recurrence_count: 0, accepted_until: null, ai_status: "none",
  lifecycle_status: "new", risk_score: 92.5, kev: true, epss: 0.94, epss_percentile: 0.999, confidence: "high", ...over,
});

describe("findings page", () => {
  it("shows risk, KEV and lifecycle and sorts by risk on the server", async () => {
    const api = mockApi({
      "GET /api/v1/findings": () => ({ items: [finding()], next_cursor: null }),
      "GET /api/v1/findings/summary": () => ({ critical: 1, high: 0, medium: 0, low: 0, info: 0 }),
      "GET /api/v1/scanners": () => ({ items: [] }),
      "GET /api/v1/repositories": () => ({ items: [] }),
    });
    renderApp(<FindingsPage />, { permissions: ["findings.read"], path: "/findings" });
    expect(await screen.findByText("Log4Shell")).toBeInTheDocument();
    const table = screen.getByRole("table");
    expect(within(table).getByText("93")).toBeInTheDocument();
    expect(within(table).getByText("KEV")).toBeInTheDocument();
    expect(within(table).getByText("New")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("combobox", { name: "Order" }), { target: { value: "risk" } });
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/findings" && c.url.searchParams.get("sort") === "risk")).toBe(true));
  });
});
