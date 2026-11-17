import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { mockApi, renderApp } from "@/test/harness";
import { ExecutivePage } from "./ExecutivePage";
import { ReportsPage } from "./ReportsPage";
import { WebhooksTab } from "@/features/notify/WebhooksTab";
import { FindingTickets, IntegrationsPage } from "@/features/integrations/IntegrationsPage";

afterEach(() => vi.unstubAllGlobals());

const exec = {
  generated_at: "2026-11-18T02:00:00Z", days: 90, scope: "Organization",
  open_by_severity: { critical: 3, high: 10, medium: 4, low: 1 }, open_actively_exploited: 1, open_critical_risk: 2, open_past_sla: 5,
  new_in_period: 20, fixed_in_period: 12, mean_days_to_fix: { critical: 4.5, high: 12, medium: null, low: null }, fixed_within_sla_percent: 83.3,
  repositories: 8, repositories_scanned_30_days: 7,
  trend: [{ week: "2026-11-02", new: 5, fixed: 2, open_at_end: 15 }, { week: "2026-11-09", new: 3, fixed: 4, open_at_end: 14 }],
  top_applications: [{ id: "a1", name: "Payments", critical: 2, high: 4, open: 9, kev: 1, max_risk: 91 }], business_units: [],
};

describe("executive overview", () => {
  it("shows the figures from the API", async () => {
    mockApi({ "GET /api/v1/executive": () => exec });
    renderApp(<ExecutivePage />, { permissions: ["findings.read"] });
    expect(await screen.findByText("13")).toBeInTheDocument();
    expect(screen.getByText("83.3%")).toBeInTheDocument();
    expect(screen.getByText("20 / 12")).toBeInTheDocument();
    expect(screen.getByText("Payments")).toBeInTheDocument();
    expect(screen.getByText("4.5 days")).toBeInTheDocument();
  });
});

describe("reports", () => {
  it("runs a saved report and offers CSV with export rights", async () => {
    mockApi({
      "GET /api/v1/reports": () => ({ items: [{ id: "r1", name: "Open SAST", description: "", definition: { filters: { status: "open" }, group_by: "", columns: ["severity", "title"] },
        shared: true, schedule: "weekly", recipients: [], owner: "ada@acme.test", next_run_at: "2026-11-25T00:00:00Z", last_run_at: null, updated_at: "2026-11-18T00:00:00Z", can_edit: true }],
        group_by: { severity: "Severity" }, columns: { severity: "Severity", title: "Title" }, filters: [] }),
      "GET /api/v1/reports/r1/run": () => ({ columns: ["Severity", "Title"], rows: [["critical", "SQL injection"]], total: 1, truncated: false, run_at: "2026-11-18T02:00:00Z" }),
    });
    renderApp(<ReportsPage />, { permissions: ["findings.read", "findings.export"], path: "/?report=r1" });
    expect(await screen.findByText("SQL injection")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /CSV/ })).toBeInTheDocument();
    expect(screen.getAllByText(/weekly/).length).toBeGreaterThan(0);
  });
});

describe("webhooks", () => {
  it("lists endpoints and sends a test message", async () => {
    const api = mockApi({
      "GET /api/v1/notifications/webhooks": () => ({ items: [{ id: "w1", name: "SOC", format: "slack", host: "hooks.slack.com", signed: false, events: ["findings.new"],
        min_severity: "high", allow_private: false, enabled: true, created_at: "2026-11-18T00:00:00Z", last_status: "succeeded", last_delivery_at: null, failed_24h: 0 }] }),
      "POST /api/v1/notifications/webhooks/w1/test": () => ({ ok: true, status: 200 }),
    });
    renderApp(<WebhooksTab />, { permissions: ["notifications.manage"] });
    expect(await screen.findByText("SOC")).toBeInTheDocument();
    expect(screen.getByText(/Slack · hooks.slack.com/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Test/ }));
    expect(await screen.findByText("Delivered (HTTP 200)")).toBeInTheDocument();
    expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/notifications/webhooks/w1/test")).toBe(true);
  });
});

describe("ticketing", () => {
  it("lists connections for administrators", async () => {
    mockApi({ "GET /api/v1/ticket-connections": () => ({ items: [{ id: "c1", kind: "jira", name: "Jira Security", base_url: "https://acme.atlassian.net", config: { project_key: "SEC" }, enabled: true, tickets: 4 }] }) });
    renderApp(<IntegrationsPage />, { permissions: ["settings.manage"] });
    expect(await screen.findByText("Jira Security")).toBeInTheDocument();
    expect(screen.getByText(/project SEC/)).toBeInTheDocument();
  });

  it("shows a finding's tickets and opens a new one", async () => {
    const api = mockApi({
      "GET /api/v1/ticket-connections": () => ({ items: [{ id: "c1", kind: "jira", name: "Jira Security", enabled: true }, { id: "c2", kind: "servicenow", name: "SN", enabled: true }] }),
      "GET /api/v1/findings/f1/tickets": () => ({ items: [{ id: "t1", connection_name: "Jira Security", kind: "jira", key: "SEC-7", url: "https://acme.atlassian.net/browse/SEC-7",
        status: "In Progress", done: false, sync_error: "", synced_at: null, created_by: "ada@acme.test", created_at: "2026-11-18T00:00:00Z" }] }),
      "POST /api/v1/findings/f1/tickets": () => ({ id: "t2", key: "INC1" }),
    });
    renderApp(<FindingTickets findingId="f1" />, { permissions: ["findings.read", "findings.triage"] });
    expect(await screen.findByText("SEC-7")).toBeInTheDocument();
    fireEvent.change(await screen.findByLabelText("Ticketing connection"), { target: { value: "c2" } });
    fireEvent.click(screen.getByRole("button", { name: /Create ticket/ }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/findings/f1/tickets")).toBe(true));
  });
});
