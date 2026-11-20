import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { jsonResponse, mockApi, renderApp } from "@/test/harness";
import type { Drift, DriftDetail, MonitoringEvent, Summary } from "./api";
import { MonitoringPage } from "./MonitoringPage";
import { MonitoringWidget } from "./MonitoringWidget";
import { validateMonitoringSearch } from "./search";

afterEach(() => vi.unstubAllGlobals());

// Example data for tests only (labelled fixtures, not real events).
const meta = (on: boolean) => () => ({ product: "PATHOS", vendor: "Quditmind", version: "3.0.0-test", feature_flags: { continuous_monitoring: on } });
const APP = "0190a000-0000-7000-8000-000000000001";

const event = (over: Partial<MonitoringEvent> = {}): MonitoringEvent => ({
  id: "e1", type: "architecture.drift", type_label: "Architecture drift", loop: 3, severity: "high",
  title: "2 new routes, 1 new internet exposure in example-api (test fixture)", summary: "Example summary (test fixture).",
  evidence_label: "verified",
  evidence: { from_snapshot_id: "s0aaaaaa-0000", to_snapshot_id: "s1bbbbbb-0000", commit: "a41c9e2aaaaaaaaaaaaa" },
  application_id: APP, application_name: "Example application", repository_id: "r1", repository_name: "example/api",
  subject_type: "drift", subject_id: "d1", link: `/monitoring?tab=drift&drift=d1`, details: null, created_at: "2026-11-20T10:00:00Z",
  ...over,
});
const summary: Summary = {
  days: 30, total: 12, by_type: { "architecture.drift": 2 }, by_severity: { critical: 1, high: 3 }, latest_at: "2026-11-20T10:00:00Z",
  drift: { total: 5, with_changes: 2, latest_at: "2026-11-20T10:00:00Z" },
};
const drift: Drift = {
  id: "d1", application_id: APP, application_name: "Example application", repository_id: "r1", repository_name: "example/api",
  from_snapshot_id: "s0aaaaaa-0000", to_snapshot_id: "s1bbbbbb-0000", from_commit: "9be010fbbbbbbbbbbbbb", to_commit: "a41c9e2aaaaaaaaaaaaa",
  severity: "high", has_changes: true, counts: { added_routes: 2, added_internet_exposure: 1, changed_components: 1 }, created_at: "2026-11-20T10:00:00Z",
};
const driftDetail: DriftDetail = {
  ...drift,
  truncated: false,
  items: [
    { change: "added", category: "route", key: "route:GET /pay", label: "GET /pay", detail: "", file: "api/pay.go", evidence_label: "verified",
      evidence: [{ kind: "file_line", ref: "api/pay.go:12", detail: "", file: "api/pay.go", line: 12 }] },
    { change: "changed", category: "component", key: "pkg:lodash", label: "lodash", detail: "version 4.17.20 → 4.17.21", file: "", evidence_label: "observed",
      evidence: [{ kind: "sbom", ref: "sbom:lodash", detail: "", file: "", line: 0 }] },
  ],
};
const types = { items: [{ type: "architecture.drift", label: "Architecture drift", loop: 3, description: "" }, { type: "fix.verified", label: "Fix verification finished", loop: 5, description: "" }] };

const routes = (over: Record<string, () => unknown> = {}) => ({
  "GET /api/v1/meta": meta(true),
  "GET /api/v1/monitoring/types": () => types,
  "GET /api/v1/monitoring/summary": () => summary,
  "GET /api/v1/monitoring/events": () => ({ items: [event(), event({ id: "e2", type: "ai.triage_queued", type_label: "Queued for AI triage", loop: 7, severity: "medium", evidence_label: "ai_inferred", title: "3 findings queued for AI triage", link: "", evidence: null })], next_cursor: "c2" }),
  "GET /api/v1/monitoring/drift": () => ({ items: [drift], next_cursor: null }),
  "GET /api/v1/monitoring/drift/d1": () => driftDetail,
  "GET /api/v1/monitoring/settings": () => ({ drift_alerts: false, drift_alert_min_severity: "high", updated_at: null, updated_by: null }),
  "GET /api/v1/applications": () => ({ items: [{ id: APP, name: "Example application" }] }),
  ...over,
});

describe("continuous monitoring page", () => {
  it("shows the feature-disabled state while the flag is off, without calling the API", async () => {
    const api = mockApi({ "GET /api/v1/meta": meta(false) });
    renderApp(<MonitoringPage />, { permissions: ["findings.read"], path: "/monitoring" });
    expect(await screen.findByText("Continuous monitoring is not enabled")).toBeInTheDocument();
    expect(screen.getByText("continuous_monitoring")).toBeInTheDocument();
    expect(api.calls.some((c) => c.path.startsWith("/api/v1/monitoring"))).toBe(false);
  });

  it("shows the feature-disabled state when the API answers PTH-PLAT-1007", async () => {
    mockApi(routes({ "GET /api/v1/monitoring/events": () => jsonResponse({ error: { code: "feature_disabled", error_code: "PTH-PLAT-1007", message: "off" } }, 404) }));
    renderApp(<MonitoringPage />, { permissions: ["findings.read"], path: "/monitoring" });
    expect(await screen.findByText("Continuous monitoring is not enabled")).toBeInTheDocument();
  });

  it("names the missing permission", async () => {
    mockApi(routes());
    renderApp(<MonitoringPage />, { permissions: ["repos.read"], path: "/monitoring" });
    expect(await screen.findByText("findings.read")).toBeInTheDocument();
  });

  it("shows skeletons while the feed loads", async () => {
    mockApi(routes({ "GET /api/v1/monitoring/events": () => new Promise(() => {}) }));
    renderApp(<MonitoringPage />, { permissions: ["findings.read"], path: "/monitoring" });
    expect(await screen.findByRole("status", { name: "Loading the monitoring feed" })).toBeInTheDocument();
  });

  it("explains the empty feed and how events appear", async () => {
    mockApi(routes({ "GET /api/v1/monitoring/events": () => ({ items: [], next_cursor: null }) }));
    renderApp(<MonitoringPage />, { permissions: ["findings.read"], path: "/monitoring" });
    expect(await screen.findByText("No monitoring events yet")).toBeInTheDocument();
    expect(screen.getByText(/a new commit queues a CodeGraph rediscovery/)).toBeInTheDocument();
  });

  it("renders the error envelope with ErrorPanel", async () => {
    mockApi(routes({ "GET /api/v1/monitoring/events": () => jsonResponse({ error: { code: "invalid_filter", error_code: "PTH-MON-1101", message: "invalid since" } }, 422) }));
    renderApp(<MonitoringPage />, { permissions: ["findings.read"], path: "/monitoring" });
    expect(await screen.findByText("The monitoring feed could not be loaded")).toBeInTheDocument();
  });

  it("lists events with loop, severity, evidence label and references, and sends filters to the server", async () => {
    const api = mockApi(routes());
    renderApp(<MonitoringPage />, { permissions: ["findings.read"], path: `/monitoring?application_id=${APP}` });
    const events = await screen.findAllByTestId("monitoring-event");
    expect(events).toHaveLength(2);
    const first = events[0]!;
    expect(within(first).getByText("Loop 3")).toBeInTheDocument();
    expect(within(first).getByText("verified")).toBeInTheDocument();
    expect(within(first).getByText("a41c9e2aaaaa")).toBeInTheDocument();
    expect(within(first).getByRole("link", { name: /Snapshot s0aaaaaa → s1bbbbbb/ })).toHaveAttribute(
      "href",
      `/codegraph/${APP}?view=change_impact&snapshot=s1bbbbbb-0000&compare=s0aaaaaa-0000`,
    );
    expect(within(events[1]!).getByText("AI-inferred")).toBeInTheDocument();
    expect(within(events[1]!).getByText("Loop 7")).toBeInTheDocument();
    // Summary counts.
    expect(screen.getByLabelText("Summary of the last 30 days")).toHaveTextContent("12");
    // The application filter from the URL reaches the API.
    expect(api.calls.find((c) => c.path === "/api/v1/monitoring/events")?.url.searchParams.get("application_id")).toBe(APP);
    fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "critical" } });
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/monitoring/events" && c.url.searchParams.get("severity") === "critical")).toBe(true));
    fireEvent.change(screen.getByLabelText("Time range"), { target: { value: "7d" } });
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/monitoring/events" && !!c.url.searchParams.get("since"))).toBe(true));
    // Cursor pagination.
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/monitoring/events" && c.url.searchParams.get("cursor") === "c2")).toBe(true));
  });

  it("offers the CSV export only with findings.export, with the current filters", async () => {
    mockApi(routes());
    const { unmount } = renderApp(<MonitoringPage />, { permissions: ["findings.read"], path: "/monitoring" });
    await screen.findAllByTestId("monitoring-event");
    expect(screen.queryByRole("link", { name: /Export CSV/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Drift alerts/ })).toBeNull();
    unmount();
    mockApi(routes());
    renderApp(<MonitoringPage />, { permissions: ["findings.read", "findings.export"], path: `/monitoring?application_id=${APP}&severity=high` });
    const link = await screen.findByRole("link", { name: /Export CSV/ });
    const href = new URL(link.getAttribute("href")!, "http://localhost");
    expect(href.pathname).toBe("/api/v1/monitoring/events");
    expect(href.searchParams.get("format")).toBe("csv");
    expect(href.searchParams.get("application_id")).toBe(APP);
    expect(href.searchParams.get("severity")).toBe("high");
  });

  it("shows the drift timeline and opens the detail drawer with evidence and the CodeGraph comparison", async () => {
    const api = mockApi(routes());
    renderApp(<MonitoringPage />, { permissions: ["findings.read"], path: "/monitoring?tab=drift" });
    const entry = await screen.findByTestId("drift-entry");
    expect(entry).toHaveTextContent("Routes +2");
    expect(entry).toHaveTextContent("Components ~1");
    expect(entry).toHaveTextContent("9be010fbbbbb → a41c9e2aaaaa");
    expect(api.calls.find((c) => c.path === "/api/v1/monitoring/drift")?.url.searchParams.get("changed_only")).toBe("true");
    fireEvent.click(within(entry).getByRole("button"));
    const d = await screen.findByTestId("drift-detail");
    expect(within(d).getByRole("region", { name: "Routes" })).toHaveTextContent("GET /pay");
    expect(within(d).getByText("api/pay.go:12")).toBeInTheDocument();
    expect(within(d).getByText("observed")).toBeInTheDocument();
    expect(within(d).getByRole("link", { name: /Compare the snapshots in CodeGraph/ })).toHaveAttribute(
      "href",
      `/codegraph/${APP}?view=change_impact&snapshot=s1bbbbbb-0000&compare=s0aaaaaa-0000`,
    );
    fireEvent.click(screen.getByLabelText("Show snapshots without changes"));
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/monitoring/drift" && c.url.searchParams.get("changed_only") === "false")).toBe(true));
  });

  it("explains an empty drift timeline", async () => {
    mockApi(routes({ "GET /api/v1/monitoring/drift": () => ({ items: [], next_cursor: null }) }));
    renderApp(<MonitoringPage />, { permissions: ["findings.read"], path: "/monitoring?tab=drift" });
    expect(await screen.findByText("No architecture drift yet")).toBeInTheDocument();
  });

  it("lets settings.manage turn drift alerts on with a minimum severity", async () => {
    const api = mockApi({
      ...routes(),
      "PUT /api/v1/monitoring/settings": () => ({ drift_alerts: true, drift_alert_min_severity: "critical", updated_at: "2026-11-20T10:00:00Z", updated_by: "ada@example.com" }),
    });
    renderApp(<MonitoringPage />, { permissions: ["findings.read", "settings.manage"], path: "/monitoring" });
    fireEvent.click(await screen.findByRole("button", { name: /Drift alerts/ }));
    const dlg = await screen.findByRole("dialog", { name: "Drift alerts" });
    const box = await within(dlg).findByLabelText("Alert on architecture drift");
    expect(box).not.toBeChecked();
    fireEvent.click(box);
    fireEvent.change(within(dlg).getByLabelText("Minimum severity"), { target: { value: "critical" } });
    fireEvent.click(within(dlg).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.calls.find((c) => c.method === "PUT" && c.path === "/api/v1/monitoring/settings")?.body).toEqual({ drift_alerts: true, drift_alert_min_severity: "critical" }));
  });

  it("validates the URL search", () => {
    expect(validateMonitoringSearch({ application_id: APP, tab: "drift", loop: "9", range: "7d", severity: "high,critical", since: "nope" })).toEqual({
      application_id: APP, tab: "drift", range: "7d", severity: "high,critical",
    });
  });
});

describe("application profile Monitoring widget", () => {
  it("shows the latest events and drift with a deep link", async () => {
    const api = mockApi(routes());
    renderApp(<MonitoringWidget applicationId={APP} />, { permissions: ["findings.read"] });
    expect(await screen.findByRole("link", { name: /Open in Continuous monitoring/ })).toHaveAttribute("href", `/monitoring?application_id=${APP}`);
    expect(await screen.findAllByTestId("monitoring-event")).toHaveLength(2);
    expect(await screen.findByText("9be010fbbbbb → a41c9e2aaaaa")).toBeInTheDocument();
    const ev = api.calls.find((c) => c.path === "/api/v1/monitoring/events")!;
    expect(ev.url.searchParams.get("application_id")).toBe(APP);
    expect(ev.url.searchParams.get("limit")).toBe("5");
  });

  it("is hidden while the flag is off", async () => {
    const api = mockApi({ "GET /api/v1/meta": meta(false) });
    const { container } = renderApp(<MonitoringWidget applicationId={APP} />, { permissions: ["findings.read"] });
    await waitFor(() => expect(api.calls.some((c) => c.path === "/api/v1/meta")).toBe(true));
    expect(container.querySelector("[data-testid='monitoring-widget']")).toBeNull();
    expect(api.calls.some((c) => c.path.startsWith("/api/v1/monitoring"))).toBe(false);
  });

  it("says honestly when there is nothing yet", async () => {
    mockApi(routes({ "GET /api/v1/monitoring/events": () => ({ items: [], next_cursor: null }), "GET /api/v1/monitoring/drift": () => ({ items: [], next_cursor: null }) }));
    renderApp(<MonitoringWidget applicationId={APP} />, { permissions: ["findings.read"] });
    expect(await screen.findByText(/No monitoring events for this application yet/)).toBeInTheDocument();
    expect(await screen.findByText(/No architecture drift yet/)).toBeInTheDocument();
  });
});
