import { describe, expect, it } from "vitest";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { mockApi, renderApp } from "@/test/harness";
import { SchedulesPage } from "./SchedulesPage";

const status = { leader: "s1", heartbeat_at: new Date().toISOString(), healthy: true, workers_online: 1, workers_offline: 0, queued: 0, running: 0, oldest_queued_at: null, schedules: 0, missed_runs: 0 };
const profile = { id: "p1", name: "Deep", description: "", is_default: false, repository_count: 0, current: { id: "v", version: 3 } };

describe("SchedulesPage", () => {
  it("creates a schedule with a two-row execution plan", async () => {
    const api = mockApi({
      "GET /api/v1/schedules": () => ({ items: [] }),
      "GET /api/v1/scheduler/status": () => status,
      "GET /api/v1/regions": () => ({ items: [{ id: "r1", name: "EMEA" }] }),
      "GET /api/v1/business-units": () => ({ items: [] }),
      "GET /api/v1/scan-profiles": () => ({ items: [profile] }),
      "POST /api/v1/schedules/preview": () => ({ next_runs: ["2030-01-01T02:00:00Z"], repositories: 4, executions: 7, window: "" }),
      "POST /api/v1/schedules": () => ({ id: "new" }),
    });
    renderApp(<SchedulesPage />, { permissions: ["scans.read", "schedules.manage"] });
    const user = userEvent.setup();
    await user.click(await screen.findByRole("button", { name: "New schedule" }));
    const dialog = await screen.findByRole("dialog");
    await user.type(within(dialog).getByLabelText("Name"), "Nightly");
    fireEvent.change(within(dialog).getByLabelText("Schedule type"), { target: { value: "weekly" } });
    await user.click(within(within(dialog).getByRole("group", { name: "Weekdays" })).getByRole("button", { name: "Fri" }));
    fireEvent.change(within(dialog).getByLabelText(/^Retries/), { target: { value: "2" } });
    await waitFor(() => expect(within(dialog).getByRole("option", { name: "Deep v3" })).toBeInTheDocument());
    fireEvent.change(within(dialog).getByLabelText("Plan row 1 scan profile"), { target: { value: "p1" } });
    await user.click(within(dialog).getByRole("button", { name: "Add plan row" }));
    fireEvent.change(within(dialog).getByLabelText("Plan row 2 asset scope"), { target: { value: "region" } });
    await waitFor(() => expect(within(dialog).getByRole("option", { name: "EMEA" })).toBeInTheDocument());
    fireEvent.change(within(dialog).getByLabelText("Plan row 2 region"), { target: { value: "r1" } });
    expect(await within(dialog).findByText(/7 executions per activation/)).toBeInTheDocument();
    await user.click(within(dialog).getByRole("button", { name: "Create schedule" }));
    await waitFor(() => expect(api.calls.some((c) => c.method === "POST" && c.path === "/api/v1/schedules")).toBe(true));
    const body = api.calls.find((c) => c.method === "POST" && c.path === "/api/v1/schedules")!.body;
    expect(body).toMatchObject({
      name: "Nightly", kind: "cron", cron: "0 2 * * 1,5", retry_max: 2,
      plan: [
        { target_type: "organization", target_id: null, profile_id: "p1" },
        { target_type: "region", target_id: "r1", profile_id: null },
      ],
    });
    const preview = api.calls.filter((c) => c.path === "/api/v1/schedules/preview").at(-1)!.body;
    expect(preview).toMatchObject({ plan: [{ profile_id: "p1" }, { target_type: "region", target_id: "r1" }] });
  });

  it("hides management actions without schedules.manage and opens the run history", async () => {
    mockApi({
      "GET /api/v1/schedules": () => ({
        items: [{
          id: "s1", name: "Nightly", enabled: false, kind: "interval", run_at: null, interval_minutes: 720, window_start: "01:00", window_end: "05:00", window_days: [1],
          retry_max: 0, retry_delay_minutes: 30, max_concurrent: 0, notify_on: [], plan: [{ target_type: "organization", target_id: null, profile_id: null }],
          cron: "", timezone: "UTC", target_type: "organization", target_id: null, target_name: "", priority: 30, next_run_at: null, last_run_at: null,
          last_status: "", last_queued: 0, missed_runs: 0, created_at: "", can_manage: false,
        }],
      }),
      "GET /api/v1/scheduler/status": () => status,
      "GET /api/v1/schedules/s1/runs": () => ({
        items: [{ id: "run1", due_at: "2030-01-01T02:00:00Z", trigger: "manual", status: "partial", queued: 3, skipped: 1, failed: 0, pending: 0, message: "", started_at: "2030-01-01T02:00:00Z", finished_at: null, jobs: { succeeded: 2, failed: 1 } }],
      }),
    });
    renderApp(<SchedulesPage />, { permissions: ["scans.read"] });
    expect(await screen.findByText("Every 12 hours")).toBeInTheDocument();
    expect(screen.getByText("paused")).toBeInTheDocument();
    expect(screen.getByText("01:00–05:00 Mon")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "New schedule" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Resume" })).toBeNull();
    await userEvent.setup().click(screen.getByRole("button", { name: "Run history" }));
    const drawer = await screen.findByRole("dialog");
    expect(await within(drawer).findByText("partial")).toBeInTheDocument();
    expect(within(drawer).getByText("failed 1")).toBeInTheDocument();
    expect(within(drawer).getByRole("link", { name: /View all executions/ })).toHaveAttribute("href", "/scans?schedule_id=s1");
  });
});
