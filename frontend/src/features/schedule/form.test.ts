import { describe, expect, it } from "vitest";
import type { Schedule } from "@/api/types";
import { buildRequest, emptyForm, formErrors, formFromSchedule, isoToZoned, parseCronPreset, zonedToIso, type ScheduleForm } from "./form";

const base = (patch: Partial<ScheduleForm> = {}): ScheduleForm => ({ ...emptyForm("UTC"), name: " Nightly ", ...patch });

const schedule = (patch: Partial<Schedule>): Schedule => ({
  id: "s1", name: "S", enabled: true, kind: "cron", run_at: null, interval_minutes: null, window_start: "", window_end: "", window_days: [],
  retry_max: 0, retry_delay_minutes: 30, max_concurrent: 0, notify_on: [], plan: [], cron: "0 2 * * *", timezone: "UTC",
  target_type: "organization", target_id: null, target_name: "", priority: 30, next_run_at: null, last_run_at: null, last_status: "",
  last_queued: 0, missed_runs: 0, created_at: "", can_manage: true, ...patch,
});

describe("buildRequest", () => {
  it("builds a daily cron schedule with window, retries, concurrency, notifications and plan rows", () => {
    const r = buildRequest(base({
      mode: "daily", time: "03:15", windowStart: "22:00", windowEnd: "05:00", windowDays: [5, 1, 1],
      retryMax: 2, retryDelay: 15, maxConcurrent: 4, notifyCompleted: true, notifyFailed: true, priority: 40,
      plan: [
        { key: "a", target_type: "organization", target_id: "ignored", target_name: "", profile_id: "" },
        { key: "b", target_type: "region", target_id: "r1", target_name: "EMEA", profile_id: "p1" },
      ],
    }));
    expect(r).toEqual({
      name: "Nightly", enabled: true, kind: "cron", cron: "15 3 * * *", timezone: "UTC",
      window_start: "22:00", window_end: "05:00", window_days: [1, 5],
      retry_max: 2, retry_delay_minutes: 15, max_concurrent: 4, notify_on: ["completed", "failed"], priority: 40,
      plan: [
        { target_type: "organization", target_id: null, profile_id: null },
        { target_type: "region", target_id: "r1", profile_id: "p1" },
      ],
    });
  });

  it("builds weekly and monthly presets", () => {
    expect(buildRequest(base({ mode: "weekly", time: "06:00", weekdays: [5, 1, 3] })).cron).toBe("0 6 * * 1,3,5");
    expect(buildRequest(base({ mode: "monthly", time: "04:30", monthDay: 15 })).cron).toBe("30 4 15 * *");
    expect(buildRequest(base({ mode: "cron", cron: " 0 */6 * * * " })).cron).toBe("0 */6 * * *");
  });

  it("builds a one-time schedule in the schedule's time zone", () => {
    const r = buildRequest(base({ mode: "once", runAt: "2030-01-15T09:30", timezone: "Europe/Berlin", notifyFailed: false }));
    expect(r.kind).toBe("once");
    expect(r.run_at).toBe("2030-01-15T08:30:00.000Z");
    expect(r.cron).toBeUndefined();
    expect(r.notify_on).toEqual([]);
    expect(r.window_start).toBe("");
    expect(r.window_days).toEqual([]);
  });

  it("builds interval schedules in minutes with an optional first run", () => {
    const days = buildRequest(base({ mode: "interval", intervalValue: 2, intervalUnit: "days" }));
    expect(days).toMatchObject({ kind: "interval", interval_minutes: 2880, run_at: null });
    expect(days.cron).toBeUndefined();
    const hours = buildRequest(base({ mode: "interval", intervalValue: 6, intervalUnit: "hours", firstRun: "2030-06-01T00:00" }));
    expect(hours).toMatchObject({ interval_minutes: 360, run_at: "2030-06-01T00:00:00.000Z" });
  });
});

describe("formErrors", () => {
  it("validates interval, window, weekdays and plan targets", () => {
    expect(formErrors(base())).toEqual([]);
    expect(formErrors(base({ mode: "interval", intervalValue: 30, intervalUnit: "minutes" }))).toHaveLength(1);
    expect(formErrors(base({ windowStart: "01:00" }))).toHaveLength(1);
    expect(formErrors(base({ mode: "weekly", weekdays: [] }))).toHaveLength(1);
    expect(formErrors(base({ plan: [{ key: "x", target_type: "repository", target_id: "", target_name: "", profile_id: "" }] }))[0]).toMatch(/Plan row 1/);
  });
});

describe("parseCronPreset / formFromSchedule", () => {
  it("recognises presets", () => {
    expect(parseCronPreset("0 2 * * *")).toEqual({ mode: "daily", time: "02:00" });
    expect(parseCronPreset("30 7 * * 1-5")).toEqual({ mode: "weekly", time: "07:30", weekdays: [1, 2, 3, 4, 5] });
    expect(parseCronPreset("0 4 1 * *")).toEqual({ mode: "monthly", time: "04:00", monthDay: 1 });
    expect(parseCronPreset("0 */6 * * *")).toBeNull();
  });

  it("round-trips schedules through the form", () => {
    const weekly = schedule({
      cron: "0 6 * * 1,3", window_start: "20:00", window_end: "06:00", window_days: [1, 2], retry_max: 3, retry_delay_minutes: 10,
      max_concurrent: 5, notify_on: ["failed"], priority: 50,
      plan: [{ id: "e1", target_type: "repository", target_id: "repo1", target_name: "acme/api", profile_id: "p1", profile_name: "Deep" }],
    });
    const f = formFromSchedule(weekly);
    expect(f).toMatchObject({ id: "s1", mode: "weekly", time: "06:00", weekdays: [1, 3] });
    expect(f.plan[0]).toMatchObject({ target_type: "repository", target_id: "repo1", target_name: "acme/api", profile_id: "p1" });
    expect(buildRequest(f)).toMatchObject({
      kind: "cron", cron: "0 6 * * 1,3", window_start: "20:00", window_end: "06:00", window_days: [1, 2],
      retry_max: 3, retry_delay_minutes: 10, max_concurrent: 5, notify_on: ["failed"], priority: 50,
      plan: [{ target_type: "repository", target_id: "repo1", profile_id: "p1" }],
    });

    expect(formFromSchedule(schedule({ cron: "*/90 * * * *" })).mode).toBe("cron");
    expect(formFromSchedule(schedule({ kind: "interval", interval_minutes: 4320, cron: "" }))).toMatchObject({ mode: "interval", intervalValue: 3, intervalUnit: "days" });
    const once = formFromSchedule(schedule({ kind: "once", run_at: "2030-01-15T08:30:00Z", timezone: "Europe/Berlin" }));
    expect(once.runAt).toBe("2030-01-15T09:30");
    expect(buildRequest(once).run_at).toBe("2030-01-15T08:30:00.000Z");
  });

  it("maps legacy single-target schedules to one plan row", () => {
    expect(formFromSchedule(schedule({ target_type: "profile", target_id: "p9" })).plan).toMatchObject([{ target_type: "organization", profile_id: "p9" }]);
    expect(formFromSchedule(schedule({ target_type: "business_unit", target_id: "b1", target_name: "Retail" })).plan).toMatchObject([
      { target_type: "business_unit", target_id: "b1", target_name: "Retail", profile_id: "" },
    ]);
  });

  it("converts between zoned wall time and instants", () => {
    expect(zonedToIso("2030-07-01T12:00", "America/New_York")).toBe("2030-07-01T16:00:00.000Z");
    expect(isoToZoned("2030-07-01T16:00:00Z", "America/New_York")).toBe("2030-07-01T12:00");
  });
});
