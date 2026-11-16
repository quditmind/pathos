import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { Page, Schedule, SchedulePlanEntry, SchedulePreview, ScheduleRequest, ScheduleRun, SchedulerStatus } from "@/api/types";
import { weekdayShort } from "./form";

export const useSchedules = () =>
  useQuery({ queryKey: ["schedules"], queryFn: () => api<Page<Schedule>>("/api/v1/schedules").then((r) => r.items), refetchInterval: 30_000 });

export const useSchedulerStatus = () =>
  useQuery({ queryKey: ["scheduler-status"], queryFn: () => api<SchedulerStatus>("/api/v1/scheduler/status"), refetchInterval: 15_000 });

export function useScheduleMutation<T, V>(fn: (v: V) => Promise<T>) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["schedules"] });
      void qc.invalidateQueries({ queryKey: ["scheduler-status"] });
      void qc.invalidateQueries({ queryKey: ["scans"] });
      void qc.invalidateQueries({ queryKey: ["scans-overview"] });
    },
  });
}

export const useScheduleRuns = (id: string | undefined) =>
  useQuery({
    queryKey: ["schedule-runs", id],
    queryFn: () => api<{ items: ScheduleRun[] }>(`/api/v1/schedules/${id}/runs`).then((r) => r.items),
    enabled: !!id,
    refetchInterval: (q) => (q.state.data?.some((r) => r.status === "running" || r.status === "waiting") ? 10_000 : false),
  });

/** POST /schedules/{id}/run */
export interface RunResult {
  queued: number;
  coalesced: number;
  skipped: number;
  failed: number;
  deferred: number;
}

export const previewSchedule = (body: ScheduleRequest, signal?: AbortSignal) =>
  api<SchedulePreview>("/api/v1/schedules/preview", { method: "POST", body: { ...body, name: body.name || "preview" }, signal });
export const saveSchedule = (id: string | undefined, body: ScheduleRequest) =>
  id ? api<Schedule>(`/api/v1/schedules/${id}`, { method: "PUT", body }) : api<Schedule>("/api/v1/schedules", { method: "POST", body });
export const pauseSchedule = (s: Pick<Schedule, "id" | "enabled">) => api<Schedule>(`/api/v1/schedules/${s.id}/${s.enabled ? "pause" : "resume"}`, { method: "POST" });
export const runSchedule = (id: string) => api<RunResult>(`/api/v1/schedules/${id}/run`, { method: "POST" });
export const deleteSchedule = (id: string) => api<void>(`/api/v1/schedules/${id}`, { method: "DELETE" });

/** Human cadence of a schedule. */
export function describeSchedule(s: Pick<Schedule, "kind" | "cron" | "run_at" | "interval_minutes">): string {
  if (s.kind === "once") return s.run_at ? `Once, ${new Date(s.run_at).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}` : "Once";
  if (s.kind === "interval") {
    const n = s.interval_minutes ?? 0;
    if (n % 1440 === 0) return `Every ${n / 1440 === 1 ? "day" : `${n / 1440} days`}`;
    if (n % 60 === 0) return `Every ${n / 60 === 1 ? "hour" : `${n / 60} hours`}`;
    return `Every ${n} minutes`;
  }
  return describeCron(s.cron);
}

export const kindLabel: Record<string, string> = { cron: "Recurring", once: "One-time", interval: "Interval" };

/** "02:00–05:00 Mon,Tue" or "" when there is no window. */
export function describeWindow(s: Pick<Schedule, "window_start" | "window_end" | "window_days">): string {
  if (!s.window_start || !s.window_end) return "";
  const days = s.window_days?.length ? ` ${s.window_days.map((d) => weekdayShort[d]).join(",")}` : "";
  return `${s.window_start}–${s.window_end}${days}`;
}

const planTarget: Record<SchedulePlanEntry["target_type"], string> = { organization: "All repositories", region: "Region", business_unit: "Business unit", repository: "Repository" };

export function describePlanEntry(e: SchedulePlanEntry): string {
  const target = e.target_type === "organization" ? planTarget.organization : `${planTarget[e.target_type]}: ${e.target_name || e.target_id || "?"}`;
  return `${target} × ${e.profile_id ? e.profile_name || "profile" : "own profile"}`;
}

export const presets = [
  { label: "Daily at 02:00", cron: "0 2 * * *" },
  { label: "Weekdays at 06:00", cron: "0 6 * * 1-5" },
  { label: "Weekly (Sunday 03:00)", cron: "0 3 * * 0" },
  { label: "Monthly (1st, 04:00)", cron: "0 4 1 * *" },
  { label: "Every 6 hours", cron: "0 */6 * * *" },
];

const days = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];

/** describeCron renders common cron shapes in words; others are shown raw. */
export function describeCron(expr: string): string {
  const preset = presets.find((p) => p.cron === expr);
  if (preset) return preset.label;
  const macros: Record<string, string> = { "@hourly": "Every hour", "@daily": "Daily at 00:00", "@midnight": "Daily at 00:00", "@weekly": "Weekly (Sunday 00:00)", "@monthly": "Monthly (1st, 00:00)", "@yearly": "Yearly (1 Jan)", "@annually": "Yearly (1 Jan)" };
  if (macros[expr]) return macros[expr];
  const f = expr.trim().split(/\s+/);
  if (f.length !== 5) return expr;
  const [m, h, dom, mon, dow] = f as [string, string, string, string, string];
  const time = /^\d+$/.test(m) && /^\d+$/.test(h) ? `${h.padStart(2, "0")}:${m.padStart(2, "0")}` : null;
  if (time && dom === "*" && mon === "*") {
    if (dow === "*") return `Daily at ${time}`;
    if (/^\d$/.test(dow)) return `Every ${days[Number(dow) % 7]} at ${time}`;
    if (dow === "1-5") return `Weekdays at ${time}`;
    if (/^[0-7](,[0-7])+$/.test(dow)) return `Every ${dow.split(",").map((d) => days[Number(d) % 7]!.slice(0, 3)).join(", ")} at ${time}`;
  }
  if (time && /^\d+$/.test(dom) && mon === "*" && dow === "*") return `Monthly on day ${dom} at ${time}`;
  if (m === "0" && /^\*\/\d+$/.test(h) && dom === "*" && mon === "*" && dow === "*") return `Every ${h.slice(2)} hours`;
  return expr;
}
