import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/api/client";
import type { Page, Schedule, SchedulerStatus } from "@/api/types";

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
    },
  });
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
  }
  if (time && /^\d+$/.test(dom) && mon === "*" && dow === "*") return `Monthly on day ${dom} at ${time}`;
  if (m === "0" && /^\*\/\d+$/.test(h) && dom === "*" && mon === "*" && dow === "*") return `Every ${h.slice(2)} hours`;
  return expr;
}
