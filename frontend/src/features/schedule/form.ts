import type { Schedule, SchedulePlanEntry, ScheduleRequest } from "@/api/types";

/** How the cadence is edited; daily/weekly/monthly are cron presets. */
export type ScheduleMode = "once" | "daily" | "weekly" | "monthly" | "cron" | "interval";
export type IntervalUnit = "minutes" | "hours" | "days";
export type PlanTarget = SchedulePlanEntry["target_type"];

export interface PlanRow {
  key: string;
  target_type: PlanTarget;
  target_id: string;
  target_name: string;
  /** "" = each repository's own profile */
  profile_id: string;
}

export interface ScheduleForm {
  id?: string;
  name: string;
  enabled: boolean;
  mode: ScheduleMode;
  /** HH:MM for daily / weekly / monthly */
  time: string;
  /** 0 = Sunday … 6 = Saturday (weekly) */
  weekdays: number[];
  /** 1..31 (monthly) */
  monthDay: number;
  cron: string;
  /** datetime-local value ("YYYY-MM-DDTHH:MM") in the schedule's time zone (once) */
  runAt: string;
  intervalValue: number;
  intervalUnit: IntervalUnit;
  /** Optional first run of an interval schedule (datetime-local in the schedule's time zone) */
  firstRun: string;
  timezone: string;
  windowStart: string;
  windowEnd: string;
  windowDays: number[];
  retryMax: number;
  retryDelay: number;
  maxConcurrent: number;
  notifyCompleted: boolean;
  notifyFailed: boolean;
  priority: number;
  plan: PlanRow[];
}

export const weekdayNames = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"];
export const weekdayShort = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

export const targetLabels: Record<PlanTarget, string> = {
  organization: "All repositories",
  region: "Region",
  business_unit: "Business unit",
  repository: "Repository",
};

let seq = 0;
export const rowKey = () => `row-${++seq}`;

export const newPlanRow = (): PlanRow => ({ key: rowKey(), target_type: "organization", target_id: "", target_name: "", profile_id: "" });

export function browserZone(): string {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

export function timeZones(): string[] {
  try {
    const z = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.("timeZone");
    if (z?.length) return z.includes("UTC") ? z : ["UTC", ...z];
  } catch {
    /* unsupported */
  }
  return ["UTC", "Europe/London", "Europe/Berlin", "America/New_York", "America/Los_Angeles", "Asia/Singapore", "Asia/Tokyo", "Australia/Sydney"];
}

export function emptyForm(timezone = browserZone()): ScheduleForm {
  return {
    name: "",
    enabled: true,
    mode: "daily",
    time: "02:00",
    weekdays: [1],
    monthDay: 1,
    cron: "0 2 * * *",
    runAt: "",
    intervalValue: 12,
    intervalUnit: "hours",
    firstRun: "",
    timezone,
    windowStart: "",
    windowEnd: "",
    windowDays: [],
    retryMax: 0,
    retryDelay: 30,
    maxConcurrent: 0,
    notifyCompleted: false,
    notifyFailed: true,
    priority: 30,
    plan: [newPlanRow()],
  };
}

const pad = (n: number) => String(n).padStart(2, "0");

/** Offset (ms) of a time zone at an instant: wall clock in tz minus UTC. */
function tzOffset(utcMs: number, tz: string): number {
  const f = new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
  const p = Object.fromEntries(f.formatToParts(new Date(utcMs)).map((x) => [x.type, x.value]));
  const wall = Date.UTC(Number(p.year), Number(p.month) - 1, Number(p.day), Number(p.hour) % 24, Number(p.minute), Number(p.second));
  return wall - Math.floor(utcMs / 1000) * 1000;
}

/** Converts a datetime-local value in time zone tz to an RFC 3339 UTC string. */
export function zonedToIso(local: string, tz: string): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(local);
  if (!m) return null;
  const guess = Date.UTC(+m[1]!, +m[2]! - 1, +m[3]!, +m[4]!, +m[5]!);
  try {
    let t = guess - tzOffset(guess, tz);
    t = guess - tzOffset(t, tz);
    return new Date(t).toISOString();
  } catch {
    return new Date(guess).toISOString();
  }
}

/** Converts an instant to a datetime-local value in time zone tz. */
export function isoToZoned(iso: string | null | undefined, tz: string): string {
  if (!iso) return "";
  const ms = new Date(iso).getTime();
  if (Number.isNaN(ms)) return "";
  let off = 0;
  try {
    off = tzOffset(ms, tz);
  } catch {
    /* unknown zone: UTC */
  }
  const d = new Date(ms + off);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}T${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

function expandDays(field: string): number[] | null {
  const out = new Set<number>();
  for (const part of field.split(",")) {
    const r = /^([0-7])(?:-([0-7]))?$/.exec(part);
    if (!r) return null;
    const a = Number(r[1]);
    const b = r[2] ? Number(r[2]) : a;
    if (b < a) return null;
    for (let d = a; d <= b; d++) out.add(d % 7);
  }
  return [...out].sort((x, y) => x - y);
}

/** Recognises the daily / weekly / monthly cron shapes the form builds. */
export function parseCronPreset(cron: string): { mode: "daily" | "weekly" | "monthly"; time: string; weekdays?: number[]; monthDay?: number } | null {
  const f = cron.trim().split(/\s+/);
  if (f.length !== 5) return null;
  const [m, h, dom, mon, dow] = f as [string, string, string, string, string];
  if (!/^\d{1,2}$/.test(m) || !/^\d{1,2}$/.test(h) || Number(m) > 59 || Number(h) > 23 || mon !== "*") return null;
  const time = `${pad(Number(h))}:${pad(Number(m))}`;
  if (dom === "*" && dow === "*") return { mode: "daily", time };
  if (dom === "*") {
    const days = expandDays(dow);
    return days?.length ? { mode: "weekly", time, weekdays: days } : null;
  }
  if (dow === "*" && /^\d{1,2}$/.test(dom) && Number(dom) >= 1 && Number(dom) <= 31) return { mode: "monthly", time, monthDay: Number(dom) };
  return null;
}

/** The cron expression of a preset mode. */
export function presetCron(f: Pick<ScheduleForm, "mode" | "time" | "weekdays" | "monthDay" | "cron">): string {
  const [h = "0", m = "0"] = (f.time || "00:00").split(":");
  const hm = `${Number(m)} ${Number(h)}`;
  switch (f.mode) {
    case "daily":
      return `${hm} * * *`;
    case "weekly":
      return `${hm} * * ${[...new Set(f.weekdays)].sort((a, b) => a - b).join(",") || "*"}`;
    case "monthly":
      return `${hm} ${f.monthDay} * *`;
    default:
      return f.cron.trim();
  }
}

const unitMinutes: Record<IntervalUnit, number> = { minutes: 1, hours: 60, days: 1440 };

export function intervalMinutes(f: Pick<ScheduleForm, "intervalValue" | "intervalUnit">): number {
  return Math.round(f.intervalValue * unitMinutes[f.intervalUnit]);
}

/** Builds the API body (POST/PUT /schedules and POST /schedules/preview). */
export function buildRequest(f: ScheduleForm): ScheduleRequest {
  const req: ScheduleRequest = {
    name: f.name.trim(),
    enabled: f.enabled,
    kind: f.mode === "once" ? "once" : f.mode === "interval" ? "interval" : "cron",
    timezone: f.timezone,
    retry_max: f.retryMax,
    retry_delay_minutes: f.retryDelay,
    max_concurrent: f.maxConcurrent,
    notify_on: [...(f.notifyCompleted ? (["completed"] as const) : []), ...(f.notifyFailed ? (["failed"] as const) : [])],
    priority: f.priority,
    plan: f.plan.map((r) => ({
      target_type: r.target_type,
      target_id: r.target_type === "organization" ? null : r.target_id || null,
      profile_id: r.profile_id || null,
    })),
  };
  if (req.kind === "once") {
    req.run_at = zonedToIso(f.runAt, f.timezone);
  } else if (req.kind === "interval") {
    req.interval_minutes = intervalMinutes(f);
    req.run_at = f.firstRun ? zonedToIso(f.firstRun, f.timezone) : null;
  } else {
    req.cron = presetCron(f);
  }
  if (f.windowStart && f.windowEnd) {
    req.window_start = f.windowStart;
    req.window_end = f.windowEnd;
    req.window_days = [...new Set(f.windowDays)].sort((a, b) => a - b);
  } else {
    req.window_start = "";
    req.window_end = "";
    req.window_days = [];
  }
  return req;
}

/** Problems that make the request invalid before it reaches the server. */
export function formErrors(f: ScheduleForm): string[] {
  const e: string[] = [];
  if (!f.name.trim()) e.push("Enter a name.");
  if (f.mode === "once" && !f.runAt) e.push("Choose when the scan runs.");
  if (f.mode === "weekly" && !f.weekdays.length) e.push("Choose at least one weekday.");
  if (f.mode === "cron" && !f.cron.trim()) e.push("Enter a cron expression.");
  if (f.mode === "interval") {
    const n = intervalMinutes(f);
    if (!(n >= 60 && n <= 525600)) e.push("The interval must be between 1 hour and 365 days.");
  }
  if (!!f.windowStart !== !!f.windowEnd) e.push("Set both the start and the end of the scan window, or neither.");
  else if (f.windowStart && f.windowStart === f.windowEnd) e.push("The scan window start and end must differ.");
  if (!f.plan.length) e.push("Add at least one execution plan row.");
  f.plan.forEach((r, i) => {
    if (r.target_type !== "organization" && !r.target_id) e.push(`Plan row ${i + 1}: choose a ${targetLabels[r.target_type].toLowerCase()}.`);
  });
  return e;
}

/** Edit form for an existing schedule (legacy single-target schedules become one plan row). */
export function formFromSchedule(s: Schedule): ScheduleForm {
  const base = emptyForm(s.timezone || "UTC");
  const f: ScheduleForm = {
    ...base,
    id: s.id,
    name: s.name,
    enabled: s.enabled,
    windowStart: s.window_start ?? "",
    windowEnd: s.window_end ?? "",
    windowDays: s.window_days ?? [],
    retryMax: s.retry_max ?? 0,
    retryDelay: s.retry_delay_minutes || base.retryDelay,
    maxConcurrent: s.max_concurrent ?? 0,
    notifyCompleted: (s.notify_on ?? []).includes("completed"),
    notifyFailed: (s.notify_on ?? []).includes("failed"),
    priority: s.priority ?? base.priority,
  };
  const kind = s.kind || "cron";
  if (kind === "once") {
    f.mode = "once";
    f.runAt = isoToZoned(s.run_at, f.timezone);
  } else if (kind === "interval") {
    f.mode = "interval";
    const n = s.interval_minutes ?? 720;
    if (n % 1440 === 0) Object.assign(f, { intervalValue: n / 1440, intervalUnit: "days" });
    else if (n % 60 === 0) Object.assign(f, { intervalValue: n / 60, intervalUnit: "hours" });
    else Object.assign(f, { intervalValue: n, intervalUnit: "minutes" });
    f.firstRun = isoToZoned(s.run_at, f.timezone);
  } else {
    f.cron = s.cron;
    const p = parseCronPreset(s.cron);
    if (p) {
      f.mode = p.mode;
      f.time = p.time;
      if (p.weekdays) f.weekdays = p.weekdays;
      if (p.monthDay) f.monthDay = p.monthDay;
    } else {
      f.mode = "cron";
    }
  }
  if (s.plan?.length) {
    f.plan = s.plan.map((e) => ({ key: rowKey(), target_type: e.target_type, target_id: e.target_id ?? "", target_name: e.target_name ?? "", profile_id: e.profile_id ?? "" }));
  } else if (s.target_type === "profile") {
    f.plan = [{ key: rowKey(), target_type: "organization", target_id: "", target_name: "", profile_id: s.target_id ?? "" }];
  } else {
    f.plan = [{ key: rowKey(), target_type: s.target_type ?? "organization", target_id: s.target_id ?? "", target_name: s.target_name ?? "", profile_id: "" }];
  }
  return f;
}
