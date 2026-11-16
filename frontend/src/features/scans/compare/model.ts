import type { ScanComparison } from "@/api/types";

export const MIN_COMPARE = 2;
export const MAX_COMPARE = 10;
export const MAX_RANGE_DAYS = 360;
export const MATRIX_LIMIT = 500;

export type CompareSearch = {
  ids?: string;
  q?: string;
  scan_key?: string;
  from?: string;
  to?: string;
  profile_id?: string;
  status?: string;
  scanner?: string;
};

const keys = ["ids", "q", "scan_key", "from", "to", "profile_id", "status", "scanner"] as const;

export const validateCompareSearch = (s: Record<string, unknown>): CompareSearch => {
  const out: CompareSearch = {};
  for (const k of keys) if (typeof s[k] === "string" && s[k]) out[k] = (s[k] as string).slice(0, 2000);
  return out;
};

/** ids from the URL: unique, non-empty, at most MAX_COMPARE. */
export function parseIds(v: string | undefined): string[] {
  if (!v) return [];
  return [...new Set(v.split(",").map((x) => x.trim()).filter(Boolean))].slice(0, MAX_COMPARE);
}

const day = 86_400_000;
export const isoDay = (d: Date) => d.toISOString().slice(0, 10);

function parseDay(v: string | undefined): Date | null {
  if (!v || !/^\d{4}-\d{2}-\d{2}$/.test(v)) return null;
  const d = new Date(`${v}T00:00:00Z`);
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Effective picker date range: defaults to the last 360 days; a range longer
 * than 360 days is clamped by moving `from` forward.
 */
export function dateRange(from: string | undefined, to: string | undefined, now = new Date()) {
  const t = parseDay(to) ?? parseDay(isoDay(now))!;
  let f = parseDay(from) ?? new Date(t.getTime() - MAX_RANGE_DAYS * day);
  let clamped = false;
  if (f.getTime() > t.getTime()) f = t;
  if (t.getTime() - f.getTime() > MAX_RANGE_DAYS * day) {
    f = new Date(t.getTime() - MAX_RANGE_DAYS * day);
    clamped = true;
  }
  return { from: isoDay(f), to: isoDay(t), clamped };
}

export type FindingState = "present" | "new" | "recurring" | "unchanged" | "fixed" | "not_covered" | "absent";

export const stateMeta: Record<FindingState, { label: string; cls: string; description: string }> = {
  present: { label: "Present", cls: "bg-primary/10 text-primary", description: "Found in the first compared scan" },
  new: { label: "New", cls: "bg-danger-soft text-danger", description: "Not in the previous scan, found in this one" },
  recurring: { label: "Recurring", cls: "bg-warning-soft text-warning", description: "Was fixed earlier and is back" },
  unchanged: { label: "Unchanged", cls: "bg-surface-muted text-foreground", description: "Also found in the previous scan" },
  fixed: { label: "Fixed", cls: "bg-success-soft text-success", description: "Gone, and the covering scanner completed" },
  not_covered: { label: "Not covered", cls: "border border-dashed border-warning text-warning", description: "Gone, but the covering scanner did not complete" },
  absent: { label: "Absent", cls: "text-muted-foreground", description: "Not found" },
};

export const states = Object.keys(stateMeta) as FindingState[];

export const stateOf = (v: string | undefined): FindingState => (v && v in stateMeta ? (v as FindingState) : "absent");

export type ComparedScan = ScanComparison["scans"][number];
export type ComparedFinding = ScanComparison["findings"][number];

export function filterFindings(findings: ComparedFinding[], f: { state?: string; severity?: string }) {
  return findings.filter(
    (x) => (!f.severity || x.severity === f.severity) && (!f.state || Object.values(x.states).some((s) => stateOf(s) === f.state)),
  );
}

/** "+1m 5s" / "−12s" / "±0s" */
export function signedDuration(ms: number | null | undefined, fmt: (ms: number) => string): string {
  if (ms == null) return "";
  if (ms === 0) return "±0s";
  return `${ms > 0 ? "+" : "−"}${fmt(Math.abs(ms))}`;
}
