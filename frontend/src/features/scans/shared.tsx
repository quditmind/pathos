import { Link } from "@tanstack/react-router";
import type { ScanJob, Severity } from "@/api/types";
import { ProgressBar } from "@/components/ui/progress";
import { severityColor } from "@/components/data/Severity";
import { cn } from "@/lib/utils";
import { isActive, stageLabel } from "./api";

export const severities: Severity[] = ["critical", "high", "medium", "low", "info"];

export const triggerLabel: Record<string, string> = {
  manual: "Manual",
  schedule: "Schedule",
  push: "Push",
  pull_request: "Pull request",
  merge: "Merge",
  emergency: "Emergency",
  onboarding: "Onboarding",
};

export const statusOptions = [
  { value: "active", label: "Queued or running" },
  { value: "queued", label: "Queued" },
  { value: "running", label: "Running" },
  { value: "succeeded", label: "Succeeded" },
  { value: "partial", label: "Partial" },
  { value: "failed", label: "Failed" },
  { value: "cancelled", label: "Cancelled" },
];

/** Monospace Scan ID linking to the execution details. */
export function ScanIdLink({ job, className }: { job: Pick<ScanJob, "id" | "scan_key">; className?: string }) {
  return (
    <Link
      to="/scans/$id"
      params={{ id: job.id }}
      onClick={(e) => e.stopPropagation()}
      className={cn("whitespace-nowrap font-mono text-[12px] text-primary hover:underline", className)}
    >
      {job.scan_key || job.id.slice(0, 8)}
    </Link>
  );
}

/** Progress bar with the current stage. */
export function ScanProgress({ job, className }: { job: Pick<ScanJob, "progress" | "stage" | "status">; className?: string }) {
  const tone = job.status === "failed" ? "danger" : job.status === "partial" ? "warning" : job.status === "cancelled" ? "muted" : job.status === "succeeded" ? "success" : "primary";
  return (
    <div className={cn("min-w-28", className)}>
      <div className="mb-1 flex items-baseline justify-between gap-2 text-[11.5px]">
        <span className="truncate text-muted-foreground">{isActive(job) ? stageLabel(job.stage) : stageLabel(job.stage || "finished")}</span>
        <span className="tabular">{Math.round(job.progress ?? 0)}%</span>
      </div>
      <ProgressBar value={(job.progress ?? 0) / 100} label={`Progress ${Math.round(job.progress ?? 0)}%`} tone={tone} />
    </div>
  );
}

/** Compact stacked severity distribution: a thin bar plus non-zero counts. */
export function SeverityBar({ severity, className }: { severity: Partial<Record<Severity, number>> | undefined; className?: string }) {
  const counts = severities.map((s) => [s, severity?.[s] ?? 0] as const);
  const total = counts.reduce((n, [, v]) => n + v, 0);
  if (!total) return <span className="text-[12px] text-muted-foreground">—</span>;
  const summary = counts.filter(([, v]) => v).map(([s, v]) => `${v} ${s}`).join(", ");
  return (
    <div className={cn("min-w-28", className)} title={summary} aria-label={`Severity distribution: ${summary}`} role="img">
      <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-surface-muted">
        {counts.map(([s, v]) => v > 0 && <div key={s} style={{ width: `${(100 * v) / total}%`, background: severityColor[s] }} />)}
      </div>
      <div className="mt-1 flex flex-wrap gap-x-1.5 text-[11px] tabular">
        {counts.filter(([, v]) => v).map(([s, v]) => (
          <span key={s} style={{ color: severityColor[s] }} className="font-semibold">
            {v}
            <span className="ml-px font-normal uppercase">{s[0]}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

export function formatDuration(ms: number | null | undefined): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  return `${Math.floor(m / 60)}h ${m % 60}m`;
}

/** Duration of a job: recorded duration, else elapsed while running. */
export function jobDuration(j: Pick<ScanJob, "duration_ms" | "started_at" | "finished_at">): string {
  if (j.duration_ms != null) return formatDuration(j.duration_ms);
  if (!j.started_at) return "—";
  const end = j.finished_at ? new Date(j.finished_at).getTime() : Date.now();
  return formatDuration(end - new Date(j.started_at).getTime());
}

/** Tab bar in the style used across PATHOS (role=tablist). */
export function Tabs<K extends string>({ tabs, value, onChange, label, idPrefix }: { tabs: readonly (readonly [K, string])[]; value: K; onChange: (k: K) => void; label: string; idPrefix: string }) {
  return (
    <div className="flex gap-1 overflow-x-auto border-b border-border" role="tablist" aria-label={label}>
      {tabs.map(([k, l]) => (
        <button
          key={k}
          role="tab"
          type="button"
          id={`${idPrefix}-tab-${k}`}
          aria-selected={value === k}
          aria-controls={`${idPrefix}-panel-${k}`}
          onClick={() => onChange(k)}
          className={cn("-mb-px whitespace-nowrap border-b-2 px-3 py-1.5 text-[13px]", value === k ? "border-primary font-medium text-primary" : "border-transparent text-muted-foreground hover:text-foreground")}
        >
          {l}
        </button>
      ))}
    </div>
  );
}
