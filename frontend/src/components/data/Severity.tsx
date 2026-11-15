import { CheckCircle2, CircleDashed, CircleX, Loader2, MinusCircle, TriangleAlert } from "lucide-react";
import type { JobStatus, Severity } from "@/api/types";
import { cn } from "@/lib/utils";

export const severityColor: Record<Severity, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  info: "var(--sev-info)",
};

export function SeverityBadge({ value, className }: { value: Severity; className?: string }) {
  return (
    <span
      className={cn("inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold capitalize", className)}
      style={{ color: severityColor[value], backgroundColor: `color-mix(in srgb, ${severityColor[value]} 13%, transparent)` }}
    >
      <span className="size-1.5 rounded-full" style={{ backgroundColor: severityColor[value] }} aria-hidden />
      {value}
    </span>
  );
}

const statusStyle: Record<JobStatus, { cls: string; icon: React.ReactNode }> = {
  queued: { cls: "text-muted-foreground", icon: <CircleDashed className="size-3.5" /> },
  running: { cls: "text-primary", icon: <Loader2 className="size-3.5 animate-spin" /> },
  succeeded: { cls: "text-success", icon: <CheckCircle2 className="size-3.5" /> },
  partial: { cls: "text-warning", icon: <TriangleAlert className="size-3.5" /> },
  failed: { cls: "text-danger", icon: <CircleX className="size-3.5" /> },
  cancelled: { cls: "text-muted-foreground", icon: <MinusCircle className="size-3.5" /> },
};

export function JobStatusPill({ status }: { status: JobStatus }) {
  const s = statusStyle[status];
  return (
    <span className={cn("inline-flex items-center gap-1 text-[12px] font-medium capitalize", s.cls)}>
      {s.icon}
      {status}
    </span>
  );
}

export function duration(ms: number | null | undefined): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms} ms`;
  const s = Math.round(ms / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${s % 60}s`;
}

export function between(a: string | null, b: string | null): string {
  if (!a) return "—";
  const end = b ? new Date(b).getTime() : Date.now();
  return duration(end - new Date(a).getTime());
}
