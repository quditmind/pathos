import { cn } from "@/lib/utils";

/** Determinate progress bar (value 0..1). */
export function ProgressBar({ value, label, tone = "primary", className }: { value: number; label: string; tone?: "primary" | "success" | "danger" | "warning" | "muted"; className?: string }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100);
  const fill = { primary: "bg-primary", success: "bg-success", danger: "bg-danger", warning: "bg-warning", muted: "bg-muted-foreground/50" }[tone];
  return (
    <div
      role="progressbar"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={pct}
      className={cn("h-1.5 w-full overflow-hidden rounded-full bg-surface-muted", className)}
    >
      <div className={cn("h-full rounded-full transition-[width] duration-300", fill)} style={{ width: `${pct}%` }} />
    </div>
  );
}
