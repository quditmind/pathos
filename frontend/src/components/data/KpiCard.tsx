import { Link } from "@tanstack/react-router";
import { ArrowDownRight, ArrowUpRight, Lock, Minus } from "lucide-react";
import type { Kpi, Point } from "@/api/types";
import { cn, isAppRoute, splitHref } from "@/lib/utils";

const nf = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });

export function formatKpiValue(value: number, unit: Kpi["unit"]): string {
  switch (unit) {
    case "percent":
      return `${nf.format(value)}%`;
    case "days":
      return `${nf.format(value)}d`;
    default:
      return nf.format(value);
  }
}

/** Direction and tone of the change versus the previous period. */
export function kpiDelta(k: Pick<Kpi, "value" | "previous" | "polarity">) {
  if (k.value == null || k.previous == null) return null;
  const diff = k.value - k.previous;
  if (diff === 0) return { diff, pct: 0, tone: "neutral" as const };
  const pct = k.previous === 0 ? null : (diff / k.previous) * 100;
  const good = k.polarity === "neutral" ? null : (diff > 0) === (k.polarity === "higher_is_better");
  return { diff, pct, tone: good === null ? ("neutral" as const) : good ? ("good" as const) : ("bad" as const) };
}

export function Sparkline({ points, className }: { points: Point[]; className?: string }) {
  if (points.length < 2) return null;
  const w = 96;
  const h = 28;
  const vals = points.map((p) => p.value);
  const max = Math.max(...vals);
  const min = Math.min(...vals);
  const span = max - min || 1;
  const xy = vals.map((v, i) => [(i / (vals.length - 1)) * w, h - 2 - ((v - min) / span) * (h - 4)] as const);
  const d = xy.map(([x, y], i) => `${i ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`).join("");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className={cn("h-7 w-24", className)} aria-hidden preserveAspectRatio="none">
      <path d={`${d}L${w},${h}L0,${h}Z`} fill="var(--primary)" opacity={0.08} />
      <path d={d} fill="none" stroke="var(--primary)" strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export function KpiCard({ kpi, period }: { kpi: Kpi; period: string }) {
  const delta = kpiDelta(kpi);
  const available = kpi.status === "ok";

  const body = (
    <div
      className={cn(
        "group flex h-full flex-col rounded-lg border border-border bg-surface p-4 transition-colors",
        available && "hover:border-primary/40",
      )}
      title={kpi.description}
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-[12px] font-medium text-muted-foreground">{kpi.label}</span>
        {kpi.org_wide && available && (
          <span className="rounded bg-surface-muted px-1 text-[10px] text-muted-foreground" title="Not affected by region / business unit filters">
            org-wide
          </span>
        )}
      </div>
      {kpi.status === "ok" && kpi.value != null ? (
        <>
          <div className="mt-1.5 flex items-end justify-between gap-2">
            <span className="tabular text-2xl font-semibold tracking-tight">{formatKpiValue(kpi.value, kpi.unit)}</span>
            {kpi.sparkline && <Sparkline points={kpi.sparkline} />}
          </div>
          <div className="mt-1 h-4 text-[11.5px]">
            {delta && (
              <span
                className={cn(
                  "tabular inline-flex items-center gap-0.5",
                  delta.tone === "good" && "text-success",
                  delta.tone === "bad" && "text-danger",
                  delta.tone === "neutral" && "text-muted-foreground",
                )}
              >
                {delta.diff > 0 ? <ArrowUpRight className="size-3.5" /> : delta.diff < 0 ? <ArrowDownRight className="size-3.5" /> : <Minus className="size-3.5" />}
                {delta.diff > 0 ? "+" : ""}
                {nf.format(delta.diff)}
                {delta.pct != null && delta.diff !== 0 && ` (${nf.format(Math.abs(delta.pct))}%)`}
                <span className="ml-1 text-muted-foreground">vs previous {period}</span>
              </span>
            )}
          </div>
        </>
      ) : kpi.status === "restricted" ? (
        <div className="mt-2 flex items-center gap-1.5 text-[12px] text-muted-foreground">
          <Lock className="size-3.5" /> Requires additional permission
        </div>
      ) : (
        <div className="mt-2">
          <div className="text-[13px] font-medium text-muted-foreground">Not yet available</div>
          <div className="text-[11.5px] text-muted-foreground/80">Data source arrives in phase {kpi.phase}</div>
        </div>
      )}
    </div>
  );

  // Drill-down only for routes that exist (Phase 1 admin routes); later
  // phases add their own pages.
  return available && isAppRoute(kpi.drill) ? (
    <Link {...(splitHref(kpi.drill) as { to: string })} className="block rounded-lg focus-visible:outline-2 focus-visible:outline-ring" aria-label={`${kpi.label}: view details`}>
      {body}
    </Link>
  ) : (
    body
  );
}
