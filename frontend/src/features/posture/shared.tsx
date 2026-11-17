import { Link } from "@tanstack/react-router";
import { severityColor } from "@/components/data/Severity";
import type { Severity } from "@/api/types";
import type { PostureGroup } from "./api";
import { cn, formatDateTime } from "@/lib/utils";

const sevs: Severity[] = ["critical", "high", "medium", "low", "info"];

/** Open findings by severity: a proportional bar plus the counts as text. */
export function SeverityBar({ open, className }: { open: PostureGroup["open"]; className?: string }) {
  const total = sevs.reduce((n, s) => n + (open[s] ?? 0), 0);
  const label = sevs.filter((s) => open[s]).map((s) => `${open[s]} ${s}`).join(", ") || "no open findings";
  return (
    <div className={cn("min-w-36", className)} title={label} aria-label={`Open findings: ${label}`} role="img">
      <div className="flex h-2 w-full gap-[2px] overflow-hidden rounded-sm bg-surface-muted">
        {total > 0 &&
          sevs.map((s) =>
            open[s] ? <span key={s} style={{ width: `${(open[s] / total) * 100}%`, backgroundColor: severityColor[s] }} className="h-full first:rounded-l-sm last:rounded-r-sm" /> : null,
          )}
      </div>
      <div className="tabular mt-0.5 flex gap-2 text-[11px] text-muted-foreground">
        {total === 0 ? (
          <span>none open</span>
        ) : (
          sevs.slice(0, 4).map((s) => (
            <span key={s} className={open[s] ? "text-foreground" : undefined}>
              {open[s] ?? 0} <span className="capitalize text-muted-foreground">{s.slice(0, 4)}</span>
            </span>
          ))
        )}
      </div>
    </div>
  );
}

export function Percent({ value }: { value: number | null | undefined }) {
  if (value == null) return <span className="text-muted-foreground">—</span>;
  return <span className="tabular">{value.toFixed(value % 1 ? 1 : 0)}%</span>;
}

export function When({ at }: { at: string | null | undefined }) {
  if (!at) return <span className="text-muted-foreground">never</span>;
  return <span className="tabular whitespace-nowrap">{formatDateTime(at)}</span>;
}

/** Explains a rollup risk score. */
export function riskExplanation(g: PostureGroup) {
  if (g.max_risk == null) return "No open findings.";
  const b = g.risk_basis;
  return b.uplift
    ? `Riskiest open finding ${b.max_finding_risk.toFixed(0)}, plus ${b.uplift.toFixed(0)} for ${b.other_high_risk_findings} more findings with risk ≥ 50 (at most 15).`
    : `Riskiest open finding ${b.max_finding_risk.toFixed(0)}.`;
}

export function GraphLink({ node, children }: { node: string; children: React.ReactNode }) {
  return (
    <Link to="/posture/graph" search={{ node } as never} className="text-primary hover:underline">
      {children}
    </Link>
  );
}

export const daysOptions = [30, 90, 180, 365];
