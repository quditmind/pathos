import { useQuery } from "@tanstack/react-query";
import { Flame, Skull } from "lucide-react";
import { api } from "@/api/client";
import type { FindingRisk, LifecycleStatus } from "@/api/types";
import { Badge, Skeleton } from "@/components/ui/primitives";
import { cn, formatDateTime } from "@/lib/utils";

export const lifecycleLabel: Record<LifecycleStatus, string> = {
  new: "New",
  open: "Open",
  in_progress: "In progress",
  under_review: "Under review",
  confirmed: "Confirmed",
  false_positive: "False positive",
  accepted_risk: "Accepted risk",
  resolved: "Resolved",
  reopened: "Reopened",
};

const lifecycleTone: Record<LifecycleStatus, "neutral" | "primary" | "warning" | "success" | "danger"> = {
  new: "primary",
  open: "neutral",
  in_progress: "primary",
  under_review: "warning",
  confirmed: "danger",
  false_positive: "success",
  accepted_risk: "warning",
  resolved: "success",
  reopened: "danger",
};

export function LifecycleBadge({ value }: { value?: LifecycleStatus | null }) {
  if (!value) return <span className="text-muted-foreground">—</span>;
  return <Badge tone={lifecycleTone[value]}>{lifecycleLabel[value]}</Badge>;
}

export const riskBand = (s: number) => (s >= 75 ? "critical" : s >= 50 ? "high" : s >= 25 ? "medium" : s > 0 ? "low" : "none");

const bandColor: Record<string, string> = {
  critical: "var(--sev-critical)",
  high: "var(--sev-high)",
  medium: "var(--sev-medium)",
  low: "var(--sev-low)",
  none: "var(--muted-foreground)",
};

/** Contextual risk score with its band (text, not colour alone). */
export function RiskBadge({ score, className }: { score?: number | null; className?: string }) {
  if (score == null) return <span className="text-[12px] text-muted-foreground" title="Not scored yet">—</span>;
  const band = riskBand(score);
  return (
    <span
      className={cn("tabular inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11.5px] font-semibold", className)}
      style={{ color: bandColor[band], backgroundColor: `color-mix(in srgb, ${bandColor[band]} 12%, transparent)` }}
      title={`Contextual risk ${score.toFixed(1)} (${band})`}
    >
      {Math.round(score)}
      <span className="font-normal capitalize">{band}</span>
    </span>
  );
}

export function MaliciousBadge() {
  return (
    <Badge tone="danger" className="gap-0.5">
      <Skull className="size-3" aria-hidden /> Malicious
    </Badge>
  );
}

export function KevBadge() {
  return (
    <Badge tone="danger" className="gap-0.5" >
      <Flame className="size-3" aria-hidden /> KEV
    </Badge>
  );
}

export const pct = (v?: number | null) => (v == null ? "—" : `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`);

/** Score explanation for one finding (drawer, review workspace). */
export function RiskPanel({ findingId }: { findingId: string }) {
  const q = useQuery({ queryKey: ["finding-risk", findingId], queryFn: () => api<FindingRisk>(`/api/v1/findings/${findingId}/risk`) });
  const r = q.data;
  return (
    <div>
      <h3 className="mb-2 text-[13px] font-semibold">Contextual risk</h3>
      {q.isError ? (
        <p className="text-[12px] text-danger">{q.error.message}</p>
      ) : !r ? (
        <Skeleton className="h-24" />
      ) : (
        <div className="space-y-2 rounded-md border border-border p-3 text-[12.5px]">
          <div className="flex flex-wrap items-center gap-2">
            <RiskBadge score={r.risk_score} />
            {r.kev && <KevBadge />}
            {r.pending && <span className="text-[11.5px] text-muted-foreground">Recalculating…</span>}
            {r.explanation?.reason && <span className="text-muted-foreground">{r.explanation.reason}</span>}
          </div>
          {r.explanation && r.explanation.factors.length > 0 && (
            <table className="w-full text-[12px]">
              <caption className="sr-only">Risk factors</caption>
              <tbody>
                {r.explanation.factors.map((f) => (
                  <tr key={f.key} className="border-b border-border last:border-0">
                    <td className="py-1 text-muted-foreground">{f.label}</td>
                    <td className="py-1">{f.value}</td>
                    <td className="tabular py-1 text-right font-mono">{f.key === "base" ? f.weight.toFixed(1) : `× ${f.weight.toFixed(2)}`}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-[12px]">
            <dt className="text-muted-foreground">EPSS (30-day exploit probability)</dt>
            <dd>{r.epss != null ? `${pct(r.epss)} · percentile ${pct(r.epss_percentile)}` : r.cve ? "No score for this CVE" : "No CVE"}</dd>
            <dt className="text-muted-foreground">CISA KEV</dt>
            <dd>{r.kev ? `Exploited in the wild${r.kev_due_date ? ` · federal due date ${r.kev_due_date.slice(0, 10)}` : ""}` : "Not listed"}</dd>
            <dt className="text-muted-foreground">Confidence</dt>
            <dd className="capitalize">{r.confidence}</dd>
            <dt className="text-muted-foreground">Reachability</dt>
            <dd>{r.reachability === "unknown" ? "Not analysed" : r.reachability.replace("_", " ")}</dd>
            {r.cvss_vector && (
              <>
                <dt className="text-muted-foreground">CVSS {r.cvss_version}</dt>
                <dd className="break-all font-mono text-[11px]">{r.cvss_vector}</dd>
              </>
            )}
          </dl>
          <p className="text-[11px] text-muted-foreground">
            Model v{r.explanation?.model_version ?? 0} · scored {formatDateTime(r.scored_at)}. Severity is unchanged; the score ranks work.
          </p>
        </div>
      )}
    </div>
  );
}
