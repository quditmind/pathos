import { Check, Circle, Lock, Minus } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Phase } from "./api";

/** Short label per phase for the compact strip. */
export const phaseShort: Record<string, string> = {
  connect: "Connect",
  inventory: "Inventory",
  discover: "Discover",
  threat_model: "Threat model",
  reverse_engineering: "Reverse eng.",
  assess: "Assess",
  validate: "Validate",
  remediate: "Remediate",
  report: "Report",
};

export function phaseState(p: Phase): "data" | "empty" | "unavailable" | "restricted" {
  if (!p.available) return "unavailable";
  if (p.restricted) return "restricted";
  return p.has_data ? "data" : "empty";
}

/** Labels of the phase metrics (GET /api/v1/applications/{id}/lifecycle), in display order. Unknown keys are not shown. */
export const metricLabels: Record<string, string> = {
  repositories: "repositories",
  onboarding_repositories: "in onboarding",
  codegraph_snapshots: "CodeGraph snapshots",
  components: "SBOM components",
  threat_models: "threat models",
  threats: "threats",
  open_threats: "open threats",
  scans: "scans",
  findings: "findings",
  open_findings: "open findings",
  ai_reviews: "AI reviews",
  human_reviews: "human reviews",
  remediation_items: "remediation items",
  open_remediation_items: "open remediation items",
  gate_decisions: "gate decisions",
  failed_gate_decisions: "failed gate decisions",
  fix_pull_requests: "fix pull requests",
  risk_acceptances: "risk acceptances",
  pull_request_checks: "pull request checks",
  monitoring_events: "monitoring events (30 days)",
  drift_changes: "architecture drifts with changes",
  versions: "release versions",
  runtime_mappings: "runtime mappings",
};

/** The phase's non-zero metrics with labels (real counts from the API only). */
export function phaseMetrics(p: Phase): { key: string; label: string; value: number }[] {
  if (p.restricted || !p.metrics) return [];
  return Object.keys(metricLabels)
    .filter((k) => typeof p.metrics[k] === "number" && p.metrics[k]! > 0)
    .map((k) => ({ key: k, label: metricLabels[k]!, value: p.metrics[k]! }));
}

/** The summary, or an honest empty-state line when the server sent none. */
export function phaseSummary(p: Phase): string {
  if (p.summary) return p.summary;
  const st = phaseState(p);
  return st === "unavailable" ? "Not available yet" : st === "restricted" ? "Not visible to you" : st === "empty" ? "No data yet" : "";
}

const metricsText = (p: Phase) => phaseMetrics(p).map((m) => `${m.value} ${m.label}`).join(", ");

const stateLabel = { data: "has data", empty: "no data yet", unavailable: "not available yet", restricted: "not visible to you" };

/** One phase cell: icon + state for screen readers; the summary is the tooltip. */
export function PhaseCell({ p, compact = false }: { p: Phase; compact?: boolean }) {
  const st = phaseState(p);
  const Icon = st === "data" ? Check : st === "unavailable" ? Minus : st === "restricted" ? Lock : Circle;
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded",
        compact ? "size-6" : "size-7",
        st === "data" && "bg-success-soft text-success",
        st === "empty" && "border border-dashed border-border text-muted-foreground",
        st === "unavailable" && "bg-surface-muted text-muted-foreground/70",
        st === "restricted" && "bg-surface-muted text-muted-foreground",
      )}
      title={`${p.number} · ${p.title}: ${phaseSummary(p)}${metricsText(p) ? ` (${metricsText(p)})` : ""}`}
    >
      <Icon className="size-3.5" aria-hidden />
      <span className="sr-only">{`${p.title}: ${stateLabel[st]}. ${phaseSummary(p)}${metricsText(p) ? `. ${metricsText(p)}` : ""}`}</span>
    </span>
  );
}

/**
 * The application profile's lifecycle progress strip: the nine phases, which
 * of them hold real data, and the summary of each (real data only).
 */
export function LifecycleStrip({ phases }: { phases: Phase[] }) {
  return (
    <ol className="grid grid-cols-3 gap-1.5 sm:grid-cols-5 lg:grid-cols-9" aria-label="Lifecycle progress">
      {phases.map((p) => {
        const st = phaseState(p);
        return (
          <li
            key={p.key}
            className={cn(
              "rounded-md border px-2 py-1.5 text-[11.5px]",
              st === "data" ? "border-success/40 bg-success-soft/40" : "border-border",
              st === "unavailable" && "opacity-70",
            )}
          >
            <div className="flex items-center gap-1.5">
              <span className="font-mono text-[10.5px] text-muted-foreground">{p.number}</span>
              <span className="truncate font-medium">{phaseShort[p.key] ?? p.title}</span>
              <span className="sr-only">{`: ${stateLabel[st]}`}</span>
              {st === "data" && <Check className="ml-auto size-3.5 shrink-0 text-success" aria-hidden />}
            </div>
            <div className="mt-0.5 line-clamp-2 text-[11px] text-muted-foreground">{phaseSummary(p)}</div>
            {phaseMetrics(p).length > 0 && (
              <ul className="mt-1 space-y-0.5 text-[10.5px] text-muted-foreground" aria-label={`${p.title} metrics`}>
                {phaseMetrics(p).map((m) => (
                  <li key={m.key}>
                    <span className="font-medium text-foreground tabular-nums">{m.value}</span> {m.label}
                  </li>
                ))}
              </ul>
            )}
          </li>
        );
      })}
    </ol>
  );
}
