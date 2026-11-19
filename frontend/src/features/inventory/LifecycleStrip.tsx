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
      title={`${p.number} · ${p.title}: ${p.summary}`}
    >
      <Icon className="size-3.5" aria-hidden />
      <span className="sr-only">{`${p.title}: ${stateLabel[st]}. ${p.summary}`}</span>
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
            <div className="mt-0.5 line-clamp-2 text-[11px] text-muted-foreground">{p.summary}</div>
          </li>
        );
      })}
    </ol>
  );
}
