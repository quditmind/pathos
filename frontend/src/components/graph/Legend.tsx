import { diffStyle, evidenceStyle, trustBoundaryStyle } from "./model";
import { evidenceKinds, type DiffStatus } from "./types";

/** Evidence line styles and trust boundaries; the diff colours in compare mode. */
export function GraphLegend({ diffCounts }: { diffCounts?: Record<Exclude<DiffStatus, "unchanged">, number> }) {
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[12px] text-muted-foreground" role="group" aria-label="Legend">
      {evidenceKinds.map((k) => {
        const s = evidenceStyle[k];
        return (
          <span key={k} className="inline-flex items-center gap-1.5" data-legend={k}>
            <svg width="28" height="8" aria-hidden>
              <line x1="0" y1="4" x2="28" y2="4" stroke={s.color} strokeWidth="2" strokeDasharray={s.dash || undefined} />
            </svg>
            {s.description}
          </span>
        );
      })}
      <span className="inline-flex items-center gap-1.5" data-legend="trust_boundary">
        <svg width="28" height="10" aria-hidden>
          <rect x="1" y="1" width="26" height="8" rx="2" fill="none" stroke={trustBoundaryStyle.color} strokeDasharray="4 3" />
        </svg>
        {trustBoundaryStyle.label}
      </span>
      {diffCounts && (
        <span className="inline-flex flex-wrap items-center gap-3 border-l border-border pl-4" role="group" aria-label="Compare legend">
          {(["added", "removed", "changed"] as const).map((s) => (
            <span key={s} className="inline-flex items-center gap-1.5" data-legend={`diff-${s}`}>
              <span className="inline-block size-3 rounded-sm border-2" style={{ borderColor: diffStyle[s].color }} aria-hidden />
              {diffStyle[s].label} ({diffCounts[s]})
            </span>
          ))}
        </span>
      )}
    </div>
  );
}

/** A small evidence chip (inspector, list view). */
export function EvidenceChip({ evidence }: { evidence: keyof typeof evidenceStyle }) {
  const s = evidenceStyle[evidence];
  return (
    <span
      className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[11px] font-semibold"
      style={{ color: s.color, backgroundColor: `color-mix(in srgb, ${s.color} 13%, transparent)` }}
    >
      <svg width="14" height="6" aria-hidden>
        <line x1="0" y1="3" x2="14" y2="3" stroke={s.color} strokeWidth="2" strokeDasharray={s.dash || undefined} />
      </svg>
      {s.label}
    </span>
  );
}
