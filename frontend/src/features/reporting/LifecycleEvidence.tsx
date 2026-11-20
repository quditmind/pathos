import { Card } from "@/components/ui/primitives";
import { EvidenceBadge } from "@/features/monitoring/shared";
import { redactToolNames } from "@/lib/checkKinds";

/**
 * One lifecycle evidence section (PATHOS 3.0 M9): the compliance report's
 * `lifecycle_evidence` and the technical AI report's `facts.lifecycle`.
 */
export interface LifecycleSection {
  key: string;
  title: string;
  available: boolean;
  reason?: string;
  evidence_label?: string;
  evidence?: string;
  metrics?: Record<string, number>;
}

/** "open_threat_models" → "Open threat models". */
export function humanizeMetric(key: string): string {
  const s = key.replace(/_/g, " ").trim();
  return s ? s[0]!.toUpperCase() + s.slice(1) : key;
}

/** Tolerant parse of the sections (unknown shapes are dropped, never invented). */
export function lifecycleSections(v: unknown): LifecycleSection[] {
  if (!Array.isArray(v)) return [];
  return v.filter((s): s is LifecycleSection => !!s && typeof s === "object" && typeof (s as LifecycleSection).key === "string");
}

function SectionCard({ s }: { s: LifecycleSection }) {
  const metrics = Object.entries(s.metrics ?? {}).filter(([, n]) => typeof n === "number");
  const headingId = `lc-ev-${s.key}`;
  return (
    <Card className="p-3 text-[12.5px]" aria-labelledby={headingId} role="region" data-testid="lifecycle-evidence-section">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <h4 id={headingId} className="text-[13px] font-semibold">
          {redactToolNames(s.title || humanizeMetric(s.key))}
        </h4>
        {s.available && s.evidence_label && <EvidenceBadge label={s.evidence_label} />}
      </div>
      {!s.available ? (
        <p className="text-muted-foreground">{s.reason ? redactToolNames(s.reason) : "No evidence available for this part of the lifecycle yet."}</p>
      ) : (
        <>
          {s.evidence && <p className="mb-2 text-muted-foreground">{redactToolNames(s.evidence)}</p>}
          {metrics.length ? (
            <dl className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-0.5">
              {metrics.map(([k, n]) => (
                <div key={k} className="contents">
                  <dt className="text-muted-foreground">{humanizeMetric(k)}</dt>
                  <dd className="tabular text-right font-medium">{n}</dd>
                </div>
              ))}
            </dl>
          ) : (
            <p className="text-muted-foreground">No figures recorded yet.</p>
          )}
        </>
      )}
    </Card>
  );
}

/** "Lifecycle evidence": one card per section; unavailable sections say why. Renders nothing without sections. */
export function LifecycleEvidence({ sections, headingLevel = 3 }: { sections: LifecycleSection[]; headingLevel?: 2 | 3 }) {
  if (!sections.length) return null;
  const H = headingLevel === 2 ? "h2" : "h3";
  return (
    <section aria-label="Lifecycle evidence" className="space-y-2">
      <H className="text-[13px] font-semibold">Lifecycle evidence</H>
      <p className="text-[12px] text-muted-foreground">
        Evidence from the rest of the lifecycle — CodeGraph, threat models, remediation and security gates — computed by PATHOS from its own records.
      </p>
      <div className="grid gap-2 sm:grid-cols-2">
        {sections.map((s) => (
          <SectionCard key={s.key} s={s} />
        ))}
      </div>
    </section>
  );
}
