import { Link } from "@tanstack/react-router";
import { Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/primitives";
import { ErrorPanel } from "@/components/ui/error-panel";
import { LoadingSkeleton } from "@/components/ui/states";
import { useSession } from "@/features/auth/session";
import { useFeatureFlag } from "@/features/shell/meta";
import { LocationBadge } from "./AIEvidencePanel";
import { useCorrelation, useExplainCorrelation, type EvidenceLabelValue } from "./evidence";

/** Rule 5 chip of a joined fact. */
export function EvidenceChip({ value }: { value: EvidenceLabelValue }) {
  const tone = value === "verified" ? "success" : value === "observed" ? "primary" : "warning";
  const text = value === "ai_inferred" ? "AI-inferred" : value;
  return <Badge tone={tone}>{text}</Badge>;
}

function Group({ title, empty, children, count }: { title: string; empty: string; count: number; children: React.ReactNode }) {
  return (
    <div>
      <div className="text-[12px] font-semibold">
        {title} <span className="text-muted-foreground">({count})</span>
      </div>
      {count === 0 ? <p className="text-[12px] text-muted-foreground">{empty}</p> : <ul className="space-y-0.5">{children}</ul>}
    </div>
  );
}

/**
 * Cross-phase correlation of a finding (M7): the deterministic join to
 * CodeGraph, threat models, the SBOM, runtime and related findings, then an
 * optional AI explanation that only proposes.
 */
export function CorrelationSection({ findingId }: { findingId: string }) {
  const on = useFeatureFlag("ai_intelligence");
  const { can } = useSession();
  const q = useCorrelation(findingId, on);
  const explain = useExplainCorrelation(findingId);
  if (!on) return null;
  const c = q.data;
  return (
    <section aria-label="Correlation" className="space-y-2 rounded-md border border-border p-3 text-[12.5px]">
      <div className="flex items-center justify-between gap-2">
        <h3 className="text-[13px] font-semibold">Correlation</h3>
        {can("ai.review") && (
          <Button size="sm" variant="secondary" disabled={explain.isPending || !c} onClick={() => explain.mutate()}>
            <Sparkles /> {explain.isPending ? "Asking the AI…" : "Explain with AI"}
          </Button>
        )}
      </div>
      <p className="text-[12px] text-muted-foreground">Joined from stored facts, without AI.</p>
      {q.isPending ? (
        <LoadingSkeleton rows={3} label="Loading the correlation" />
      ) : q.isError ? (
        <ErrorPanel error={q.error} title="Could not load the correlation" onVerify={() => q.refetch()} />
      ) : c ? (
        <div className="space-y-2">
          <Group title="CodeGraph elements" count={c.codegraph?.nodes.length ?? 0} empty={c.codegraph?.note ?? "CodeGraph is not enabled."}>
            {c.codegraph?.nodes.map((n) => (
              <li key={n.key} className="flex flex-wrap items-center gap-1.5">
                <EvidenceChip value={n.evidence} />
                <span className="text-muted-foreground">{n.type}</span> {n.label}
                {n.file_path && <span className="font-mono text-[11px] text-muted-foreground">{n.file_path}{n.start_line ? `:${n.start_line}` : ""}</span>}
              </li>
            ))}
            {c.codegraph?.edges.map((e) => (
              <li key={e.key} className="flex flex-wrap items-center gap-1.5">
                <EvidenceChip value={e.evidence} />
                <span className="font-mono text-[11px]">{e.source} —{e.type}→ {e.target}</span>
              </li>
            ))}
          </Group>
          <Group title="Threats" count={c.threats.length} empty={c.threats_note ?? "No threat is linked to this finding."}>
            {c.threats.map((t) => (
              <li key={t.id} className="flex flex-wrap items-center gap-1.5">
                <EvidenceChip value={t.evidence} />
                <Link className="text-primary hover:underline" to="/threat-models/$modelId" params={{ modelId: t.threat_model_id }} search={{ threat: t.id } as never}>{t.title}</Link>
                <span className="text-muted-foreground">{t.severity} · {t.status.replaceAll("_", " ")} · linked by {t.link}</span>
              </li>
            ))}
          </Group>
          {c.threats.length > 0 && c.threats_note && <p className="text-[12px] text-muted-foreground">{c.threats_note}</p>}
          <Group title="SBOM components" count={c.components.length} empty="No SBOM component for this finding's package.">
            {c.components.map((x) => (
              <li key={x.purl + x.version} className="flex flex-wrap items-center gap-1.5">
                <EvidenceChip value={x.evidence} />
                <span className="font-mono text-[11px]">{x.name}@{x.version}</span>
                {x.licenses.length > 0 && <span className="text-muted-foreground">{x.licenses.join(", ")}</span>}
              </li>
            ))}
          </Group>
          <Group title="Runtime" count={c.runtime ? 1 : 0} empty="No runtime context for this finding.">
            {c.runtime && (
              <li className="flex flex-wrap items-center gap-1.5">
                <EvidenceChip value={c.runtime.evidence} />
                {c.runtime.status || "seen"}
                {c.runtime.exposed && <Badge tone="danger">exposed</Badge>}
                {c.runtime.privileged && <Badge tone="warning">privileged</Badge>}
                {c.runtime.alert && <Badge tone="danger">runtime alert</Badge>}
              </li>
            )}
          </Group>
          <Group title="Related findings" count={c.related_findings.length} empty="No finding at the same place or of the same vulnerability.">
            {c.related_findings.map((x) => (
              <li key={x.id} className="flex flex-wrap items-center gap-1.5">
                <EvidenceChip value={x.evidence} />
                <Link className="text-primary hover:underline" to="/findings" search={{ finding: x.id } as never}>{x.title}</Link>
                <span className="text-muted-foreground">{x.relation.replaceAll("_", " ")}</span>
              </li>
            ))}
          </Group>
        </div>
      ) : null}
      {explain.isError && <ErrorPanel error={explain.error} title="The AI did not explain the correlation" />}
      {explain.data && (
        <div className="space-y-1 rounded-md border border-warning/40 p-2" data-testid="correlation-explanation">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="warning" className="font-semibold">AI-inferred · awaiting a decision</Badge>
            <LocationBadge location={explain.data.provider_location} />
            <span>Priority {explain.data.explanation.priority}</span>
            <span>{explain.data.explanation.exploitability.replaceAll("_", " ")} ({Math.round(explain.data.explanation.confidence * 100)}%)</span>
          </div>
          <p>{explain.data.explanation.explanation}</p>
          {explain.data.explanation.reasoning.length > 0 && (
            <ol className="list-decimal pl-5">{explain.data.explanation.reasoning.map((s, i) => <li key={i}>{s}</li>)}</ol>
          )}
          <p className="text-[12px] text-muted-foreground">The finding is unchanged: this is a proposal; a person decides in triage or Human Eye.</p>
        </div>
      )}
    </section>
  );
}
