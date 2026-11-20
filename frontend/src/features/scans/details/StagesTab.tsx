import { ListChecks } from "lucide-react";
import type { ScanJob, ScanKindProgress, ScanStage } from "@/api/types";
import { ProgressBar } from "@/components/ui/progress";
import { kindName, kindOfTool, redactToolNames } from "@/lib/checkKinds";
import { Badge, Card, EmptyState, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { isActive, useScanStages } from "../api";
import { formatDuration } from "../shared";
import { ErrorPanel } from "@/components/ui/error-panel";

const tone: Record<ScanStage["status"], "neutral" | "primary" | "success" | "danger" | "warning"> = {
  pending: "neutral",
  running: "primary",
  succeeded: "success",
  failed: "danger",
  skipped: "neutral",
  timed_out: "danger",
  cancelled: "warning",
};

export function StagesTab({ job }: { job: ScanJob }) {
  const q = useScanStages(job.id, isActive(job));
  if (q.isError) return <ErrorPanel error={q.error} title="Could not load stages" />;
  if (q.isPending) return <Skeleton className="h-48" />;
  const { stages, events } = q.data;
  const kinds = q.data.kinds ?? kindProgressOf(stages);
  // Scanner stages are numbered within their kind of check: the UI names
  // kinds, never engines (rule 3).
  const ordinal = new Map<string, number>();
  const stageName = (s: ScanStage) => {
    if (!s.scanner) return s.label;
    const kind = s.kind_of_check_name || kindName(kindOfTool(s.scanner));
    const n = (ordinal.get(kind) ?? 0) + 1;
    ordinal.set(kind, n);
    return `${kind} · check ${n}`;
  };
  return (
    <div className="space-y-4">
      {kinds.length > 0 && <KindProgressCard kinds={kinds} />}
      <Card>
        {stages.length ? (
          <Table>
            <thead>
              <tr>
                <Th>Stage</Th>
                <Th>Status</Th>
                <Th>Started</Th>
                <Th>Finished</Th>
                <Th>Duration</Th>
                <Th className="text-right">Findings</Th>
                <Th>Error</Th>
              </tr>
            </thead>
            <tbody>
              {stages.map((s) => (
                <tr key={s.key}>
                  <Td>
                    <div className="font-medium">{stageName(s)}</div>
                  </Td>
                  <Td><Badge tone={tone[s.status] ?? "neutral"}>{s.status.replace("_", " ")}</Badge></Td>
                  <Td className="tabular whitespace-nowrap text-[12px]">{formatDateTime(s.started_at)}</Td>
                  <Td className="tabular whitespace-nowrap text-[12px]">{formatDateTime(s.finished_at)}</Td>
                  <Td className="tabular text-[12px]">{formatDuration(s.duration_ms)}</Td>
                  <Td className="tabular text-right">{s.findings ?? "—"}</Td>
                  <Td className="max-w-xs text-[12px] text-danger">{s.error ? redactToolNames(s.error) : <span className="text-muted-foreground">—</span>}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <EmptyState icon={<ListChecks />} title="No stages recorded yet" />
        )}
      </Card>
      <Card>
        <details>
          <summary className="cursor-pointer px-4 py-3 text-[13px] font-semibold">Raw events ({events.length})</summary>
          {events.length ? (
            <ol className="max-h-96 overflow-y-auto border-t border-border font-mono text-[12px]">
              {events.map((e, i) => (
                <li key={i} className="flex flex-wrap gap-x-3 border-b border-border px-4 py-1.5 last:border-0">
                  <time className="tabular text-muted-foreground" dateTime={e.at}>{formatDateTime(e.at)}</time>
                  <span className="font-semibold">{e.stage}{e.scanner && `: ${kindName(kindOfTool(e.scanner))}`}</span>
                  <span className="text-muted-foreground">{e.status}</span>
                  <span className="min-w-0 flex-1 break-words">{redactToolNames(e.message)}</span>
                </li>
              ))}
            </ol>
          ) : (
            <p className="border-t border-border px-4 py-3 text-[13px] text-muted-foreground">No events.</p>
          )}
        </details>
      </Card>
    </div>
  );
}

/** Groups scanner stages by kind of check (older servers send no kinds). */
function kindProgressOf(stages: ScanStage[]): ScanKindProgress[] {
  const by = new Map<string, ScanKindProgress>();
  for (const s of stages) {
    if (!s.scanner) continue;
    const id = s.kind_of_check || kindOfTool(s.scanner);
    const k = by.get(id) ?? { id, name: s.kind_of_check_name || kindName(id), total: 0, finished: 0, failed: 0, running: 0 };
    k.total++;
    if (["succeeded", "skipped", "cancelled", "failed", "timed_out"].includes(s.status)) k.finished++;
    if (s.status === "failed" || s.status === "timed_out") k.failed++;
    if (s.status === "running") k.running++;
    by.set(id, k);
  }
  return [...by.values()];
}

/** Scan progress by kind of check: "Infrastructure as code: 7 of 10 checks finished". */
export function KindProgressCard({ kinds }: { kinds: ScanKindProgress[] }) {
  return (
    <Card className="p-4" data-testid="kind-progress">
      <h2 className="mb-3 text-[13px] font-semibold">Progress by kind of check</h2>
      <ul className="grid gap-3 sm:grid-cols-2">
        {kinds.map((k) => (
          <li key={k.id}>
            <div className="mb-1 flex items-baseline justify-between gap-2 text-[12.5px]">
              <span>
                <span className="font-medium">{k.name}:</span> {k.finished} of {k.total} {k.total === 1 ? "check" : "checks"} finished
              </span>
              {k.failed > 0 && <Badge tone="danger">{k.failed} failed</Badge>}
            </div>
            <ProgressBar value={k.total ? k.finished / k.total : 0} label={`${k.name}: ${k.finished} of ${k.total} checks finished`} tone={k.failed ? "danger" : k.finished === k.total ? "success" : "primary"} />
          </li>
        ))}
      </ul>
    </Card>
  );
}
