import { ListChecks } from "lucide-react";
import type { ScanJob, ScanStage } from "@/api/types";
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
  return (
    <div className="space-y-4">
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
                <Th>Version</Th>
                <Th className="text-right">Findings</Th>
                <Th>Error</Th>
              </tr>
            </thead>
            <tbody>
              {stages.map((s) => (
                <tr key={s.key}>
                  <Td>
                    <div className="font-medium">{s.label}</div>
                    {s.scanner && <div className="text-[11.5px] text-muted-foreground">engine: {s.scanner}</div>}
                  </Td>
                  <Td><Badge tone={tone[s.status] ?? "neutral"}>{s.status.replace("_", " ")}</Badge></Td>
                  <Td className="tabular whitespace-nowrap text-[12px]">{formatDateTime(s.started_at)}</Td>
                  <Td className="tabular whitespace-nowrap text-[12px]">{formatDateTime(s.finished_at)}</Td>
                  <Td className="tabular text-[12px]">{formatDuration(s.duration_ms)}</Td>
                  <Td className="font-mono text-[12px]">{s.scanner_version || "—"}</Td>
                  <Td className="tabular text-right">{s.findings ?? "—"}</Td>
                  <Td className="max-w-xs text-[12px] text-danger">{s.error || <span className="text-muted-foreground">—</span>}</Td>
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
                  <span className="font-semibold">{e.stage}{e.scanner && `:${e.scanner}`}</span>
                  <span className="text-muted-foreground">{e.status}</span>
                  <span className="min-w-0 flex-1 break-words">{e.message}</span>
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
