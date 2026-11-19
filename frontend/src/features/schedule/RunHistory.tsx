import { Link } from "@tanstack/react-router";
import type { Schedule, ScheduleRun } from "@/api/types";
import { Dialog } from "@/components/ui/dialog";
import { Badge, Card, EmptyState, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { describeSchedule, useScheduleRuns } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

const runTone: Record<ScheduleRun["status"], "success" | "warning" | "danger" | "primary" | "neutral"> = {
  completed: "success",
  partial: "warning",
  failed: "danger",
  running: "primary",
  waiting: "neutral",
};

const triggerText: Record<string, string> = { schedule: "Scheduled", manual: "Manual", catch_up: "Catch-up" };

/** Run history drawer of one schedule. */
export function RunHistory({ schedule, onClose }: { schedule: Schedule | null; onClose: () => void }) {
  const runs = useScheduleRuns(schedule?.id);
  return (
    <Dialog side size="xl" open={!!schedule} onOpenChange={(o) => !o && onClose()} title={schedule ? `Run history: ${schedule.name}` : "Run history"}
      description={schedule ? describeSchedule(schedule) : undefined}>
      {schedule && (
        <div className="space-y-3 text-[13px]">
          <Link to="/scans" search={{ schedule_id: schedule.id } as never} className="inline-block text-primary hover:underline">
            View all executions of this schedule →
          </Link>
          {runs.isError ? <ErrorPanel error={runs.error} /> : runs.isPending ? <Skeleton className="h-40" /> : !runs.data.length ? (
            <EmptyState title="No runs yet">Runs appear here when the schedule fires or is run manually.</EmptyState>
          ) : (
            <Card>
              <Table>
                <thead>
                  <tr><Th>Due</Th><Th>Trigger</Th><Th>Status</Th><Th>Queued</Th><Th>Skipped</Th><Th>Failed</Th><Th>Pending</Th><Th>Executions</Th></tr>
                </thead>
                <tbody>
                  {runs.data.map((r) => (
                    <tr key={r.id}>
                      <Td className="whitespace-nowrap text-[12px]">
                        <div>{formatDateTime(r.due_at)}</div>
                        {r.finished_at && <div className="text-muted-foreground">finished {formatDateTime(r.finished_at)}</div>}
                      </Td>
                      <Td className="text-[12px]">{triggerText[r.trigger] ?? r.trigger}</Td>
                      <Td>
                        <Badge tone={runTone[r.status] ?? "neutral"}>{r.status}</Badge>
                        {r.message && <div className="mt-0.5 max-w-56 text-[11.5px] text-muted-foreground" title={r.message}>{r.message}</div>}
                      </Td>
                      <Td className="tabular">{r.queued}</Td>
                      <Td className="tabular">{r.skipped}</Td>
                      <Td className="tabular">{r.failed ? <span className="text-danger">{r.failed}</span> : 0}</Td>
                      <Td className="tabular">{r.pending}</Td>
                      <Td>
                        <div className="flex flex-wrap gap-1">
                          {Object.entries(r.jobs ?? {}).filter(([, n]) => n > 0).map(([st, n]) => (
                            <Badge key={st} tone={st === "failed" ? "danger" : st === "succeeded" ? "success" : st === "partial" ? "warning" : st === "running" ? "primary" : "neutral"}>
                              {st} {n}
                            </Badge>
                          ))}
                          {!Object.values(r.jobs ?? {}).some((n) => n > 0) && <span className="text-[12px] text-muted-foreground">—</span>}
                        </div>
                      </Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            </Card>
          )}
        </div>
      )}
    </Dialog>
  );
}
