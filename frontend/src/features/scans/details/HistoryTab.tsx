import { useState } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { GitCompareArrows, History } from "lucide-react";
import type { ScanJob } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Badge, Card, EmptyState, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { JobStatusPill } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { useScanHistory } from "../api";
import { jobDuration, ScanIdLink, SeverityBar } from "../shared";
import { ErrorPanel } from "@/components/ui/error-panel";

export const MIN_COMPARE = 2;
export const MAX_COMPARE = 10;

/** Previous executions of the same asset (last 360 days) with comparison shortcuts. */
export function HistoryTab({ job }: { job: ScanJob }) {
  const { can } = useSession();
  const navigate = useNavigate();
  const history = useScanHistory(job.id);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const canCompare = can("scans.compare");
  const compare = (ids: string[]) => void navigate({ to: "/scans/compare", search: { ids: ids.join(",") } as never });

  if (history.isError) return <ErrorPanel error={history.error} title="Could not load history" />;
  if (history.isPending) return <Skeleton className="h-48" />;
  const rows = history.data;
  if (!rows.length) return <Card><EmptyState icon={<History />} title="No other executions">This asset has no executions in the last 360 days.</EmptyState></Card>;

  const toggle = (id: string) => {
    const n = new Set(sel);
    if (n.has(id)) n.delete(id);
    else if (n.size < MAX_COMPARE) n.add(id);
    setSel(n);
  };

  return (
    <Card>
      {canCompare && (
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3 text-[12px] text-muted-foreground">
          <span className="tabular">{sel.size} of {MAX_COMPARE} selected</span>
          {sel.size > 0 && sel.size < MIN_COMPARE && <span>Select at least {MIN_COMPARE} executions to compare.</span>}
          <Button size="sm" className="ml-auto" disabled={sel.size < MIN_COMPARE || sel.size > MAX_COMPARE} onClick={() => compare([...sel])}>
            <GitCompareArrows /> Compare selected
          </Button>
        </div>
      )}
      <Table>
        <thead>
          <tr>
            {canCompare && <Th className="w-8"><span className="sr-only">Select</span></Th>}
            <Th>Scan ID</Th>
            <Th>Status</Th>
            <Th className="text-right">Findings</Th>
            <Th>Severity</Th>
            <Th>Profile</Th>
            <Th>Duration</Th>
            <Th>Date</Th>
            {canCompare && <Th><span className="sr-only">Actions</span></Th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((h) => {
            const current = h.id === job.id;
            return (
              <tr key={h.id} className={current ? "bg-primary/5" : undefined}>
                {canCompare && (
                  <Td className="w-8">
                    <input
                      type="checkbox"
                      className="size-3.5 accent-[var(--primary)]"
                      aria-label={`Select ${h.scan_key}`}
                      checked={sel.has(h.id)}
                      disabled={!sel.has(h.id) && sel.size >= MAX_COMPARE}
                      onChange={() => toggle(h.id)}
                    />
                  </Td>
                )}
                <Td>
                  <ScanIdLink job={h} />
                  {current && <Badge tone="primary" className="ml-1.5">this scan</Badge>}
                </Td>
                <Td><JobStatusPill status={h.status} /></Td>
                <Td className="tabular text-right">{h.findings_total ?? 0}</Td>
                <Td><SeverityBar severity={h.severity} /></Td>
                <Td className="whitespace-nowrap text-[12px]">{h.profile_name} <span className="text-muted-foreground">v{h.profile_version}</span></Td>
                <Td className="tabular text-[12px]">{jobDuration(h)}</Td>
                <Td className="tabular whitespace-nowrap text-[12px] text-muted-foreground">{formatDateTime(h.started_at ?? h.queued_at)}</Td>
                {canCompare && (
                  <Td className="text-right">
                    {!current && (
                      <Link to="/scans/compare" search={{ ids: `${h.id},${job.id}` } as never} className="whitespace-nowrap text-[12px] text-primary hover:underline">
                        Compare with this scan
                      </Link>
                    )}
                  </Td>
                )}
              </tr>
            );
          })}
        </tbody>
      </Table>
    </Card>
  );
}
