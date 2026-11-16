import { lazy, Suspense } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { CalendarClock, Radar } from "lucide-react";
import type { Kpi, ScanJob } from "@/api/types";
import { Alert, Card, EmptyState, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { KpiCard } from "@/components/data/KpiCard";
import { JobStatusPill } from "@/components/data/Severity";
import { formatDateTime } from "@/lib/utils";
import { useScanOverview } from "../api";
import { ScanIdLink, ScanProgress } from "../shared";

const TrendChart = lazy(() => import("./TrendChart"));

export const periods = [7, 30, 90, 360] as const;
export type OverviewSearch = { days?: number };
export const validateOverviewSearch = (s: Record<string, unknown>): OverviewSearch => {
  const d = Number(s.days);
  return periods.includes(d as (typeof periods)[number]) ? { days: d } : {};
};

const kindLabel: Record<string, string> = { cron: "Recurring", once: "One-time", interval: "Interval" };

function kpi(key: string, label: string, value: number, drill: string, description: string, polarity: Kpi["polarity"] = "neutral"): Kpi {
  return { key, label, group: "scans", description, unit: "count", polarity, drill, status: "ok", phase: 0, value, previous: null };
}

function RecentTable({ rows }: { rows: ScanJob[] }) {
  if (!rows.length) return <EmptyState icon={<Radar />} title="No executions in this period" />;
  return (
    <Table>
      <thead>
        <tr>
          <Th>Scan ID</Th>
          <Th>Name</Th>
          <Th>Asset</Th>
          <Th>Status</Th>
          <Th>Progress</Th>
          <Th className="text-right">Findings</Th>
          <Th>Started</Th>
        </tr>
      </thead>
      <tbody>
        {rows.map((j) => (
          <tr key={j.id}>
            <Td><ScanIdLink job={j} /></Td>
            <Td className="text-[12.5px]">{j.name || <span className="text-muted-foreground">—</span>}</Td>
            <Td>
              <div className="max-w-56 truncate font-medium">{j.repository_name}</div>
              <div className="font-mono text-[11px] text-muted-foreground">{j.repository_key}</div>
            </Td>
            <Td><JobStatusPill status={j.status} /></Td>
            <Td><ScanProgress job={j} /></Td>
            <Td className="tabular text-right">{j.findings_total ?? 0}</Td>
            <Td className="tabular whitespace-nowrap text-[12px] text-muted-foreground">{formatDateTime(j.started_at ?? j.queued_at)}</Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

export function ScanOverviewPage() {
  const search = useSearch({ strict: false }) as OverviewSearch;
  const navigate = useNavigate();
  const days = search.days ?? 30;
  const ov = useScanOverview(days);
  const d = ov.data;
  const period = `${days} days`;

  return (
    <>
      <PageHeader
        title="Scan overview"
        description="Executions, outcomes and open findings across the repositories you can see."
        actions={
          <Select aria-label="Period" value={days} onChange={(e) => void navigate({ to: ".", search: { days: Number(e.target.value) } as never, replace: true })}>
            {periods.map((p) => (
              <option key={p} value={p}>Last {p} days</option>
            ))}
          </Select>
        }
      />
      {ov.isError && <Alert>Could not load the overview: {ov.error.message}</Alert>}
      {ov.isPending ? (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
          {Array.from({ length: 8 }, (_, i) => <Skeleton key={i} className="h-24" />)}
        </div>
      ) : d ? (
        <div className="space-y-4">
          <section aria-label="Key figures" className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <KpiCard period={period} kpi={kpi("total", "Total scans", d.scans.total, "/scans", `Executions queued in the last ${period}`)} />
            <KpiCard period={period} kpi={kpi("running", "Running", d.scans.running, "/scans?status=running", "Executions running now")} />
            <KpiCard period={period} kpi={kpi("queued", "Queued", d.scans.queued, "/scans?status=queued", "Executions waiting for a worker")} />
            <KpiCard period={period} kpi={kpi("completed", "Completed", d.scans.completed, "/scans?status=succeeded", "Executions finished in the period")} />
            <KpiCard period={period} kpi={kpi("failed", "Failed", d.scans.failed, "/scans?status=failed", "Executions that failed in the period", "lower_is_better")} />
            <KpiCard period={period} kpi={kpi("cancelled", "Cancelled", d.scans.cancelled, "/scans?status=cancelled", "Executions cancelled in the period")} />
            <KpiCard period={period} kpi={kpi("open_findings", "Open findings", d.open_findings_total, "/findings", "Open findings now", "lower_is_better")} />
            <KpiCard period={period} kpi={kpi("critical_high", "Critical + high", d.critical_high, "/findings?severity=critical", "Open critical and high findings", "lower_is_better")} />
          </section>

          <Card className="p-4">
            <h2 className="mb-2 text-[13px] font-semibold">Execution trend</h2>
            <Suspense fallback={<Skeleton className="h-[240px]" />}>
              <TrendChart trend={d.trend} />
            </Suspense>
          </Card>

          <div className="grid gap-4 lg:grid-cols-3">
            <Card className="lg:col-span-2">
              <div className="flex items-center justify-between border-b border-border px-4 py-3">
                <h2 className="text-[13px] font-semibold">Recent executions</h2>
                <Link to="/scans" className="text-[12px] text-primary hover:underline">All scans →</Link>
              </div>
              <RecentTable rows={d.recent} />
            </Card>
            <Card>
              <div className="flex items-center justify-between border-b border-border px-4 py-3">
                <h2 className="text-[13px] font-semibold">Upcoming scheduled scans</h2>
                <Link to="/scans/schedules" className="text-[12px] text-primary hover:underline">Schedules →</Link>
              </div>
              {d.upcoming.length ? (
                <ul className="divide-y divide-border">
                  {d.upcoming.map((u) => (
                    <li key={`${u.schedule_id}-${u.next_run_at}`} className="flex items-center gap-3 px-4 py-2.5 text-[13px]">
                      <CalendarClock className="size-4 shrink-0 text-muted-foreground" aria-hidden />
                      <div className="min-w-0 flex-1">
                        <Link to="/scans" search={{ schedule_id: u.schedule_id } as never} className="block truncate font-medium hover:underline">{u.name}</Link>
                        <div className="text-[11.5px] text-muted-foreground">{kindLabel[u.kind] ?? u.kind}</div>
                      </div>
                      <span className="tabular whitespace-nowrap text-[12px] text-muted-foreground">{formatDateTime(u.next_run_at)}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState icon={<CalendarClock />} title="Nothing scheduled">Active schedules show their next runs here.</EmptyState>
              )}
            </Card>
          </div>
        </div>
      ) : null}
    </>
  );
}
