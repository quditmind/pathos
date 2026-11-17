import { lazy, Suspense } from "react";
import { Link } from "@tanstack/react-router";
import { Wrench } from "lucide-react";
import type { Kpi } from "@/api/types";
import { KpiCard } from "@/components/data/KpiCard";
import { SeverityBadge } from "@/components/data/Severity";
import { Alert, Card, EmptyState, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { qs, useOverview } from "./api";
import { useFilterNav } from "./QueuePage";
import { fmtHours, remediationLabel, ReviewFilterBar, ReviewKeyLink } from "./shared";

const OverviewCharts = lazy(() => import("./OverviewCharts"));

function kpi(key: string, label: string, value: number, drill: string, description: string, polarity: Kpi["polarity"] = "neutral"): Kpi {
  return { key, label, group: "human_review", description, unit: "count", polarity, drill, status: "ok", phase: 0, value, previous: null };
}

export function OverviewPage() {
  const { filters, setFilters, onChange } = useFilterNav("/human-review");
  const ov = useOverview(filters);
  const d = ov.data;
  const scope = { ...filters };
  delete scope.from;
  delete scope.to;
  const drill = (extra: Record<string, string>) => `/human-review/assessments?${qs({ ...scope, ...extra })}`;
  const period = filters.from || filters.to ? "the selected period" : "all time";
  return (
    <>
      <PageHeader title="Human Eye" description="Manual security assessment of findings: workload, outcomes and what is waiting for remediation." />
      <Card className="mb-4 p-3">
        <ReviewFilterBar
          values={filters}
          onChange={onChange}
          onReset={() => setFilters({})}
          show={["date", "repository", "application", "scanner", "severity", "reviewer", "status", "disposition"]}
        />
      </Card>
      {ov.isError && <Alert>Could not load the overview: {ov.error.message}</Alert>}
      {ov.isPending ? (
        <div className="grid grid-cols-2 gap-3 md:grid-cols-4">{Array.from({ length: 12 }, (_, i) => <Skeleton key={i} className="h-24" />)}</div>
      ) : d ? (
        <div className="space-y-4">
          <section aria-label="Key figures" className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-6">
            <KpiCard period={period} kpi={kpi("total", "Findings requiring review", d.metrics.total, drill({}), "Reviews matching the filters")} />
            <KpiCard period={period} kpi={kpi("pending", "Pending reviews", d.metrics.pending, drill({ status: "pending,assigned,reopened" }), "Not started yet (pending, assigned, reopened)")} />
            <KpiCard period={period} kpi={kpi("in_progress", "In progress", d.metrics.in_progress, drill({ status: "in_progress,awaiting_information,awaiting_independent_review" }), "Being investigated, waiting for information or for an independent reviewer")} />
            <KpiCard period={period} kpi={kpi("completed", "Completed", d.metrics.completed, drill({ status: "completed" }), "Reviews with a final disposition")} />
            <KpiCard period={period} kpi={kpi("confirmed", "Confirmed vulnerabilities", d.metrics.confirmed, drill({ status: "completed", disposition: "confirmed" }), "Completed with disposition Confirmed")} />
            <KpiCard period={period} kpi={kpi("fp", "False positives", d.metrics.false_positives, drill({ disposition: "false_positive" }), "Completed as false positive")} />
            <KpiCard period={period} kpi={kpi("dup", "Duplicates", d.metrics.duplicates, drill({ disposition: "duplicate" }), "Completed as duplicate")} />
            <KpiCard period={period} kpi={kpi("ne", "Not exploitable", d.metrics.not_exploitable, drill({ disposition: "not_exploitable" }), "Completed as not exploitable")} />
            <KpiCard period={period} kpi={kpi("ar", "Accepted risks", d.metrics.accepted_risks, drill({ disposition: "accepted_risk" }), "Completed as accepted risk")} />
            <KpiCard period={period} kpi={kpi("overdue", "Overdue reviews", d.metrics.overdue, drill({ overdue: "true" }), "Open reviews past their due date", "lower_is_better")} />
            <KpiCard period={period} kpi={kpi("second", "Awaiting independent review", d.metrics.awaiting_independent_review, drill({ status: "awaiting_independent_review" }), "Decisions waiting for a second reviewer")} />
            <Card className="flex flex-col p-4" title="Average time from queue to completion">
              <span className="text-[12px] font-medium text-muted-foreground">Avg. review completion time</span>
              <span className="tabular mt-2 text-2xl font-semibold tracking-tight">{fmtHours(d.metrics.avg_completion_hours)}</span>
            </Card>
          </section>
          <Suspense fallback={<Skeleton className="h-[420px]" />}>
            <OverviewCharts data={d} />
          </Suspense>
          <Card>
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <h2 className="text-[13px] font-semibold">Confirmed vulnerabilities awaiting remediation ({d.metrics.confirmed_awaiting_remediation})</h2>
              <Link to="/human-review/assessments" search={{ disposition: "confirmed", status: "completed" } as never} className="text-[12px] text-primary hover:underline">
                All confirmed →
              </Link>
            </div>
            {d.awaiting_remediation.length ? (
              <Table>
                <thead>
                  <tr>
                    <Th>Finding ID</Th>
                    <Th>Vulnerability</Th>
                    <Th>Severity</Th>
                    <Th>Repository</Th>
                    <Th>Remediation</Th>
                    <Th>Confirmed</Th>
                  </tr>
                </thead>
                <tbody>
                  {d.awaiting_remediation.map((r) => (
                    <tr key={r.id}>
                      <Td><ReviewKeyLink id={r.id} reviewKey={r.review_key} /></Td>
                      <Td><span className="block max-w-80 truncate" title={r.title}>{r.title}</span></Td>
                      <Td><SeverityBadge value={r.assessed_severity ?? r.severity} /></Td>
                      <Td className="text-[12px]">{r.repository_name}</Td>
                      <Td className="text-[12px]">{r.remediation_status ? remediationLabel[r.remediation_status] : "—"}</Td>
                      <Td className="tabular whitespace-nowrap text-[12px] text-muted-foreground">{formatDateTime(r.completed_at)}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            ) : (
              <EmptyState icon={<Wrench />} title="Nothing awaiting remediation" />
            )}
          </Card>
        </div>
      ) : null}
    </>
  );
}
