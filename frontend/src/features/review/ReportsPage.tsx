import { Download, FileText, Printer } from "lucide-react";
import { countsByKind } from "@/lib/checkKinds";
import { SeverityBadge } from "@/components/data/Severity";
import { Button } from "@/components/ui/button";
import { Card, EmptyState, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { exportUrl, useReport } from "./api";
import { useFilterNav } from "./QueuePage";
import { dispositionLabel, fmtHours, humanize, remediationLabel, ReviewFilterBar, ReviewKeyLink } from "./shared";
import type { Count, Disposition } from "./types";
import { ErrorPanel } from "@/components/ui/error-panel";

function Stat({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <Card className="p-4" title={hint}>
      <div className="text-[12px] font-medium text-muted-foreground">{label}</div>
      <div className="tabular mt-1 text-2xl font-semibold tracking-tight">{value}</div>
    </Card>
  );
}

function CountTable({ title, rows, label }: { title: string; rows: Count[]; label?: (c: Count) => string }) {
  const total = rows.reduce((n, r) => n + r.count, 0);
  return (
    <Card className="break-inside-avoid">
      <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">{title}</h2>
      {rows.length === 0 ? (
        <p className="px-4 py-3 text-[12.5px] text-muted-foreground">No data</p>
      ) : (
        <Table>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key}>
                <Td>{label ? label(r) : r.label || humanize(r.key)}</Td>
                <Td className="tabular w-20 text-right">{r.count}</Td>
                <Td className="tabular w-16 text-right text-muted-foreground">{total ? `${Math.round((100 * r.count) / total)}%` : ""}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

export function ReportsPage() {
  const { filters, setFilters, onChange } = useFilterNav("/human-review/reports");
  const { can } = useSession();
  const rep = useReport(filters);
  const r = rep.data;
  return (
    <>
      <PageHeader
        title="Review reports"
        description="Outcomes of reviews completed in the period (default: last 30 days)."
        actions={
          <>
            {can("findings.export") && (
              <Button variant="secondary" asChild>
                <a href={exportUrl(filters)} download>
                  <Download /> Export CSV
                </a>
              </Button>
            )}
            <Button variant="secondary" onClick={() => window.print()} title="Use your browser's print dialog to save as PDF">
              <Printer /> Print / PDF
            </Button>
          </>
        }
      />
      <Card className="mb-4 p-3 print:hidden">
        <ReviewFilterBar
          values={filters}
          onChange={onChange}
          onReset={() => setFilters({})}
          show={["date", "repository", "application", "scanner", "reviewer", "severity", "disposition"]}
        />
      </Card>
      {rep.isError && <ErrorPanel error={rep.error} title="Could not load the report" />}
      {rep.isPending ? (
        <Skeleton className="h-96" />
      ) : r ? (
        <div className="space-y-4">
          <p className="text-[12px] text-muted-foreground">
            Period: {new Date(r.from).toLocaleDateString()} – {new Date(new Date(r.to).getTime() - 1).toLocaleDateString()}
          </p>
          <section className="grid grid-cols-2 gap-3 md:grid-cols-4" aria-label="Summary">
            <Stat label="Findings reviewed" value={r.total_reviewed} />
            <Stat label="Confirmed vulnerabilities" value={r.confirmed} />
            <Stat label="False-positive rate" value={`${r.false_positive_pct}%`} hint={`${r.false_positives} false positives`} />
            <Stat label="Average review time" value={fmtHours(r.avg_review_hours)} />
            <Stat label="Overdue assessments (now)" value={r.overdue} />
            <Stat label="Severity raised" value={r.severity_raised} />
            <Stat label="Severity lowered" value={r.severity_lowered} />
            <Stat label="Confirmed awaiting remediation" value={r.confirmed_awaiting_remediation} />
          </section>
          {r.total_reviewed === 0 && <EmptyState icon={<FileText />} title="No reviews were completed in this period" />}
          <div className="grid gap-4 md:grid-cols-2">
            <CountTable title="Findings by severity" rows={r.by_severity} />
            <CountTable title="Final dispositions" rows={r.by_disposition} label={(c) => dispositionLabel[c.key as Disposition] ?? c.key} />
            <CountTable title="Findings by kind of check" rows={countsByKind(r.by_scanner)} label={(c) => c.label || c.key} />
            <CountTable title="Findings by repository" rows={r.by_repository} label={(c) => c.label || c.key} />
            <CountTable title="Independent review results" rows={r.independent_review_results} />
          </div>
          <Card className="break-inside-avoid">
            <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">Findings by analyst</h2>
            <Table>
              <thead>
                <tr>
                  <Th>Analyst</Th>
                  <Th className="text-right">Completed</Th>
                  <Th className="text-right">Average review time</Th>
                </tr>
              </thead>
              <tbody>
                {r.by_analyst.map((a) => (
                  <tr key={a.reviewer_id ?? "none"}>
                    <Td>{a.reviewer_id ? a.reviewer_name : "Unassigned"}</Td>
                    <Td className="tabular text-right">{a.completed}</Td>
                    <Td className="tabular text-right">{fmtHours(a.avg_completion_hours)}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card>
          <Card className="break-inside-avoid">
            <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">Severity adjustments</h2>
            {r.severity_adjustments.length === 0 ? (
              <p className="px-4 py-3 text-[12.5px] text-muted-foreground">No severity changes in this period.</p>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Finding ID</Th>
                    <Th>Vulnerability</Th>
                    <Th>Scanner</Th>
                    <Th>Assessed</Th>
                    <Th>Justification</Th>
                  </tr>
                </thead>
                <tbody>
                  {r.severity_adjustments.map((a) => (
                    <tr key={a.review_id}>
                      <Td><ReviewKeyLink id={a.review_id} reviewKey={a.review_key} /></Td>
                      <Td><span className="block max-w-64 truncate" title={a.title}>{a.title}</span></Td>
                      <Td><SeverityBadge value={a.original} /></Td>
                      <Td><SeverityBadge value={a.assessed} /></Td>
                      <Td className="max-w-80 text-[12px]">{a.justification}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
          <Card className="break-inside-avoid">
            <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">Confirmed findings awaiting remediation</h2>
            {r.awaiting_remediation.length === 0 ? (
              <p className="px-4 py-3 text-[12.5px] text-muted-foreground">None.</p>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Finding ID</Th>
                    <Th>Vulnerability</Th>
                    <Th>Severity</Th>
                    <Th>Repository</Th>
                    <Th>Remediation</Th>
                  </tr>
                </thead>
                <tbody>
                  {r.awaiting_remediation.map((x) => (
                    <tr key={x.id}>
                      <Td><ReviewKeyLink id={x.id} reviewKey={x.review_key} /></Td>
                      <Td><span className="block max-w-72 truncate" title={x.title}>{x.title}</span></Td>
                      <Td><SeverityBadge value={x.assessed_severity ?? x.severity} /></Td>
                      <Td className="text-[12px]">{x.repository_name}</Td>
                      <Td className="text-[12px]">{x.remediation_status ? remediationLabel[x.remediation_status] : "—"}</Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>
        </div>
      ) : null}
    </>
  );
}
