import { lazy, Suspense, useState, type ReactNode } from "react";
import { Info } from "lucide-react";
import type { Severity } from "@/api/types";
import { Badge, Card, Select, Skeleton } from "@/components/ui/primitives";
import { JobStatusPill, SeverityBadge } from "@/components/data/Severity";
import { cn, formatDateTime } from "@/lib/utils";
import { useScanComparison } from "../api";
import { formatDuration, ScanIdLink, severities } from "../shared";
import { filterFindings, MATRIX_LIMIT, signedDuration, stateMeta, stateOf, states, type ComparedScan, type FindingState } from "./model";
import { ErrorPanel } from "@/components/ui/error-panel";

const CompareCharts = lazy(() => import("./Charts"));

export function StateChip({ state }: { state: FindingState }) {
  const m = stateMeta[state];
  return (
    <span title={m.description} className={cn("inline-flex whitespace-nowrap rounded px-1.5 py-0.5 text-[11px] font-medium", m.cls)}>
      {state === "absent" ? "—" : m.label}
      {state === "absent" && <span className="sr-only">{m.label}</span>}
    </span>
  );
}

type Metric = { label: string; cell: (s: ComparedScan) => ReactNode };

const sevCell = (k: Severity) => (s: ComparedScan) => <span className="tabular">{s.severity?.[k] ?? 0}</span>;

const metrics: Metric[] = [
  { label: "Date", cell: (s) => <span className="whitespace-nowrap text-[12px]">{formatDateTime(s.started_at ?? s.queued_at)}</span> },
  { label: "Asset", cell: (s) => <span className="text-[12px]">{s.repository_name}</span> },
  {
    label: "Status",
    cell: (s) => (
      <div className="flex flex-wrap items-center gap-1">
        <JobStatusPill status={s.status} />
        {!s.complete && <Badge tone="warning">incomplete</Badge>}
      </div>
    ),
  },
  { label: "Total findings", cell: (s) => <span className="tabular font-semibold">{s.findings_total ?? 0}</span> },
  { label: "Critical", cell: sevCell("critical") },
  { label: "High", cell: sevCell("high") },
  { label: "Medium", cell: sevCell("medium") },
  { label: "Low", cell: sevCell("low") },
  { label: "New", cell: (s) => <span className="tabular text-danger">{s.new}</span> },
  { label: "Fixed", cell: (s) => <span className="tabular text-success">{s.fixed}</span> },
  { label: "Recurring", cell: (s) => <span className="tabular">{s.recurring}</span> },
  { label: "Unchanged", cell: (s) => <span className="tabular">{s.unchanged}</span> },
  { label: "Not covered", cell: (s) => <span className={cn("tabular", s.not_covered > 0 && "text-warning")}>{s.not_covered}</span> },
  {
    label: "Duration",
    cell: (s) => (
      <span className="tabular whitespace-nowrap text-[12px]">
        {formatDuration(s.duration_ms)}
        {s.duration_delta_ms != null && <span className="ml-1 text-muted-foreground">({signedDuration(s.duration_delta_ms, formatDuration)})</span>}
      </span>
    ),
  },
  {
    label: "Scan profile",
    cell: (s) => (
      <div className="text-[12px]">
        {s.profile_name} v{s.profile_version}
        {s.profile_changed && <Badge tone="primary" className="ml-1">Profile changed</Badge>}
      </div>
    ),
  },
  {
    label: "Engine changes",
    cell: (s) =>
      s.engine_changes?.length ? (
        <ul className="list-disc space-y-0.5 pl-4 text-[12px]">{s.engine_changes.map((c) => <li key={c}>{c}</li>)}</ul>
      ) : (
        <span className="text-[12px] text-muted-foreground">—</span>
      ),
  },
];

/** Side-by-side comparison of 2–10 executions (GET /scans/compare). */
export function ComparisonView({ ids }: { ids: string[] }) {
  const cmp = useScanComparison(ids);
  const [state, setState] = useState("");
  const [severity, setSeverity] = useState("");

  if (cmp.isError) return <ErrorPanel error={cmp.error} title="Could not compare these executions" />;
  if (cmp.isPending) return <div className="space-y-3"><Skeleton className="h-64" /><Skeleton className="h-48" /></div>;
  const { scans, findings } = cmp.data;
  const shown = filterFindings(findings, { state, severity });

  return (
    <div className="space-y-4">
      <Card>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-[13px]" aria-label="Per-scan comparison">
            <thead>
              <tr>
                <th scope="col" className="sticky left-0 border-b border-border bg-surface-muted px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Scan ID</th>
                {scans.map((s) => (
                  <th key={s.id} scope="col" className="border-b border-border bg-surface-muted/60 px-3 py-2">
                    <ScanIdLink job={s} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {metrics.map((m) => (
                <tr key={m.label}>
                  <th scope="row" className="sticky left-0 whitespace-nowrap border-b border-border bg-surface px-3 py-2 text-[12px] font-medium text-muted-foreground">{m.label}</th>
                  {scans.map((s) => <td key={s.id} className="border-b border-border px-3 py-2 align-top">{m.cell(s)}</td>)}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="flex gap-2 p-3 text-[12px] text-muted-foreground" role="note">
          <Info className="mt-px size-4 shrink-0" aria-hidden />
          <p>
            Each scan is compared with the previous one (chronological order). A finding is counted as <strong className="text-success">fixed</strong> only when the later
            scan completed with the scanner that covers it; if that scan failed or the covering scanner did not succeed, the finding is reported as{" "}
            <strong className="text-warning">not covered</strong> instead.
          </p>
        </div>
      </Card>

      <Suspense fallback={<Skeleton className="h-64" />}>
        <CompareCharts scans={scans} />
      </Suspense>

      <Card>
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-3">
          <h2 className="mr-auto text-[13px] font-semibold">Finding matrix</h2>
          <Select aria-label="Filter by state" value={state} onChange={(e) => setState(e.target.value)}>
            <option value="">All states</option>
            {states.filter((s) => s !== "absent").map((s) => <option key={s} value={s}>{stateMeta[s].label}</option>)}
          </Select>
          <Select aria-label="Filter by severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All severities</option>
            {severities.map((s) => <option key={s} value={s}>{s[0]!.toUpperCase() + s.slice(1)}</option>)}
          </Select>
        </div>
        <div className="flex flex-wrap gap-2 border-b border-border px-3 py-2" aria-label="Legend">
          {states.map((s) => (
            <span key={s} className="flex items-center gap-1 text-[11.5px] text-muted-foreground">
              <StateChip state={s} /> {s === "absent" && "Absent"}
            </span>
          ))}
        </div>
        {findings.length === 0 ? (
          <p className="px-3 py-10 text-center text-[13px] text-muted-foreground">None of the selected executions reported findings.</p>
        ) : shown.length === 0 ? (
          <p className="px-3 py-10 text-center text-[13px] text-muted-foreground">No findings match these filters.</p>
        ) : (
          <>
            <div className="max-h-[70vh] overflow-auto">
              <table className="w-full border-collapse text-left text-[13px]" aria-label="Finding matrix">
                <thead className="sticky top-0 z-10">
                  <tr>
                    <th scope="col" className="border-b border-border bg-surface-muted px-3 py-2 text-[11px] font-semibold uppercase tracking-wide text-muted-foreground">Finding</th>
                    {scans.map((s) => (
                      <th key={s.id} scope="col" className="whitespace-nowrap border-b border-border bg-surface-muted px-3 py-2 font-mono text-[11px] font-medium">
                        {s.scan_key || s.id.slice(0, 8)}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {shown.slice(0, MATRIX_LIMIT).map((f) => (
                    <tr key={f.id}>
                      <td className="border-b border-border px-3 py-2">
                        <div className="flex items-center gap-2">
                          <SeverityBadge value={f.severity} />
                          <span className="max-w-md truncate font-medium" title={f.title}>{f.title}</span>
                        </div>
                        {f.scanners.length > 0 && <div className="mt-0.5 text-[11.5px] text-muted-foreground">{f.scanners.join(", ")}</div>}
                      </td>
                      {scans.map((s) => (
                        <td key={s.id} className="border-b border-border px-3 py-2">
                          <StateChip state={stateOf(f.states[s.id])} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="tabular border-t border-border px-3 py-2 text-[11.5px] text-muted-foreground">
              {shown.length > MATRIX_LIMIT ? `Showing first ${MATRIX_LIMIT} of ${shown.length} findings — narrow the filters to see the rest.` : `${shown.length} finding${shown.length === 1 ? "" : "s"}`}
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
