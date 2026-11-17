import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { Download } from "lucide-react";
import type { ScanJob } from "@/api/types";
import { Alert, Badge, Card, Table, Td, Th } from "@/components/ui/primitives";
import { JobStatusPill, SeverityBadge, duration } from "@/components/data/Severity";
import { formatDateTime } from "@/lib/utils";
import { jobDuration, ScanProgress, severities, triggerLabel } from "../shared";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-[12px] text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 break-words text-[13px]">{children}</dd>
    </div>
  );
}

export function OverviewTab({ job: j }: { job: ScanJob }) {
  return (
    <div className="space-y-4">
      {j.error && <Alert tone={j.status === "partial" ? "warning" : "danger"}>{j.error}</Alert>}
      {j.gate_failed && <Alert>Security gate failed: new critical findings were introduced.</Alert>}

      <Card className="p-4">
        <div className="mb-4 flex flex-wrap items-center gap-4">
          <JobStatusPill status={j.status} />
          <ScanProgress job={j} className="max-w-md flex-1" />
        </div>
        <dl className="grid grid-cols-2 gap-x-6 gap-y-3 md:grid-cols-3 lg:grid-cols-4">
          <Field label="Scan ID"><span className="font-mono">{j.scan_key}</span></Field>
          <Field label="Asset">
            <Link to="/repositories" search={{ repo: j.repository_id } as never} className="font-medium text-primary hover:underline">{j.repository_name}</Link>
            <div className="font-mono text-[11.5px] text-muted-foreground">{j.repository_key}</div>
          </Field>
          <Field label="Asset type"><span className="capitalize">{j.asset_type || "repository"}</span></Field>
          {j.target_name && (
            <Field label="Scan target">
              <Link to="/scans/targets" className="text-primary hover:underline">{j.target_name}</Link>
              <div className="break-all font-mono text-[11.5px] text-muted-foreground">{j.target_reference}</div>
            </Field>
          )}
          <Field label="Scan profile">
            {j.profile_id ? (
              <Link to="/configurations/scan-profiles" className="text-primary hover:underline">{j.profile_name}</Link>
            ) : (
              j.profile_name
            )}{" "}
            <span className="text-muted-foreground">v{j.profile_version}</span>
          </Field>
          <Field label="Trigger">{triggerLabel[j.trigger] ?? j.trigger}{j.requested_by && <span className="text-muted-foreground"> · {j.requested_by}</span>}</Field>
          <Field label="Schedule">
            {j.schedule_id ? <Link to="/scans" search={{ schedule_id: j.schedule_id } as never} className="text-primary hover:underline">Executions of this schedule</Link> : "—"}
          </Field>
          <Field label="Retry of">
            {j.retry_of ? <Link to="/scans/$id" params={{ id: j.retry_of }} className="text-primary hover:underline">Previous execution</Link> : "—"}
            {j.retry_count > 0 && <span className="ml-1 text-muted-foreground">(retry #{j.retry_count})</span>}
          </Field>
          <Field label="Ref">{j.ref || "—"}</Field>
          <Field label={j.commit_sha ? "Commit SHA" : "Snapshot"}>
            <span className="font-mono text-[12px]">{j.commit_sha || j.snapshot_id || "—"}</span>
          </Field>
          <Field label="Worker">{j.worker_name ?? "—"}</Field>
          <Field label="Queued">{formatDateTime(j.queued_at)}</Field>
          <Field label="Started">{formatDateTime(j.started_at)}</Field>
          <Field label="Finished">{formatDateTime(j.finished_at)}</Field>
          <Field label="Duration">{jobDuration(j)}</Field>
          <Field label="Attempts">{j.attempts}</Field>
        </dl>
      </Card>

      <Card className="p-4">
        <h2 className="mb-3 text-[13px] font-semibold">Findings summary</h2>
        <div className="flex flex-wrap items-end gap-6">
          <div>
            <div className="text-[12px] text-muted-foreground">Total</div>
            <div className="tabular text-2xl font-semibold">{j.findings_total ?? 0}</div>
          </div>
          {severities.map((s) => (
            <div key={s}>
              <SeverityBadge value={s} />
              <div className="tabular mt-1 text-lg font-semibold">{j.severity?.[s] ?? 0}</div>
            </div>
          ))}
          <div>
            <div className="text-[12px] text-muted-foreground">New</div>
            <div className="tabular text-lg font-semibold text-danger">{j.findings_new}</div>
          </div>
          <div>
            <div className="text-[12px] text-muted-foreground">Fixed</div>
            <div className="tabular text-lg font-semibold text-success">{j.findings_fixed}</div>
          </div>
        </div>
      </Card>

      {!!j.results?.length && (
        <Card>
          <h2 className="border-b border-border px-4 py-3 text-[13px] font-semibold">Scanner engines</h2>
          <Table>
            <thead>
              <tr><Th>Engine</Th><Th>Version</Th><Th>Status</Th><Th className="text-right">Findings</Th><Th>Duration</Th><Th><span className="sr-only">Report</span></Th></tr>
            </thead>
            <tbody>
              {j.results.map((r) => (
                <tr key={r.scanner_key}>
                  <Td className="font-medium">{r.scanner_key}{r.error && <div className="max-w-md text-[11.5px] font-normal text-danger">{r.error}</div>}</Td>
                  <Td className="font-mono text-[12px]">{r.scanner_version || "—"}</Td>
                  <Td><Badge tone={r.status === "succeeded" ? "success" : r.status === "skipped" ? "neutral" : "danger"}>{r.status.replace("_", " ")}</Badge></Td>
                  <Td className="tabular text-right">{r.scanner_key === "syft" ? "SBOM" : r.findings_count}</Td>
                  <Td className="tabular text-[12px]">{duration(r.duration_ms)}</Td>
                  <Td>
                    {r.has_artifact && (
                      <a className="text-primary" href={`/api/v1/scans/${j.id}/results/${r.scanner_key}/artifact`} aria-label={`Download ${r.scanner_key} report`} title="Download raw report">
                        <Download className="size-4" />
                      </a>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
    </div>
  );
}
