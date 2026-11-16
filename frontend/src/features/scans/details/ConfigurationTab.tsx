import type { ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { Lock } from "lucide-react";
import type { ScanJob } from "@/api/types";
import { Badge, Card, EmptyState, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";
import { formatDuration } from "../shared";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[minmax(0,180px)_1fr] gap-3 border-b border-border px-4 py-2 text-[13px] last:border-0">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </div>
  );
}

const yesNo = (v: boolean) => (v ? <Badge tone="primary">Yes</Badge> : <Badge>No</Badge>);

/** Read-only rendering of the immutable configuration snapshot. No edit controls. */
export function ConfigurationTab({ job }: { job: ScanJob }) {
  const c = job.config_snapshot;
  const used = job.results ?? [];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-border bg-surface-muted/50 px-3 py-2 text-[12.5px]" role="note">
        <Lock className="size-4 text-muted-foreground" aria-hidden />
        <span className="font-medium">Snapshot — read-only; profiles are managed in Configurations.</span>
        <Link to="/configurations/scan-profiles" className="text-primary hover:underline">
          Open {c?.profile_name ?? job.profile_name} in Configurations →
        </Link>
      </div>
      {!c ? (
        <Card>
          <EmptyState icon={<Lock />} title="No configuration snapshot">This execution was recorded before configuration snapshots were captured.</EmptyState>
        </Card>
      ) : (
        <>
          <Card>
            <h2 className="border-b border-border px-4 py-3 text-[13px] font-semibold">Profile</h2>
            <dl>
              <Row label="Profile">{c.profile_name} <span className="text-muted-foreground">v{c.profile_version}</span></Row>
              <Row label="Change note">{c.change_note || <span className="text-muted-foreground">—</span>}</Row>
              <Row label="Severity threshold"><span className="capitalize">{c.severity_threshold || "—"}</span></Row>
              <Row label="Timeout">{formatDuration(c.timeout_seconds * 1000)}</Row>
              <Row label="SBOM">{yesNo(c.sbom)}</Row>
              <Row label="Fail on critical">{yesNo(c.fail_on_critical)}</Row>
              <Row label="Retention">{c.retention_days} days</Row>
              <Row label="Exclusions">
                {c.exclusions.length ? (
                  <ul className="flex flex-wrap gap-1">
                    {c.exclusions.map((e) => <li key={e} className="rounded bg-surface-muted px-1.5 py-0.5 font-mono text-[11.5px]">{e}</li>)}
                  </ul>
                ) : (
                  <span className="text-muted-foreground">None</span>
                )}
              </Row>
              <Row label="Captured at">{formatDateTime(c.captured_at)}</Row>
            </dl>
          </Card>
          <Card>
            <h2 className="border-b border-border px-4 py-3 text-[13px] font-semibold">Scanners ({c.scanners.length})</h2>
            <ul className="divide-y divide-border">
              {c.scanners.map((s) => (
                <li key={s.key} className="px-4 py-2.5">
                  <div className="text-[13px] font-medium">{s.key}</div>
                  {s.config !== undefined && s.config !== null ? (
                    <pre aria-label={`${s.key} configuration`} className="mt-1.5 max-h-64 overflow-auto rounded-md bg-surface-muted/60 p-2.5 font-mono text-[11.5px]">
                      {JSON.stringify(s.config, null, 2)}
                    </pre>
                  ) : (
                    <div className="text-[12px] text-muted-foreground">Default configuration</div>
                  )}
                </li>
              ))}
            </ul>
          </Card>
        </>
      )}
      <Card>
        <h2 className="border-b border-border px-4 py-3 text-[13px] font-semibold">Scanner versions used</h2>
        {used.length ? (
          <Table>
            <thead><tr><Th>Engine</Th><Th>Version</Th><Th>Status</Th></tr></thead>
            <tbody>
              {used.map((r) => (
                <tr key={r.scanner_key}>
                  <Td className="font-medium">{r.scanner_key}</Td>
                  <Td className="font-mono text-[12px]">{r.scanner_version || "—"}</Td>
                  <Td className="text-[12px] capitalize">{r.status.replace("_", " ")}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        ) : (
          <p className="px-4 py-3 text-[13px] text-muted-foreground">No engine results yet.</p>
        )}
      </Card>
    </div>
  );
}
