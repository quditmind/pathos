import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Download, Radar, Server } from "lucide-react";
import type { ScanJob } from "@/api/types";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { between, duration, JobStatusPill } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { useScan, useScanMutation, useScans, useWorkers } from "./api";

export type ScanSearch = { status?: string; repository_id?: string; job?: string };
export const validateScanSearch = (s: Record<string, unknown>): ScanSearch => ({
  status: typeof s.status === "string" ? s.status : undefined,
  repository_id: typeof s.repository_id === "string" ? s.repository_id : undefined,
  job: typeof s.job === "string" ? s.job : undefined,
});

const columns: Column<ScanJob>[] = [
  {
    id: "repo",
    header: "Repository",
    required: true,
    cell: (j) => (
      <div>
        <div className="font-medium">{j.repository_name}</div>
        <div className="text-[12px] text-muted-foreground">
          {j.ref}
          {j.commit_sha && ` @ ${j.commit_sha.slice(0, 8)}`}
        </div>
      </div>
    ),
    csv: (j) => j.repository_name,
  },
  { id: "status", header: "Status", cell: (j) => <JobStatusPill status={j.status} />, csv: (j) => j.status },
  {
    id: "findings",
    header: "Findings",
    cell: (j) =>
      j.finished_at ? (
        <span className="tabular text-[12px]">
          <span className="text-danger">+{j.findings_new}</span> <span className="text-success">−{j.findings_fixed}</span>
          {j.gate_failed && <Badge tone="danger" className="ml-1.5">gate failed</Badge>}
        </span>
      ) : (
        "—"
      ),
    csv: (j) => `+${j.findings_new} -${j.findings_fixed}`,
  },
  { id: "trigger", header: "Trigger", cell: (j) => <span className="text-[12px] capitalize">{j.trigger}</span>, csv: (j) => j.trigger },
  { id: "profile", header: "Profile", cell: (j) => <span className="text-[12px]">{j.profile_name} v{j.profile_version}</span>, csv: (j) => `${j.profile_name} v${j.profile_version}` },
  { id: "queued", header: "Queued", className: "tabular text-[12px] text-muted-foreground", cell: (j) => formatDateTime(j.queued_at), csv: (j) => j.queued_at },
  { id: "duration", header: "Duration", className: "tabular text-[12px]", cell: (j) => between(j.started_at, j.finished_at), csv: (j) => between(j.started_at, j.finished_at) },
  { id: "worker", header: "Worker", defaultHidden: true, className: "text-[12px]", cell: (j) => j.worker_name ?? "—", csv: (j) => j.worker_name },
];

export function ScansPage() {
  const search = useSearch({ strict: false }) as ScanSearch;
  const navigate = useNavigate();
  const set = (n: Partial<ScanSearch>) => void navigate({ to: "/scans", search: { ...search, ...n } as never, replace: true });
  const scans = useScans({ status: search.status, repository_id: search.repository_id });
  const workers = useWorkers();
  const online = (workers.data ?? []).filter((w) => w.online).length;
  const rows = scans.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <>
      <PageHeader
        title="Scans"
        description="Scan jobs run by isolated workers. Scans are queued manually, from webhooks or by schedules."
        actions={
          <Link to="/admin/scanners" className="flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground">
            <Server className="size-4" />
            {workers.isPending ? "…" : online ? `${online} worker${online === 1 ? "" : "s"} online` : <span className="text-warning">No workers online</span>}
          </Link>
        }
      />
      <Card>
        <DataTable
          tableId="scans"
          exportName="pathos-scans"
          columns={columns}
          rows={rows}
          rowKey={(j) => j.id}
          isPending={scans.isPending}
          error={scans.error}
          hasMore={scans.hasNextPage}
          loadingMore={scans.isFetchingNextPage}
          onLoadMore={() => void scans.fetchNextPage()}
          onRowClick={(j) => set({ job: j.id })}
          empty={<EmptyState icon={<Radar />} title="No scans yet">Open a repository and choose “Scan now”, or select several repositories and scan them together.</EmptyState>}
          toolbar={
            <Select aria-label="Filter by status" value={search.status ?? ""} onChange={(e) => set({ status: e.target.value || undefined })}>
              <option value="">All statuses</option>
              <option value="active">Queued or running</option>
              {["succeeded", "partial", "failed", "cancelled"].map((s) => <option key={s} value={s}>{s[0]!.toUpperCase() + s.slice(1)}</option>)}
            </Select>
          }
        />
      </Card>
      <ScanDrawer id={search.job} onClose={() => set({ job: undefined })} />
    </>
  );
}

export function ScanDrawer({ id, onClose }: { id?: string; onClose: () => void }) {
  const { can } = useSession();
  const scan = useScan(id);
  const cancel = useScanMutation(() => api(`/api/v1/scans/${id}/cancel`, { method: "POST" }));
  const j = scan.data;
  return (
    <Dialog side open={!!id} onOpenChange={(o) => !o && onClose()} title={j?.repository_name ?? "Scan"}
      description={j ? `${j.ref}${j.commit_sha ? ` @ ${j.commit_sha.slice(0, 12)}` : ""} · ${j.profile_name} v${j.profile_version}` : undefined}
      footer={j && can("scans.run") && (j.status === "queued" || j.status === "running") ? (
        <Button variant="danger-outline" disabled={cancel.isPending} onClick={() => cancel.mutate(undefined)}>Cancel scan</Button>
      ) : undefined}>
      {!j ? <Skeleton className="h-40" /> : (
        <div className="space-y-5 text-[13px]">
          {cancel.isError && <Alert>{cancel.error.message}</Alert>}
          {j.error && <Alert tone={j.status === "partial" ? "warning" : "danger"}>{j.error}</Alert>}
          {j.gate_failed && <Alert>Security gate failed: new critical findings were introduced.</Alert>}
          <dl className="grid grid-cols-3 gap-3">
            <div><dt className="text-[12px] text-muted-foreground">Status</dt><dd className="mt-0.5"><JobStatusPill status={j.status} /></dd></div>
            <div><dt className="text-[12px] text-muted-foreground">New findings</dt><dd className="tabular mt-0.5 text-lg font-semibold">{j.findings_new}</dd></div>
            <div><dt className="text-[12px] text-muted-foreground">Fixed</dt><dd className="tabular mt-0.5 text-lg font-semibold">{j.findings_fixed}</dd></div>
            <div><dt className="text-[12px] text-muted-foreground">Trigger</dt><dd className="mt-0.5 capitalize">{j.trigger}</dd></div>
            <div><dt className="text-[12px] text-muted-foreground">Duration</dt><dd className="tabular mt-0.5">{between(j.started_at, j.finished_at)}</dd></div>
            <div><dt className="text-[12px] text-muted-foreground">Worker</dt><dd className="mt-0.5">{j.worker_name ?? "—"}</dd></div>
          </dl>
          <div>
            <h3 className="mb-2 text-[13px] font-semibold">Scanners</h3>
            {j.results?.length ? (
              <Card>
                <Table>
                  <thead><tr><Th>Scanner</Th><Th>Status</Th><Th>Findings</Th><Th>Time</Th><Th /></tr></thead>
                  <tbody>
                    {j.results.map((r) => (
                      <tr key={r.scanner_key}>
                        <Td>
                          <div className="font-medium">{r.scanner_key}</div>
                          <div className="text-[11px] text-muted-foreground">{r.scanner_version}</div>
                          {r.error && <div className="mt-0.5 max-w-64 text-[11px] text-danger">{r.error}</div>}
                        </Td>
                        <Td className="text-[12px] capitalize">{r.status.replace("_", " ")}</Td>
                        <Td className="tabular">{r.scanner_key === "syft" ? "SBOM" : r.findings_count}</Td>
                        <Td className="tabular text-[12px]">{duration(r.duration_ms)}</Td>
                        <Td>
                          {r.has_artifact && (
                            <a className="text-primary" href={`/api/v1/scans/${j.id}/results/${r.scanner_key}/artifact`} title="Download raw report" aria-label={`Download ${r.scanner_key} report`}>
                              <Download className="size-4" />
                            </a>
                          )}
                        </Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              </Card>
            ) : (
              <p className="text-muted-foreground">{j.status === "queued" ? "Waiting for a worker…" : j.status === "running" ? "Scanning…" : "No scanner results."}</p>
            )}
          </div>
          {j.finished_at && (
            <Link to="/findings" search={{ repository_id: j.repository_id } as never} className="inline-block text-primary hover:underline">
              View findings for this repository →
            </Link>
          )}
          <p className="text-[12px] text-muted-foreground">Queued {formatDateTime(j.queued_at)}{j.requested_by && ` by ${j.requested_by}`} · attempt {j.attempts}</p>
        </div>
      )}
    </Dialog>
  );
}
