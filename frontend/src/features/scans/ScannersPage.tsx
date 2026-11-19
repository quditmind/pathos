import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { CircleDot, ExternalLink, Server, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import type { CatalogScanner } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, PageHeader, Select, Skeleton } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { useSession } from "@/features/auth/session";
import { categoryName } from "@/lib/findingCategories";
import { formatDateTime } from "@/lib/utils";
import { useCatalog, useScanMutation, useWorkers } from "./api";

const columns: Column<CatalogScanner>[] = [
  {
    id: "name",
    header: "Scanner",
    required: true,
    cell: (s) => (
      <div>
        <div className="flex items-center gap-1.5 font-medium">
          {s.name}
          {s.homepage && <a href={s.homepage} target="_blank" rel="noopener noreferrer" onClick={(e) => e.stopPropagation()} aria-label={`${s.name} homepage`}><ExternalLink className="size-3 text-muted-foreground" /></a>}
        </div>
        {s.notes && <div className="text-[12px] text-muted-foreground">{s.notes}</div>}
      </div>
    ),
    csv: (s) => s.name,
  },
  { id: "category", header: "Category", cell: (s) => <span className="text-[12px]">{categoryName(s.category)}</span>, csv: (s) => s.category },
  {
    id: "scan_types",
    header: "Scan types",
    cell: (s) => <span className="text-[12px]">{(s.scan_types ?? []).join(", ") || "—"}</span>,
    csv: (s) => (s.scan_types ?? []).join(" "),
  },
  { id: "license", header: "License", cell: (s) => <span className="font-mono text-[11.5px]">{s.license_spdx}</span>, csv: (s) => s.license_spdx },
  {
    id: "status",
    header: "Availability",
    cell: (s) =>
      s.runnable ? (
        <Badge tone="success">Runnable · {s.worker_family}</Badge>
      ) : s.adapter_available ? (
        <Badge tone="warning">Available · {s.worker_family} (no online worker)</Badge>
      ) : (
        <Badge>Planned · {s.worker_family} workers</Badge>
      ),
    csv: (s) => (s.runnable ? "runnable" : s.adapter_available ? "available" : "planned"),
  },
  {
    id: "decision",
    header: "Policy",
    cell: (s) => (
      <span className="flex flex-wrap gap-1">
        {s.mandatory && <Badge tone="primary">mandatory</Badge>}
        {s.decision === "restricted" && <Badge tone="danger">license-restricted</Badge>}
        {s.decision === "optional" && <Badge tone="warning">optional</Badge>}
        {s.requires_build && <Badge tone="warning">requires build</Badge>}
        {s.intrusive && <Badge tone="danger">intrusive</Badge>}
        {!s.intrusive && s.network === "target" && <Badge tone="warning">contacts target</Badge>}
      </span>
    ),
    csv: (s) => s.decision,
  },
];

export function ScannersPage() {
  const { canOrgWide } = useSession();
  const catalog = useCatalog();
  const workers = useWorkers();
  const [filter, setFilter] = useState("");
  const revoke = useScanMutation((id: string) => api(`/api/v1/workers/${id}/revoke`, { method: "POST" }));
  const del = useScanMutation((id: string) => api(`/api/v1/workers/${id}`, { method: "DELETE" }));
  const manage = canOrgWide("scanners.manage");
  const rows = (catalog.data ?? []).filter((s) =>
    !filter || (filter === "available" ? s.adapter_available : filter === "runnable" ? !!s.runnable : s.category === filter));
  const cats = [...new Set((catalog.data ?? []).map((s) => s.category))].sort();

  return (
    <>
      <PageHeader title="Scanners & workers" description="The scanner catalog and the isolated workers that execute scans. Workers never receive platform secrets or a Docker socket." />
      <h2 className="mb-2 text-[13px] font-semibold">Workers</h2>
      {(revoke.error ?? del.error) && <div className="mb-2"><Alert>{(revoke.error ?? del.error)!.message}</Alert></div>}
      {workers.isPending ? <Skeleton className="mb-6 h-20" /> : !workers.data?.length ? (
        <Card className="mb-6"><EmptyState icon={<Server />} title="No workers registered">Start one with <code>docker compose up -d worker-core</code>.</EmptyState></Card>
      ) : (
        <div className="mb-6 grid gap-3 lg:grid-cols-2">
          {workers.data.map((w) => (
            <Card key={w.id} className="p-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <div className="flex items-center gap-2 font-medium">
                    <CircleDot className={`size-3.5 ${w.revoked_at ? "text-danger" : w.online ? "text-success" : "text-muted-foreground"}`} />
                    {w.name}
                  </div>
                  <div className="text-[12px] text-muted-foreground">
                    {w.revoked_at ? `Revoked ${formatDateTime(w.revoked_at)}` : w.online ? `Online · ${w.active_jobs} running` : `Last seen ${formatDateTime(w.last_seen_at)}`} · {w.family} · agent {w.version}
                  </div>
                </div>
                {manage && (
                  <div className="flex gap-1">
                    {!w.revoked_at && <Button size="sm" variant="danger-outline" onClick={() => confirm(`Revoke ${w.name}? Its token stops working and it cannot re-register until deleted.`) && revoke.mutate(w.id)}>Revoke</Button>}
                    <Button size="icon" variant="ghost" aria-label={`Delete ${w.name}`} onClick={() => confirm(`Delete worker record ${w.name}?`) && del.mutate(w.id)}><Trash2 /></Button>
                  </div>
                )}
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {Object.entries(w.scanners).map(([k, v]) => <Badge key={k}>{k} {v}</Badge>)}
              </div>
            </Card>
          ))}
        </div>
      )}
      <h2 className="mb-2 flex items-center justify-between text-[13px] font-semibold">
        Scanner catalog
        <Link to="/configurations/scan-coverage" className="text-[12px] font-normal underline">Coverage by scan type</Link>
      </h2>
      <Card>
        <DataTable tableId="scanner-catalog" exportName="pathos-scanner-catalog" columns={columns} rows={rows} rowKey={(s) => s.key}
          isPending={catalog.isPending} error={catalog.error} empty={<EmptyState title="No scanners" />}
          toolbar={
            <Select aria-label="Filter scanners" value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="">All {catalog.data?.length ?? ""} integrations</option>
              <option value="runnable">Runnable on an online worker</option>
              <option value="available">Available in a worker image</option>
              {cats.map((c) => <option key={c} value={c}>{categoryName(c)}</option>)}
            </Select>
          } />
      </Card>
    </>
  );
}
