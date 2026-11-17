import { useEffect, useState } from "react";
import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { ExternalLink, Play, Radar, RotateCcw, Search, Server, Square } from "lucide-react";
import { api } from "@/api/client";
import type { Page, Repository, ScanJob } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Combobox, type ComboOption } from "@/components/ui/combobox";
import { Alert, Card, EmptyState, Input, PageHeader } from "@/components/ui/primitives";
import { DataTable, type Column } from "@/components/data/DataTable";
import { FilterBar, type FilterDef } from "@/components/data/FilterBar";
import { JobStatusPill } from "@/components/data/Severity";
import { useSession } from "@/features/auth/session";
import { useRepository } from "@/features/repos/api";
import { useSchedules } from "@/features/schedule/api";
import { useDebounced } from "@/lib/useDebounced";
import { formatDateTime } from "@/lib/utils";
import { cancelScan, isActive, retryScan, useCatalog, useProfiles, useScanMutation, useScans, useWorkers, type ScanListFilters } from "./api";
import { jobDuration, ScanIdLink, ScanProgress, SeverityBar, statusOptions, triggerLabel } from "./shared";
import { StartScanDialog } from "./StartScanDialog";

const filterKeys = ["q", "status", "profile_id", "trigger", "scanner", "from", "to", "schedule_id", "repository_id", "repository_key", "asset_type"] as const;
export type ScanSearch = ScanListFilters & { start?: string; job?: string };

export const validateScanSearch = (s: Record<string, unknown>): ScanSearch => {
  const out: ScanSearch = {};
  for (const k of [...filterKeys, "start", "job"] as const) if (typeof s[k] === "string" && s[k]) out[k] = (s[k] as string).slice(0, 200);
  if (s.start === 1 || s.start === true) out.start = "1";
  return out;
};

const retryable = (j: ScanJob) => j.status === "failed" || j.status === "partial" || j.status === "cancelled";

export function scanColumns(actions?: (j: ScanJob) => React.ReactNode): Column<ScanJob>[] {
  const cols: Column<ScanJob>[] = [
    { id: "scan_key", header: "Scan ID", required: true, cell: (j) => <ScanIdLink job={j} />, csv: (j) => j.scan_key },
    { id: "name", header: "Scan name", cell: (j) => <span className="text-[12.5px]">{j.name || <span className="text-muted-foreground">—</span>}</span>, csv: (j) => j.name },
    {
      id: "asset",
      header: "Asset",
      required: true,
      cell: (j) => (
        <div className="min-w-0">
          <div className="max-w-64 truncate font-medium" title={j.repository_name}>{j.repository_name}</div>
          <div className="font-mono text-[11px] text-muted-foreground">{j.repository_key || "—"}</div>
        </div>
      ),
      csv: (j) => j.repository_name,
    },
    { id: "repository_key", header: "Repository ID", defaultHidden: true, exportAlways: true, className: "font-mono text-[12px]", cell: (j) => j.repository_key || "—", csv: (j) => j.repository_key },
    { id: "asset_type", header: "Asset type", className: "text-[12px] capitalize", cell: (j) => (j.target_name ? <span title={j.target_reference ?? undefined}>{j.asset_type} · {j.target_name}</span> : j.asset_type || "repository"), csv: (j) => j.asset_type || "repository" },
    {
      id: "profile",
      header: "Scan profile",
      cell: (j) => (
        <span className="whitespace-nowrap text-[12px]">
          {j.profile_name} <span className="text-muted-foreground">v{j.profile_version}</span>
        </span>
      ),
      csv: (j) => `${j.profile_name} v${j.profile_version}`,
    },
    { id: "status", header: "Execution status", cell: (j) => <JobStatusPill status={j.status} />, csv: (j) => j.status },
    { id: "progress", header: "Progress", cell: (j) => <ScanProgress job={j} />, csv: (j) => j.progress },
    { id: "findings", header: "Findings", className: "tabular text-right", cell: (j) => j.findings_total ?? 0, csv: (j) => j.findings_total },
    { id: "severity", header: "Severity", cell: (j) => <SeverityBar severity={j.severity} />, csv: (j) => (j.severity ? Object.entries(j.severity).map(([k, v]) => `${k}:${v}`).join(" ") : "") },
    { id: "started", header: "Started at", className: "tabular whitespace-nowrap text-[12px] text-muted-foreground", cell: (j) => (j.started_at ? formatDateTime(j.started_at) : <span title={`Queued ${formatDateTime(j.queued_at)}`}>—</span>), csv: (j) => j.started_at },
    { id: "duration", header: "Duration", className: "tabular whitespace-nowrap text-[12px]", cell: (j) => jobDuration(j), csv: (j) => j.duration_ms },
    { id: "trigger", header: "Trigger source", className: "whitespace-nowrap text-[12px]", cell: (j) => triggerLabel[j.trigger] ?? j.trigger, csv: (j) => j.trigger },
    { id: "worker", header: "Worker", defaultHidden: true, className: "text-[12px]", cell: (j) => j.worker_name ?? "—", csv: (j) => j.worker_name },
  ];
  if (actions) cols.push({ id: "actions", header: "Actions", required: true, cell: actions });
  return cols;
}

/** Repository filter: server-side search showing name + Repository ID. */
function RepositoryFilter({ id, onChange }: { id?: string; onChange: (id: string | undefined) => void }) {
  const [picked, setPicked] = useState<ComboOption | null>(null);
  const repo = useRepository(id && picked?.value !== id ? id : undefined);
  const value = id ? (picked?.value === id ? picked : { value: id, label: repo.data?.full_name ?? "Selected repository" }) : null;
  return (
    <Combobox
      ariaLabel="Filter by repository"
      className="w-56"
      placeholder="Repository…"
      queryKey="scan-filter-repo"
      value={value}
      load={(q, signal) => {
        const p = new URLSearchParams({ limit: "20" });
        if (q) p.set("q", q);
        return api<Page<Repository>>(`/api/v1/repositories?${p}`, { signal }).then((r) => r.items.map((x) => ({ value: x.id, label: x.full_name, description: x.repository_key })));
      }}
      onChange={(o) => {
        setPicked(o);
        onChange(o?.value);
      }}
    />
  );
}

export function ScansPage() {
  const search = useSearch({ strict: false }) as ScanSearch;
  const navigate = useNavigate();
  const { can } = useSession();
  const set = (n: Partial<ScanSearch>) => void navigate({ to: "/scans", search: { ...search, ...n } as never, replace: true });

  // Legacy links (/scans?job=…) open the execution details.
  useEffect(() => {
    if (search.job) void navigate({ to: "/scans/$id", params: { id: search.job }, replace: true });
  }, [search.job, navigate]);

  const [q, setQ] = useState(search.q ?? "");
  const dq = useDebounced(q.trim(), 300);
  useEffect(() => setQ(search.q ?? ""), [search.q]);
  useEffect(() => {
    if ((dq || undefined) !== search.q) set({ q: dq || undefined });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dq]);

  const filters: ScanListFilters = {};
  for (const k of filterKeys) if (search[k]) filters[k] = search[k];
  const scans = useScans(filters, true, 5000);
  const rows = scans.data?.pages.flatMap((p) => p.items) ?? [];

  const workers = useWorkers();
  const profiles = useProfiles();
  const catalog = useCatalog();
  const schedules = useSchedules();
  const online = (workers.data ?? []).filter((w) => w.online).length;

  const cancel = useScanMutation(cancelScan);
  const retry = useScanMutation(retryScan);
  const mutError = cancel.error ?? retry.error;

  const filterDefs: FilterDef[] = [
    { key: "status", label: "Execution status", allLabel: "All statuses", options: statusOptions },
    { key: "profile_id", label: "Scan profile", allLabel: "All profiles", options: (profiles.data ?? []).map((p) => ({ value: p.id, label: p.name })) },
    { key: "trigger", label: "Trigger source", allLabel: "All triggers", options: Object.entries(triggerLabel).map(([value, label]) => ({ value, label })) },
    { key: "scanner", label: "Scanner", allLabel: "All scanners", options: (catalog.data ?? []).map((s) => ({ value: s.key, label: s.name })) },
    { key: "schedule_id", label: "Schedule", allLabel: "All schedules", options: (schedules.data ?? []).map((s) => ({ value: s.id, label: s.name })) },
    { key: "asset_type", label: "Asset type", allLabel: "All asset types", options: [{ value: "repository", label: "Repository" }, { value: "image", label: "Container image" }, { value: "url", label: "Web application" }, { value: "api", label: "API" }, { value: "sbom", label: "SBOM" }] },
  ];

  const actions = (j: ScanJob) => (
    <div className="flex justify-end gap-1" onClick={(e) => e.stopPropagation()}>
      <Button asChild size="sm" variant="ghost" aria-label={`Open ${j.scan_key}`} title="Open">
        <Link to="/scans/$id" params={{ id: j.id }}><ExternalLink /></Link>
      </Button>
      {can("scans.run") && isActive(j) && (
        <Button size="sm" variant="ghost" className="text-danger" aria-label={`Cancel ${j.scan_key}`} title="Cancel" disabled={cancel.isPending} onClick={() => cancel.mutate(j.id)}>
          <Square />
        </Button>
      )}
      {can("scans.run") && retryable(j) && (
        <Button size="sm" variant="ghost" aria-label={`Retry ${j.scan_key}`} title="Retry" disabled={retry.isPending} onClick={() => retry.mutate(j.id)}>
          <RotateCcw />
        </Button>
      )}
    </div>
  );

  const anyFilter = filterKeys.some((k) => search[k]);

  return (
    <>
      <PageHeader
        title="Scans"
        description="Every scan execution with its permanent Scan ID, progress, findings and trigger. Executions are queued manually, by webhooks or by schedules."
        actions={
          <>
            <Link to="/configurations/scanners" className="flex items-center gap-1.5 text-[12px] text-muted-foreground hover:text-foreground">
              <Server className="size-4" />
              {workers.isPending ? "…" : online ? `${online} worker${online === 1 ? "" : "s"} online` : <span className="text-warning">No workers online</span>}
            </Link>
            {can("scans.run") && (
              <Button onClick={() => set({ start: "1" })}>
                <Play /> Start scan
              </Button>
            )}
          </>
        }
      />
      {mutError && <div className="mb-3"><Alert>{mutError.message}</Alert></div>}
      <Card>
        <DataTable
          tableId="scans-v3"
          exportName="pathos-scans"
          columns={scanColumns(actions)}
          rows={rows}
          rowKey={(j) => j.id}
          isPending={scans.isPending}
          error={scans.error}
          hasMore={scans.hasNextPage}
          loadingMore={scans.isFetchingNextPage}
          onLoadMore={() => void scans.fetchNextPage()}
          onRowClick={(j) => void navigate({ to: "/scans/$id", params: { id: j.id } })}
          empty={
            <EmptyState icon={<Radar />} title={anyFilter ? "No executions match" : "No scans yet"}>
              {anyFilter ? "Change or clear the filters." : "Start a scan for one or more repositories, or create a schedule."}
            </EmptyState>
          }
          toolbar={
            <div className="flex w-full flex-col gap-2">
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative w-64">
                  <Search className="pointer-events-none absolute left-2 top-2 size-4 text-muted-foreground" aria-hidden />
                  <Input aria-label="Search scans" className="pl-8" placeholder="Scan ID, name, repository…" value={q} onChange={(e) => setQ(e.target.value)} />
                </div>
                <RepositoryFilter id={search.repository_id} onChange={(id) => set({ repository_id: id })} />
                <Input aria-label="Repository ID" className="w-40 font-mono" placeholder="Repository ID" value={search.repository_key ?? ""} onChange={(e) => set({ repository_key: e.target.value.trim() || undefined })} />
                <label className="flex items-center gap-1 text-[12px] text-muted-foreground">
                  From
                  <Input type="date" aria-label="Started from" className="w-36" value={search.from ?? ""} max={search.to} onChange={(e) => set({ from: e.target.value || undefined })} />
                </label>
                <label className="flex items-center gap-1 text-[12px] text-muted-foreground">
                  To
                  <Input type="date" aria-label="Started to" className="w-36" value={search.to ?? ""} min={search.from} onChange={(e) => set({ to: e.target.value || undefined })} />
                </label>
              </div>
              <FilterBar
                filters={filterDefs}
                values={search as Record<string, string | undefined>}
                onChange={(k, v) => set({ [k]: v })}
                onReset={() => {
                  setQ("");
                  void navigate({ to: "/scans", search: {} as never, replace: true });
                }}
              />
            </div>
          }
        />
      </Card>
      <StartScanDialog open={search.start === "1"} onOpenChange={(o) => set({ start: o ? "1" : undefined })} />
    </>
  );
}
