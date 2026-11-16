import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { History, Plus } from "lucide-react";
import type { ImportJob } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Card, EmptyState, PageHeader, Select } from "@/components/ui/primitives";
import { ProgressBar } from "@/components/ui/progress";
import { DataTable, type Column } from "@/components/data/DataTable";
import { useSession } from "@/features/auth/session";
import { formatDateTime } from "@/lib/utils";
import { useImportJobs } from "./api";
import { ImportStatusBadge } from "./ImportStatusBadge";

export interface ImportsSearch {
  status?: "active" | "finished" | "all";
  mine?: boolean;
}

export function validateImportsSearch(s: Record<string, unknown>): ImportsSearch {
  return {
    status: s.status === "active" || s.status === "finished" || s.status === "all" ? s.status : undefined,
    mine: s.mine === true || s.mine === "true" ? true : undefined,
  };
}

export const sourceLabel: Record<ImportJob["source_type"], string> = { upload: "Local upload", git: "Git", devops: "DevOps" };

const columns: Column<ImportJob>[] = [
  { id: "created", header: "Started", required: true, className: "tabular whitespace-nowrap text-[12px]", cell: (j) => formatDateTime(j.created_at), csv: (j) => j.created_at },
  {
    id: "source",
    header: "Source",
    cell: (j) => (
      <div>
        <div>{sourceLabel[j.source_type] ?? j.source_type}</div>
        {j.scm_connection_name && <div className="text-[12px] text-muted-foreground">{j.scm_connection_name}</div>}
      </div>
    ),
    csv: (j) => `${j.source_type} ${j.scm_connection_name}`,
  },
  { id: "status", header: "Status", cell: (j) => <ImportStatusBadge status={j.status} />, csv: (j) => j.status },
  {
    id: "progress",
    header: "Progress",
    className: "min-w-44",
    cell: (j) => {
      const done = j.completed_items + j.failed_items + j.attention_items;
      return (
        <div className="space-y-1">
          <ProgressBar value={j.total_items ? done / j.total_items : 0} label={`Import progress ${done} of ${j.total_items}`} tone={j.failed_items ? "danger" : "primary"} />
          <div className="tabular text-[11.5px] text-muted-foreground">
            {j.completed_items}/{j.total_items} completed
            {j.failed_items > 0 && <span className="text-danger"> · {j.failed_items} failed</span>}
            {j.attention_items > 0 && <span className="text-warning"> · {j.attention_items} need attention</span>}
          </div>
        </div>
      );
    },
    csv: (j) => `${j.completed_items}/${j.total_items}`,
  },
  { id: "by", header: "Requested by", cell: (j) => j.requested_by?.name || j.requested_by?.email, csv: (j) => j.requested_by?.email },
  { id: "finished", header: "Finished", defaultHidden: true, className: "tabular text-[12px] text-muted-foreground", cell: (j) => formatDateTime(j.completed_at), csv: (j) => j.completed_at },
];

export function ImportsPage() {
  const { can } = useSession();
  const search = useSearch({ strict: false }) as ImportsSearch;
  const navigate = useNavigate();
  const status = search.status ?? "all";
  const jobs = useImportJobs({ status, mine: !!search.mine });
  const rows = jobs.data?.pages.flatMap((p) => p.items) ?? [];
  const set = (n: Partial<ImportsSearch>) => void navigate({ to: "/repositories/imports", search: { ...search, ...n } as never, replace: true });

  return (
    <>
      <PageHeader
        title="Import history"
        description="Background import jobs. Active jobs refresh automatically."
        actions={
          can("repos.manage") && (
            <Button asChild>
              <Link to="/repositories/import">
                <Plus /> New import
              </Link>
            </Button>
          )
        }
      />
      <Card>
        <DataTable
          tableId="repository-imports"
          exportName="pathos-imports"
          columns={columns}
          rows={rows}
          rowKey={(j) => j.id}
          isPending={jobs.isPending}
          error={jobs.error}
          hasMore={jobs.hasNextPage}
          loadingMore={jobs.isFetchingNextPage}
          onLoadMore={() => void jobs.fetchNextPage()}
          onRowClick={(j) => void navigate({ to: "/repositories/imports/$id", params: { id: j.id } })}
          toolbar={
            <>
              <Select aria-label="Status" value={status} onChange={(e) => set({ status: e.target.value as ImportsSearch["status"] })}>
                <option value="all">All jobs</option>
                <option value="active">Active</option>
                <option value="finished">Finished</option>
              </Select>
              <div className="flex rounded-md border border-border p-0.5" role="group" aria-label="Requested by">
                {[
                  [false, "Everyone"],
                  [true, "Mine"],
                ].map(([v, l]) => (
                  <button
                    key={String(v)}
                    type="button"
                    aria-pressed={!!search.mine === v}
                    onClick={() => set({ mine: v ? true : undefined })}
                    className={`rounded px-2.5 py-1 text-[12px] ${!!search.mine === v ? "bg-primary/10 font-medium text-primary" : "text-muted-foreground"}`}
                  >
                    {l as string}
                  </button>
                ))}
              </div>
            </>
          }
          empty={
            <EmptyState icon={<History />} title={status === "all" && !search.mine ? "No imports yet" : "No imports match"}>
              {can("repos.manage") && (
                <Link to="/repositories/import" className="text-primary underline">
                  Import repositories
                </Link>
              )}
            </EmptyState>
          }
        />
      </Card>
    </>
  );
}
