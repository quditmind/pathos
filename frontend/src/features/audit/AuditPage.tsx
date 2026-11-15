import { useDeferredValue, useEffect, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { FileClock } from "lucide-react";
import { api } from "@/api/client";
import type { AuditRecord, Page } from "@/api/types";
import { DataTable, type Column } from "@/components/data/DataTable";
import { Badge, Card, EmptyState, Input, PageHeader, Select } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";

const outcomeTone = { success: "success", denied: "warning", failure: "danger" } as const;
type Outcome = AuditRecord["outcome"];

export function describeAudit(r: AuditRecord): string {
  const m = r.metadata ?? {};
  const parts: string[] = [];
  for (const k of ["email", "role", "scope_type", "name", "reason", "status", "method", "path"]) {
    if (m[k] !== undefined && m[k] !== "") parts.push(`${k}=${String(m[k])}`);
  }
  if (m.bootstrap_super_admin) parts.push("granted bootstrap super_admin");
  if (m.jit_created) parts.push("first sign-in (provisioned)");
  return parts.join(" · ");
}

const columns: Column<AuditRecord>[] = [
  { id: "time", header: "Time", required: true, className: "tabular whitespace-nowrap text-muted-foreground", cell: (r) => formatDateTime(r.created_at), csv: (r) => r.created_at },
  { id: "actor", header: "Actor", className: "max-w-48 truncate", cell: (r) => r.actor_email || "system", csv: (r) => r.actor_email },
  {
    id: "action",
    header: "Action",
    cell: (r) => <code className="rounded bg-surface-muted px-1 py-0.5 text-[12px]">{r.action}</code>,
    csv: (r) => r.action,
  },
  { id: "outcome", header: "Outcome", cell: (r) => <Badge tone={outcomeTone[r.outcome]}>{r.outcome}</Badge>, csv: (r) => r.outcome },
  { id: "details", header: "Details", className: "max-w-80 truncate text-[12px] text-muted-foreground", cell: describeAudit, csv: describeAudit },
  { id: "target", header: "Target", defaultHidden: true, className: "text-[12px] text-muted-foreground", cell: (r) => (r.target_type ? `${r.target_type}:${r.target_id}` : "—"), csv: (r) => `${r.target_type}:${r.target_id}` },
  { id: "ip", header: "IP", className: "tabular text-[12px] text-muted-foreground", cell: (r) => r.ip ?? "—", csv: (r) => r.ip },
  { id: "request", header: "Request ID", defaultHidden: true, className: "font-mono text-[11px] text-muted-foreground", cell: (r) => r.request_id || "—", csv: (r) => r.request_id },
];

export function AuditPage() {
  const search = useSearch({ strict: false }) as { action?: string; outcome?: Outcome };
  const navigate = useNavigate();
  const [action, setAction] = useState(search.action ?? "");
  const deferred = useDeferredValue(action.trim());
  useEffect(() => setAction(search.action ?? ""), [search.action]);

  const q = useInfiniteQuery({
    queryKey: ["audit", deferred, search.outcome ?? ""],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = new URLSearchParams();
      if (deferred) p.set("action", deferred);
      if (search.outcome) p.set("outcome", search.outcome);
      if (pageParam) p.set("cursor", pageParam);
      return api<Page<AuditRecord>>(`/api/v1/audit-logs?${p}`, { signal });
    },
    getNextPageParam: (last) => last.next_cursor ?? undefined,
  });
  const rows = q.data?.pages.flatMap((p) => p.items) ?? [];

  return (
    <>
      <PageHeader title="Audit log" description="Append-only record of sign-ins, administrative changes and denied actions." />
      <Card>
        <DataTable
          tableId="audit"
          exportName="pathos-audit"
          columns={columns}
          rows={rows}
          rowKey={(r) => r.id}
          isPending={q.isPending}
          error={q.error}
          hasMore={q.hasNextPage}
          loadingMore={q.isFetchingNextPage}
          onLoadMore={() => void q.fetchNextPage()}
          empty={<EmptyState icon={<FileClock />} title="No audit entries match these filters" />}
          toolbar={
            <>
              <Input
                aria-label="Filter by action"
                placeholder="Action, e.g. user or role_assignment.create"
                className="max-w-sm"
                value={action}
                onChange={(e) => setAction(e.target.value)}
                onBlur={() => void navigate({ to: "/admin/audit", search: { ...search, action: action.trim() || undefined } as never, replace: true })}
              />
              <Select
                aria-label="Filter by outcome"
                value={search.outcome ?? ""}
                onChange={(e) =>
                  void navigate({ to: "/admin/audit", search: { ...search, outcome: (e.target.value || undefined) as Outcome | undefined } as never, replace: true })
                }
              >
                <option value="">All outcomes</option>
                <option value="success">Success</option>
                <option value="denied">Denied</option>
                <option value="failure">Failure</option>
              </Select>
            </>
          }
        />
      </Card>
    </>
  );
}
