import { useDeferredValue, useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { FileClock } from "lucide-react";
import { api } from "@/api/client";
import type { AuditRecord, Page } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, Input, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { formatDateTime } from "@/lib/utils";

const outcomeTone = { success: "success", denied: "warning", failure: "danger" } as const;

function describe(r: AuditRecord): string {
  const m = r.metadata;
  const parts: string[] = [];
  for (const k of ["email", "role", "scope_type", "name", "reason", "status"]) {
    if (m[k] !== undefined && m[k] !== "") parts.push(`${k}=${String(m[k])}`);
  }
  if (m.bootstrap_super_admin) parts.push("granted bootstrap super_admin");
  if (m.jit_created) parts.push("first sign-in (provisioned)");
  return parts.join(" · ");
}

export function AuditPage() {
  const [action, setAction] = useState("");
  const deferred = useDeferredValue(action.trim());
  const q = useInfiniteQuery({
    queryKey: ["audit", deferred],
    initialPageParam: "",
    queryFn: ({ pageParam, signal }) => {
      const p = new URLSearchParams();
      if (deferred) p.set("action", deferred);
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
        <div className="border-b border-border p-3">
          <Input
            aria-label="Filter by action"
            placeholder="Filter by action, e.g. user or role_assignment.create"
            className="max-w-sm"
            value={action}
            onChange={(e) => setAction(e.target.value)}
          />
        </div>
        {q.isError ? (
          <div className="p-4">
            <Alert>Could not load the audit log: {q.error.message}</Alert>
          </div>
        ) : q.isPending ? (
          <div className="space-y-2 p-4">
            {Array.from({ length: 6 }, (_, i) => (
              <Skeleton key={i} className="h-8" />
            ))}
          </div>
        ) : rows.length === 0 ? (
          <EmptyState icon={<FileClock />} title="No audit entries" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Time</Th>
                <Th>Actor</Th>
                <Th>Action</Th>
                <Th>Outcome</Th>
                <Th>Details</Th>
                <Th>IP</Th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <Td className="tabular whitespace-nowrap text-muted-foreground">{formatDateTime(r.created_at)}</Td>
                  <Td className="max-w-48 truncate">{r.actor_email || "system"}</Td>
                  <Td>
                    <code className="rounded bg-surface-muted px-1 py-0.5 text-[12px]">{r.action}</code>
                  </Td>
                  <Td>
                    <Badge tone={outcomeTone[r.outcome]}>{r.outcome}</Badge>
                  </Td>
                  <Td className="max-w-80 truncate text-[12px] text-muted-foreground" >{describe(r)}</Td>
                  <Td className="tabular text-[12px] text-muted-foreground">{r.ip ?? "—"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
        {q.hasNextPage && (
          <div className="flex justify-center p-3">
            <Button variant="secondary" onClick={() => void q.fetchNextPage()} disabled={q.isFetchingNextPage}>
              {q.isFetchingNextPage ? "Loading…" : "Load more"}
            </Button>
          </div>
        )}
      </Card>
    </>
  );
}
