import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { GitBranch, RefreshCw, ShieldQuestion } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { cn, formatDateTime } from "@/lib/utils";
import type { UnmanagedResponse } from "./api";
import { When } from "./shared";
import { ErrorPanel } from "@/components/ui/error-panel";

const issueOrder = ["no_application", "no_owner", "never_scanned", "stale_scan", "scanning_disabled", "sync_failing", "archived_in_scm"];

export function UnmanagedPage() {
  const { canOrgWide } = useSession();
  const qc = useQueryClient();
  const [issue, setIssue] = useState("");
  const [active, setActive] = useState(90);
  const q = useQuery({
    queryKey: ["posture", "unmanaged", active],
    queryFn: () => api<UnmanagedResponse>(`/api/v1/posture/unmanaged?active_days=${active}`),
  });
  const refresh = useMutation({
    mutationFn: (id: string) => api(`/api/v1/scm-connections/${id}/inventory`, { method: "POST" }),
    onSettled: () => void qc.invalidateQueries({ queryKey: ["posture", "unmanaged"] }),
  });
  const canRefresh = canOrgWide("repos.manage");
  const rows = q.data?.repositories.filter((r) => !issue || r.issues.includes(issue)) ?? [];
  return (
    <>
      <PageHeader
        title="Unmanaged assets"
        description="Repositories PATHOS manages with governance gaps, and shadow repositories: active in a connected SCM but never imported. The SCM inventory refreshes daily."
      />
      {q.isError && <ErrorPanel error={q.error} />}
      {q.isPending && <Skeleton className="h-48" />}
      {q.data && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-8">
            {q.data.shadow_visible && (
              <Card className="p-3">
                <div className="text-[11.5px] text-muted-foreground">Shadow repositories</div>
                <div className="tabular text-lg font-semibold">{q.data.counts.shadow ?? 0}</div>
              </Card>
            )}
            {issueOrder.map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => setIssue(issue === k ? "" : k)}
                aria-pressed={issue === k}
                className={cn("rounded-lg border bg-surface p-3 text-left transition-colors", issue === k ? "border-[color:var(--ring)] ring-1 ring-[color:var(--ring)]" : "border-border hover:border-primary/40")}
              >
                <div className="text-[11.5px] text-muted-foreground">{q.data.issue_labels[k]}</div>
                <div className="tabular text-lg font-semibold">{q.data.counts[k] ?? 0}</div>
              </button>
            ))}
          </div>

          <Card>
            <h2 className="border-b border-border px-4 py-2.5 text-[13px] font-semibold">
              Governance gaps{issue && <span className="font-normal text-muted-foreground"> · {q.data.issue_labels[issue]}</span>}
            </h2>
            {!rows.length ? (
              <EmptyState icon={<ShieldQuestion />} title="No gaps">Every repository in your scope has an application, an owner and recent scans.</EmptyState>
            ) : (
              <Table>
                <thead>
                  <tr>
                    <Th>Repository</Th>
                    <Th>Gaps</Th>
                    <Th>Open findings</Th>
                    <Th>Last scan</Th>
                    <Th>Last push</Th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id}>
                      <Td>
                        <Link to="/repositories" search={{ repo: r.id } as never} className="font-medium text-primary hover:underline">{r.name}</Link>
                        <div className="text-[11px] text-muted-foreground"><span className="font-mono">{r.repository_key}</span> · <span className="capitalize">{r.criticality}</span></div>
                      </Td>
                      <Td>
                        <div className="flex flex-wrap gap-1">
                          {r.issues.map((i) => <Badge key={i} tone={i === "never_scanned" || i === "sync_failing" ? "danger" : "warning"}>{q.data.issue_labels[i]}</Badge>)}
                        </div>
                      </Td>
                      <Td className="tabular text-[12px]">{r.open_findings}</Td>
                      <Td className="text-[12px]"><When at={r.last_scan_at} /></Td>
                      <Td className="text-[12px]"><When at={r.last_pushed_at} /></Td>
                    </tr>
                  ))}
                </tbody>
              </Table>
            )}
          </Card>

          {q.data.shadow_visible ? (
            <Card>
              <div className="flex flex-wrap items-center gap-2 border-b border-border px-4 py-2.5">
                <h2 className="text-[13px] font-semibold">Shadow repositories</h2>
                <Select aria-label="Activity window" value={active} onChange={(e) => setActive(Number(e.target.value))} className="ml-auto">
                  {[30, 90, 365].map((d) => <option key={d} value={d}>Pushed in the last {d} days</option>)}
                </Select>
              </div>
              {refresh.error && <div className="p-3"><ErrorPanel error={refresh.error} /></div>}
              <div className="flex flex-wrap gap-2 border-b border-border px-4 py-2 text-[12px]">
                {(q.data.inventory ?? []).map((c) => (
                  <span key={c.scm_connection_id} className="inline-flex items-center gap-1.5 rounded border border-border px-2 py-1">
                    <GitBranch className="size-3.5" />
                    {c.scm_connection_name}:{" "}
                    {c.status == null ? (
                      <span className="text-muted-foreground">not inventoried yet</span>
                    ) : c.status === "failed" ? (
                      <span className="text-danger" title={c.error ?? ""}>inventory failed</span>
                    ) : (
                      <span className="text-muted-foreground">
                        {c.repositories} repositories{c.truncated ? " (first 20,000)" : ""}, {c.finished_at ? formatDateTime(c.finished_at) : "running"}
                      </span>
                    )}
                    {canRefresh && (
                      <Button size="icon" variant="ghost" className="size-6" aria-label={`Refresh inventory of ${c.scm_connection_name}`}
                        disabled={refresh.isPending} onClick={() => refresh.mutate(c.scm_connection_id)}>
                        <RefreshCw className={cn(refresh.isPending && refresh.variables === c.scm_connection_id && "animate-spin")} />
                      </Button>
                    )}
                  </span>
                ))}
              </div>
              {!q.data.shadow?.length ? (
                <EmptyState icon={<GitBranch />} title="No shadow repositories">Every recently active repository the SCM connections can see is in PATHOS.</EmptyState>
              ) : (
                <Table>
                  <thead>
                    <tr>
                      <Th>Repository</Th>
                      <Th>Connection</Th>
                      <Th>Visibility</Th>
                      <Th>Last push</Th>
                      <Th>First seen</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {q.data.shadow.map((s) => (
                      <tr key={s.scm_connection_id + s.external_id}>
                        <Td>
                          {s.url ? (
                            <a href={s.url} target="_blank" rel="noopener noreferrer" className="font-medium text-primary hover:underline">{s.full_name}</a>
                          ) : (
                            <span className="font-medium">{s.full_name}</span>
                          )}
                        </Td>
                        <Td className="text-[12px]">{s.scm_connection_name} <span className="text-muted-foreground">({s.provider})</span></Td>
                        <Td className="text-[12px] capitalize">{s.visibility || "—"}</Td>
                        <Td className="text-[12px]"><When at={s.pushed_at} /></Td>
                        <Td className="text-[12px]"><When at={s.first_seen_at} /></Td>
                      </tr>
                    ))}
                  </tbody>
                </Table>
              )}
              <p className="px-4 py-2 text-[12px] text-muted-foreground">
                Import them from <Link to="/repositories/import" className="text-primary hover:underline">Repositories → Import</Link>.
              </p>
            </Card>
          ) : (
            <Alert tone="warning">Shadow repositories are shown to people who can see every repository in the organization.</Alert>
          )}
        </div>
      )}
    </>
  );
}
