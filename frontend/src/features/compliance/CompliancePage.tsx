import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ClipboardCheck } from "lucide-react";
import { api } from "@/api/client";
import type { Severity } from "@/api/types";
import { SeverityBadge } from "@/components/data/Severity";
import { Alert, Badge, Card, EmptyState, PageHeader, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { cn } from "@/lib/utils";

interface ControlStatus {
  id: string;
  title: string;
  categories?: string[];
  cwe?: string[];
  malicious?: boolean;
  status: "failing" | "attention" | "passing" | "not_applicable";
  open_findings: number;
  by_severity: Record<string, number>;
  repositories: number;
}
interface Summary {
  key: string;
  name: string;
  version: string;
  scope_key: string;
  description: string;
  repositories_in_scope: number;
  failing: number;
  attention: number;
  passing: number;
  controls?: ControlStatus[];
}

const statusTone = { failing: "danger", attention: "warning", passing: "success", not_applicable: "neutral" } as const;
const statusLabel = { failing: "Failing", attention: "Attention", passing: "No open findings", not_applicable: "Not in scope" };
const sevs: Severity[] = ["critical", "high", "medium", "low", "info"];

function Framework({ fkey }: { fkey: string }) {
  const q = useQuery({ queryKey: ["compliance", fkey], queryFn: () => api<Summary>(`/api/v1/compliance/frameworks/${fkey}`) });
  if (q.isError) return <Alert>{q.error.message}</Alert>;
  if (q.isPending) return <Skeleton className="h-64" />;
  const f = q.data;
  return (
    <Card>
      <div className="border-b border-border px-4 py-3">
        <h2 className="text-[14px] font-semibold">{f.name} {f.version}</h2>
        <p className="text-[12px] text-muted-foreground">
          {f.description} {f.scope_key ? `${f.repositories_in_scope} repositor${f.repositories_in_scope === 1 ? "y" : "ies"} in scope.` : "Applies to every repository."}
        </p>
      </div>
      {f.repositories_in_scope === 0 ? (
        <EmptyState icon={<ClipboardCheck />} title="No repository in this scope">
          Add the <strong>{f.scope_key}</strong> compliance scope to the repositories it covers (repository details → classification).
        </EmptyState>
      ) : (
        <Table>
          <thead><tr><Th>Control</Th><Th>Status</Th><Th>Open findings</Th><Th className="text-right">Repositories</Th></tr></thead>
          <tbody>
            {f.controls!.map((c) => (
              <tr key={c.id}>
                <Td>
                  <div className="font-mono text-[11.5px] text-muted-foreground">{c.id}</div>
                  <div className="text-[12.5px]">{c.title}</div>
                  <div className="text-[11px] text-muted-foreground">
                    Mapped by {[c.categories?.length ? c.categories.join(", ") : "", c.cwe?.length ? `${c.cwe.length} CWE${c.cwe.length === 1 ? "" : "s"}` : "", c.malicious ? "malicious packages" : ""].filter(Boolean).join(" · ")}
                  </div>
                </Td>
                <Td><Badge tone={statusTone[c.status]}>{statusLabel[c.status]}</Badge></Td>
                <Td>
                  {c.open_findings ? (
                    <Link to="/findings" search={{ control: `${f.key}:${c.id}` } as never} className="inline-flex flex-wrap items-center gap-1 hover:underline">
                      {sevs.filter((s) => c.by_severity[s]).map((s) => <span key={s} className="inline-flex items-center gap-0.5"><SeverityBadge value={s} /> {c.by_severity[s]}</span>)}
                    </Link>
                  ) : <span className="text-[12px] text-muted-foreground">0</span>}
                </Td>
                <Td className="tabular text-right text-[12px]">{c.repositories || "—"}</Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

export function CompliancePage() {
  const search = useSearch({ strict: false }) as { framework?: string };
  const navigate = useNavigate();
  const list = useQuery({ queryKey: ["compliance"], queryFn: () => api<{ items: Summary[]; note: string }>("/api/v1/compliance/frameworks") });
  const active = search.framework ?? list.data?.items[0]?.key;
  return (
    <>
      <PageHeader
        title="Compliance"
        description="Open findings mapped to the controls of security frameworks, for the repositories in each framework's compliance scope. The mapping is indicative evidence for an assessment, not a compliance verdict."
      />
      {list.isError ? <Alert>{list.error.message}</Alert> : list.isPending ? <Skeleton className="h-24" /> : (
        <>
          <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
            {list.data.items.map((f) => (
              <button key={f.key} type="button" onClick={() => void navigate({ to: "/compliance", search: { framework: f.key } as never })}
                className={cn("rounded-lg border p-3 text-left transition-colors hover:border-primary", active === f.key ? "border-primary bg-primary/5" : "border-border bg-surface")}>
                <div className="text-[13px] font-semibold">{f.name}</div>
                <div className="text-[11px] text-muted-foreground">{f.version}{f.scope_key ? ` · ${f.repositories_in_scope} in scope` : ""}</div>
                <div className="mt-2 flex flex-wrap gap-1 text-[11px]">
                  {f.repositories_in_scope === 0 ? <Badge>not in scope</Badge> : (
                    <>
                      <Badge tone="danger">{f.failing} failing</Badge>
                      <Badge tone="warning">{f.attention} attention</Badge>
                      <Badge tone="success">{f.passing} clear</Badge>
                    </>
                  )}
                </div>
              </button>
            ))}
          </div>
          {active && <Framework key={active} fkey={active} />}
        </>
      )}
    </>
  );
}
