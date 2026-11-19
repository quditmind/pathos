import { useDeferredValue, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { CheckCircle2, CircleDashed, Clock, MinusCircle, Radar } from "lucide-react";
import { api } from "@/api/client";
import { Card, EmptyState, Input, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { cn, formatDateTime } from "@/lib/utils";
import { type CoverageResponse, type CoverageStatus, coverageLabel } from "./api";
import { ErrorPanel } from "@/components/ui/error-panel";

const statusMeta: Record<CoverageStatus, { label: string; icon: React.ReactNode; cls: string }> = {
  covered: { label: "Covered", icon: <CheckCircle2 className="size-3.5" />, cls: "text-success" },
  stale: { label: "Stale", icon: <Clock className="size-3.5" />, cls: "text-warning" },
  never: { label: "Never", icon: <CircleDashed className="size-3.5" />, cls: "text-danger" },
  not_configured: { label: "No target", icon: <MinusCircle className="size-3.5" />, cls: "text-muted-foreground" },
};

export function CoveragePage() {
  const [days, setDays] = useState(30);
  const [q, setQ] = useState("");
  const dq = useDeferredValue(q.trim());
  const cov = useQuery({
    queryKey: ["posture", "coverage", days, dq],
    queryFn: () => api<CoverageResponse>(`/api/v1/posture/coverage?days=${days}${dq ? `&q=${encodeURIComponent(dq)}` : ""}`),
  });
  return (
    <>
      <PageHeader
        title="Scan coverage"
        description="Which kinds of scanning ran successfully for each repository. Container and DAST coverage come from scan targets; CI/CD from zizmor; imported results count for their category."
      />
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Input aria-label="Search repositories" placeholder="Repository or Repository ID…" value={q} onChange={(e) => setQ(e.target.value)} className="w-64" />
        <Select aria-label="Coverage window" value={days} onChange={(e) => setDays(Number(e.target.value))}>
          {[7, 30, 90].map((d) => <option key={d} value={d}>Covered = within {d} days</option>)}
        </Select>
        <span className="ml-auto flex flex-wrap gap-3 text-[11.5px] text-muted-foreground">
          {(Object.keys(statusMeta) as CoverageStatus[]).map((s) => (
            <span key={s} className={cn("inline-flex items-center gap-1", statusMeta[s].cls)}>
              {statusMeta[s].icon}
              <span className="text-muted-foreground">{statusMeta[s].label}</span>
            </span>
          ))}
        </span>
      </div>
      {cov.data && (
        <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4 lg:grid-cols-7">
          {cov.data.summary.map((s) => (
            <Card key={s.category} className="p-3">
              <div className="text-[11.5px] text-muted-foreground">{coverageLabel[s.category] ?? s.category}</div>
              <div className="tabular text-lg font-semibold">{s.percent.toFixed(s.percent % 1 ? 1 : 0)}%</div>
              <div className="tabular text-[11px] text-muted-foreground">{s.covered} of {cov.data.items.length}</div>
            </Card>
          ))}
        </div>
      )}
      <Card>
        {cov.isError ? (
          <div className="p-4"><ErrorPanel error={cov.error} /></div>
        ) : cov.isPending ? (
          <Skeleton className="m-4 h-40" />
        ) : !cov.data.items.length ? (
          <EmptyState icon={<Radar />} title="No repositories" />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Repository</Th>
                {cov.data.categories.map((c) => <Th key={c} className="text-center">{coverageLabel[c] ?? c}</Th>)}
              </tr>
            </thead>
            <tbody>
              {cov.data.items.map((r) => (
                <tr key={r.repository_id}>
                  <Td>
                    <div className="font-medium">{r.repository_name}</div>
                    <div className="text-[11px] text-muted-foreground">
                      <span className="font-mono">{r.repository_key}</span>
                      {r.application_name && ` · ${r.application_name}`}
                      {!r.scan_enabled && " · scanning disabled"}
                    </div>
                  </Td>
                  {cov.data.categories.map((c) => {
                    const cell = r.cells[c]!;
                    const m = statusMeta[cell.status];
                    const title = cell.last_at ? `${m.label}: last success ${formatDateTime(cell.last_at)} (${cell.scanners.join(", ")})` : m.label;
                    return (
                      <Td key={c} className="text-center">
                        <span className={cn("inline-flex items-center gap-1 text-[11.5px]", m.cls)} title={title} aria-label={`${coverageLabel[c]}: ${title}`}>
                          {m.icon}
                          <span className="sr-only">{m.label}</span>
                        </span>
                      </Td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {cov.data?.truncated && <p className="mt-2 text-[12px] text-muted-foreground">Showing the first 1,000 repositories; search to narrow down.</p>}
    </>
  );
}
