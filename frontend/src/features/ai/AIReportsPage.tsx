import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileText, Sparkles } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Alert, Badge, Card, EmptyState, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { RepoFilter } from "@/features/review/shared";
import { useApplications } from "@/features/repos/api";
import { formatDateTime } from "@/lib/utils";
import { ErrorPanel } from "@/components/ui/error-panel";
import { LifecycleEvidence, lifecycleSections } from "@/features/reporting/LifecycleEvidence";

interface Report {
  id: string;
  kind: "technical" | "executive";
  scope_type: string;
  title: string;
  facts: Record<string, unknown>;
  narrative: { summary: string; key_risks: string[]; recommendations: string[] } | null;
  narrative_error: string;
  model: string;
  created_by: string | null;
  created_at: string;
}

export function AIReportsPage() {
  const qc = useQueryClient();
  const { can } = useSession();
  const apps = useApplications();
  const [kind, setKind] = useState<"executive" | "technical">("executive");
  const [scope, setScope] = useState("organization");
  const [scopeId, setScopeId] = useState<string | undefined>();
  const [narrative, setNarrative] = useState(true);
  const [open, setOpen] = useState<string | null>(null);
  const list = useQuery({ queryKey: ["ai-reports"], queryFn: () => api<{ items: Report[] }>("/api/v1/ai/reports").then((r) => r.items) });
  const detail = useQuery({ queryKey: ["ai-report", open], queryFn: () => api<Report>(`/api/v1/ai/reports/${open}`), enabled: !!open });
  const create = useMutation({
    mutationFn: () => api<Report>("/api/v1/ai/reports", { method: "POST", body: { kind, scope_type: scope, scope_id: scope === "organization" ? undefined : scopeId, narrative } }),
    onSuccess: (r) => {
      void qc.invalidateQueries({ queryKey: ["ai-reports"] });
      setOpen(r.id);
    },
  });
  const ok = scope === "organization" || !!scopeId;
  const r = detail.data;
  return (
    <>
      <PageHeader
        title="AI reports"
        description="Technical and executive security reports. PATHOS computes every figure for your scope; AI only writes the narrative from those figures (or the report has the figures alone)."
      />
      <Card className="mb-4 p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div>
            <Label htmlFor="rep-kind">Report</Label>
            <Select id="rep-kind" value={kind} onChange={(e) => setKind(e.target.value as "executive" | "technical")}>
              <option value="executive">Executive summary</option>
              <option value="technical">Technical report</option>
            </Select>
          </div>
          <div>
            <Label htmlFor="rep-scope">Scope</Label>
            <Select id="rep-scope" value={scope} onChange={(e) => { setScope(e.target.value); setScopeId(undefined); }}>
              <option value="organization">Organization</option>
              <option value="application">One application</option>
              <option value="repository">One repository</option>
            </Select>
          </div>
          {scope === "application" && (
            <div>
              <Label htmlFor="rep-app">Application</Label>
              <Select id="rep-app" value={scopeId ?? ""} onChange={(e) => setScopeId(e.target.value || undefined)}>
                <option value="">Choose…</option>
                {(apps.data ?? []).map((a) => <option key={a.id} value={a.id}>{a.name}</option>)}
              </Select>
            </div>
          )}
          {scope === "repository" && <div><span className="mb-1 block text-[12px] font-medium">Repository</span><RepoFilter value={scopeId} onChange={setScopeId} /></div>}
          <label className="flex items-center gap-1.5 text-[12.5px]">
            <input type="checkbox" className="accent-[var(--primary)]" checked={narrative} disabled={!can("ai.review")} onChange={(e) => setNarrative(e.target.checked)} />
            AI narrative
          </label>
          <Button onClick={() => create.mutate()} disabled={!ok || create.isPending}><Sparkles /> {create.isPending ? "Generating…" : "Generate"}</Button>
        </div>
        {create.error && <div className="mt-3"><ErrorPanel error={create.error} /></div>}
      </Card>
      <div className="grid gap-4 xl:grid-cols-[360px_minmax(0,1fr)]">
        <Card>
          {list.isError ? <div className="p-3"><ErrorPanel error={list.error} /></div> : list.isPending ? <Skeleton className="m-3 h-24" /> : !list.data.length ? (
            <EmptyState icon={<FileText />} title="No reports yet" />
          ) : (
            <Table>
              <thead><tr><Th>Report</Th><Th>Created</Th></tr></thead>
              <tbody>
                {list.data.map((x) => (
                  <tr key={x.id} className={open === x.id ? "bg-primary/5" : undefined}>
                    <Td><button type="button" className="text-left text-[12.5px] text-primary hover:underline" onClick={() => setOpen(x.id)}>{x.title}</button></Td>
                    <Td className="whitespace-nowrap text-[11.5px] text-muted-foreground">{formatDateTime(x.created_at)}<div>{x.created_by}</div></Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
        <Card className="p-4 text-[13px]">
          {!open ? <p className="text-muted-foreground">Generate a report or select one.</p> : detail.isPending || !r ? <Skeleton className="h-48" /> : (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-[15px] font-semibold">{r.title}</h2>
                <Badge>{r.kind}</Badge>
                <a href={`/api/v1/ai/reports/${r.id}/markdown`} download className="ml-auto inline-flex items-center gap-1 text-[12px] text-primary hover:underline">
                  <Download className="size-3.5" /> Markdown
                </a>
              </div>
              <p className="text-[11.5px] text-muted-foreground">
                {formatDateTime(r.created_at)}{r.model ? ` · narrative by ${r.model} from the figures below` : ""}
              </p>
              {r.narrative ? (
                <>
                  <p className="whitespace-pre-wrap">{r.narrative.summary}</p>
                  {r.narrative.key_risks.length > 0 && <><h3 className="font-semibold">Key risks</h3><ul className="list-disc pl-5">{r.narrative.key_risks.map((x) => <li key={x}>{x}</li>)}</ul></>}
                  {r.narrative.recommendations.length > 0 && <><h3 className="font-semibold">Recommendations</h3><ul className="list-disc pl-5">{r.narrative.recommendations.map((x) => <li key={x}>{x}</li>)}</ul></>}
                </>
              ) : r.narrative_error ? <Alert tone="warning">{r.narrative_error}</Alert> : null}
              <h3 className="font-semibold">Figures</h3>
              <FactsTable f={r.facts} />
              {r.kind === "technical" && <LifecycleEvidence sections={lifecycleSections(r.facts?.lifecycle)} />}
            </div>
          )}
        </Card>
      </div>
    </>
  );
}

function FactsTable({ f }: { f: Record<string, unknown> }) {
  const open = (f.open_by_severity ?? {}) as Record<string, number>;
  const v = (x: unknown, unit = "") => (x == null ? "not available" : `${x}${unit}`);
  const rows: [string, string][] = [
    ["Open critical / high / medium / low", `${open.critical ?? 0} / ${open.high ?? 0} / ${open.medium ?? 0} / ${open.low ?? 0}`],
    ["Open, actively exploited (KEV)", v(f.open_actively_exploited)],
    ["Open with critical contextual risk", v(f.open_with_critical_risk)],
    ["New in the last 30 days", v(f.new_last_30_days)],
    ["Fixed in the last 90 days", v(f.fixed_last_90_days)],
    ["Mean time to fix", v(f.mean_days_to_fix, " days")],
    ["Fixed within SLA", v(f.fixed_within_sla_percent, "%")],
    ["Repositories", v(f.repositories)],
    ["Scan coverage (30 days)", v(f.scan_coverage_percent, "%")],
  ];
  return (
    <Table>
      <tbody>{rows.map(([k, val]) => <tr key={k}><Td className="text-muted-foreground">{k}</Td><Td className="tabular">{val}</Td></tr>)}</tbody>
    </Table>
  );
}
