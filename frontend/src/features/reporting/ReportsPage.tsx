import { useEffect, useMemo, useState } from "react";
import { useNavigate, useSearch } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Download, FileSpreadsheet, Pencil, Play, Plus, Printer, Trash2 } from "lucide-react";
import { api } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Dialog } from "@/components/ui/dialog";
import { Alert, Badge, Card, EmptyState, Input, Label, PageHeader, Select, Skeleton, Table, Td, Th } from "@/components/ui/primitives";
import { useSession } from "@/features/auth/session";
import { RepoFilter } from "@/features/review/shared";
import { useUsers } from "@/features/users/api";
import { formatDateTime } from "@/lib/utils";
import { FINDING_CATEGORIES, categoryName } from "@/lib/findingCategories";

interface Definition { filters: Record<string, string>; group_by: string; columns: string[] }
interface Report {
  id: string;
  name: string;
  description: string;
  definition: Definition;
  shared: boolean;
  schedule: "daily" | "weekly" | "monthly" | null;
  recipients: string[];
  owner: string;
  next_run_at: string | null;
  last_run_at: string | null;
  updated_at: string;
  can_edit: boolean;
}
interface Result { columns: string[]; rows: string[][]; total: number; truncated: boolean; run_at: string }
interface Meta { group_by: Record<string, string>; columns: Record<string, string> }

const defaultColumns = ["severity", "title", "repository", "location", "status", "first_seen"];

function ResultTable({ r }: { r: Result }) {
  return (
    <div className="space-y-1">
      <p className="text-[12px] text-muted-foreground">{r.total.toLocaleString()} finding{r.total === 1 ? "" : "s"}{r.truncated ? ` · showing the first ${r.rows.length.toLocaleString()}` : ""} · run {formatDateTime(r.run_at)}</p>
      {!r.rows.length ? <p className="text-[12.5px] text-muted-foreground">No findings match.</p> : (
        <div className="max-h-[60vh] overflow-auto">
          <Table>
            <thead><tr>{r.columns.map((c) => <Th key={c}>{c}</Th>)}</tr></thead>
            <tbody>{r.rows.map((row, i) => <tr key={i}>{row.map((v, j) => <Td key={j} className="max-w-80 truncate text-[12px]" >{v}</Td>)}</tr>)}</tbody>
          </Table>
        </div>
      )}
    </div>
  );
}

function ReportDialog({ open, onClose, report, meta }: { open: boolean; onClose: () => void; report: Report | null; meta: Meta }) {
  const qc = useQueryClient();
  const { can, me } = useSession();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [groupBy, setGroupBy] = useState("");
  const [columns, setColumns] = useState<string[]>(defaultColumns);
  const [shared, setShared] = useState(false);
  const [schedule, setSchedule] = useState("");
  const [recipients, setRecipients] = useState<string[]>([]);
  const users = useUsers("", "active");
  useEffect(() => {
    if (!open) return;
    setName(report?.name ?? "");
    setDescription(report?.description ?? "");
    setFilters(report?.definition.filters ?? { status: "open" });
    setGroupBy(report?.definition.group_by ?? "");
    setColumns(report?.definition.columns?.length ? report.definition.columns : defaultColumns);
    setShared(report?.shared ?? false);
    setSchedule(report?.schedule ?? "");
    setRecipients(report?.recipients ?? []);
  }, [open, report]);
  const definition = useMemo(() => ({ filters: Object.fromEntries(Object.entries(filters).filter(([, v]) => v)), group_by: groupBy, columns }), [filters, groupBy, columns]);
  const preview = useQuery({
    queryKey: ["report-preview", definition],
    queryFn: () => api<Result>("/api/v1/reports/preview", { method: "POST", body: definition }),
    enabled: open,
    retry: false,
  });
  const save = useMutation({
    mutationFn: () => api<Report>(report ? `/api/v1/reports/${report.id}` : "/api/v1/reports", {
      method: report ? "PUT" : "POST",
      body: { name, description, definition, shared, schedule: schedule || null, recipients: schedule ? (recipients.length ? recipients : [me.user.id]) : [] },
    }),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["reports"] });
      onClose();
    },
  });
  const setF = (k: string, v: string) => setFilters((x) => ({ ...x, [k]: v }));
  const toggleCol = (c: string) => setColumns((x) => (x.includes(c) ? x.filter((y) => y !== c) : [...x, c]));
  const people = users.data?.pages.flatMap((p) => p.items) ?? [];
  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()} size="xl" title={report ? `Edit ${report.name}` : "New report"}
      description="A saved view of findings. Whoever opens it sees only the findings they may access."
      footer={<><Button variant="secondary" onClick={onClose}>Cancel</Button><Button disabled={!name.trim() || save.isPending} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save report"}</Button></>}>
      <div className="grid gap-4 text-[13px] lg:grid-cols-[minmax(0,340px)_minmax(0,1fr)]">
        <div className="space-y-3">
          {save.error && <Alert>{save.error.message}</Alert>}
          <div><Label htmlFor="rp-name">Name</Label><Input id="rp-name" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} placeholder="e.g. Open critical dependencies" /></div>
          <div><Label htmlFor="rp-desc">Description</Label><Input id="rp-desc" value={description} maxLength={2000} onChange={(e) => setDescription(e.target.value)} /></div>
          <fieldset className="space-y-2 rounded-md border border-border p-3">
            <legend className="px-1 text-[12px] font-semibold">Findings</legend>
            <div className="grid grid-cols-2 gap-2">
              <div><Label htmlFor="rp-status">Status</Label>
                <Select id="rp-status" value={filters.status ?? ""} onChange={(e) => setF("status", e.target.value)}>
                  <option value="open">Open</option><option value="fixed">Fixed</option><option value="accepted_risk">Accepted risk</option><option value="false_positive">False positive</option><option value="all">All</option>
                </Select></div>
              <div><Label htmlFor="rp-sev">Severity</Label>
                <Select id="rp-sev" value={filters.severity ?? ""} onChange={(e) => setF("severity", e.target.value)}>
                  <option value="">Any</option><option value="critical">Critical</option><option value="critical,high">Critical and high</option><option value="critical,high,medium">Medium or above</option>
                </Select></div>
              <div><Label htmlFor="rp-cat">Type</Label>
                <Select id="rp-cat" value={filters.category ?? ""} onChange={(e) => setF("category", e.target.value)}>
                  <option value="">Any</option>{FINDING_CATEGORIES.filter((c) => c !== "other").map((c) => <option key={c} value={c}>{categoryName(c)}</option>)}
                </Select></div>
              <div><Label htmlFor="rp-risk">Risk</Label>
                <Select id="rp-risk" value={filters.risk_min ?? ""} onChange={(e) => setF("risk_min", e.target.value)}>
                  <option value="">Any</option><option value="75">Critical (≥ 75)</option><option value="50">High or more (≥ 50)</option>
                </Select></div>
            </div>
            <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={filters.kev === "true"} onChange={(e) => setF("kev", e.target.checked ? "true" : "")} /> Actively exploited (KEV) only</label>
            <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={filters.sla === "breached"} onChange={(e) => setF("sla", e.target.checked ? "breached" : "")} /> Past their SLA only</label>
            <div><span className="mb-1 block text-[12px] font-medium">Repository</span><RepoFilter value={filters.repository_id} onChange={(v) => setF("repository_id", v ?? "")} /></div>
          </fieldset>
          <div><Label htmlFor="rp-group">Show</Label>
            <Select id="rp-group" value={groupBy} onChange={(e) => setGroupBy(e.target.value)}>
              <option value="">A list of findings</option>
              {Object.entries(meta.group_by).map(([k, l]) => <option key={k} value={k}>Counts per {l.toLowerCase()}</option>)}
            </Select></div>
          {!groupBy && (
            <fieldset><legend className="mb-1 text-[12px] font-medium">Columns</legend>
              <div className="grid grid-cols-2 gap-x-2 gap-y-0.5">{Object.entries(meta.columns).map(([k, l]) => (
                <label key={k} className="flex items-center gap-1.5 text-[12.5px]"><input type="checkbox" className="accent-[var(--primary)]" checked={columns.includes(k)} onChange={() => toggleCol(k)} /> {l}</label>
              ))}</div>
            </fieldset>
          )}
          <label className="flex items-center gap-1.5"><input type="checkbox" className="accent-[var(--primary)]" checked={shared} onChange={(e) => setShared(e.target.checked)} /> Share with everyone who can read findings</label>
          <div><Label htmlFor="rp-sched">Deliver</Label>
            <Select id="rp-sched" value={schedule} disabled={!can("findings.export")} onChange={(e) => setSchedule(e.target.value)}>
              <option value="">Not scheduled</option><option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option>
            </Select>
            {!can("findings.export") && <p className="mt-1 text-[11.5px] text-muted-foreground">Scheduling needs the findings export permission.</p>}
          </div>
          {schedule && (
            <div><Label htmlFor="rp-rcpt" hint="(they get a link; each sees only their own scope)">Recipients</Label>
              <select id="rp-rcpt" multiple size={5} value={recipients} onChange={(e) => setRecipients(Array.from(e.target.selectedOptions).map((o) => o.value))}
                className="w-full rounded-md border border-border bg-surface p-1 text-[12.5px]">
                {(people.length ? people : [{ id: me.user.id, email: me.user.email, display_name: me.user.display_name }]).map((u) => <option key={u.id} value={u.id}>{u.display_name || u.email}</option>)}
              </select></div>
          )}
        </div>
        <div className="min-w-0">
          <h3 className="mb-1 text-[12px] font-semibold">Preview</h3>
          {preview.isError ? <Alert>{preview.error.message}</Alert> : preview.isPending ? <Skeleton className="h-48" /> : <ResultTable r={preview.data} />}
        </div>
      </div>
    </Dialog>
  );
}

export function ReportsPage() {
  const qc = useQueryClient();
  const { can } = useSession();
  const search = useSearch({ strict: false }) as { report?: string };
  const navigate = useNavigate();
  const list = useQuery({ queryKey: ["reports"], queryFn: () => api<{ items: Report[] } & Meta>("/api/v1/reports") });
  const [dialog, setDialog] = useState<{ report: Report | null } | null>(null);
  const open = search.report;
  const run = useQuery({ queryKey: ["report-run", open], queryFn: () => api<Result>(`/api/v1/reports/${open}/run`), enabled: !!open });
  const remove = useMutation({
    mutationFn: (id: string) => api(`/api/v1/reports/${id}`, { method: "DELETE" }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["reports"] }),
  });
  const current = list.data?.items.find((r) => r.id === open);
  const select = (id?: string) => void navigate({ to: "/reports", search: (id ? { report: id } : {}) as never });
  return (
    <>
      <PageHeader title="Reports" description="Saved, shareable and scheduled views of findings: filters, grouping and columns of your choice, as a table, CSV or print." actions={<Button onClick={() => setDialog({ report: null })}><Plus /> New report</Button>} />
      {remove.error && <div className="mb-3"><Alert>{remove.error.message}</Alert></div>}
      <div className="grid gap-4 xl:grid-cols-[340px_minmax(0,1fr)]">
        <Card className="print:hidden">
          {list.isError ? <div className="p-3"><Alert>{list.error.message}</Alert></div> : list.isPending ? <Skeleton className="m-3 h-24" /> : !list.data.items.length ? (
            <EmptyState icon={<FileSpreadsheet />} title="No reports yet">Create one, for example “Open critical dependencies by application”.</EmptyState>
          ) : (
            <ul className="divide-y divide-border">
              {list.data.items.map((r) => (
                <li key={r.id} className={`px-3 py-2 ${open === r.id ? "bg-primary/5" : ""}`}>
                  <div className="flex items-start gap-1">
                    <button type="button" className="min-w-0 flex-1 text-left" onClick={() => select(r.id)}>
                      <div className="truncate text-[13px] font-medium">{r.name}</div>
                      <div className="text-[11px] text-muted-foreground">{r.owner}{r.shared ? " · shared" : ""}{r.schedule ? ` · ${r.schedule}` : ""}</div>
                    </button>
                    {r.can_edit && (
                      <>
                        <Button size="icon" variant="ghost" aria-label={`Edit ${r.name}`} onClick={() => setDialog({ report: r })}><Pencil /></Button>
                        <Button size="icon" variant="ghost" aria-label={`Delete ${r.name}`} onClick={() => { if (window.confirm(`Delete the report “${r.name}”?`)) { remove.mutate(r.id); if (open === r.id) select(); } }}><Trash2 /></Button>
                      </>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Card>
        <Card className="p-4">
          {!open ? <p className="text-[13px] text-muted-foreground">Select a report to run it.</p> : (
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-2">
                <h2 className="text-[15px] font-semibold">{current?.name ?? "Report"}</h2>
                {current?.schedule && <Badge>{current.schedule}{current.next_run_at ? ` · next ${formatDateTime(current.next_run_at)}` : ""}</Badge>}
                <div className="ml-auto flex gap-2 print:hidden">
                  <Button size="sm" variant="secondary" onClick={() => void run.refetch()} disabled={run.isFetching}><Play /> Run again</Button>
                  {can("findings.export") && <a href={`/api/v1/reports/${open}/run?format=csv`} download className="inline-flex"><Button size="sm" variant="secondary"><Download /> CSV</Button></a>}
                  <Button size="sm" variant="secondary" onClick={() => window.print()}><Printer /> Print</Button>
                </div>
              </div>
              {current?.description && <p className="text-[12.5px] text-muted-foreground">{current.description}</p>}
              {run.isError ? <Alert>{run.error.message}</Alert> : run.isPending ? <Skeleton className="h-48" /> : <ResultTable r={run.data} />}
            </div>
          )}
        </Card>
      </div>
      {list.data && <ReportDialog open={!!dialog} onClose={() => setDialog(null)} report={dialog?.report ?? null} meta={list.data} />}
    </>
  );
}
